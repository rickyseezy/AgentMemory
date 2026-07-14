"""All-or-nothing PF-001 readiness evidence and receipt policy."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum, StrEnum
from typing import Self

from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.value_objects import (
    OperationId,
    ReleaseId,
    Sha256Digest,
    Uuid7Id,
    require_utc_microseconds,
)

MAXIMUM_EVIDENCE_AGE = timedelta(minutes=5)


class ReadinessProbe(IntEnum):
    """Closed PF-001 probe set in normative execution order."""

    SQLITE_INTEGRITY = 1
    MIGRATION_HEAD = 2
    WRITABLE_VOLUMES = 3
    GRAPH_COMPATIBILITY = 4
    KEY_ACCESS = 5
    AUDIT_APPEND = 6
    DELETION_GUARD = 7
    EXPIRED_LEASE_RECOVERY = 8
    LOCAL_PROVIDERS = 9
    SEMANTIC_WRITE_INDEX_RECALL = 10
    DEFAULT_EGRESS_DENIED = 11

    @property
    def evidence_key(self) -> str:
        """Return the Go launcher-compatible stable key."""
        return {
            ReadinessProbe.SQLITE_INTEGRITY: "sqlite_integrity",
            ReadinessProbe.MIGRATION_HEAD: "migration_head",
            ReadinessProbe.WRITABLE_VOLUMES: "writable_volumes",
            ReadinessProbe.GRAPH_COMPATIBILITY: "graph_compatibility",
            ReadinessProbe.KEY_ACCESS: "key_access",
            ReadinessProbe.AUDIT_APPEND: "audit_append",
            ReadinessProbe.DELETION_GUARD: "deletion_guard",
            ReadinessProbe.EXPIRED_LEASE_RECOVERY: "expired_lease_recovery",
            ReadinessProbe.LOCAL_PROVIDERS: "local_providers",
            ReadinessProbe.SEMANTIC_WRITE_INDEX_RECALL: "semantic_write_index_recall",
            ReadinessProbe.DEFAULT_EGRESS_DENIED: "default_egress_denied",
        }[self]


class ProbeStatus(StrEnum):
    """Closed readiness probe outcome."""

    PASSED = "passed"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ReadinessBinding:
    """Bind evidence to exactly one signed install plan and data generation."""

    operation_id: OperationId
    plan_digest: Sha256Digest
    release_id: ReleaseId
    generation_id: Uuid7Id
    manifest_digest: Sha256Digest
    compose_digest: Sha256Digest


@dataclass(frozen=True, slots=True)
class ProbeEvidence:
    """One independently observed and privacy-safe probe result."""

    probe: ReadinessProbe
    status: ProbeStatus
    binding: ReadinessBinding
    evidence_digest: Sha256Digest
    observed_at: datetime

    def __post_init__(self) -> None:
        """Normalize timestamp validation at the domain boundary."""
        require_utc_microseconds(self.observed_at)


@dataclass(frozen=True, slots=True)
class ReadinessReceipt:
    """The sole complete Core proof that may authorize release activation."""

    binding: ReadinessBinding
    evaluated_at: datetime
    results: tuple[ProbeEvidence, ...]
    digest: Sha256Digest

    @classmethod
    def create(
        cls,
        binding: ReadinessBinding,
        evaluated_at: datetime,
        results: tuple[ProbeEvidence, ...],
    ) -> Self:
        """Validate the closed gate and create a Go-compatible deterministic receipt."""
        normalized_time = require_utc_microseconds(evaluated_at)
        by_probe = {result.probe: result for result in results}
        required = tuple(ReadinessProbe)
        if len(by_probe) != len(results) or tuple(sorted(by_probe)) != required:
            msg = "readiness evidence set is incomplete or ambiguous"
            raise DomainValidationError(msg)
        for result in results:
            observed_at = require_utc_microseconds(result.observed_at)
            if result.binding != binding or result.status is not ProbeStatus.PASSED:
                msg = "readiness evidence did not pass for this binding"
                raise DomainValidationError(msg)
            if (
                observed_at > normalized_time
                or normalized_time - observed_at > MAXIMUM_EVIDENCE_AGE
            ):
                msg = "readiness evidence is stale or future-dated"
                raise DomainValidationError(msg)
        ordered = tuple(by_probe[probe] for probe in required)
        receipt_digest = Sha256Digest(
            hashlib.sha256(_canonical_bytes(binding, normalized_time, ordered)).hexdigest()
        )
        return cls(
            binding=binding, evaluated_at=normalized_time, results=ordered, digest=receipt_digest
        )


def evidence_digest(probe: ReadinessProbe, binding: ReadinessBinding, proof: str) -> Sha256Digest:
    """Bind non-secret canonical proof facts to one probe and install operation."""
    fields = (
        "agentmemory.readiness-evidence.v1",
        probe.evidence_key,
        binding.operation_id.value,
        binding.plan_digest.value,
        binding.release_id.value,
        binding.generation_id.value,
        proof,
    )
    return Sha256Digest(hashlib.sha256("\x00".join(fields).encode()).hexdigest())


def _canonical_bytes(
    binding: ReadinessBinding,
    evaluated_at: datetime,
    results: tuple[ProbeEvidence, ...],
) -> bytes:
    output = bytearray()
    for value in (
        "agentmemory.readiness-receipt.v1",
        binding.operation_id.value,
        binding.plan_digest.value,
        binding.release_id.value,
        binding.generation_id.value,
        binding.manifest_digest.value,
        binding.compose_digest.value,
    ):
        _append_field(output, value)
    output.extend(struct.pack(">Q", _unix_microseconds(evaluated_at)))
    for result in results:
        output.extend(struct.pack(">Q", result.probe.value))
        _append_field(output, result.evidence_digest.value)
        output.extend(struct.pack(">Q", _unix_microseconds(result.observed_at)))
    return bytes(output)


def _append_field(output: bytearray, value: str) -> None:
    encoded = value.encode()
    output.extend(struct.pack(">Q", len(encoded)))
    output.extend(encoded)


def _unix_microseconds(value: datetime) -> int:
    normalized = require_utc_microseconds(value)
    return int(normalized.timestamp()) * 1_000_000 + normalized.microsecond
