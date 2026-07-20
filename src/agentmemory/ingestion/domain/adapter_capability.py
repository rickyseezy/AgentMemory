"""Immutable adapter manifests and versioned effective evidence availability."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from uuid import UUID

from agentmemory.ingestion.domain.agent_event import (
    CaptureCapability,
    CaptureMethod,
    EventFamily,
    required_capability,
)
from agentmemory.ingestion.domain.errors import IngestionValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UUID_VERSION = 7
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_OBSERVABLE = frozenset(
    {
        CaptureMethod.NATIVE,
        CaptureMethod.INFERRED,
        CaptureMethod.EXPLICIT_TOOL_ONLY,
    }
)


@dataclass(frozen=True, slots=True, order=True)
class EvidenceAvailability:
    """Availability of one evidence class without any host-name assumption."""

    capability: CaptureCapability
    status: CaptureMethod

    @property
    def observable(self) -> bool:
        """Return whether downstream logic may expect evidence of this class."""
        return self.status in _OBSERVABLE


@dataclass(frozen=True, slots=True)
class AdapterCapabilityManifest:
    """Complete immutable capability declaration for one exact adapter version."""

    adapter_id: str
    adapter_version: str
    adapter_digest: str
    schema_major: int
    supported_families: tuple[EventFamily, ...]
    evidence_availability: tuple[EvidenceAvailability, ...]

    @classmethod
    def create(  # noqa: PLR0913 -- the public manifest identity is intentionally explicit.
        cls,
        *,
        adapter_id: str,
        adapter_version: str,
        adapter_digest: str,
        schema_major: int,
        supported_families: tuple[EventFamily, ...],
        evidence_availability: tuple[EvidenceAvailability, ...],
    ) -> AdapterCapabilityManifest:
        """Canonicalize unordered declarations without hiding duplicate entries."""
        return cls(
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            adapter_digest=adapter_digest,
            schema_major=schema_major,
            supported_families=tuple(sorted(supported_families, key=str)),
            evidence_availability=tuple(
                sorted(evidence_availability, key=lambda item: str(item.capability))
            ),
        )

    def __post_init__(self) -> None:
        """Require exact identity, completeness, ordering, and observable family evidence."""
        if _TOKEN.fullmatch(self.adapter_id) is None:
            msg = "adapter_id"
            raise IngestionValidationError.single(msg, "invalid_token")
        if _SEMVER.fullmatch(self.adapter_version) is None:
            msg = "adapter_version"
            raise IngestionValidationError.single(msg, "invalid_semver")
        if _DIGEST.fullmatch(self.adapter_digest) is None:
            msg = "adapter_digest"
            raise IngestionValidationError.single(msg, "invalid_digest")
        if self.schema_major != 1:
            msg = "schema_major"
            raise IngestionValidationError.single(msg, "unsupported")
        canonical_families = tuple(sorted(set(self.supported_families), key=str))
        if not canonical_families or canonical_families != self.supported_families:
            msg = "supported_families"
            raise IngestionValidationError.single(msg, "not_canonical")
        expected = tuple(sorted(CaptureCapability, key=str))
        actual = tuple(item.capability for item in self.evidence_availability)
        if len(actual) != len(expected) or set(actual) != set(expected):
            msg = "evidence_availability"
            raise IngestionValidationError.single(
                msg,
                "incomplete_capability_matrix",
            )
        if actual != expected:
            msg = "evidence_availability"
            raise IngestionValidationError.single(msg, "not_canonical")
        for family in self.supported_families:
            if not self.availability_for(required_capability(family)).observable:
                msg = "supported_families"
                raise IngestionValidationError.single(
                    msg,
                    "evidence_not_observable",
                )

    @property
    def capture_capabilities(self) -> tuple[CaptureCapability, ...]:
        """Return only observable capabilities for legacy event contract composition."""
        return tuple(item.capability for item in self.evidence_availability if item.observable)

    @property
    def manifest_sha256(self) -> str:
        """Return the canonical identity of the complete status matrix."""
        document = {
            "adapter_digest": self.adapter_digest,
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "evidence_availability": [
                {"capability": item.capability.value, "status": item.status.value}
                for item in self.evidence_availability
            ],
            "schema_major": self.schema_major,
            "supported_families": [family.value for family in self.supported_families],
        }
        encoded = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
        return hashlib.sha256(encoded).hexdigest()

    def availability_for(self, capability: CaptureCapability) -> EvidenceAvailability:
        """Return explicit evidence availability for a capability."""
        return _availability_map(self.evidence_availability)[capability]


@dataclass(frozen=True, slots=True)
class AdapterCapabilityObservation:
    """Append-only effective status snapshot for one registered manifest."""

    observation_id: str
    operation_id: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    capability_manifest_digest: str
    revision: int
    evidence_availability: tuple[EvidenceAvailability, ...]
    observed_at: datetime

    @classmethod
    def create(  # noqa: PLR0913 -- immutable observation evidence is explicit.
        cls,
        *,
        observation_id: str,
        operation_id: str,
        adapter_id: str,
        adapter_version: str,
        adapter_digest: str,
        capability_manifest_digest: str,
        revision: int,
        evidence_availability: tuple[EvidenceAvailability, ...],
        observed_at: datetime,
    ) -> AdapterCapabilityObservation:
        """Canonicalize a complete effective snapshot."""
        return cls(
            observation_id,
            operation_id,
            adapter_id,
            adapter_version,
            adapter_digest,
            capability_manifest_digest,
            revision,
            tuple(sorted(evidence_availability, key=lambda item: str(item.capability))),
            observed_at,
        )

    def __post_init__(self) -> None:
        """Reject malformed observation identity, revision, time, or matrix."""
        _require_uuid7(self.observation_id, "observation_id")
        if _OPERATION.fullmatch(self.operation_id) is None:
            msg = "operation_id"
            raise IngestionValidationError.single(msg, "invalid")
        if _TOKEN.fullmatch(self.adapter_id) is None:
            msg = "adapter_id"
            raise IngestionValidationError.single(msg, "invalid_token")
        if _SEMVER.fullmatch(self.adapter_version) is None:
            msg = "adapter_version"
            raise IngestionValidationError.single(msg, "invalid_semver")
        for value, field in (
            (self.adapter_digest, "adapter_digest"),
            (self.capability_manifest_digest, "capability_manifest_digest"),
        ):
            if _DIGEST.fullmatch(value) is None:
                raise IngestionValidationError.single(field, "invalid_digest")
        if self.revision < 1:
            msg = "revision"
            raise IngestionValidationError.single(msg, "out_of_range")
        expected = tuple(sorted(CaptureCapability, key=str))
        actual = tuple(item.capability for item in self.evidence_availability)
        if len(actual) != len(expected) or set(actual) != set(expected):
            msg = "evidence_availability"
            raise IngestionValidationError.single(
                msg,
                "incomplete_capability_matrix",
            )
        if actual != expected:
            msg = "evidence_availability"
            raise IngestionValidationError.single(msg, "not_canonical")
        if self.observed_at.tzinfo is None or self.observed_at.utcoffset() != UTC.utcoffset(None):
            msg = "observed_at"
            raise IngestionValidationError.single(msg, "not_utc")


@dataclass(frozen=True, slots=True)
class RegisteredAdapterCapabilities:
    """One immutable declaration paired with its latest effective observation."""

    manifest: AdapterCapabilityManifest
    observation: AdapterCapabilityObservation

    def __post_init__(self) -> None:
        """Bind exact identities and prohibit runtime fabrication or undeclared upgrades."""
        observed = self.observation
        exact_identity = (
            observed.adapter_id == self.manifest.adapter_id
            and observed.adapter_version == self.manifest.adapter_version
            and observed.adapter_digest == self.manifest.adapter_digest
            and observed.capability_manifest_digest == self.manifest.manifest_sha256
        )
        if not exact_identity:
            msg = "observation"
            raise IngestionValidationError.single(msg, "identity_mismatch")
        declared = _availability_map(self.manifest.evidence_availability)
        effective = _availability_map(observed.evidence_availability)
        for capability, base in declared.items():
            current = effective[capability]
            allowed = (
                {base.status, CaptureMethod.PERMISSION_DENIED} if base.observable else {base.status}
            )
            if current.status not in allowed:
                msg = "evidence_availability"
                raise IngestionValidationError.single(
                    msg,
                    "effective_status_exceeds_manifest",
                )

    def availability_for(self, capability: CaptureCapability) -> EvidenceAvailability:
        """Return latest effective evidence status for downstream policy decisions."""
        return _availability_map(self.observation.evidence_availability)[capability]

    def authorizes(self, family: EventFamily, method: CaptureMethod) -> bool:
        """Authorize only exact observable evidence declared for the event family."""
        capability = required_capability(family)
        availability = self.availability_for(capability)
        return (
            family in self.manifest.supported_families
            and availability.observable
            and availability.status is method
        )


class CapabilityCompatibilityImpact(StrEnum):
    """Operator impact assigned to one capability status transition."""

    INFORMATIONAL = "informational"
    DEGRADED = "degraded"
    BREAKING = "breaking"


class CapabilityChangeDisposition(StrEnum):
    """Stable outcome of a registration or effective-status command."""

    REGISTERED = "registered"
    OBSERVED = "observed"
    UNCHANGED = "unchanged"
    DUPLICATE = "duplicate"


@dataclass(frozen=True, slots=True)
class CapabilityCompatibilityWarning:
    """Content-free explanation of one status transition."""

    capability: CaptureCapability
    previous_status: CaptureMethod
    current_status: CaptureMethod
    impact: CapabilityCompatibilityImpact
    code: str


@dataclass(frozen=True, slots=True)
class CapabilityChangeResult:
    """Content-free result for one manifest or observation command."""

    registration: RegisteredAdapterCapabilities
    disposition: CapabilityChangeDisposition
    warnings: tuple[CapabilityCompatibilityWarning, ...]


def compare_capability_availability(
    previous: tuple[EvidenceAvailability, ...],
    current: tuple[EvidenceAvailability, ...],
) -> tuple[CapabilityCompatibilityWarning, ...]:
    """Return a deterministic warning for every changed capability."""
    before = _availability_map(previous)
    after = _availability_map(current)
    warnings: list[CapabilityCompatibilityWarning] = []
    for capability in sorted(CaptureCapability, key=str):
        old = before[capability]
        new = after[capability]
        if old.status is new.status:
            continue
        code, impact = _transition(old, new)
        warnings.append(
            CapabilityCompatibilityWarning(
                capability,
                old.status,
                new.status,
                impact,
                code,
            )
        )
    return tuple(warnings)


def _transition(
    previous: EvidenceAvailability,
    current: EvidenceAvailability,
) -> tuple[str, CapabilityCompatibilityImpact]:
    if current.status is CaptureMethod.PERMISSION_DENIED:
        return "permission_lost", CapabilityCompatibilityImpact.BREAKING
    if previous.status is CaptureMethod.PERMISSION_DENIED and current.observable:
        return "permission_restored", CapabilityCompatibilityImpact.INFORMATIONAL
    if previous.observable and not current.observable:
        return "signal_removed", CapabilityCompatibilityImpact.BREAKING
    if not previous.observable and current.observable:
        return "signal_added", CapabilityCompatibilityImpact.INFORMATIONAL
    ranks = MappingProxyType(
        {
            CaptureMethod.NATIVE: 3,
            CaptureMethod.INFERRED: 2,
            CaptureMethod.EXPLICIT_TOOL_ONLY: 1,
        }
    )
    impact = (
        CapabilityCompatibilityImpact.DEGRADED
        if ranks.get(current.status, 0) < ranks.get(previous.status, 0)
        else CapabilityCompatibilityImpact.INFORMATIONAL
    )
    return "capture_method_changed", impact


def _availability_map(
    values: tuple[EvidenceAvailability, ...],
) -> dict[CaptureCapability, EvidenceAvailability]:
    return {item.capability: item for item in values}


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise IngestionValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise IngestionValidationError.single(field, "invalid_uuid7")
