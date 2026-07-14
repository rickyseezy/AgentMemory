"""Strict Go-launcher-compatible readiness receipt persistence mapping."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Final, cast

from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.readiness import (
    ProbeEvidence,
    ProbeStatus,
    ReadinessBinding,
    ReadinessProbe,
    ReadinessReceipt,
)
from agentmemory.operations.domain.value_objects import (
    OperationId,
    ReleaseId,
    Sha256Digest,
    Uuid7Id,
    format_rfc3339_microseconds,
    require_utc_microseconds,
)

_RECEIPT_FIELDS: Final = {
    "schema_version",
    "operation_id",
    "plan_digest",
    "release_id",
    "generation_id",
    "manifest_digest",
    "compose_digest",
    "evaluated_at",
    "results",
    "receipt_digest",
}
_RESULT_FIELDS: Final = {
    "probe",
    "status",
    "operation_id",
    "plan_digest",
    "release_id",
    "generation_id",
    "manifest_digest",
    "compose_digest",
    "evidence_digest",
    "observed_at",
}


def encode_receipt(receipt: ReadinessReceipt) -> str:
    """Encode one complete receipt as canonical JSON without secret values."""
    binding = receipt.binding
    record = {
        "schema_version": 1,
        "operation_id": binding.operation_id.value,
        "plan_digest": binding.plan_digest.value,
        "release_id": binding.release_id.value,
        "generation_id": binding.generation_id.value,
        "manifest_digest": binding.manifest_digest.value,
        "compose_digest": binding.compose_digest.value,
        "evaluated_at": format_rfc3339_microseconds(receipt.evaluated_at),
        "results": [_encode_result(result) for result in receipt.results],
        "receipt_digest": receipt.digest.value,
    }
    return json.dumps(record, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def decode_receipt(payload: str) -> ReadinessReceipt:
    """Restore only strict canonical JSON whose deterministic digest still matches."""
    try:
        decoded: object = json.loads(payload)
    except (json.JSONDecodeError, UnicodeError) as error:
        msg = "readiness receipt JSON is invalid"
        raise DomainValidationError(msg) from error
    if not isinstance(decoded, dict):
        msg = "readiness receipt schema is invalid"
        raise DomainValidationError(msg)
    raw = cast("dict[str, object]", decoded)
    if set(raw) != _RECEIPT_FIELDS or raw.get("schema_version") != 1:
        msg = "readiness receipt schema is invalid"
        raise DomainValidationError(msg)
    binding = _binding(raw)
    raw_results = raw.get("results")
    if not isinstance(raw_results, list):
        msg = "readiness result list is invalid"
        raise DomainValidationError(msg)
    results = tuple(_decode_result(result, binding) for result in cast("list[object]", raw_results))
    evaluated_at = _parse_time(raw.get("evaluated_at"))
    restored = ReadinessReceipt.create(binding, evaluated_at, results)
    supplied_digest = _require_string(raw.get("receipt_digest"))
    if restored.digest.value != supplied_digest or encode_receipt(restored) != payload:
        msg = "readiness receipt integrity check failed"
        raise DomainValidationError(msg)
    return restored


def _encode_result(result: ProbeEvidence) -> dict[str, object]:
    binding = result.binding
    return {
        "probe": result.probe.evidence_key,
        "status": result.status.value,
        "operation_id": binding.operation_id.value,
        "plan_digest": binding.plan_digest.value,
        "release_id": binding.release_id.value,
        "generation_id": binding.generation_id.value,
        "manifest_digest": binding.manifest_digest.value,
        "compose_digest": binding.compose_digest.value,
        "evidence_digest": result.evidence_digest.value,
        "observed_at": format_rfc3339_microseconds(result.observed_at),
    }


def _decode_result(raw: object, binding: ReadinessBinding) -> ProbeEvidence:
    if not isinstance(raw, dict):
        msg = "readiness result schema is invalid"
        raise DomainValidationError(msg)
    record = cast("dict[str, object]", raw)
    if set(record) != _RESULT_FIELDS:
        msg = "readiness result schema is invalid"
        raise DomainValidationError(msg)
    result_binding = _binding(record)
    if result_binding != binding:
        msg = "readiness result binding is invalid"
        raise DomainValidationError(msg)
    probe_key = _require_string(record.get("probe"))
    try:
        probe = next(
            candidate for candidate in ReadinessProbe if candidate.evidence_key == probe_key
        )
        status = ProbeStatus(_require_string(record.get("status")))
    except (StopIteration, ValueError) as error:
        msg = "readiness result enum is invalid"
        raise DomainValidationError(msg) from error
    return ProbeEvidence(
        probe=probe,
        status=status,
        binding=binding,
        evidence_digest=Sha256Digest(_require_string(record.get("evidence_digest"))),
        observed_at=_parse_time(record.get("observed_at")),
    )


def _binding(raw: dict[str, object]) -> ReadinessBinding:
    return ReadinessBinding(
        operation_id=OperationId(_require_string(raw.get("operation_id"))),
        plan_digest=Sha256Digest(_require_string(raw.get("plan_digest"))),
        release_id=ReleaseId(_require_string(raw.get("release_id"))),
        generation_id=Uuid7Id(_require_string(raw.get("generation_id"))),
        manifest_digest=Sha256Digest(_require_string(raw.get("manifest_digest"))),
        compose_digest=Sha256Digest(_require_string(raw.get("compose_digest"))),
    )


def _parse_time(raw: object) -> datetime:
    value = _require_string(raw)
    if not value.endswith("Z"):
        msg = "readiness timestamp is not canonical UTC"
        raise DomainValidationError(msg)
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00")
    except ValueError as error:
        msg = "readiness timestamp is invalid"
        raise DomainValidationError(msg) from error
    normalized = require_utc_microseconds(parsed)
    if format_rfc3339_microseconds(normalized) != value:
        msg = "readiness timestamp is not canonical"
        raise DomainValidationError(msg)
    return normalized


def _require_string(raw: object) -> str:
    if not isinstance(raw, str):
        msg = "readiness receipt field has the wrong type"
        raise DomainValidationError(msg)
    return raw
