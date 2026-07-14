"""Core value, receipt, and deterministic serialization contracts."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from agentmemory.operations.adapters.outbound.receipt_codec import decode_receipt, encode_receipt
from agentmemory.operations.domain.bootstrap import BootstrapRequest
from agentmemory.operations.domain.errors import DomainValidationError, ErrorCode, OperationError
from agentmemory.operations.domain.readiness import (
    ProbeEvidence,
    ProbeStatus,
    ReadinessProbe,
    ReadinessReceipt,
    evidence_digest,
)
from agentmemory.operations.domain.value_objects import (
    OperationId,
    ReleaseId,
    Sha256Digest,
    Uuid7Id,
    format_rfc3339_microseconds,
    require_utc_microseconds,
)
from agentmemory.shared.clock import SystemClock
from tests.core.support import NOW, binding, bootstrap_request, digest, receipt


@pytest.mark.parametrize(
    ("factory", "value"),
    [
        (Sha256Digest, "0" * 64),
        (Sha256Digest, "A" * 64),
        (OperationId, "bad operation"),
        (ReleaseId, "Invalid"),
        (Uuid7Id, "018f0000-0000-4000-8000-000000000001"),
        (Uuid7Id, "not-a-uuid"),
    ],
)
def test_value_objects_reject_noncanonical_values(
    factory: type[Sha256Digest | OperationId | ReleaseId | Uuid7Id],
    value: str,
) -> None:
    with pytest.raises(DomainValidationError):
        factory(value)


def test_time_contract_requires_aware_utc_and_uses_go_fraction_shape() -> None:
    with pytest.raises(DomainValidationError):
        require_utc_microseconds(datetime(2026, 1, 1))  # noqa: DTZ001 -- Deliberately naive.
    assert format_rfc3339_microseconds(NOW) == "2026-07-14T08:09:10.123456Z"
    assert format_rfc3339_microseconds(NOW.replace(microsecond=120000)) == (
        "2026-07-14T08:09:10.12Z"
    )
    assert format_rfc3339_microseconds(NOW.replace(microsecond=0)) == "2026-07-14T08:09:10Z"


def test_bootstrap_request_rejects_ambiguous_name() -> None:
    valid = bootstrap_request()
    with pytest.raises(DomainValidationError):
        BootstrapRequest(
            command_id=valid.command_id,
            installation_id=valid.installation_id,
            owner_principal_id=valid.owner_principal_id,
            owner_grant_id=valid.owner_grant_id,
            owner_subject_digest=valid.owner_subject_digest,
            brain_id=valid.brain_id,
            brain_name="Personal Brain",
            release_digest=valid.release_digest,
            generation_id=valid.generation_id,
        )


def test_receipt_is_ordered_deterministic_and_go_compatible() -> None:
    expected_digest = "cc4397d20213bad210ade64cd7f3b9a2eac5365b87d4c0f2568d7ea49a384bfa"
    value = receipt()
    assert value.digest.value == expected_digest
    assert tuple(result.probe for result in value.results) == tuple(ReadinessProbe)
    assert decode_receipt(encode_receipt(value)) == value
    assert encode_receipt(value) == encode_receipt(receipt())


def test_receipt_rejects_missing_failed_mismatched_stale_and_future_evidence() -> None:
    complete = receipt()
    with pytest.raises(DomainValidationError):
        ReadinessReceipt.create(complete.binding, NOW, complete.results[:-1])
    with pytest.raises(DomainValidationError):
        ReadinessReceipt.create(
            complete.binding,
            NOW,
            (replace(complete.results[0], status=ProbeStatus.FAILED), *complete.results[1:]),
        )
    with pytest.raises(DomainValidationError):
        ReadinessReceipt.create(
            complete.binding,
            NOW,
            (replace(complete.results[0], binding=binding("different")), *complete.results[1:]),
        )
    with pytest.raises(DomainValidationError):
        ReadinessReceipt.create(
            complete.binding,
            NOW,
            (
                replace(complete.results[0], observed_at=NOW - timedelta(minutes=6)),
                *complete.results[1:],
            ),
        )
    with pytest.raises(DomainValidationError):
        ReadinessReceipt.create(
            complete.binding,
            NOW,
            (
                replace(complete.results[0], observed_at=NOW + timedelta(seconds=1)),
                *complete.results[1:],
            ),
        )


def test_receipt_codec_rejects_tamper_schema_type_and_noncanonical_json() -> None:
    payload = encode_receipt(receipt())
    raw_object: object = json.loads(payload)
    assert isinstance(raw_object, dict)
    raw = cast("dict[str, object]", raw_object)
    raw["compose_digest"] = digest("tampered").value
    tampered = json.dumps(raw, separators=(",", ":"), sort_keys=True)
    with pytest.raises(DomainValidationError):
        decode_receipt(tampered)
    with pytest.raises(DomainValidationError):
        decode_receipt("[]")
    with pytest.raises(DomainValidationError):
        decode_receipt("not-json")
    with pytest.raises(DomainValidationError):
        decode_receipt(payload.replace(":", ": ", 1))


def test_receipt_codec_rejects_every_closed_schema_and_time_boundary() -> None:
    payload = encode_receipt(receipt())

    def fresh() -> dict[str, object]:
        value: object = json.loads(payload)
        assert isinstance(value, dict)
        return cast("dict[str, object]", value)

    unknown_top_level = fresh()
    unknown_top_level["unknown"] = True
    results_not_a_list = fresh()
    results_not_a_list["results"] = "invalid"
    result_not_an_object = fresh()
    result_not_an_object["results"] = [1]
    incomplete_result = fresh()
    raw_results = incomplete_result["results"]
    assert isinstance(raw_results, list)
    first_result = cast("list[object]", raw_results)[0]
    assert isinstance(first_result, dict)
    cast("dict[str, object]", first_result).pop("probe")
    non_utc_time = fresh()
    non_utc_time["evaluated_at"] = "2026-07-14T08:09:10+00:00"
    noncanonical_time = fresh()
    noncanonical_time["evaluated_at"] = "2026-07-14T08:09:10.1234560Z"
    wrong_field_type = fresh()
    wrong_field_type["operation_id"] = 1

    for invalid in (
        unknown_top_level,
        results_not_a_list,
        result_not_an_object,
        incomplete_result,
        non_utc_time,
        noncanonical_time,
        wrong_field_type,
    ):
        with pytest.raises(DomainValidationError):
            decode_receipt(json.dumps(invalid, separators=(",", ":"), sort_keys=True))


def test_evidence_digest_binds_probe_operation_and_proof() -> None:
    readiness_binding = binding()
    base = evidence_digest(ReadinessProbe.KEY_ACCESS, readiness_binding, "usable")
    assert base != evidence_digest(ReadinessProbe.AUDIT_APPEND, readiness_binding, "usable")
    assert base != evidence_digest(ReadinessProbe.KEY_ACCESS, binding("other"), "usable")
    assert base != evidence_digest(ReadinessProbe.KEY_ACCESS, readiness_binding, "not-usable")


def test_operation_error_exposes_only_safe_typed_fields() -> None:
    error = OperationError(ErrorCode.CONFLICT, "safe conflict", retryable=True)
    assert str(error) == "safe conflict"
    assert error.code is ErrorCode.CONFLICT
    assert error.retryable
    assert SystemClock().now().tzinfo is UTC


def test_probe_evidence_rejects_naive_observation_time() -> None:
    with pytest.raises(DomainValidationError):
        ProbeEvidence(
            probe=ReadinessProbe.KEY_ACCESS,
            status=ProbeStatus.PASSED,
            binding=binding(),
            evidence_digest=digest("evidence"),
            observed_at=datetime(2026, 7, 14),  # noqa: DTZ001 -- Deliberately naive.
        )
