"""ADP-001 canonical AgentEvent domain contract tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentmemory.ingestion.domain.agent_event import (
    AdapterCapabilityDescriptor,
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
    PayloadReference,
    ResolvedAgentEventIdentity,
    format_rfc3339_microseconds,
    required_capability,
)
from agentmemory.ingestion.domain.errors import IngestionValidationError

EVENT_ID = "018f0000-0000-7000-8000-000000000101"
BRAIN_ID = "018f0000-0000-7000-8000-000000000001"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000002"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000030"
SESSION_ID = "018f0000-0000-7000-8000-000000000111"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000121"
ORDERING_KEY = "018f0000-0000-7000-8000-000000000131"
DIGEST = "a" * 64


def _payload(value: bytes = b'{"status":"observed"}') -> AgentEventData:
    return AgentEventData(value, hashlib.sha256(value).hexdigest())


def _provenance(*, adapter_id: str = "agentmemory.reference") -> AgentEventProvenance:
    return AgentEventProvenance(
        agent_host="reference",
        adapter_id=adapter_id,
        adapter_version="1.0.0",
        adapter_digest=DIGEST,
        model_id="unknown",
        session_id=SESSION_ID,
        task_id=None,
        turn_id=None,
        subagent_id=None,
        capability_manifest_digest=DIGEST,
        capture_method=CaptureMethod.NATIVE,
        source_sha256=DIGEST,
    )


def _identity(*, brain_id: str = BRAIN_ID) -> AgentEventIdentity:
    return AgentEventIdentity(
        brain_id=brain_id,
        principal_id=PRINCIPAL_ID,
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        checkout_id=CHECKOUT_ID,
        branch_name=None,
        commit_sha=None,
    )


def _event(  # noqa: PLR0913 -- test builder exposes orthogonal invalidation points.
    family: EventFamily = EventFamily.SESSION_STARTED,
    *,
    payload: AgentEventData | None = None,
    payload_reference: PayloadReference | None = None,
    occurred_at: datetime = datetime(2026, 7, 20, 10, 11, 12, 123456, tzinfo=UTC),
    provenance: AgentEventProvenance | None = None,
    capabilities: tuple[CaptureCapability, ...] | None = None,
) -> AgentEvent:
    capability = required_capability(family)
    return AgentEvent.create(
        specversion="1.0",
        event_id=EVENT_ID,
        source="urn:agentmemory:adapter:reference",
        event_type=family,
        subject=f"session/{SESSION_ID}",
        occurred_at=occurred_at,
        datacontenttype="application/json",
        dataschema=family.dataschema,
        identity=_identity(),
        provenance=provenance or _provenance(),
        correlation_id=CORRELATION_ID,
        causation_id=None,
        ordering_key=ORDERING_KEY,
        sequence=1,
        classification=Classification.INTERNAL,
        retention_policy_id="default",
        capture_capabilities=capabilities or (capability,),
        payload=payload or _payload(),
        payload_reference=payload_reference,
    )


@pytest.mark.parametrize("family", tuple(EventFamily), ids=lambda family: family.value)
def test_every_required_canonical_family_has_a_valid_fixture(family: EventFamily) -> None:
    """The normative fixture corpus must contain every closed PRD family."""
    event = _event(family)
    assert event.event_type is family
    assert event.dataschema == family.dataschema
    assert required_capability(family) in event.capture_capabilities


def test_canonical_event_preserves_every_required_envelope_dimension() -> None:
    event = _event()
    assert event.event_id == EVENT_ID
    assert event.identity == _identity()
    assert event.provenance.model_id == "unknown"
    assert event.provenance.subagent_id is None
    assert event.occurred_at.microsecond == 123456
    assert event.correlation_id == CORRELATION_ID
    assert event.ordering_key == ORDERING_KEY
    assert event.sequence == 1
    assert event.classification is Classification.INTERNAL
    assert event.retention_policy_id == "default"
    assert event.content_sha256 == _payload().content_sha256


def test_event_requires_exactly_one_data_or_dataref() -> None:
    with pytest.raises(IngestionValidationError) as missing:
        replace(_event(), payload=None)
    assert missing.value.has_field("data")

    reference = PayloadReference(f"cas://sha256/{DIGEST}", DIGEST, 128)
    with pytest.raises(IngestionValidationError) as ambiguous:
        _event(payload_reference=reference)
    assert ambiguous.value.has_field("dataref")


def test_payload_hash_mismatch_is_rejected_with_field_error_before_json_decoding() -> None:
    with pytest.raises(IngestionValidationError) as raised:
        AgentEventData(b"not-json", DIGEST)
    assert raised.value.has_field("content_sha256")
    assert raised.value.code_for("content_sha256") == "hash_mismatch"


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (b'{"duplicate":1,"duplicate":2}', "duplicate_key"),
        (b'{"value":NaN}', "non_finite_number"),
        (b'{"z":1, "a":2}', "non_canonical_json"),
        (b'{"chain_of_thought":"private"}', "prohibited_field"),
        (b"{}" * 40_000, "payload_too_large"),
    ],
)
def test_inline_json_is_strict_bounded_canonical_and_privacy_safe(value: bytes, code: str) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        _payload(value)
    assert raised.value.code_for("data") == code


def test_missing_family_capability_is_rejected() -> None:
    with pytest.raises(IngestionValidationError) as raised:
        _event(capabilities=(CaptureCapability.TOOL_LIFECYCLE,))
    assert raised.value.has_field("capture_capabilities")
    assert raised.value.code_for("capture_capabilities") == "missing_capability"


def test_capabilities_must_be_unique_and_canonically_sorted() -> None:
    with pytest.raises(IngestionValidationError) as duplicate:
        _event(
            capabilities=(
                CaptureCapability.SESSION_LIFECYCLE,
                CaptureCapability.SESSION_LIFECYCLE,
            )
        )
    assert duplicate.value.has_field("capture_capabilities")


@given(st.text(min_size=0, max_size=80).filter(lambda value: value != EVENT_ID))
def test_schema_fuzz_rejects_noncanonical_uuid7_event_ids(value: str) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        replace(_event(), event_id=value)
    assert raised.value.has_field("id")


@pytest.mark.parametrize(
    "occurred_at",
    [
        datetime(2026, 7, 20, 10, 11, 12, tzinfo=UTC).replace(tzinfo=None),
    ],
)
def test_occurrence_time_requires_aware_utc(occurred_at: datetime) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        _event(occurred_at=occurred_at)
    assert raised.value.has_field("time")


def test_payload_binding_and_identity_are_immutable() -> None:
    event = _event()
    with pytest.raises(AttributeError):
        event.event_id = "different"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (b"", "payload_empty"),
        (b'"\xff"', "invalid_utf8"),
        (b'{"unterminated":', "invalid_json"),
        (b'{"items":[{"scratchpad":"private"}]}', "prohibited_field"),
    ],
)
def test_payload_failure_matrix_is_field_addressable(value: bytes, code: str) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        _payload(value)
    assert raised.value.code_for("data") == code


@pytest.mark.parametrize(
    ("uri", "digest", "size", "field", "code"),
    [
        (f"cas://sha256/{'0' * 64}", "0" * 64, 1, "content_sha256", "invalid_digest"),
        ("cas://sha256/wrong", DIGEST, 1, "dataref", "digest_binding_mismatch"),
        (f"cas://sha256/{DIGEST}", DIGEST, 0, "dataref", "invalid_size"),
    ],
)
def test_payload_reference_failure_matrix(
    uri: str,
    digest: str,
    size: int,
    field: str,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        PayloadReference(uri, digest, size)
    assert raised.value.code_for(field) == code


def test_optional_scope_and_provenance_are_validated_when_observed() -> None:
    identity = replace(_identity(), branch_name="main", commit_sha="b" * 40)
    assert identity.branch_name == "main"
    resolved = ResolvedAgentEventIdentity(
        BRAIN_ID,
        PRINCIPAL_ID,
        PROJECT_ID,
        REPOSITORY_ID,
        CHECKOUT_ID,
    )
    assert resolved.checkout_id == CHECKOUT_ID
    provenance = replace(
        _provenance(),
        task_id="018f0000-0000-7000-8000-000000000141",
        turn_id="018f0000-0000-7000-8000-000000000142",
        subagent_id="018f0000-0000-7000-8000-000000000143",
    )
    assert provenance.subagent_id is not None


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"branch_name": "bad\nbranch"}, "branch_name"),
        ({"commit_sha": "not-a-commit"}, "commit_sha"),
        ({"checkout_id": "not-a-uuid"}, "checkout_id"),
    ],
)
def test_optional_scope_failure_matrix(changes: dict[str, str], field: str) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        replace(_identity(), **changes)
    assert raised.value.has_field(field)


@pytest.mark.parametrize(
    ("changes", "field"),
    [
        ({"adapter_version": "latest"}, "adapter_version"),
        ({"adapter_digest": "0" * 64}, "adapter_digest"),
        ({"task_id": "not-a-uuid"}, "task_id"),
        ({"model_id": ""}, "model_id"),
    ],
)
def test_provenance_failure_matrix(changes: dict[str, str], field: str) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        replace(_provenance(), **cast("Any", changes))
    assert raised.value.has_field(field)


@pytest.mark.parametrize(
    ("changes", "field", "code"),
    [
        ({"adapter_version": "latest"}, "adapter_version", "invalid_semver"),
        ({"adapter_digest": "0" * 64}, "adapter_digest", "invalid_digest"),
        ({"schema_major": 2}, "schema_major", "unsupported_major"),
        ({"supported_families": ()}, "supported_families", "empty"),
        ({"capture_capabilities": ()}, "capture_capabilities", "empty"),
        (
            {
                "supported_families": (EventFamily.SESSION_STARTED,),
                "capture_capabilities": (CaptureCapability.TOOL_LIFECYCLE,),
            },
            "capture_capabilities",
            "missing_family_capability",
        ),
    ],
)
def test_adapter_descriptor_failure_matrix(
    changes: dict[str, object],
    field: str,
    code: str,
) -> None:
    values: dict[str, object] = {
        "adapter_id": "agentmemory.reference",
        "adapter_version": "1.0.0",
        "adapter_digest": DIGEST,
        "schema_major": 1,
        "supported_families": (EventFamily.SESSION_STARTED,),
        "capture_capabilities": (CaptureCapability.SESSION_LIFECYCLE,),
    }
    values.update(changes)
    with pytest.raises(IngestionValidationError) as raised:
        AdapterCapabilityDescriptor(**cast("Any", values))
    assert raised.value.code_for(field) == code


@pytest.mark.parametrize(
    ("changes", "field", "code"),
    [
        ({"specversion": "0.3"}, "specversion", "unsupported"),
        ({"source": "not-a-uri"}, "source", "invalid_uri"),
        ({"datacontenttype": "text/plain"}, "datacontenttype", "unsupported"),
        ({"dataschema": "urn:wrong"}, "dataschema", "type_mismatch"),
        ({"sequence": 2**64}, "sequence", "out_of_range"),
        ({"retention_policy_id": "INVALID"}, "retention_policy_id", "invalid_token"),
    ],
)
def test_envelope_failure_matrix(
    changes: dict[str, object],
    field: str,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError) as raised:
        replace(_event(), **cast("Any", changes))
    assert raised.value.code_for(field) == code


def test_known_causation_and_rfc3339_format_are_preserved() -> None:
    event = replace(
        _event(),
        causation_id="018f0000-0000-7000-8000-000000000151",
    )
    assert event.causation_id is not None
    assert format_rfc3339_microseconds(event.occurred_at) == "2026-07-20T10:11:12.123456Z"


def test_rfc3339_formatter_rejects_naive_time() -> None:
    naive = datetime(2026, 7, 20, tzinfo=UTC).replace(tzinfo=None)
    with pytest.raises(IngestionValidationError) as raised:
        format_rfc3339_microseconds(naive)
    assert raised.value.has_field("time")
