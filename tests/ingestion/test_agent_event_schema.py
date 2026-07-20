"""ADP-001 generated boundary-schema and fuzz tests."""

from __future__ import annotations

import hashlib
import json

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentmemory.ingestion.adapters.inbound.agent_event_schema import (
    AgentEventEnvelopeV1,
    agent_event_json_schema,
    parse_agent_event_json,
)
from agentmemory.ingestion.domain.agent_event import EventFamily, required_capability
from agentmemory.ingestion.domain.errors import IngestionValidationError

DIGEST = "a" * 64
PAYLOAD = {"status": "observed"}
PAYLOAD_BYTES = b'{"status":"observed"}'


def _document(family: EventFamily = EventFamily.SESSION_STARTED) -> dict[str, object]:
    return {
        "specversion": "1.0",
        "id": "018f0000-0000-7000-8000-000000000101",
        "source": "urn:agentmemory:adapter:reference",
        "type": family.value,
        "subject": "session/018f0000-0000-7000-8000-000000000111",
        "time": "2026-07-20T10:11:12.123456Z",
        "datacontenttype": "application/json",
        "dataschema": family.dataschema,
        "brain_id": "018f0000-0000-7000-8000-000000000001",
        "principal_id": "018f0000-0000-7000-8000-000000000002",
        "project_id": "018f0000-0000-7000-8000-000000000010",
        "repository_id": "018f0000-0000-7000-8000-000000000020",
        "checkout_id": None,
        "branch_name": None,
        "commit_sha": None,
        "agent_host": "reference",
        "adapter_id": "agentmemory.reference",
        "adapter_version": "1.0.0",
        "adapter_digest": DIGEST,
        "model_id": "unknown",
        "session_id": "018f0000-0000-7000-8000-000000000111",
        "task_id": None,
        "turn_id": None,
        "subagent_id": None,
        "correlation_id": "018f0000-0000-7000-8000-000000000121",
        "causation_id": None,
        "ordering_key": "018f0000-0000-7000-8000-000000000131",
        "sequence": 1,
        "classification": "internal",
        "retention_policy_id": "default",
        "capture_capabilities": ["session_lifecycle"],
        "capture_method": "native",
        "capability_manifest_digest": DIGEST,
        "source_sha256": DIGEST,
        "content_sha256": hashlib.sha256(PAYLOAD_BYTES).hexdigest(),
        "data": PAYLOAD,
    }


def _canonical_bytes(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def test_generated_type_is_shared_by_adapter_and_daemon_boundary() -> None:
    event = parse_agent_event_json(_canonical_bytes(_document()))
    assert event.event_type is EventFamily.SESSION_STARTED
    envelope = AgentEventEnvelopeV1.from_domain(event)
    assert envelope.to_domain() == event
    first = envelope.to_canonical_json()
    assert first == envelope.to_canonical_json()
    assert b'"dataref"' not in first
    assert parse_agent_event_json(first) == event


@pytest.mark.parametrize("family", tuple(EventFamily), ids=lambda family: family.value)
def test_every_family_fixture_crosses_the_generated_schema_boundary(
    family: EventFamily,
) -> None:
    document = _document(family)
    document["capture_capabilities"] = [required_capability(family).value]
    event = parse_agent_event_json(_canonical_bytes(document))
    assert event.event_type is family


def test_generated_json_schema_is_closed_versioned_and_models_data_xor_dataref() -> None:
    schema = agent_event_json_schema()
    assert schema["$id"] == "urn:agentmemory:schema:agent-event-envelope:v1"
    assert schema["additionalProperties"] is False
    assert len(schema["oneOf"]) == 2
    assert AgentEventEnvelopeV1.model_fields["type"].annotation is EventFamily


def test_boundary_reports_all_pydantic_field_violations_without_echoing_values() -> None:
    document = _document()
    document["id"] = "invalid"
    sensitive_value = "do" + "-not-echo"
    document["unexpected_field"] = sensitive_value
    with pytest.raises(IngestionValidationError) as raised:
        parse_agent_event_json(_canonical_bytes(document))
    assert raised.value.has_field("id")
    assert raised.value.has_field("unexpected_field")
    assert sensitive_value not in str(raised.value)


def test_boundary_rejects_duplicate_keys_before_model_validation() -> None:
    raw = _canonical_bytes(_document())[:-1] + b',"id":"duplicate"}'
    with pytest.raises(IngestionValidationError) as raised:
        parse_agent_event_json(raw)
    assert raised.value.code_for("$json") == "duplicate_key"


def test_dataref_schema_round_trip_and_digest_binding() -> None:
    document = _document()
    document.pop("data")
    document["content_sha256"] = DIGEST
    document["dataref"] = {
        "uri": f"cas://sha256/{DIGEST}",
        "content_sha256": DIGEST,
        "size_bytes": 70_000,
    }
    event = parse_agent_event_json(_canonical_bytes(document))
    assert event.payload_reference is not None
    assert AgentEventEnvelopeV1.from_domain(event).to_domain() == event

    document["content_sha256"] = "b" * 64
    with pytest.raises(IngestionValidationError) as raised:
        parse_agent_event_json(_canonical_bytes(document))
    assert raised.value.code_for("content_sha256") == "dataref_digest_mismatch"


@pytest.mark.parametrize("mode", ["missing", "both"])
def test_schema_enforces_data_xor_dataref(mode: str) -> None:
    document = _document()
    if mode == "both":
        document["dataref"] = {
            "uri": f"cas://sha256/{DIGEST}",
            "content_sha256": DIGEST,
            "size_bytes": 1,
        }
    else:
        document.pop("data")
    with pytest.raises(IngestionValidationError) as raised:
        parse_agent_event_json(_canonical_bytes(document))
    assert raised.value.has_field("$")


def test_impossible_calendar_time_is_a_field_level_domain_error() -> None:
    document = _document()
    document["time"] = "2026-02-31T10:11:12.123456Z"
    with pytest.raises(IngestionValidationError) as raised:
        parse_agent_event_json(_canonical_bytes(document))
    assert raised.value.code_for("time") == "invalid_rfc3339"


@given(st.binary(min_size=0, max_size=512))
def test_schema_fuzz_never_leaks_parser_exceptions_or_accepts_arbitrary_bytes(raw: bytes) -> None:
    with pytest.raises(IngestionValidationError):
        parse_agent_event_json(raw)
