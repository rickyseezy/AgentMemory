"""Generated-style strict AgentEvent v1 transport type shared by all boundaries."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Annotated, Any, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    ValidationError,
    model_validator,
)

from agentmemory.ingestion.domain.agent_event import (
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
    PayloadReference,
    format_rfc3339_microseconds,
)
from agentmemory.ingestion.domain.errors import FieldViolation, IngestionValidationError

_TIME_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
_UUID7_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
Uuid7Text = Annotated[str, StringConstraints(pattern=_UUID7_PATTERN)]


class PayloadReferenceV1(BaseModel):
    """Strict wire representation of an encrypted CAS reference."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    uri: str
    content_sha256: str
    size_bytes: int


class AgentEventEnvelopeV1(BaseModel):
    """CloudEvents-compatible AgentEvent v1 schema-generated boundary type."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        json_schema_extra={
            "$id": "urn:agentmemory:schema:agent-event-envelope:v1",
            "oneOf": [
                {"required": ["data"], "not": {"required": ["dataref"]}},
                {"required": ["dataref"], "not": {"required": ["data"]}},
            ],
        },
    )

    specversion: str
    id: Uuid7Text
    source: str
    type: EventFamily
    subject: str
    time: str = Field(pattern=_TIME_PATTERN)
    datacontenttype: str
    dataschema: str
    brain_id: Uuid7Text
    principal_id: Uuid7Text
    project_id: Uuid7Text
    repository_id: Uuid7Text
    checkout_id: Uuid7Text | None
    branch_name: str | None
    commit_sha: str | None
    agent_host: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    model_id: str
    session_id: Uuid7Text
    task_id: Uuid7Text | None
    turn_id: Uuid7Text | None
    subagent_id: Uuid7Text | None
    correlation_id: Uuid7Text
    causation_id: Uuid7Text | None
    ordering_key: Uuid7Text
    sequence: int | None
    classification: Classification
    retention_policy_id: str
    capture_capabilities: tuple[CaptureCapability, ...]
    capture_method: CaptureMethod
    capability_manifest_digest: str
    source_sha256: str
    content_sha256: str
    data: JsonValue | None = None
    dataref: PayloadReferenceV1 | None = None

    @model_validator(mode="after")
    def require_payload_xor_reference(self) -> Self:
        """Model the CloudEvents data/dataref exclusive choice."""
        if (self.data is None) == (self.dataref is None):
            msg = "exactly one of data or dataref is required"
            raise ValueError(msg)
        return self

    def to_domain(self) -> AgentEvent:
        """Translate validated transport fields into framework-free domain values."""
        payload = None
        if self.data is not None:
            raw_data = _canonical_json_bytes(self.data)
            payload = AgentEventData(raw_data, self.content_sha256)
        reference = None
        if self.dataref is not None:
            if self.dataref.content_sha256 != self.content_sha256:
                msg = "content_sha256"
                raise IngestionValidationError.single(msg, "dataref_digest_mismatch")
            reference = PayloadReference(
                self.dataref.uri,
                self.dataref.content_sha256,
                self.dataref.size_bytes,
            )
        return AgentEvent.create(
            specversion=self.specversion,
            event_id=self.id,
            source=self.source,
            event_type=self.type,
            subject=self.subject,
            occurred_at=_parse_time(self.time),
            datacontenttype=self.datacontenttype,
            dataschema=self.dataschema,
            identity=AgentEventIdentity(
                brain_id=self.brain_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
                repository_id=self.repository_id,
                checkout_id=self.checkout_id,
                branch_name=self.branch_name,
                commit_sha=self.commit_sha,
            ),
            provenance=AgentEventProvenance(
                agent_host=self.agent_host,
                adapter_id=self.adapter_id,
                adapter_version=self.adapter_version,
                adapter_digest=self.adapter_digest,
                model_id=self.model_id,
                session_id=self.session_id,
                task_id=self.task_id,
                turn_id=self.turn_id,
                subagent_id=self.subagent_id,
                capability_manifest_digest=self.capability_manifest_digest,
                capture_method=self.capture_method,
                source_sha256=self.source_sha256,
            ),
            correlation_id=self.correlation_id,
            causation_id=self.causation_id,
            ordering_key=self.ordering_key,
            sequence=self.sequence,
            classification=self.classification,
            retention_policy_id=self.retention_policy_id,
            capture_capabilities=self.capture_capabilities,
            payload=payload,
            payload_reference=reference,
        )

    def to_canonical_json(self) -> bytes:
        """Serialize stable producer bytes while omitting only the unused payload arm."""
        excluded = {"dataref"} if self.data is not None else {"data"}
        document = self.model_dump(mode="json", exclude=excluded)
        return _canonical_json_bytes(cast("JsonValue", document))

    @classmethod
    def from_domain(cls, event: AgentEvent) -> AgentEventEnvelopeV1:
        """Create the exact shared wire type from an immutable domain event."""
        data: JsonValue | None = None
        dataref: PayloadReferenceV1 | None = None
        if event.payload is not None:
            data = json.loads(event.payload.value)
        if event.payload_reference is not None:
            dataref = PayloadReferenceV1(
                uri=event.payload_reference.uri,
                content_sha256=event.payload_reference.content_sha256,
                size_bytes=event.payload_reference.size_bytes,
            )
        identity = event.identity
        provenance = event.provenance
        return cls(
            specversion=event.specversion,
            id=event.event_id,
            source=event.source,
            type=event.event_type,
            subject=event.subject,
            time=format_rfc3339_microseconds(event.occurred_at),
            datacontenttype=event.datacontenttype,
            dataschema=event.dataschema,
            brain_id=identity.brain_id,
            principal_id=identity.principal_id,
            project_id=identity.project_id,
            repository_id=identity.repository_id,
            checkout_id=identity.checkout_id,
            branch_name=identity.branch_name,
            commit_sha=identity.commit_sha,
            agent_host=provenance.agent_host,
            adapter_id=provenance.adapter_id,
            adapter_version=provenance.adapter_version,
            adapter_digest=provenance.adapter_digest,
            model_id=provenance.model_id,
            session_id=provenance.session_id,
            task_id=provenance.task_id,
            turn_id=provenance.turn_id,
            subagent_id=provenance.subagent_id,
            correlation_id=event.correlation_id,
            causation_id=event.causation_id,
            ordering_key=event.ordering_key,
            sequence=event.sequence,
            classification=event.classification,
            retention_policy_id=event.retention_policy_id,
            capture_capabilities=event.capture_capabilities,
            capture_method=provenance.capture_method,
            capability_manifest_digest=provenance.capability_manifest_digest,
            source_sha256=provenance.source_sha256,
            content_sha256=event.content_sha256,
            data=data,
            dataref=dataref,
        )


class AgentEventBatchV1(BaseModel):
    """Strict bounded replay batch accepted by the local Core."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    events: tuple[AgentEventEnvelopeV1, ...] = Field(min_length=1, max_length=100)


def parse_agent_event_json(raw: bytes) -> AgentEvent:
    """Validate strict JSON/schema/domain invariants at any producer or daemon boundary."""
    _preflight_strict_json(raw)
    try:
        envelope = AgentEventEnvelopeV1.model_validate_json(raw, strict=True)
    except ValidationError as error:
        violations = tuple(
            FieldViolation(
                ".".join(str(part) for part in item["loc"]) or "$",
                str(item["type"]),
            )
            for item in error.errors(include_input=False, include_url=False)
        )
        raise IngestionValidationError(violations) from error
    return envelope.to_domain()


def parse_agent_event_batch_json(raw: bytes) -> tuple[AgentEvent, ...]:
    """Validate a bounded batch completely before any item can be persisted."""
    _preflight_strict_json(raw)
    try:
        batch = AgentEventBatchV1.model_validate_json(raw, strict=True)
    except ValidationError as error:
        violations = tuple(
            FieldViolation(
                ".".join(str(part) for part in item["loc"]) or "$",
                str(item["type"]),
            )
            for item in error.errors(include_input=False, include_url=False)
        )
        raise IngestionValidationError(violations) from error
    return tuple(envelope.to_domain() for envelope in batch.events)


def agent_event_json_schema() -> dict[str, Any]:
    """Emit the immutable JSON Schema used to generate language-specific SDK types."""
    return AgentEventEnvelopeV1.model_json_schema(mode="validation")


def render_agent_event_json_schema() -> bytes:
    """Render deterministic checked-in contract bytes for SDK generators."""
    return (
        json.dumps(
            agent_event_json_schema(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _preflight_strict_json(raw: bytes) -> None:
    def reject_constant(_: str) -> None:
        msg = "$json"
        raise IngestionValidationError.single(msg, "non_finite_number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                msg = "$json"
                raise IngestionValidationError.single(msg, "duplicate_key")
            result[key] = value
        return result

    try:
        json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except UnicodeDecodeError as error:
        msg = "$json"
        raise IngestionValidationError.single(msg, "invalid_utf8") from error
    except json.JSONDecodeError as error:
        msg = "$json"
        raise IngestionValidationError.single(msg, "invalid_json") from error


def _parse_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)
    except ValueError as error:
        msg = "time"
        raise IngestionValidationError.single(msg, "invalid_rfc3339") from error


def _canonical_json_bytes(value: JsonValue) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
