"""ADP-001 canonical CloudEvents-compatible AgentEvent domain contract."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import cast
from urllib.parse import urlsplit
from uuid import UUID

from agentmemory.ingestion.domain.errors import IngestionValidationError

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_MAX_DATA_BYTES = 65_536
_MAX_TEXT = 1024
_MAX_MODEL_ID = 256
_C0_CONTROL_LIMIT = 32
_DELETE_CONTROL = 127
_PROHIBITED_PAYLOAD_FIELDS = frozenset(
    {
        "chain_of_thought",
        "hidden_reasoning",
        "private_reasoning",
        "reasoning_trace",
        "scratchpad",
    }
)

type JsonScalar = None | bool | int | float | str
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]


class EventFamily(StrEnum):
    """Closed canonical observable event families required by the PRD."""

    SESSION_STARTED = "agentmemory.session.started.v1"
    SESSION_COMPLETED = "agentmemory.session.completed.v1"
    PROMPT_RECEIVED = "agentmemory.prompt.received.v1"
    TURN_STARTED = "agentmemory.turn.started.v1"
    TURN_COMPLETED = "agentmemory.turn.completed.v1"
    TASK_STARTED = "agentmemory.task.started.v1"
    TASK_CHECKPOINTED = "agentmemory.task.checkpointed.v1"
    TASK_COMPLETED = "agentmemory.task.completed.v1"
    TOOL_STARTED = "agentmemory.tool.started.v1"
    TOOL_COMPLETED = "agentmemory.tool.completed.v1"
    TOOL_FAILED = "agentmemory.tool.failed.v1"
    FILE_READ = "agentmemory.file.read.v1"
    FILE_CHANGED = "agentmemory.file.changed.v1"
    FILE_DELETED = "agentmemory.file.deleted.v1"
    FILE_RENAMED = "agentmemory.file.renamed.v1"
    COMMAND_COMPLETED = "agentmemory.command.completed.v1"
    TEST_COMPLETED = "agentmemory.test.completed.v1"
    GIT_COMMIT_OBSERVED = "agentmemory.git.commit.observed.v1"
    CHECKOUT_CHANGED = "agentmemory.checkout.changed.v1"
    BRANCH_CHANGED = "agentmemory.branch.changed.v1"
    CONTEXT_INJECTED = "agentmemory.context.injected.v1"
    MEMORY_FEEDBACK_RECORDED = "agentmemory.memory.feedback.recorded.v1"
    MEMORY_CORRECTED = "agentmemory.memory.corrected.v1"
    ATTEMPT_STARTED = "agentmemory.attempt.started.v1"
    ATTEMPT_COMPLETED = "agentmemory.attempt.completed.v1"
    OUTCOME_OBSERVED = "agentmemory.outcome.observed.v1"
    ARTIFACT_REVERTED = "agentmemory.artifact.reverted.v1"
    INCIDENT_RECORDED = "agentmemory.incident.recorded.v1"
    FEEDBACK_RECORDED = "agentmemory.feedback.recorded.v1"
    LEARNING_CANDIDATE_CREATED = "agentmemory.learning.candidate_created.v1"
    LEARNING_REVIEWED = "agentmemory.learning.reviewed.v1"
    EVALUATION_COMPLETED = "agentmemory.evaluation.completed.v1"
    PROCEDURE_INJECTED = "agentmemory.procedure.injected.v1"
    PROCEDURE_APPLIED = "agentmemory.procedure.applied.v1"
    PROCEDURE_VALIDATION_COMPLETED = "agentmemory.procedure.validation_completed.v1"
    PROCEDURE_ROLLED_BACK = "agentmemory.procedure.rolled_back.v1"

    @property
    def schema_name(self) -> str:
        """Return the immutable schema token carried by dataschema."""
        return self.value.removeprefix("agentmemory.").removesuffix(".v1").replace(".", "-")

    @property
    def dataschema(self) -> str:
        """Return the immutable canonical schema URI for this family."""
        return f"urn:agentmemory:schema:agent-event:{self.schema_name}:v1"


class CaptureCapability(StrEnum):
    """Closed observable lifecycle capabilities used by canonical events."""

    SESSION_LIFECYCLE = "session_lifecycle"
    PROMPT_CONTENT = "prompt_content"
    TURN_LIFECYCLE = "turn_lifecycle"
    TASK_LIFECYCLE = "task_lifecycle"
    TOOL_LIFECYCLE = "tool_lifecycle"
    FILE_OBSERVATION = "file_observation"
    COMMAND_OBSERVATION = "command_observation"
    TEST_OBSERVATION = "test_observation"
    VCS_OBSERVATION = "vcs_observation"
    CONTEXT_INJECTION = "context_injection"
    MEMORY_FEEDBACK = "memory_feedback"
    ATTEMPT_LIFECYCLE = "attempt_lifecycle"
    OUTCOME_OBSERVATION = "outcome_observation"
    ARTIFACT_OBSERVATION = "artifact_observation"
    INCIDENT_OBSERVATION = "incident_observation"
    EXPLICIT_FEEDBACK = "explicit_feedback"
    LEARNING_LIFECYCLE = "learning_lifecycle"
    EVALUATION_OBSERVATION = "evaluation_observation"
    PROCEDURE_LIFECYCLE = "procedure_lifecycle"


class CaptureMethod(StrEnum):
    """How the host made an observation available."""

    NATIVE = "native"
    INFERRED = "inferred"
    EXPLICIT_TOOL_ONLY = "explicit_tool_only"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"


class Classification(StrEnum):
    """Ascending information restriction applied before persistence."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    LOCAL_ONLY = "local_only"


_REQUIRED_CAPABILITY = MappingProxyType(
    {
        EventFamily.SESSION_STARTED: CaptureCapability.SESSION_LIFECYCLE,
        EventFamily.SESSION_COMPLETED: CaptureCapability.SESSION_LIFECYCLE,
        EventFamily.PROMPT_RECEIVED: CaptureCapability.PROMPT_CONTENT,
        EventFamily.TURN_STARTED: CaptureCapability.TURN_LIFECYCLE,
        EventFamily.TURN_COMPLETED: CaptureCapability.TURN_LIFECYCLE,
        EventFamily.TASK_STARTED: CaptureCapability.TASK_LIFECYCLE,
        EventFamily.TASK_CHECKPOINTED: CaptureCapability.TASK_LIFECYCLE,
        EventFamily.TASK_COMPLETED: CaptureCapability.TASK_LIFECYCLE,
        EventFamily.TOOL_STARTED: CaptureCapability.TOOL_LIFECYCLE,
        EventFamily.TOOL_COMPLETED: CaptureCapability.TOOL_LIFECYCLE,
        EventFamily.TOOL_FAILED: CaptureCapability.TOOL_LIFECYCLE,
        EventFamily.FILE_READ: CaptureCapability.FILE_OBSERVATION,
        EventFamily.FILE_CHANGED: CaptureCapability.FILE_OBSERVATION,
        EventFamily.FILE_DELETED: CaptureCapability.FILE_OBSERVATION,
        EventFamily.FILE_RENAMED: CaptureCapability.FILE_OBSERVATION,
        EventFamily.COMMAND_COMPLETED: CaptureCapability.COMMAND_OBSERVATION,
        EventFamily.TEST_COMPLETED: CaptureCapability.TEST_OBSERVATION,
        EventFamily.GIT_COMMIT_OBSERVED: CaptureCapability.VCS_OBSERVATION,
        EventFamily.CHECKOUT_CHANGED: CaptureCapability.VCS_OBSERVATION,
        EventFamily.BRANCH_CHANGED: CaptureCapability.VCS_OBSERVATION,
        EventFamily.CONTEXT_INJECTED: CaptureCapability.CONTEXT_INJECTION,
        EventFamily.MEMORY_FEEDBACK_RECORDED: CaptureCapability.MEMORY_FEEDBACK,
        EventFamily.MEMORY_CORRECTED: CaptureCapability.MEMORY_FEEDBACK,
        EventFamily.ATTEMPT_STARTED: CaptureCapability.ATTEMPT_LIFECYCLE,
        EventFamily.ATTEMPT_COMPLETED: CaptureCapability.ATTEMPT_LIFECYCLE,
        EventFamily.OUTCOME_OBSERVED: CaptureCapability.OUTCOME_OBSERVATION,
        EventFamily.ARTIFACT_REVERTED: CaptureCapability.ARTIFACT_OBSERVATION,
        EventFamily.INCIDENT_RECORDED: CaptureCapability.INCIDENT_OBSERVATION,
        EventFamily.FEEDBACK_RECORDED: CaptureCapability.EXPLICIT_FEEDBACK,
        EventFamily.LEARNING_CANDIDATE_CREATED: CaptureCapability.LEARNING_LIFECYCLE,
        EventFamily.LEARNING_REVIEWED: CaptureCapability.LEARNING_LIFECYCLE,
        EventFamily.EVALUATION_COMPLETED: CaptureCapability.EVALUATION_OBSERVATION,
        EventFamily.PROCEDURE_INJECTED: CaptureCapability.PROCEDURE_LIFECYCLE,
        EventFamily.PROCEDURE_APPLIED: CaptureCapability.PROCEDURE_LIFECYCLE,
        EventFamily.PROCEDURE_VALIDATION_COMPLETED: CaptureCapability.PROCEDURE_LIFECYCLE,
        EventFamily.PROCEDURE_ROLLED_BACK: CaptureCapability.PROCEDURE_LIFECYCLE,
    }
)


def required_capability(family: EventFamily) -> CaptureCapability:
    """Return the evidence capability required by a canonical family."""
    return _REQUIRED_CAPABILITY[family]


@dataclass(frozen=True, slots=True)
class AgentEventData:
    """Bounded canonical inline JSON bytes and their producer content hash."""

    value: bytes
    content_sha256: str

    def __post_init__(self) -> None:
        """Require hash-bound strict canonical JSON without hidden reasoning."""
        if not _valid_digest(self.content_sha256) or not self.verify():
            msg = "content_sha256"
            raise IngestionValidationError.single(msg, "hash_mismatch")
        if not self.value:
            msg = "data"
            raise IngestionValidationError.single(msg, "payload_empty")
        if len(self.value) > _MAX_DATA_BYTES:
            msg = "data"
            raise IngestionValidationError.single(msg, "payload_too_large")
        decoded = _decode_strict_json(self.value)
        if _contains_prohibited_field(decoded):
            msg = "data"
            raise IngestionValidationError.single(msg, "prohibited_field")
        if _canonical_json_bytes(decoded) != self.value:
            msg = "data"
            raise IngestionValidationError.single(msg, "non_canonical_json")

    def verify(self) -> bool:
        """Recalculate the payload hash without trusting producer metadata."""
        return hashlib.sha256(self.value).hexdigest() == self.content_sha256


@dataclass(frozen=True, slots=True)
class PayloadReference:
    """Immutable content-addressed payload reference, digest, and byte size."""

    uri: str
    content_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        """Require the CAS URI and digest to bind the same content identity."""
        if not _valid_digest(self.content_sha256):
            msg = "content_sha256"
            raise IngestionValidationError.single(msg, "invalid_digest")
        if self.uri != f"cas://sha256/{self.content_sha256}":
            msg = "dataref"
            raise IngestionValidationError.single(msg, "digest_binding_mismatch")
        if self.size_bytes < 1:
            msg = "dataref"
            raise IngestionValidationError.single(msg, "invalid_size")


@dataclass(frozen=True, slots=True)
class AgentEventIdentity:
    """Untrusted producer-claimed scope awaiting daemon identity resolution."""

    brain_id: str
    principal_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    branch_name: str | None
    commit_sha: str | None

    def __post_init__(self) -> None:
        """Validate claimed identifiers without granting them authority."""
        for stable_id, field in (
            (self.brain_id, "brain_id"),
            (self.principal_id, "principal_id"),
            (self.project_id, "project_id"),
            (self.repository_id, "repository_id"),
        ):
            _require_uuid7(stable_id, field)
        if self.checkout_id is not None:
            _require_uuid7(self.checkout_id, "checkout_id")
        if self.branch_name is not None:
            _require_text(self.branch_name, "branch_name", 255)
        if self.commit_sha is not None and _COMMIT.fullmatch(self.commit_sha) is None:
            msg = "commit_sha"
            raise IngestionValidationError.single(msg, "invalid_commit")


@dataclass(frozen=True, slots=True)
class ResolvedAgentEventIdentity:
    """Daemon-resolved authoritative scope used by later persistence."""

    brain_id: str
    principal_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None

    def __post_init__(self) -> None:
        """Require stable resolved identity values."""
        for stable_id, field in (
            (self.brain_id, "brain_id"),
            (self.principal_id, "principal_id"),
            (self.project_id, "project_id"),
            (self.repository_id, "repository_id"),
        ):
            _require_uuid7(stable_id, field)
        if self.checkout_id is not None:
            _require_uuid7(self.checkout_id, "checkout_id")


@dataclass(frozen=True, slots=True)
class AgentEventProvenance:
    """Observable host, adapter, model, session, and subagent provenance."""

    agent_host: str
    adapter_id: str
    adapter_version: str
    adapter_digest: str
    model_id: str
    session_id: str
    task_id: str | None
    turn_id: str | None
    subagent_id: str | None
    capability_manifest_digest: str
    capture_method: CaptureMethod
    source_sha256: str

    def __post_init__(self) -> None:
        """Require explicit unknowns and cryptographically bound adapter evidence."""
        _require_token(self.agent_host, "agent_host")
        _require_token(self.adapter_id, "adapter_id")
        if _SEMVER.fullmatch(self.adapter_version) is None:
            msg = "adapter_version"
            raise IngestionValidationError.single(msg, "invalid_semver")
        for digest, field in (
            (self.adapter_digest, "adapter_digest"),
            (self.capability_manifest_digest, "capability_manifest_digest"),
            (self.source_sha256, "source_sha256"),
        ):
            if not _valid_digest(digest):
                raise IngestionValidationError.single(field, "invalid_digest")
        _require_text(self.model_id, "model_id", _MAX_MODEL_ID)
        _require_uuid7(self.session_id, "session_id")
        for optional_id, field in (
            (self.task_id, "task_id"),
            (self.turn_id, "turn_id"),
            (self.subagent_id, "subagent_id"),
        ):
            if optional_id is not None:
                _require_uuid7(optional_id, field)


@dataclass(frozen=True, slots=True)
class AgentEvent:
    """One immutable canonical CloudEvents-compatible agent observation."""

    specversion: str
    event_id: str
    source: str
    event_type: EventFamily
    subject: str
    occurred_at: datetime
    datacontenttype: str
    dataschema: str
    identity: AgentEventIdentity
    provenance: AgentEventProvenance
    correlation_id: str
    causation_id: str | None
    ordering_key: str
    sequence: int | None
    classification: Classification
    retention_policy_id: str
    capture_capabilities: tuple[CaptureCapability, ...]
    payload: AgentEventData | None
    payload_reference: PayloadReference | None

    @classmethod
    def create(  # noqa: PLR0913 -- Canonical envelope fields are intentionally explicit.
        cls,
        *,
        specversion: str,
        event_id: str,
        source: str,
        event_type: EventFamily,
        subject: str,
        occurred_at: datetime,
        datacontenttype: str,
        dataschema: str,
        identity: AgentEventIdentity,
        provenance: AgentEventProvenance,
        correlation_id: str,
        causation_id: str | None,
        ordering_key: str,
        sequence: int | None,
        classification: Classification,
        retention_policy_id: str,
        capture_capabilities: tuple[CaptureCapability, ...],
        payload: AgentEventData | None,
        payload_reference: PayloadReference | None,
    ) -> AgentEvent:
        """Construct an event through the same invariants used by dataclass replacement."""
        return cls(
            specversion,
            event_id,
            source,
            event_type,
            subject,
            occurred_at,
            datacontenttype,
            dataschema,
            identity,
            provenance,
            correlation_id,
            causation_id,
            ordering_key,
            sequence,
            classification,
            retention_policy_id,
            capture_capabilities,
            payload,
            payload_reference,
        )

    def __post_init__(self) -> None:
        """Validate all immutable envelope invariants before use or persistence."""
        _validate_cloud_event_envelope(self)
        _validate_event_payload(self)

    @property
    def content_sha256(self) -> str:
        """Return the content identity regardless of inline/reference storage."""
        if self.payload is not None:
            return self.payload.content_sha256
        if self.payload_reference is None:  # pragma: no cover - constructor invariant.
            raise AssertionError
        return self.payload_reference.content_sha256

    @property
    def semantic_digest(self) -> str:
        """Compare canonical meaning while excluding adapter-specific provenance."""
        document: JsonValue = {
            "capture_capabilities": [item.value for item in self.capture_capabilities],
            "classification": self.classification.value,
            "content_sha256": self.content_sha256,
            "correlation_id": self.correlation_id,
            "event_type": self.event_type.value,
            "identity": {
                "brain_id": self.identity.brain_id,
                "checkout_id": self.identity.checkout_id,
                "commit_sha": self.identity.commit_sha,
                "principal_id": self.identity.principal_id,
                "project_id": self.identity.project_id,
                "repository_id": self.identity.repository_id,
            },
            "occurred_at": format_rfc3339_microseconds(self.occurred_at),
            "ordering_key": self.ordering_key,
            "retention_policy_id": self.retention_policy_id,
            "sequence": self.sequence,
            "subject": self.subject,
        }
        return hashlib.sha256(_canonical_json_bytes(document)).hexdigest()


def _validate_cloud_event_envelope(event: AgentEvent) -> None:
    """Validate identity, time, source, schema, and ordering envelope fields."""
    _require_uuid7(event.event_id, "id")
    _require_uuid7(event.correlation_id, "correlation_id")
    _require_uuid7(event.ordering_key, "ordering_key")
    if event.causation_id is not None:
        _require_uuid7(event.causation_id, "causation_id")
    if event.specversion != "1.0":
        msg = "specversion"
        raise IngestionValidationError.single(msg, "unsupported")
    parsed_source = urlsplit(event.source)
    if (
        not parsed_source.scheme
        or len(event.source) > _MAX_TEXT
        or parsed_source.username is not None
    ):
        msg = "source"
        raise IngestionValidationError.single(msg, "invalid_uri")
    _require_text(event.subject, "subject", _MAX_TEXT)
    if event.occurred_at.tzinfo is None or event.occurred_at.utcoffset() != UTC.utcoffset(None):
        msg = "time"
        raise IngestionValidationError.single(msg, "not_utc")
    if event.datacontenttype != "application/json":
        msg = "datacontenttype"
        raise IngestionValidationError.single(msg, "unsupported")
    if event.dataschema != event.event_type.dataschema:
        msg = "dataschema"
        raise IngestionValidationError.single(msg, "type_mismatch")
    _require_token(event.retention_policy_id, "retention_policy_id")
    if event.sequence is not None and not 1 <= event.sequence <= (2**64 - 1):
        msg = "sequence"
        raise IngestionValidationError.single(msg, "out_of_range")


def _validate_event_payload(event: AgentEvent) -> None:
    """Validate exclusive payload binding and declared family capabilities."""
    if (event.payload is None) == (event.payload_reference is None):
        field = "data" if event.payload is None else "dataref"
        raise IngestionValidationError.single(field, "exactly_one_required")
    canonical_capabilities = tuple(sorted(set(event.capture_capabilities), key=str))
    if not canonical_capabilities or canonical_capabilities != event.capture_capabilities:
        msg = "capture_capabilities"
        raise IngestionValidationError.single(msg, "not_canonical")
    if required_capability(event.event_type) not in canonical_capabilities:
        msg = "capture_capabilities"
        raise IngestionValidationError.single(msg, "missing_capability")


def format_rfc3339_microseconds(value: datetime) -> str:
    """Serialize one aware UTC timestamp with mandatory microseconds and Z."""
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        msg = "time"
        raise IngestionValidationError.single(msg, "not_utc")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise IngestionValidationError.single(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise IngestionValidationError.single(field, "invalid_uuid7")


def _require_token(value: str, field: str) -> None:
    if _TOKEN.fullmatch(value) is None:
        raise IngestionValidationError.single(field, "invalid_token")


def _require_text(value: str, field: str, maximum: int) -> None:
    if not value or len(value) > maximum or _has_control(value):
        raise IngestionValidationError.single(field, "invalid_text")


def _valid_digest(value: str) -> bool:
    return _DIGEST.fullmatch(value) is not None and set(value) != {"0"}


def _has_control(value: str) -> bool:
    return any(
        ord(character) < _C0_CONTROL_LIMIT or ord(character) == _DELETE_CONTROL
        for character in value
    )


def _decode_strict_json(value: bytes) -> JsonValue:
    def reject_constant(_: str) -> None:
        msg = "data"
        raise IngestionValidationError.single(msg, "non_finite_number")

    def unique_object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {}
        for key, item in pairs:
            if key in result:
                msg = "data"
                raise IngestionValidationError.single(msg, "duplicate_key")
            result[key] = item
        return result

    try:
        decoded = json.loads(
            value,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
        return cast("JsonValue", decoded)
    except UnicodeDecodeError as error:
        msg = "data"
        raise IngestionValidationError.single(msg, "invalid_utf8") from error
    except json.JSONDecodeError as error:
        msg = "data"
        raise IngestionValidationError.single(msg, "invalid_json") from error


def _contains_prohibited_field(value: JsonValue) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).casefold() in _PROHIBITED_PAYLOAD_FIELDS or _contains_prohibited_field(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_prohibited_field(item) for item in value)
    return False


def _canonical_json_bytes(value: JsonValue) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
