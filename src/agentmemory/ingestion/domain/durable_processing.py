"""ING-001 durable outbox recovery and terminal projection values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from agentmemory.ingestion.domain.errors import IngestionValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_OWNER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$")
_MAX_PAYLOAD_BYTES = 64 * 1024


class ProcessingDisposition(StrEnum):
    """Closed per-attempt result exposed to the worker."""

    IDLE = "idle"
    COMPLETED = "completed"
    REPAIR_REQUIRED = "repair_required"
    RETRY_SCHEDULED = "retry_scheduled"


@dataclass(frozen=True, slots=True)
class ClaimedOutboxMessage:
    """One bounded message owned by an exact, unexpired processing lease."""

    message_id: str
    event_id: str
    brain_id: str
    topic: str
    payload: bytes
    payload_sha256: str
    attempt: int
    lease_owner: str
    lease_until_microseconds: int

    def __post_init__(self) -> None:
        """Reject malformed queue state before canonical content is accessed."""
        for value, field_name in (
            (self.message_id, "message_id"),
            (self.event_id, "event_id"),
            (self.brain_id, "brain_id"),
        ):
            if _UUID7.fullmatch(value) is None:
                raise IngestionValidationError.single(field_name, "invalid_id")
        expected_topic = f"am.local.{self.brain_id}.ingestion.agent-event-appended.v1"
        if self.topic != expected_topic:
            field_name = "topic"
            raise IngestionValidationError.single(field_name, "scope_mismatch")
        if not self.payload or len(self.payload) > _MAX_PAYLOAD_BYTES:
            field_name = "payload"
            raise IngestionValidationError.single(field_name, "invalid_size")
        if _DIGEST.fullmatch(self.payload_sha256) is None:
            field_name = "payload_sha256"
            raise IngestionValidationError.single(field_name, "invalid_digest")
        if self.attempt < 1:
            field_name = "attempt"
            raise IngestionValidationError.single(field_name, "out_of_range")
        if _OWNER.fullmatch(self.lease_owner) is None:
            field_name = "lease_owner"
            raise IngestionValidationError.single(field_name, "invalid")
        if self.lease_until_microseconds < 0:
            field_name = "lease_until_microseconds"
            raise IngestionValidationError.single(field_name, "out_of_range")


@dataclass(frozen=True, slots=True)
class VerifiedEventProjection:
    """Integrity-bound terminal projection receipt material."""

    event_id: str
    canonical_sha256: str
    projection_sha256: str

    def __post_init__(self) -> None:
        """Bind a valid canonical event to a deterministic terminal digest."""
        if _UUID7.fullmatch(self.event_id) is None:
            field_name = "event_id"
            raise IngestionValidationError.single(field_name, "invalid_id")
        for value, field_name in (
            (self.canonical_sha256, "canonical_sha256"),
            (self.projection_sha256, "projection_sha256"),
        ):
            if _DIGEST.fullmatch(value) is None:
                raise IngestionValidationError.single(field_name, "invalid_digest")


@dataclass(frozen=True, slots=True)
class DurableProcessingResult:
    """Content-free outcome for one bounded worker iteration."""

    message_id: str | None
    event_id: str | None
    disposition: ProcessingDisposition

    def __post_init__(self) -> None:
        """Allow missing identities only for an idle queue."""
        idle = self.disposition is ProcessingDisposition.IDLE
        if idle != (self.message_id is None and self.event_id is None):
            field_name = "processing_result"
            raise IngestionValidationError.single(field_name, "invalid_identity")
        if not idle:
            for value, field_name in (
                (self.message_id, "message_id"),
                (self.event_id, "event_id"),
            ):
                if not isinstance(value, str) or _UUID7.fullmatch(value) is None:
                    raise IngestionValidationError.single(field_name, "invalid_id")

    @classmethod
    def idle(cls) -> DurableProcessingResult:
        """Return the sole valid content-free idle result."""
        return cls(None, None, ProcessingDisposition.IDLE)
