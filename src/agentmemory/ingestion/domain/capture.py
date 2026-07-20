"""ADP-002 durable-capture values with no infrastructure dependencies."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.errors import IngestionValidationError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.ingestion.domain.agent_event import AgentEvent, ResolvedAgentEventIdentity

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_NONCE_BYTES = 12
_TAG_BYTES = 16


class AppendDisposition(StrEnum):
    """Safe per-item result returned to a capture hook."""

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    DEFERRED = "deferred"


@dataclass(frozen=True, slots=True)
class AdmittedAgentEvent:
    """Validated event paired with authoritative scope and daemon time evidence."""

    event: AgentEvent
    identity: ResolvedAgentEventIdentity
    ingested_at: datetime
    clock_skew_microseconds: int


@dataclass(frozen=True, slots=True)
class EncryptedAgentEvent:
    """One AES-256-GCM envelope and wrapped per-event data key."""

    envelope_version: int
    algorithm: str
    brain_key_id: str
    data_key_id: str
    payload_nonce: bytes
    ciphertext: bytes
    wrapped_data_key_nonce: bytes
    wrapped_data_key: bytes
    aad_sha256: str
    canonical_sha256: str

    def __post_init__(self) -> None:
        """Reject incomplete or structurally unsafe encrypted envelopes."""
        if self.envelope_version != 1:
            field = "envelope_version"
            raise IngestionValidationError.single(field, "unsupported")
        if self.algorithm != "AES-256-GCM":
            field = "algorithm"
            raise IngestionValidationError.single(field, "unsupported")
        if not self.brain_key_id or _UUID7.fullmatch(self.data_key_id) is None:
            field = "key_id"
            raise IngestionValidationError.single(field, "invalid")
        if len(self.payload_nonce) != _NONCE_BYTES:
            field = "payload_nonce"
            raise IngestionValidationError.single(field, "invalid_length")
        if len(self.wrapped_data_key_nonce) != _NONCE_BYTES:
            field = "wrapped_data_key_nonce"
            raise IngestionValidationError.single(field, "invalid_length")
        if len(self.ciphertext) <= _TAG_BYTES or len(self.wrapped_data_key) <= _TAG_BYTES:
            field = "ciphertext"
            raise IngestionValidationError.single(field, "invalid_length")
        if _DIGEST.fullmatch(self.aad_sha256) is None:
            field = "aad_sha256"
            raise IngestionValidationError.single(field, "invalid_digest")
        if _DIGEST.fullmatch(self.canonical_sha256) is None:
            field = "canonical_sha256"
            raise IngestionValidationError.single(field, "invalid_digest")


@dataclass(frozen=True, slots=True)
class AppendAgentEventResult:
    """Content-free durable-capture acknowledgement."""

    event_id: str
    disposition: AppendDisposition
    ingested_at_microseconds: int
