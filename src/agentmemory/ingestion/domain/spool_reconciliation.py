"""ADP-005 interruption-recovery values and deterministic acknowledgement policy."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from agentmemory.ingestion.domain.errors import IngestionValidationError

_MAX_EVENT_BYTES = 96 * 1024
_MAX_SIGNED_64 = 2**63 - 1


class SpoolUploadDisposition(StrEnum):
    """Closed per-item outcome returned by the recovered local Core."""

    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    RETRYABLE = "retryable"
    REJECTED = "rejected"
    CONFLICT = "conflict"

    @property
    def durable(self) -> bool:
        """Return whether Core proved this exact event is durably present."""
        return self in {self.ACCEPTED, self.DUPLICATE}


@dataclass(frozen=True, slots=True)
class SpoolRecord:
    """One decrypted pending event with a repository-owned delivery coordinate."""

    event_id: str
    ordering_key: str
    spool_sequence: int
    event_sequence: int | None
    canonical_event: bytes

    def __post_init__(self) -> None:
        """Reject records that cannot be bounded, ordered, or correlated safely."""
        if not self.event_id or not self.ordering_key:
            field = "identity"
            raise IngestionValidationError.single(field, "required")
        if self.spool_sequence < 1:
            field = "spool_sequence"
            raise IngestionValidationError.single(field, "out_of_range")
        if self.event_sequence is not None and self.event_sequence < 0:
            field = "event_sequence"
            raise IngestionValidationError.single(field, "out_of_range")
        if not self.canonical_event or len(self.canonical_event) > _MAX_EVENT_BYTES:
            field = "canonical_event"
            raise IngestionValidationError.single(field, "invalid_size")

    @property
    def sequence(self) -> int | None:
        """Return the original canonical sequence for ADP-002 compatibility."""
        return self.event_sequence


@dataclass(frozen=True, slots=True)
class ClockSkew:
    """Server-observed occurrence delta retained without rewriting event time."""

    microseconds: int
    server_ingested_at_microseconds: int

    def __post_init__(self) -> None:
        """Require signed bounded skew and a valid daemon ingestion instant."""
        if isinstance(self.microseconds, bool) or not (
            -_MAX_SIGNED_64 - 1 <= self.microseconds <= _MAX_SIGNED_64
        ):
            field = "clock_skew_microseconds"
            raise IngestionValidationError.single(field, "out_of_range")
        if (
            isinstance(self.server_ingested_at_microseconds, bool)
            or self.server_ingested_at_microseconds < 0
            or self.server_ingested_at_microseconds >= 2**63
        ):
            field = "server_ingested_at_microseconds"
            raise IngestionValidationError.single(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class SpoolUploadResult:
    """One content-free Core result for an attempted spool record."""

    event_id: str
    disposition: SpoolUploadDisposition
    ingested_at_microseconds: int | None = None
    clock_skew_microseconds: int | None = None

    def __post_init__(self) -> None:
        """Require complete time evidence exactly for durable outcomes."""
        if not self.event_id:
            field = "event_id"
            raise IngestionValidationError.single(field, "required")
        ingested_at = self.ingested_at_microseconds
        clock_skew = self.clock_skew_microseconds
        evidence = (ingested_at, clock_skew)
        if self.disposition.durable:
            if (
                not isinstance(ingested_at, int)
                or isinstance(ingested_at, bool)
                or not isinstance(clock_skew, int)
                or isinstance(clock_skew, bool)
            ):
                field = "time_evidence"
                raise IngestionValidationError.single(field, "required")
            ClockSkew(clock_skew, ingested_at)
        elif any(value is not None for value in evidence):
            field = "time_evidence"
            raise IngestionValidationError.single(field, "forbidden")


@dataclass(frozen=True, slots=True)
class SpoolAcknowledgement:
    """A durable prefix item authorized for ciphertext erasure and watermark advance."""

    event_id: str
    ordering_key: str
    spool_sequence: int
    disposition: SpoolUploadDisposition
    clock_skew: ClockSkew

    def __post_init__(self) -> None:
        """Prevent non-durable or invalid coordinates from reaching a repository."""
        if not self.event_id or not self.ordering_key or self.spool_sequence < 1:
            field = "acknowledgement"
            raise IngestionValidationError.single(field, "invalid")
        if not self.disposition.durable:
            field = "disposition"
            raise IngestionValidationError.single(field, "not_durable")


def select_acknowledgements(
    records: tuple[SpoolRecord, ...],
    results: tuple[SpoolUploadResult, ...],
) -> tuple[SpoolAcknowledgement, ...]:
    """Select only each ordering key's contiguous durable response prefix."""
    expected_ids = tuple(record.event_id for record in records)
    result_ids = tuple(result.event_id for result in results)
    if len(set(expected_ids)) != len(expected_ids):
        field = "records"
        raise IngestionValidationError.single(field, "duplicate_event_id")
    if len(set(result_ids)) != len(result_ids) or set(result_ids) != set(expected_ids):
        field = "upload_results"
        raise IngestionValidationError.single(field, "identity_mismatch")
    by_id = {result.event_id: result for result in results}
    blocked: set[str] = set()
    acknowledgements: list[SpoolAcknowledgement] = []
    for record in records:
        result = by_id[record.event_id]
        if record.ordering_key in blocked:
            continue
        if not result.disposition.durable:
            blocked.add(record.ordering_key)
            continue
        if result.ingested_at_microseconds is None or result.clock_skew_microseconds is None:
            raise AssertionError  # pragma: no cover - SpoolUploadResult invariant.
        acknowledgements.append(
            SpoolAcknowledgement(
                record.event_id,
                record.ordering_key,
                record.spool_sequence,
                result.disposition,
                ClockSkew(result.clock_skew_microseconds, result.ingested_at_microseconds),
            )
        )
    return tuple(acknowledgements)
