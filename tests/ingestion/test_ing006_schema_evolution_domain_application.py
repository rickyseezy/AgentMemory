"""ING-006 golden upcast, compatibility, quarantine, and resume tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, override

import pytest

from agentmemory.ingestion.application.schema_evolution import (
    EventUpcasterRegistry,
    EvolveEventSchemaHandler,
    GetEventSchemaMigrationProgressHandler,
    ResumeEventSchemaMigrationHandler,
)
from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.domain.schema_evolution import (
    EventSchemaDocument,
    EventSchemaKey,
    EventSchemaOutcome,
    EventSchemaSource,
    JsonValue,
    SchemaEvolutionDisposition,
    SchemaMigrationProgress,
    SchemaMigrationState,
    SchemaQuarantineReason,
    UpcastStepEvidence,
    canonical_document,
    extension_fields,
)
from tests.ingestion.adp002_support import EVENT_ID

if TYPE_CHECKING:
    from collections.abc import Mapping


def wire(version: int, **extra: JsonValue) -> bytes:
    document: dict[str, JsonValue] = {
        "id": EVENT_ID,
        "schema_family": "agent_event",
        "schema_major": 1,
        "schema_version": version,
        "status": "observed",
        **extra,
    }
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


@dataclass(frozen=True, slots=True)
class V1ToV2:
    source: EventSchemaKey = field(default_factory=lambda: EventSchemaKey("agent_event", 1, 1))
    target: EventSchemaKey = field(default_factory=lambda: EventSchemaKey("agent_event", 1, 2))
    upcaster_id: str = "agent_event.v1_to_v2"
    known_source_fields: frozenset[str] = frozenset(
        {"id", "schema_family", "schema_major", "schema_version", "status"}
    )

    def transform(self, fields: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        result = dict(fields)
        result["lifecycle_status"] = result.pop("status")
        return result


@dataclass(frozen=True, slots=True)
class V2ToV3:
    source: EventSchemaKey = field(default_factory=lambda: EventSchemaKey("agent_event", 1, 2))
    target: EventSchemaKey = field(default_factory=lambda: EventSchemaKey("agent_event", 1, 3))
    upcaster_id: str = "agent_event.v2_to_v3"
    known_source_fields: frozenset[str] = frozenset(
        {
            "id",
            "schema_family",
            "schema_major",
            "schema_version",
            "lifecycle_status",
        }
    )

    def transform(self, fields: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        result = dict(fields)
        result["lifecycle"] = {"status": result.pop("lifecycle_status")}
        return result


def registry() -> EventUpcasterRegistry:
    return EventUpcasterRegistry(
        (EventSchemaKey("agent_event", 1, 3),),
        (V1ToV2(), V2ToV3()),
    )


def test_golden_bytes_chain_every_adjacent_version_and_preserve_unknown_fields() -> None:
    original = wire(1, vendor_extension={"opaque": [1, 2, 3]})
    outcome = EvolveEventSchemaHandler(registry()).execute(original)
    assert outcome.disposition is SchemaEvolutionDisposition.UPCASTED
    assert outcome.derived_bytes == (
        b'{"id":"018f0000-0000-7000-8000-000000000101",'
        b'"lifecycle":{"status":"observed"},"schema_family":"agent_event",'
        b'"schema_major":1,"schema_version":3,'
        b'"vendor_extension":{"opaque":[1,2,3]}}'
    )
    assert [item.upcaster_id for item in outcome.steps] == [
        "agent_event.v1_to_v2",
        "agent_event.v2_to_v3",
    ]
    assert EventSchemaDocument.decode(original).canonical_bytes == original


def test_current_version_round_trips_byte_canonically_without_transform() -> None:
    current = wire(3, lifecycle={"status": "observed"}, future_addition=True)
    outcome = EvolveEventSchemaHandler(registry()).execute(current)
    assert outcome.disposition is SchemaEvolutionDisposition.CURRENT
    assert outcome.derived_bytes == current
    assert outcome.steps == ()


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (
            json.dumps(
                {
                    "id": EVENT_ID,
                    "schema_family": "agent_event",
                    "schema_major": 2,
                    "schema_version": 1,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
            SchemaQuarantineReason.UNSUPPORTED_MAJOR,
        ),
        (wire(4), SchemaQuarantineReason.FUTURE_VERSION),
    ],
)
def test_breaking_major_and_future_revision_are_quarantined_without_derived_bytes(
    raw: bytes,
    reason: SchemaQuarantineReason,
) -> None:
    outcome = EvolveEventSchemaHandler(registry()).execute(raw)
    assert outcome.disposition is SchemaEvolutionDisposition.QUARANTINED
    assert outcome.quarantine_reason is reason
    assert outcome.derived_bytes is None


@dataclass(frozen=True, slots=True)
class DropsExtension(V1ToV2):
    @override
    def transform(self, fields: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        return {
            "id": fields["id"],
            "schema_family": "agent_event",
            "schema_major": 1,
            "schema_version": 2,
            "lifecycle_status": fields["status"],
        }


def test_extension_loss_is_quarantined_instead_of_silently_accepted() -> None:
    configured = EventUpcasterRegistry(
        (EventSchemaKey("agent_event", 1, 2),),
        (DropsExtension(),),
    )
    outcome = EvolveEventSchemaHandler(configured).execute(wire(1, unknown="retain me"))
    assert outcome.quarantine_reason is SchemaQuarantineReason.EXTENSION_LOSS


def test_registry_rejects_leaps_duplicates_and_incomplete_chains() -> None:
    with pytest.raises(IngestionValidationError):
        EventUpcasterRegistry(
            (EventSchemaKey("agent_event", 1, 3),),
            (V1ToV2(),),
        )
    with pytest.raises(IngestionValidationError):
        EventUpcasterRegistry(
            (EventSchemaKey("agent_event", 1, 2),),
            (V1ToV2(), V1ToV2()),
        )


@pytest.mark.parametrize(
    ("family", "major", "version"),
    [
        ("Agent Event", 1, 1),
        ("agent_event", 0, 1),
        ("agent_event", 1, 0),
    ],
)
def test_schema_key_rejects_noncanonical_coordinates(
    family: str,
    major: int,
    version: int,
) -> None:
    with pytest.raises(IngestionValidationError):
        EventSchemaKey(family, major, version)


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"\xff",
        b"not-json",
        b"[]",
        b'{"id":1}',
        b'{"id":"018f0000-0000-7000-8000-000000000101"}',
        (
            b'{"id":"018f0000-0000-7000-8000-000000000101",'
            b'"schema_family":1,"schema_major":1,"schema_version":1}'
        ),
        (
            b'{"id":"018f0000-0000-7000-8000-000000000101",'
            b'"schema_family":"agent_event","schema_major":true,"schema_version":1}'
        ),
        (
            b'{"id":"018f0000-0000-7000-8000-000000000101",'
            b'"schema_family":"agent_event","schema_major":1,"schema_version":false}'
        ),
        (
            b'{"id":"018f0000-0000-7000-8000-000000000101",'
            b'"id":"018f0000-0000-7000-8000-000000000101"}'
        ),
        (
            b'{"id":"018f0000-0000-7000-8000-000000000101",'
            b'"schema_family":"agent_event","schema_major":1,"schema_version":1,'
            b'"value":NaN}'
        ),
    ],
)
def test_schema_document_rejects_malformed_or_ambiguous_json(raw: bytes) -> None:
    with pytest.raises(IngestionValidationError):
        EventSchemaDocument.decode(raw)


def test_schema_document_enforces_size_and_accepts_external_schema_lineage() -> None:
    with pytest.raises(IngestionValidationError):
        EventSchemaDocument.decode(wire(1), maximum_bytes=1)
    external = json.dumps({"id": EVENT_ID, "status": "observed"}).encode()
    decoded = EventSchemaDocument.decode(external, EventSchemaKey("agent_event", 1, 1))
    assert decoded.event_id == EVENT_ID


def test_canonical_documents_and_extension_snapshots_reject_unsafe_values() -> None:
    with pytest.raises(IngestionValidationError):
        canonical_document({"value": float("nan")})
    with pytest.raises(IngestionValidationError):
        canonical_document({"value": object()})  # type: ignore[dict-item]
    with pytest.raises(IngestionValidationError):
        extension_fields({f"x{index}": index for index in range(257)}, frozenset())


@pytest.mark.parametrize(
    ("event_id", "digest"),
    [
        ("not-a-uuid", "0" * 64),
        (EVENT_ID, "not-a-digest"),
        (
            "018f0000-0000-7000-8000-000000000102",
            hashlib.sha256(wire(1)).hexdigest(),
        ),
        (EVENT_ID, "0" * 64),
    ],
)
def test_schema_source_authenticates_identity_and_digest(event_id: str, digest: str) -> None:
    with pytest.raises(IngestionValidationError):
        EventSchemaSource(
            event_id,
            EventSchemaKey("agent_event", 1, 1),
            wire(1),
            digest,
        )


def _step(
    source_version: int = 1,
    target_version: int = 2,
    *,
    upcaster_id: str = "agent_event.step",
) -> UpcastStepEvidence:
    return UpcastStepEvidence(
        EventSchemaKey("agent_event", 1, source_version),
        EventSchemaKey("agent_event", 1, target_version),
        upcaster_id,
        "1" * 64,
        "2" * 64,
    )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: _step(target_version=3),
        lambda: UpcastStepEvidence(
            EventSchemaKey("agent_event", 1, 1),
            EventSchemaKey("other_event", 1, 2),
            "agent_event.step",
            "1" * 64,
            "2" * 64,
        ),
        lambda: UpcastStepEvidence(
            EventSchemaKey("agent_event", 1, 1),
            EventSchemaKey("agent_event", 2, 2),
            "agent_event.step",
            "1" * 64,
            "2" * 64,
        ),
        lambda: _step(upcaster_id="INVALID ID"),
        lambda: UpcastStepEvidence(
            EventSchemaKey("agent_event", 1, 1),
            EventSchemaKey("agent_event", 1, 2),
            "agent_event.step",
            "bad",
            "2" * 64,
        ),
        lambda: UpcastStepEvidence(
            EventSchemaKey("agent_event", 1, 1),
            EventSchemaKey("agent_event", 1, 2),
            "agent_event.step",
            "1" * 64,
            "bad",
        ),
    ],
)
def test_upcast_step_evidence_rejects_leaps_and_forged_fingerprints(factory: object) -> None:
    with pytest.raises(IngestionValidationError):
        factory()  # type: ignore[operator]


def _outcome(**overrides: object) -> EventSchemaOutcome:
    source = EventSchemaKey("agent_event", 1, 1)
    target = EventSchemaKey("agent_event", 1, 2)
    derived = wire(2)
    values: dict[str, object] = {
        "event_id": EVENT_ID,
        "source_schema": source,
        "target_schema": target,
        "disposition": SchemaEvolutionDisposition.UPCASTED,
        "original_sha256": "0" * 64,
        "derived_bytes": derived,
        "derived_sha256": hashlib.sha256(derived).hexdigest(),
        "steps": (_step(),),
        "quarantine_reason": None,
    }
    values.update(overrides)
    return EventSchemaOutcome(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_id": "bad"},
        {"original_sha256": "bad"},
        {
            "disposition": SchemaEvolutionDisposition.QUARANTINED,
            "quarantine_reason": SchemaQuarantineReason.FUTURE_VERSION,
        },
        {
            "disposition": SchemaEvolutionDisposition.QUARANTINED,
            "derived_bytes": None,
            "derived_sha256": None,
            "quarantine_reason": None,
            "steps": (),
        },
        {"derived_bytes": None},
        {"derived_sha256": "f" * 64},
        {"quarantine_reason": SchemaQuarantineReason.INVALID_TRANSFORM},
        {"disposition": SchemaEvolutionDisposition.CURRENT},
        {"steps": ()},
        {
            "source_schema": EventSchemaKey("agent_event", 1, 2),
        },
        {
            "target_schema": EventSchemaKey("agent_event", 1, 3),
        },
        {
            "steps": (_step(), _step(1, 2)),
        },
    ],
)
def test_schema_outcome_rejects_inconsistent_shapes_and_broken_traces(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(IngestionValidationError):
        _outcome(**overrides)


def test_schema_outcome_exposes_deterministic_trace_fingerprint() -> None:
    assert _outcome().trace_sha256 == _outcome().trace_sha256


@pytest.mark.parametrize(
    "overrides",
    [
        {"scanned": -1, "upcasted": -1},
        {"scanned": 1},
        {"scanned": 2, "upcasted": 2, "total": 1},
        {"cursor": "not-a-uuid"},
        {"state": SchemaMigrationState.COMPLETED, "total": 1},
    ],
)
def test_migration_progress_rejects_impossible_checkpoints(
    overrides: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "operation_id": "ing006-migration",
        "state": SchemaMigrationState.RUNNING,
        "target": EventSchemaKey("agent_event", 1, 3),
        "cursor": None,
        "scanned": 0,
        "upcasted": 0,
        "current": 0,
        "quarantined": 0,
        "total": 0,
    }
    values.update(overrides)
    with pytest.raises(IngestionValidationError):
        SchemaMigrationProgress(**values)  # type: ignore[arg-type]


def test_registry_rejects_noncanonical_current_sets_and_nonadjacent_upcasters() -> None:
    current = EventSchemaKey("agent_event", 1, 2)
    with pytest.raises(IngestionValidationError):
        EventUpcasterRegistry((), ())
    with pytest.raises(IngestionValidationError):
        EventUpcasterRegistry((current, current), ())
    with pytest.raises(IngestionValidationError):
        EventUpcasterRegistry(
            (EventSchemaKey("agent_event", 1, 3),),
            (V1ToV2(target=EventSchemaKey("agent_event", 1, 3)),),
        )


@dataclass(frozen=True, slots=True)
class InvalidTransform(V1ToV2):
    @override
    def transform(self, fields: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        del fields
        return object()  # type: ignore[return-value]


def test_missing_and_invalid_upcasters_quarantine_without_derived_content() -> None:
    no_chain = EventUpcasterRegistry((EventSchemaKey("agent_event", 1, 3),), ())
    missing = EvolveEventSchemaHandler(no_chain).execute(wire(1))
    assert missing.quarantine_reason is SchemaQuarantineReason.MISSING_UPCASTER

    unknown = EvolveEventSchemaHandler(registry()).execute(
        wire(1).replace(b"agent_event", b"foreign_event")
    )
    assert unknown.quarantine_reason is SchemaQuarantineReason.MISSING_UPCASTER

    invalid = EventUpcasterRegistry(
        (EventSchemaKey("agent_event", 1, 2),),
        (InvalidTransform(),),
    )
    rejected = EvolveEventSchemaHandler(invalid).execute(wire(1))
    assert rejected.quarantine_reason is SchemaQuarantineReason.INVALID_TRANSFORM


class MemoryMigrationRepository:
    def __init__(self, sources: tuple[bytes, ...], *, fail_once: int | None = None) -> None:
        self.sources = tuple(
            EventSchemaSource(
                EventSchemaDocument.decode(source).event_id,
                EventSchemaDocument.decode(source).schema,
                source,
                hashlib.sha256(source).hexdigest(),
            )
            for source in sources
        )
        self.fail_once = fail_once
        self.outcomes: dict[str, EventSchemaOutcome] = {}
        self.progress: SchemaMigrationProgress | None = None

    async def start_or_resume(
        self,
        operation_id: str,
        target: EventSchemaKey,
    ) -> SchemaMigrationProgress:
        if self.progress is None:
            self.progress = SchemaMigrationProgress(
                operation_id,
                SchemaMigrationState.RUNNING,
                target,
                None,
                0,
                0,
                0,
                0,
                len(self.sources),
            )
        else:
            self.progress = SchemaMigrationProgress(
                self.progress.operation_id,
                SchemaMigrationState.RUNNING,
                self.progress.target,
                self.progress.cursor,
                self.progress.scanned,
                self.progress.upcasted,
                self.progress.current,
                self.progress.quarantined,
                self.progress.total,
            )
        return self.progress

    async def get(self, operation_id: str) -> SchemaMigrationProgress | None:
        assert operation_id == "ing006-migration"
        return self.progress

    async def load_after(
        self,
        operation_id: str,
        cursor: str | None,
        limit: int,
    ) -> tuple[EventSchemaSource, ...]:
        assert operation_id == "ing006-migration"
        start = 0
        if cursor is not None:
            start = next(
                index + 1 for index, source in enumerate(self.sources) if source.event_id == cursor
            )
        return self.sources[start : start + limit]

    async def store_and_checkpoint(
        self,
        operation_id: str,
        outcome: EventSchemaOutcome,
    ) -> SchemaMigrationProgress:
        if self.fail_once == len(self.outcomes):
            self.fail_once = None
            raise SimulatedInterruptionError
        self.outcomes[outcome.event_id] = outcome
        assert self.progress is not None
        dispositions = [item.disposition for item in self.outcomes.values()]
        self.progress = SchemaMigrationProgress(
            operation_id,
            SchemaMigrationState.RUNNING,
            self.progress.target,
            outcome.event_id,
            len(dispositions),
            dispositions.count(SchemaEvolutionDisposition.UPCASTED),
            dispositions.count(SchemaEvolutionDisposition.CURRENT),
            dispositions.count(SchemaEvolutionDisposition.QUARANTINED),
            self.progress.total,
        )
        return self.progress

    async def mark_interrupted(self, operation_id: str) -> SchemaMigrationProgress:
        assert self.progress is not None
        self.progress = SchemaMigrationProgress(
            operation_id,
            SchemaMigrationState.INTERRUPTED,
            self.progress.target,
            self.progress.cursor,
            self.progress.scanned,
            self.progress.upcasted,
            self.progress.current,
            self.progress.quarantined,
            self.progress.total,
        )
        return self.progress

    async def complete(self, operation_id: str) -> SchemaMigrationProgress:
        assert self.progress is not None
        self.progress = SchemaMigrationProgress(
            operation_id,
            SchemaMigrationState.COMPLETED,
            self.progress.target,
            self.progress.cursor,
            self.progress.scanned,
            self.progress.upcasted,
            self.progress.current,
            self.progress.quarantined,
            self.progress.total,
        )
        return self.progress


class SimulatedInterruptionError(RuntimeError):
    """Deterministic repository interruption fixture."""


@pytest.mark.asyncio
async def test_interrupted_migration_resumes_from_checkpoint_equivalent_to_replay() -> None:
    second_id = "018f0000-0000-7000-8000-000000000102"
    second = wire(1).replace(EVENT_ID.encode(), second_id.encode())
    repository = MemoryMigrationRepository((wire(1), second), fail_once=1)
    handler = ResumeEventSchemaMigrationHandler(
        repository,
        EvolveEventSchemaHandler(registry()),
    )
    target = EventSchemaKey("agent_event", 1, 3)
    with pytest.raises(SimulatedInterruptionError):
        await handler.execute("ing006-migration", target, 100)
    assert repository.progress is not None
    assert repository.progress.state is SchemaMigrationState.INTERRUPTED
    assert repository.progress.scanned == 1
    resumed = await handler.execute("ing006-migration", target, 100)
    assert resumed.state is SchemaMigrationState.COMPLETED
    assert resumed.scanned == 2
    assert resumed.upcasted == 2
    assert tuple(repository.outcomes) == (EVENT_ID, second_id)


@pytest.mark.asyncio
@pytest.mark.parametrize("batch_size", [0, 1001])
async def test_migration_rejects_unbounded_batch_sizes(batch_size: int) -> None:
    handler = ResumeEventSchemaMigrationHandler(
        MemoryMigrationRepository(()),
        EvolveEventSchemaHandler(registry()),
    )
    with pytest.raises(IngestionValidationError):
        await handler.execute(
            "ing006-migration",
            EventSchemaKey("agent_event", 1, 3),
            batch_size,
        )


@pytest.mark.asyncio
async def test_empty_completed_and_partial_migrations_have_closed_lifecycle() -> None:
    target = EventSchemaKey("agent_event", 1, 3)
    empty_repository = MemoryMigrationRepository(())
    empty_handler = ResumeEventSchemaMigrationHandler(
        empty_repository,
        EvolveEventSchemaHandler(registry()),
    )
    completed = await empty_handler.execute("ing006-migration", target, 10)
    assert completed.state is SchemaMigrationState.COMPLETED
    assert await empty_handler.execute("ing006-migration", target, 10) == completed

    second_id = "018f0000-0000-7000-8000-000000000102"
    partial_repository = MemoryMigrationRepository(
        (wire(1), wire(1).replace(EVENT_ID.encode(), second_id.encode()))
    )
    partial_handler = ResumeEventSchemaMigrationHandler(
        partial_repository,
        EvolveEventSchemaHandler(registry()),
    )
    partial = await partial_handler.execute("ing006-migration", target, 1)
    assert partial.state is SchemaMigrationState.RUNNING
    assert partial.scanned == 1


@pytest.mark.asyncio
async def test_progress_query_returns_exact_content_free_checkpoint() -> None:
    repository = MemoryMigrationRepository(())
    assert (
        await GetEventSchemaMigrationProgressHandler(repository).execute("ing006-migration") is None
    )
    expected = await repository.start_or_resume(
        "ing006-migration",
        EventSchemaKey("agent_event", 1, 3),
    )
    assert (
        await GetEventSchemaMigrationProgressHandler(repository).execute("ing006-migration")
        == expected
    )
