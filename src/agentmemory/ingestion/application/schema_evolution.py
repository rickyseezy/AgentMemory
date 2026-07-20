"""Adjacent event upcasting and resumable derived-view migration use cases."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.domain.schema_evolution import (
    EventSchemaDocument,
    EventSchemaKey,
    EventSchemaOutcome,
    JsonValue,
    SchemaEvolutionDisposition,
    SchemaMigrationProgress,
    SchemaMigrationState,
    SchemaQuarantineReason,
    UpcastStepEvidence,
    canonical_document,
    extension_fields,
)

_MAX_BATCH_SIZE = 1000

if TYPE_CHECKING:
    from collections.abc import Mapping

    from agentmemory.ingestion.domain.ports import EventSchemaMigrationRepository


class EventUpcaster(Protocol):
    """Transform exactly one adjacent revision without accessing infrastructure."""

    @property
    def source(self) -> EventSchemaKey:
        """Return the exact accepted revision."""
        ...

    @property
    def target(self) -> EventSchemaKey:
        """Return the exact adjacent produced revision."""
        ...

    @property
    def upcaster_id(self) -> str:
        """Return a stable implementation identity."""
        ...

    @property
    def known_source_fields(self) -> frozenset[str]:
        """Return fields the transform is authorized to interpret or replace."""
        ...

    def transform(self, fields: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        """Return the next revision while retaining unknown additive fields."""
        ...


@dataclass(frozen=True, slots=True)
class EventUpcasterRegistry:
    """Closed deterministic map of one-step transforms for one release."""

    current: tuple[EventSchemaKey, ...]
    upcasters: tuple[EventUpcaster, ...]

    def __post_init__(self) -> None:
        """Reject duplicate targets, leaps, and incomplete advertised chains."""
        if not self.current or tuple(sorted(set(self.current))) != self.current:
            _invalid("current_schemas", "not_canonical")
        seen: set[EventSchemaKey] = set()
        for upcaster in self.upcasters:
            if (
                upcaster.source.family != upcaster.target.family
                or upcaster.source.major != upcaster.target.major
                or upcaster.target.version != upcaster.source.version + 1
            ):
                _invalid("upcasters", "not_adjacent")
            if upcaster.source in seen:
                _invalid("upcasters", "duplicate_source")
            seen.add(upcaster.source)
        for target in self.current:
            same_line = [
                item
                for item in self.upcasters
                if item.target.family == target.family and item.target.major == target.major
            ]
            if same_line:
                versions = {item.source.version for item in same_line}
                first = min(versions)
                if versions != set(range(first, target.version)):
                    _invalid("upcasters", "incomplete_chain")

    def target_for(self, source: EventSchemaKey) -> EventSchemaKey | None:
        """Resolve the release target for an exact compatible family and major."""
        return next(
            (
                item
                for item in self.current
                if item.family == source.family and item.major == source.major
            ),
            None,
        )

    def step_for(self, source: EventSchemaKey) -> EventUpcaster | None:
        """Resolve exactly one next transform."""
        return next((item for item in self.upcasters if item.source == source), None)


@dataclass(frozen=True, slots=True)
class EvolveEventSchemaHandler:
    """Build a current derived view while preserving the immutable source bytes."""

    registry: EventUpcasterRegistry

    def execute(  # noqa: PLR0911 -- Closed outcomes.
        self,
        raw: bytes,
        source_schema: EventSchemaKey | None = None,
    ) -> EventSchemaOutcome:
        """Apply every adjacent transform or return content-free quarantine evidence."""
        original = EventSchemaDocument.decode(raw, source_schema)
        target = self.registry.target_for(original.schema)
        if target is None:
            same_family = next(
                (item for item in self.registry.current if item.family == original.schema.family),
                None,
            )
            reason = (
                SchemaQuarantineReason.UNSUPPORTED_MAJOR
                if same_family is not None
                else SchemaQuarantineReason.MISSING_UPCASTER
            )
            return _quarantine(original, original.schema, reason)
        if original.schema.version > target.version:
            return _quarantine(original, target, SchemaQuarantineReason.FUTURE_VERSION)
        if original.schema == target:
            return EventSchemaOutcome(
                original.event_id,
                original.schema,
                target,
                SchemaEvolutionDisposition.CURRENT,
                original.sha256,
                original.canonical_bytes,
                original.sha256,
                (),
                None,
            )
        fields: Mapping[str, JsonValue] = original.fields
        current = original.schema
        steps: list[UpcastStepEvidence] = []
        while current != target:
            upcaster = self.registry.step_for(current)
            if upcaster is None:
                return _quarantine(original, target, SchemaQuarantineReason.MISSING_UPCASTER)
            before_extensions = extension_fields(fields, upcaster.known_source_fields)
            input_bytes = canonical_document(fields)
            try:
                transformed = upcaster.transform(fields)
                derived = dict(transformed)
                derived["schema_family"] = upcaster.target.family
                derived["schema_major"] = upcaster.target.major
                derived["schema_version"] = upcaster.target.version
                output_bytes = canonical_document(derived)
                decoded = EventSchemaDocument.decode(output_bytes, upcaster.target)
            except IngestionValidationError, TypeError, ValueError:
                return _quarantine(original, target, SchemaQuarantineReason.INVALID_TRANSFORM)
            if any(decoded.fields.get(key) != value for key, value in before_extensions.items()):
                return _quarantine(original, target, SchemaQuarantineReason.EXTENSION_LOSS)
            steps.append(
                UpcastStepEvidence(
                    current,
                    upcaster.target,
                    upcaster.upcaster_id,
                    hashlib.sha256(input_bytes).hexdigest(),
                    decoded.sha256,
                )
            )
            fields = decoded.fields
            current = decoded.schema
        final_bytes = canonical_document(fields)
        return EventSchemaOutcome(
            original.event_id,
            original.schema,
            target,
            SchemaEvolutionDisposition.UPCASTED,
            original.sha256,
            final_bytes,
            hashlib.sha256(final_bytes).hexdigest(),
            tuple(steps),
            None,
        )


@dataclass(frozen=True, slots=True)
class ResumeEventSchemaMigrationHandler:
    """Process one bounded batch and checkpoint every outcome atomically."""

    repository: EventSchemaMigrationRepository
    evolver: EvolveEventSchemaHandler

    async def execute(
        self,
        operation_id: str,
        target: EventSchemaKey,
        batch_size: int,
    ) -> SchemaMigrationProgress:
        """Start or resume a run; another invocation continues after interruption."""
        if batch_size < 1 or batch_size > _MAX_BATCH_SIZE:
            _invalid("batch_size", "out_of_range")
        progress = await self.repository.start_or_resume(operation_id, target)
        if progress.state is SchemaMigrationState.COMPLETED:
            return progress
        sources = await self.repository.load_after(operation_id, progress.cursor, batch_size)
        if not sources:
            return await self.repository.complete(operation_id)
        current = progress
        try:
            for source in sources:
                outcome = self.evolver.execute(source.canonical_bytes, source.schema)
                current = await self.repository.store_and_checkpoint(operation_id, outcome)
        except BaseException:
            await self.repository.mark_interrupted(operation_id)
            raise
        if current.scanned == current.total:
            return await self.repository.complete(operation_id)
        return current


@dataclass(frozen=True, slots=True)
class GetEventSchemaMigrationProgressHandler:
    """Read content-free durable migration progress for operator reporting."""

    repository: EventSchemaMigrationRepository

    async def execute(self, operation_id: str) -> SchemaMigrationProgress | None:
        """Return an exact run without exposing source or derived event content."""
        return await self.repository.get(operation_id)


def _quarantine(
    original: EventSchemaDocument,
    target: EventSchemaKey,
    reason: SchemaQuarantineReason,
) -> EventSchemaOutcome:
    return EventSchemaOutcome(
        original.event_id,
        original.schema,
        target,
        SchemaEvolutionDisposition.QUARANTINED,
        original.sha256,
        None,
        None,
        (),
        reason,
    )


def _invalid(field: str, code: str) -> None:
    raise IngestionValidationError.single(field, code)
