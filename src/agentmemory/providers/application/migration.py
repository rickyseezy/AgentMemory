"""PRO-008 resumable live embedding-generation migration use cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.providers.domain.embedding_spaces import IndexGenerationState
from agentmemory.providers.domain.errors import (
    EmbeddingMigrationAuthorizationError,
    EmbeddingMigrationConflictError,
    EmbeddingMigrationValidationError,
)
from agentmemory.providers.domain.migration import (
    EmbeddingGenerationMigration,
    EmbeddingMigrationPolicy,
    EmbeddingMigrationState,
    MigrationProgress,
    migration_request_digest,
)
from agentmemory.providers.domain.migration_ports import (
    EmbeddingMigrationActivationRequest,
    EmbeddingMigrationPlan,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.embedding_space_ports import (
        EmbeddingGenerationBindingRepository,
    )
    from agentmemory.providers.domain.embedding_spaces import EmbeddingSpace, IndexGeneration
    from agentmemory.providers.domain.migration_ports import (
        CanonicalEmbeddingContentSource,
        EmbeddingGenerationCleaner,
        EmbeddingGenerationRetentionGuard,
        EmbeddingMigrationIdentityGenerator,
        EmbeddingMigrationInspector,
        EmbeddingMigrationRepository,
        EmbeddingMigrationTarget,
    )
    from agentmemory.shared.clock import Clock

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ADMIN_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})
_MAX_PAGE_SIZE = 4_096
_ERR_INPUT = "embedding migration request is invalid"
_ERR_AUTHORIZATION = "embedding migration action is not authorized"
_ERR_NOT_FOUND = "embedding migration was not found"
_ERR_CURSOR = "canonical embedding replay cursor is invalid"
_ERR_VALIDATION = "embedding migration validation failed"
_ERR_WINDOW = "embedding migration rollback window is still active"
_ERR_VERSION = "embedding migration version does not match"


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanEmbeddingMigrationCommand:
    """Plan one provider/model change at a fixed canonical content watermark."""

    operation_id: str
    scope: AuthorizedScope
    source_space: EmbeddingSpace
    source_generation: IndexGeneration
    target_space: EmbeddingSpace
    target_generation: IndexGeneration
    requested_at: datetime

    def __post_init__(self) -> None:
        """Require exact source/target bindings and a UTC request time."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or not _is_utc(self.requested_at)
            or self.source_generation.state is not IndexGenerationState.ACTIVE
            or self.target_generation.state
            not in {IndexGenerationState.CREATING, IndexGenerationState.POPULATING}
            or self.source_generation.brain_id != self.scope.brain_id.value
            or self.target_generation.brain_id != self.scope.brain_id.value
            or self.source_generation.space_id != self.source_space.space_id
            or self.target_generation.space_id != self.target_space.space_id
            or self.source_generation.space_fingerprint != self.source_space.immutable_fingerprint
            or self.target_generation.space_fingerprint != self.target_space.immutable_fingerprint
            or self.source_space.space_id == self.target_space.space_id
            or self.source_generation.generation_id == self.target_generation.generation_id
        ):
            raise EmbeddingMigrationValidationError(_ERR_INPUT)


@dataclass(frozen=True, slots=True)
class PlanEmbeddingMigrationHandler:
    """Capture the consistent canonical watermark and persist an idempotent plan."""

    source: CanonicalEmbeddingContentSource
    repository: EmbeddingMigrationRepository
    identities: EmbeddingMigrationIdentityGenerator

    async def execute(
        self,
        command: PlanEmbeddingMigrationCommand,
    ) -> EmbeddingGenerationMigration:
        """Authorize before reading a watermark or migration authority."""
        _authorize(command.scope, "provider.embedding_migration.plan")
        watermark = await self.source.latest_watermark(command.scope.brain_id.value)
        now = _micros(command.requested_at)
        candidate = EmbeddingGenerationMigration(
            migration_id=self.identities.new(),
            brain_id=command.scope.brain_id.value,
            source_space_id=command.source_space.space_id,
            source_space_fingerprint=command.source_space.immutable_fingerprint,
            source_generation_id=command.source_generation.generation_id,
            target_space_id=command.target_space.space_id,
            target_space_fingerprint=command.target_space.immutable_fingerprint,
            target_generation_id=command.target_generation.generation_id,
            source_watermark=watermark,
            progress=MigrationProgress(
                backfill_cursor=0,
                catchup_watermark=watermark,
                catchup_cursor=watermark,
            ),
            state=EmbeddingMigrationState.PLANNED,
            validation_digest=None,
            rollback_until_microseconds=None,
            source_retired_at_microseconds=None,
            source_deleted_at_microseconds=None,
            resume_state=None,
            version=1,
            created_at_microseconds=now,
            updated_at_microseconds=now,
        )
        request_digest = migration_request_digest(
            brain_id=candidate.brain_id,
            source_space_id=candidate.source_space_id,
            source_generation_id=candidate.source_generation_id,
            target_space_id=candidate.target_space_id,
            target_generation_id=candidate.target_generation_id,
            source_watermark=candidate.source_watermark,
        )
        return await self.repository.create(
            command.scope,
            command.operation_id,
            request_digest,
            EmbeddingMigrationPlan(
                candidate,
                command.source_space,
                command.source_generation,
                command.target_space,
                command.target_generation,
            ),
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class PlanEmbeddingMigrationByIdCommand:
    """Public planning input using canonical generation identities."""

    operation_id: str
    scope: AuthorizedScope
    source_generation_id: str
    target_generation_id: str
    requested_at: datetime


@dataclass(frozen=True, slots=True)
class PlanEmbeddingMigrationByIdHandler:
    """Resolve canonical bindings before delegating to the pure planning use case."""

    bindings: EmbeddingGenerationBindingRepository
    planner: PlanEmbeddingMigrationHandler

    async def execute(
        self,
        command: PlanEmbeddingMigrationByIdCommand,
    ) -> EmbeddingGenerationMigration:
        """Hide missing or cross-Brain generations behind one conflict."""
        _authorize(command.scope, "provider.embedding_migration.plan")
        source = await self.bindings.get_binding(
            command.scope,
            command.source_generation_id,
            command.requested_at,
        )
        target = await self.bindings.get_binding(
            command.scope,
            command.target_generation_id,
            command.requested_at,
        )
        if source is None or target is None:
            raise EmbeddingMigrationConflictError(_ERR_NOT_FOUND)
        return await self.planner.execute(
            PlanEmbeddingMigrationCommand(
                operation_id=command.operation_id,
                scope=command.scope,
                source_space=source.space,
                source_generation=source.generation,
                target_space=target.space,
                target_generation=target.generation,
                requested_at=command.requested_at,
            )
        )


@dataclass(frozen=True, slots=True)
class EmbeddingMigrationWorker:
    """Resume every committed state through safe atomic cutover."""

    source: CanonicalEmbeddingContentSource
    target: EmbeddingMigrationTarget
    inspector: EmbeddingMigrationInspector
    repository: EmbeddingMigrationRepository
    clock: Clock
    policy: EmbeddingMigrationPolicy
    page_size: int = 256

    def __post_init__(self) -> None:
        """Bound every replay call and in-memory content-reference page."""
        if not 1 <= self.page_size <= _MAX_PAGE_SIZE:
            raise EmbeddingMigrationValidationError(_ERR_INPUT)

    async def execute(
        self,
        scope: AuthorizedScope,
        migration_id: str,
    ) -> EmbeddingGenerationMigration:
        """Run committed idempotent phases until active, failed, or rolled back."""
        _authorize(scope, "provider.embedding_migration.run")
        current = await self.repository.get(
            scope,
            migration_id,
            _micros(self.clock.now()),
        )
        if current is None:
            raise EmbeddingMigrationConflictError(_ERR_NOT_FOUND)
        stopping = {
            EmbeddingMigrationState.READY,
            EmbeddingMigrationState.PAUSED,
            EmbeddingMigrationState.ROLLED_BACK,
            EmbeddingMigrationState.FAILED,
        }
        while current.state not in stopping:
            refreshed = await self.repository.get(
                scope,
                migration_id,
                _micros(self.clock.now()),
            )
            if refreshed is None:
                raise EmbeddingMigrationConflictError(_ERR_NOT_FOUND)
            current = refreshed
            if current.state in stopping:
                break
            current = await self._step(current)
        return current

    async def _step(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        handlers = {
            EmbeddingMigrationState.PLANNED: self._prepare,
            EmbeddingMigrationState.BUILDING: self._begin_backfill,
            EmbeddingMigrationState.BACKFILLING: self._backfill,
            EmbeddingMigrationState.DUAL_WRITE: self._begin_dual_write,
            EmbeddingMigrationState.CATCHING_UP: self._catch_up,
            EmbeddingMigrationState.VALIDATING: self._begin_shadow,
            EmbeddingMigrationState.SHADOWING: self._validate_shadow,
        }
        handler = handlers.get(current.state)
        if handler is None:
            raise EmbeddingMigrationConflictError(_ERR_VALIDATION)
        return await handler(current)

    async def _prepare(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        await self.target.prepare(current)
        return await self.repository.advance(
            current,
            EmbeddingMigrationState.BUILDING,
            _micros(self.clock.now()),
        )

    async def _begin_backfill(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        return await self.repository.advance(
            current,
            EmbeddingMigrationState.BACKFILLING,
            _micros(self.clock.now()),
        )

    async def _backfill(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        current = await self._replay(
            current,
            through=current.source_watermark,
            catchup=False,
        )
        return await self.repository.advance(
            current,
            EmbeddingMigrationState.DUAL_WRITE,
            _micros(self.clock.now()),
        )

    async def _begin_dual_write(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        catchup_watermark = await self.source.latest_watermark(current.brain_id)
        if catchup_watermark < current.source_watermark:
            raise EmbeddingMigrationConflictError(_ERR_CURSOR)
        return await self.repository.begin_dual_write(
            current,
            catchup_watermark,
            _micros(self.clock.now()),
        )

    async def _catch_up(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        current = await self._replay(
            current,
            through=current.progress.catchup_watermark,
            catchup=True,
        )
        return await self.repository.advance(
            current,
            EmbeddingMigrationState.VALIDATING,
            _micros(self.clock.now()),
        )

    async def _begin_shadow(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        target = (
            EmbeddingMigrationState.SHADOWING
            if await self.inspector.structurally_valid(current)
            else EmbeddingMigrationState.FAILED
        )
        return await self.repository.advance(
            current,
            target,
            _micros(self.clock.now()),
        )

    async def _validate_shadow(
        self,
        current: EmbeddingGenerationMigration,
    ) -> EmbeddingGenerationMigration:
        validation = await self.inspector.validate(current)
        if not validation.passes(self.policy):
            return await self.repository.advance(
                current,
                EmbeddingMigrationState.FAILED,
                _micros(self.clock.now()),
            )
        return await self.repository.advance(
            current,
            EmbeddingMigrationState.READY,
            _micros(self.clock.now()),
            validation_digest=validation.digest,
        )

    async def _replay(
        self,
        current: EmbeddingGenerationMigration,
        *,
        through: int,
        catchup: bool,
    ) -> EmbeddingGenerationMigration:
        cursor = current.progress.catchup_cursor if catchup else current.progress.backfill_cursor
        while cursor < through:
            page = await self.source.read_page(
                current.brain_id,
                cursor,
                through,
                self.page_size,
            )
            if (
                page.next_cursor <= cursor
                or page.next_cursor > through
                or (page.complete and page.next_cursor != through)
            ):
                raise EmbeddingMigrationConflictError(_ERR_CURSOR)
            await self.target.write(current, page.records)
            progress = (
                MigrationProgress(
                    current.progress.backfill_cursor,
                    current.progress.catchup_watermark,
                    page.next_cursor,
                )
                if catchup
                else MigrationProgress(
                    page.next_cursor,
                    current.progress.catchup_watermark,
                    current.progress.catchup_cursor,
                )
            )
            current = await self.repository.checkpoint(
                current,
                progress,
                _micros(self.clock.now()),
            )
            cursor = page.next_cursor
        return current


@dataclass(frozen=True, slots=True)
class GetEmbeddingMigrationQuery:
    """Read one content-free migration snapshot."""

    scope: AuthorizedScope
    migration_id: str
    requested_at: datetime


@dataclass(frozen=True, slots=True)
class GetEmbeddingMigrationHandler:
    """Authorize and read one Brain-scoped migration."""

    repository: EmbeddingMigrationRepository

    async def execute(
        self,
        query: GetEmbeddingMigrationQuery,
    ) -> EmbeddingGenerationMigration | None:
        """Return no cross-Brain existence signal."""
        _authorize(query.scope, "provider.embedding_migration.read")
        return await self.repository.get(
            query.scope,
            query.migration_id,
            _micros(query.requested_at),
        )


@dataclass(frozen=True, slots=True)
class PauseEmbeddingMigrationCommand:
    """Pause one nonterminal migration at an exact optimistic version."""

    scope: AuthorizedScope
    migration_id: str
    expected_version: int


@dataclass(frozen=True, slots=True)
class PauseEmbeddingMigrationHandler:
    """Persist a resumable pause without rewinding progress or routing."""

    repository: EmbeddingMigrationRepository
    clock: Clock

    async def execute(
        self,
        command: PauseEmbeddingMigrationCommand,
    ) -> EmbeddingGenerationMigration:
        """Compare requested and canonical versions before pausing."""
        _authorize(command.scope, "provider.embedding_migration.pause")
        current = await _required(
            self.repository,
            command.scope,
            command.migration_id,
            self.clock,
        )
        if current.state is EmbeddingMigrationState.PAUSED:
            _require_version(current, command.expected_version)
            return current
        _require_version(current, command.expected_version)
        return await self.repository.advance(
            current,
            EmbeddingMigrationState.PAUSED,
            _micros(self.clock.now()),
        )


@dataclass(frozen=True, slots=True)
class ResumeEmbeddingMigrationCommand:
    """Resume the exact phase stored by a pause."""

    scope: AuthorizedScope
    migration_id: str
    expected_version: int


@dataclass(frozen=True, slots=True)
class ResumeEmbeddingMigrationHandler:
    """Compare-and-swap a paused migration back to its durable phase."""

    repository: EmbeddingMigrationRepository
    clock: Clock

    async def execute(
        self,
        command: ResumeEmbeddingMigrationCommand,
    ) -> EmbeddingGenerationMigration:
        """Reject stale or non-paused resume requests."""
        _authorize(command.scope, "provider.embedding_migration.resume")
        current = await _required(
            self.repository,
            command.scope,
            command.migration_id,
            self.clock,
        )
        _require_version(current, command.expected_version)
        return await self.repository.resume(current, _micros(self.clock.now()))


@dataclass(frozen=True, slots=True)
class ActivateEmbeddingMigrationCommand:
    """Explicit approved cutover request bound to one Ready version."""

    operation_id: str
    scope: AuthorizedScope
    migration_id: str
    approval_id: str
    expected_version: int

    def __post_init__(self) -> None:
        """Require bounded operation/approval identities and a valid version."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or _OPERATION.fullmatch(self.approval_id) is None
            or self.expected_version < 1
        ):
            raise EmbeddingMigrationValidationError(_ERR_INPUT)


@dataclass(frozen=True, slots=True)
class ActivateEmbeddingMigrationHandler:
    """Delegate approval verification and atomic activation to canonical persistence."""

    repository: EmbeddingMigrationRepository
    clock: Clock
    policy: EmbeddingMigrationPolicy

    async def execute(
        self,
        command: ActivateEmbeddingMigrationCommand,
    ) -> EmbeddingGenerationMigration:
        """Cut over only the exact Ready version named by If-Match."""
        _authorize(command.scope, "provider.embedding_migration.activate")
        current = await _required(
            self.repository,
            command.scope,
            command.migration_id,
            self.clock,
        )
        if current.state is not EmbeddingMigrationState.ACTIVE:
            _require_version(current, command.expected_version)
        now = _micros(self.clock.now())
        return await self.repository.activate(
            current,
            EmbeddingMigrationActivationRequest(
                scope=command.scope,
                operation_id=command.operation_id,
                approval_id=command.approval_id,
                expected_version=command.expected_version,
                at_microseconds=now,
                rollback_until_microseconds=(now + self.policy.rollback_window_microseconds),
            ),
        )


@dataclass(frozen=True, slots=True)
class RollbackEmbeddingMigrationCommand:
    """Request atomic restoration of the retained source generation."""

    scope: AuthorizedScope
    migration_id: str


@dataclass(frozen=True, slots=True)
class RollbackEmbeddingMigrationHandler:
    """Restore the source only within the immutable rollback anchor."""

    repository: EmbeddingMigrationRepository
    clock: Clock

    async def execute(
        self,
        command: RollbackEmbeddingMigrationCommand,
    ) -> EmbeddingGenerationMigration:
        """Authorize and compare-and-swap the active pointer back to source."""
        _authorize(command.scope, "provider.embedding_migration.rollback")
        current = await self.repository.get(
            command.scope,
            command.migration_id,
            _micros(self.clock.now()),
        )
        if current is None:
            raise EmbeddingMigrationConflictError(_ERR_NOT_FOUND)
        now = _micros(self.clock.now())
        if not current.rollback_eligible(now):
            raise EmbeddingMigrationConflictError(_ERR_WINDOW)
        return await self.repository.rollback(current, now)


@dataclass(frozen=True, slots=True)
class DeleteExpiredEmbeddingGenerationCommand:
    """Request governed cleanup after the source rollback window."""

    scope: AuthorizedScope
    migration_id: str


@dataclass(frozen=True, slots=True)
class DeleteExpiredEmbeddingGenerationHandler:
    """Retire canonical source authority before idempotent physical deletion."""

    repository: EmbeddingMigrationRepository
    retention: EmbeddingGenerationRetentionGuard
    cleaner: EmbeddingGenerationCleaner
    clock: Clock

    async def execute(
        self,
        command: DeleteExpiredEmbeddingGenerationCommand,
    ) -> EmbeddingGenerationMigration:
        """Refuse early deletion and preserve retryability across graph failure."""
        _authorize(command.scope, "provider.embedding_migration.delete")
        current = await self.repository.get(
            command.scope,
            command.migration_id,
            _micros(self.clock.now()),
        )
        if current is None:
            raise EmbeddingMigrationConflictError(_ERR_NOT_FOUND)
        now = _micros(self.clock.now())
        if not current.deletion_eligible(now):
            raise EmbeddingMigrationConflictError(_ERR_WINDOW)
        await self.retention.require_source_deletion(
            command.scope,
            current,
            now,
        )
        retired = await self.repository.retire_source(current, now)
        await self.cleaner.delete(current.source_generation_id)
        return await self.repository.complete_source_deletion(
            retired,
            _micros(self.clock.now()),
        )


def _authorize(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action or scope.role not in _ADMIN_ROLES:
        raise EmbeddingMigrationAuthorizationError(_ERR_AUTHORIZATION)


async def _required(
    repository: EmbeddingMigrationRepository,
    scope: AuthorizedScope,
    migration_id: str,
    clock: Clock,
) -> EmbeddingGenerationMigration:
    current = await repository.get(scope, migration_id, _micros(clock.now()))
    if current is None:
        raise EmbeddingMigrationConflictError(_ERR_NOT_FOUND)
    return current


def _require_version(current: EmbeddingGenerationMigration, expected: int) -> None:
    if current.version != expected:
        raise EmbeddingMigrationConflictError(_ERR_VERSION)


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)
