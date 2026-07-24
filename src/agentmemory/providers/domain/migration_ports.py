"""PRO-008 ports for canonical replay, shadow validation, and atomic cutover."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from uuid import UUID

from agentmemory.providers.domain.errors import EmbeddingMigrationValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ERR_TARGET = "embedding migration target is invalid"
_UUID_VERSION = 7

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.embedding_spaces import EmbeddingSpace, IndexGeneration
    from agentmemory.providers.domain.migration import (
        EmbeddingGenerationMigration,
        EmbeddingMigrationState,
        EmbeddingMigrationValidation,
        MigrationContent,
        MigrationContentPage,
        MigrationProgress,
    )


@dataclass(frozen=True, slots=True)
class EmbeddingMigrationPlan:
    """Complete immutable plan passed to canonical persistence as one value."""

    migration: EmbeddingGenerationMigration
    source_space: EmbeddingSpace
    source_generation: IndexGeneration
    target_space: EmbeddingSpace
    target_generation: IndexGeneration


@dataclass(frozen=True, slots=True)
class GenerationWriteTarget:
    """One exact space/generation selected for a canonical content write."""

    space_id: str
    space_fingerprint: str
    generation_id: str

    def __post_init__(self) -> None:
        """Require canonical UUIDv7 identities and semantic fingerprint."""
        if (
            not _uuid7(self.space_id)
            or not _uuid7(self.generation_id)
            or _DIGEST.fullmatch(self.space_fingerprint) is None
        ):
            raise EmbeddingMigrationValidationError(_ERR_TARGET)


@dataclass(frozen=True, slots=True)
class EmbeddingMigrationActivationRequest:
    """Exact administrator, approval, version, and retention cutover authority."""

    scope: AuthorizedScope
    operation_id: str
    approval_id: str
    expected_version: int
    at_microseconds: int
    rollback_until_microseconds: int


class EmbeddingMigrationIdentityGenerator(Protocol):
    """Generate nonpredictive local migration identities."""

    def new(self) -> str:
        """Return one canonical UUIDv7."""
        ...


class CanonicalEmbeddingContentSource(Protocol):
    """Read canonical content at a committed sequence watermark."""

    async def latest_watermark(self, brain_id: str) -> int:
        """Return the latest fully committed canonical content sequence."""
        ...

    async def read_page(
        self,
        brain_id: str,
        after_sequence: int,
        through_sequence: int,
        limit: int,
    ) -> MigrationContentPage:
        """Read strictly ordered canonical content, never vectors, through a fixed watermark."""
        ...


class EmbeddingMigrationTarget(Protocol):
    """Re-embed canonical content into one exact shadow generation."""

    async def prepare(self, migration: EmbeddingGenerationMigration) -> None:
        """Idempotently ensure the exact target generation is physically writable."""
        ...

    async def write(
        self,
        migration: EmbeddingGenerationMigration,
        records: tuple[MigrationContent, ...],
    ) -> None:
        """Idempotently embed and write content under the target space contract."""
        ...


class EmbeddingMigrationInspector(Protocol):
    """Produce content-free structural, quality, privacy, latency, and shadow evidence."""

    async def structurally_valid(self, migration: EmbeddingGenerationMigration) -> bool:
        """Validate completeness/integrity before shadow traffic is eligible."""
        ...

    async def validate(
        self,
        migration: EmbeddingGenerationMigration,
    ) -> EmbeddingMigrationValidation:
        """Return final combined cutover evidence after shadow sampling."""
        ...


class EmbeddingGenerationCleaner(Protocol):
    """Delete only a canonically retired physical generation."""

    async def delete(self, generation_id: str) -> None:
        """Idempotently remove the exact retired generation/index."""
        ...


class EmbeddingGenerationRetentionGuard(Protocol):
    """Prove rollback expiry, backup inclusion, and absence of live dependencies."""

    async def require_source_deletion(
        self,
        scope: AuthorizedScope,
        migration: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> None:
        """Return only when governed physical deletion is safe."""
        ...


class EmbeddingMigrationRepository(Protocol):
    """Canonical SQLite authority for migration state, write routing, and activation."""

    async def create(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        plan: EmbeddingMigrationPlan,
    ) -> EmbeddingGenerationMigration:
        """Create or exactly replay one migration plan."""
        ...

    async def get(
        self,
        scope: AuthorizedScope,
        migration_id: str,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration | None:
        """Return one Brain-scoped migration without cross-Brain disclosure."""
        ...

    async def advance(
        self,
        current: EmbeddingGenerationMigration,
        target: EmbeddingMigrationState,
        at_microseconds: int,
        *,
        progress: MigrationProgress | None = None,
        validation_digest: str | None = None,
    ) -> EmbeddingGenerationMigration:
        """Compare-and-swap one ordinary state transition."""
        ...

    async def resume(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Compare-and-swap a paused migration into its stored prior phase."""
        ...

    async def checkpoint(
        self,
        current: EmbeddingGenerationMigration,
        progress: MigrationProgress,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Persist monotonic replay progress under current version."""
        ...

    async def begin_dual_write(
        self,
        current: EmbeddingGenerationMigration,
        catchup_watermark: int,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Atomically publish source+target write routing and enter catch-up."""
        ...

    async def activate(
        self,
        current: EmbeddingGenerationMigration,
        request: EmbeddingMigrationActivationRequest,
    ) -> EmbeddingGenerationMigration:
        """Verify approval and atomically switch reads/writes with an immutable receipt."""
        ...

    async def rollback(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Atomically restore the source pointer within the rollback window."""
        ...

    async def retire_source(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Mark the expired source generation retired before physical deletion."""
        ...

    async def complete_source_deletion(
        self,
        current: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> EmbeddingGenerationMigration:
        """Persist the idempotent physical-deletion receipt."""
        ...

    async def write_targets(
        self,
        brain_id: str,
        source_space_id: str,
    ) -> tuple[GenerationWriteTarget, ...]:
        """Resolve one active target plus any atomically published dual-write target."""
        ...

    async def active_target(
        self,
        brain_id: str,
        purpose: str,
    ) -> GenerationWriteTarget | None:
        """Resolve the atomically active read generation for one semantic purpose."""
        ...


def _uuid7(value: str) -> bool:
    try:
        parsed = UUID(value)
    except AttributeError, TypeError, ValueError:
        return False
    return parsed.version == _UUID_VERSION and str(parsed) == value
