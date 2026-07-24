"""Fail-closed verified-backup boundary for PRO-008 generation retirement."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import EmbeddingMigrationDependencyError

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.migration import EmbeddingGenerationMigration

_ERR_BACKUP = "embedding generation retirement requires a verified backup anchor"


@dataclass(frozen=True, slots=True)
class BackupBoundEmbeddingGenerationRetentionGuard:
    """Refuse source deletion until the backup subsystem supplies canonical proof."""

    async def require_source_deletion(
        self,
        scope: AuthorizedScope,
        migration: EmbeddingGenerationMigration,
        at_microseconds: int,
    ) -> None:
        """Fail before canonical retirement or physical graph mutation."""
        del scope, migration, at_microseconds
        raise EmbeddingMigrationDependencyError(_ERR_BACKUP)
