"""Fail-closed PRO-009 activation boundary for provider-backed migration work."""

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.providers.domain.errors import EmbeddingMigrationDependencyError

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.migration import EmbeddingGenerationMigration

_ERR_CONTAINMENT = "embedding migration execution requires the contained provider gateway"


@dataclass(frozen=True, slots=True)
class ContainedEmbeddingMigrationRunner:
    """Refuse provider-backed replay until PRO-009 composes egress containment."""

    async def execute(
        self,
        scope: AuthorizedScope,
        migration_id: str,
    ) -> EmbeddingGenerationMigration:
        """Fail before content resolution, provider invocation, or a network socket."""
        del scope, migration_id
        raise EmbeddingMigrationDependencyError(_ERR_CONTAINMENT)
