"""GRA-006 governed PF-002 graph rebuild bridge tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.graph.adapters.outbound.pf002_graph_rebuild import Pf002CanonicalGraphRebuild
from agentmemory.graph.domain.errors import GraphIntegrityError
from agentmemory.graph.domain.graph_integrity import GraphIntegrityPolicy
from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.operations.domain.projection_rebuild import (
    RebuildManifest,
    StartProjectionRebuildCommand,
)
from tests.core.support import BRAIN_ID, GRANT_ID, FixedClock, digest, migrated_store
from tests.graph.test_gra002_sqlite_assertions import (
    NOW,
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra006_graph_integrity_domain import (
    CURRENT_GENERATION,
    _observation,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import (
    PROJECT_ID,
    REPOSITORY_ID,
    _seed_roots,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.domain.projection_rebuild import ProjectionRebuild


@pytest.mark.asyncio
async def test_verified_owner_approval_starts_exact_pf002_graph_rebuild(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    await _seed_roots(store)
    starter = _Starter()
    finding = GraphIntegrityPolicy.evaluate(
        (
            replace(
                _observation(),
                brain_id=BRAIN_ID,
                project_id=PROJECT_ID.value,
                repository_id=REPOSITORY_ID.value,
                canonical_id=None,
            ),
        ),
        CURRENT_GENERATION,
        NOW,
    )[0]
    adapter = Pf002CanonicalGraphRebuild(store, FixedClock(NOW), starter, _manifest())
    scope = _scope("graph.integrity.repair")
    try:
        assert await adapter.verify(scope, finding, GRANT_ID)
        await adapter.start(scope, finding, GRANT_ID, NOW)
        command = starter.commands[0]
        assert command.operation_id == f"gra006-rebuild-{finding.id}"
        assert command.brain_id.value == BRAIN_ID
        assert command.actor_id.value == scope.principal_id.value
        assert command.grant_id.value == GRANT_ID
        assert command.projection_type.value == "graph"
        assert command.manifest == _manifest()
        assert command.requested_watermark is None
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_rebuild_rejects_forged_expired_or_non_privileged_approval(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    await _seed_roots(store)
    finding = GraphIntegrityPolicy.evaluate(
        (
            replace(
                _observation(),
                brain_id=BRAIN_ID,
                project_id=PROJECT_ID.value,
                repository_id=REPOSITORY_ID.value,
                canonical_id=None,
            ),
        ),
        CURRENT_GENERATION,
        NOW,
    )[0]
    starter = _Starter()
    adapter = Pf002CanonicalGraphRebuild(store, FixedClock(NOW), starter, _manifest())
    owner = _scope("graph.integrity.repair")
    try:
        assert not await adapter.verify(owner, finding, finding.canonical_id or finding.id)
        assert not await adapter.verify(
            replace(owner, role=RetrievalRole.EDITOR), finding, GRANT_ID
        )
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:expired WHERE id=:grant"),
                {"expired": round(NOW.timestamp() * 1_000_000), "grant": GRANT_ID},
            )
        assert not await adapter.verify(owner, finding, GRANT_ID)
        with pytest.raises(GraphIntegrityError, match="verification"):
            await adapter.start(owner, finding, GRANT_ID, NOW)
        assert starter.commands == []
    finally:
        await store.close()


def _manifest() -> RebuildManifest:
    return RebuildManifest(
        application_build="agentmemory@0.1.0",
        relational_schema="0037_pro004_embedding_spaces",
        graph_schema="0005_pro004_embedding_space_constraints",
        parser_version="not-applicable:graph-v1",
        extractor_version="agentmemory.local-extractor@1.0.0",
        provider_versions=("local:qwen@revision-1",),
        embedding_space="qwen3:1024:cosine:v1",
        implementation_fingerprint=digest("gra006-pf002-bridge-v1"),
    )


@dataclass(slots=True)
class _Starter:
    commands: list[StartProjectionRebuildCommand] = field(
        default_factory=list[StartProjectionRebuildCommand]
    )

    async def execute(self, command: StartProjectionRebuildCommand) -> ProjectionRebuild:
        self.commands.append(command)
        return None  # type: ignore[return-value]
