"""IDX-005 application authorization, replay, parser selection, and temporal query tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.artifact_topology_plugins import (
    DependencyManifestParser,
)
from agentmemory.indexing.application.artifact_topology import (
    ExtractAndRegisterArtifactTopologyCommand,
    ExtractAndRegisterArtifactTopologyHandler,
    QueryArtifactTopologyCommand,
    QueryArtifactTopologyHandler,
    RegisterArtifactTopologyBatchCommand,
    RegisterArtifactTopologyBatchHandler,
)
from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyBatch,
    ArtifactTopologySnapshot,
    ArtifactTopologySourceArtifact,
    TopologyRelationCandidate,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingValidationError,
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx005_artifact_topology_plugins import (
    _artifact,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)


@dataclass(slots=True)
class _Repository:
    existing: ArtifactTopologyBatch | None = None
    registered: list[ArtifactTopologyBatch] = field(default_factory=list[ArtifactTopologyBatch])
    result: ArtifactTopologySnapshot = field(
        default_factory=lambda: ArtifactTopologySnapshot((), (), (), NOW)
    )

    async def find_batch_by_operation(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ArtifactTopologyBatch | None:
        del scope, operation_id
        return self.existing

    async def register_batch(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ArtifactTopologyBatch,
        registered_at: datetime,
    ) -> ArtifactTopologyBatch:
        del scope, operation_id, registered_at
        self.registered.append(batch)
        return batch

    async def snapshot(self, scope: AuthorizedScope, cutoff: datetime) -> ArtifactTopologySnapshot:
        del scope, cutoff
        return self.result


@dataclass(slots=True)
class _Projection:
    calls: list[ArtifactTopologyBatch] = field(default_factory=list[ArtifactTopologyBatch])

    async def project(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ArtifactTopologyBatch,
        projected_at: datetime,
    ) -> tuple[str, ...]:
        del scope, operation_id, projected_at
        self.calls.append(batch)
        return tuple(
            f"018f0000-0000-7000-8000-{rank:012d}"
            for rank, _relation in enumerate(batch.relations, start=100)
        )


@dataclass(frozen=True, slots=True)
class _WrongProjection:
    async def project(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ArtifactTopologyBatch,
        projected_at: datetime,
    ) -> tuple[str, ...]:
        del scope, operation_id, batch, projected_at
        return ()


@dataclass(slots=True)
class _Lineage:
    calls: list[tuple[TopologyRelationCandidate, str]] = field(
        default_factory=list[tuple[TopologyRelationCandidate, str]]
    )

    async def register(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        relation: TopologyRelationCandidate,
        assertion_id: str,
        registered_at: datetime,
    ) -> str:
        del scope, operation_id, registered_at
        self.calls.append((relation, assertion_id))
        return str(relation.id)


@dataclass(frozen=True, slots=True)
class _Parser:
    supported: bool
    batch: ArtifactTopologyBatch

    def supports(self, relative_path: str) -> bool:
        del relative_path
        return self.supported

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        del artifact
        return self.batch


def test_commands_reject_invalid_operation_time_scope_and_empty_query_authority() -> None:
    batch = _batch()
    with pytest.raises(IndexingValidationError, match="conflicts with durable state"):
        RegisterArtifactTopologyBatchCommand("invalid operation!", _register_scope(), batch, NOW)
    with pytest.raises(IndexingValidationError, match="conflicts with durable state"):
        RegisterArtifactTopologyBatchCommand(
            "idx005-naive", _register_scope(), batch, NOW.replace(tzinfo=None)
        )
    with pytest.raises(IndexingAuthorizationError, match="outside authorized scope"):
        RegisterArtifactTopologyBatchCommand(
            "idx005-foreign",
            _register_scope(),
            _foreign_batch(),
            NOW,
        )
    repository_foreign = _repository_foreign_batch()
    with pytest.raises(IndexingAuthorizationError, match="outside authorized scope"):
        RegisterArtifactTopologyBatchCommand(
            "idx005-foreign-repository",
            _register_scope(),
            repository_foreign,
            NOW,
        )
    with pytest.raises(IndexingAuthorizationError):
        QueryArtifactTopologyCommand(replace(_read_scope(), members=()), NOW)


@pytest.mark.asyncio
async def test_registration_replays_projects_and_registers_exact_relation_lineage() -> None:
    batch = _batch()
    repository = _Repository()
    projection = _Projection()
    lineage = _Lineage()
    handler = RegisterArtifactTopologyBatchHandler(repository, projection, lineage)
    command = RegisterArtifactTopologyBatchCommand("idx005-register", _register_scope(), batch, NOW)

    first = await handler.execute(command)
    repository.existing = batch
    replay = await handler.execute(command)

    assert first == replay == batch
    assert repository.registered == [batch]
    assert projection.calls == [batch, batch]
    assert [item[0] for item in lineage.calls] == [*batch.relations, *batch.relations]


@pytest.mark.asyncio
async def test_registration_conflict_projection_cardinality_and_wrong_action_fail_closed() -> None:
    batch = _batch()
    repository = _Repository(existing=replace(batch, plugin_version="v2.0.0"))
    handler = RegisterArtifactTopologyBatchHandler(repository, _Projection(), _Lineage())
    with pytest.raises(IndexingConflictError):
        await handler.execute(
            RegisterArtifactTopologyBatchCommand("idx005-conflict", _register_scope(), batch, NOW)
        )
    with pytest.raises(IndexingAuthorizationError, match="action is not authorized"):
        await RegisterArtifactTopologyBatchHandler(
            _Repository(), _Projection(), _Lineage()
        ).execute(
            RegisterArtifactTopologyBatchCommand(
                "idx005-action", _scope("indexing.search"), batch, NOW
            )
        )

    with pytest.raises(IndexingConflictError):
        await RegisterArtifactTopologyBatchHandler(
            _Repository(), _WrongProjection(), _Lineage()
        ).execute(
            RegisterArtifactTopologyBatchCommand(
                "idx005-cardinality", _register_scope(), batch, NOW
            )
        )


@pytest.mark.asyncio
async def test_extraction_selects_exactly_one_deterministic_parser() -> None:
    batch = _batch()
    registration = RegisterArtifactTopologyBatchHandler(_Repository(), _Projection(), _Lineage())
    command = ExtractAndRegisterArtifactTopologyCommand(
        "idx005-extract", _register_scope(), _scoped_artifact(), NOW
    )
    with pytest.raises(IndexingValidationError, match="does not exclusively support"):
        await ExtractAndRegisterArtifactTopologyHandler((), registration).execute(command)
    with pytest.raises(IndexingValidationError, match="does not exclusively support"):
        await ExtractAndRegisterArtifactTopologyHandler(
            (
                _Parser(supported=True, batch=batch),
                _Parser(supported=True, batch=batch),
            ),
            registration,
        ).execute(command)

    parsed = await ExtractAndRegisterArtifactTopologyHandler(
        (_Parser(supported=True, batch=batch),), registration
    ).execute(command)
    assert parsed == batch


@pytest.mark.asyncio
async def test_query_requires_read_action_and_returns_uncollapsed_snapshot() -> None:
    batch = _batch()
    snapshot = ArtifactTopologySnapshot(batch.candidates, batch.relations, (), NOW)
    repository = _Repository(result=snapshot)
    with pytest.raises(IndexingAuthorizationError):
        await QueryArtifactTopologyHandler(repository).execute(
            QueryArtifactTopologyCommand(_register_scope(), NOW)
        )
    result = await QueryArtifactTopologyHandler(repository).execute(
        QueryArtifactTopologyCommand(_read_scope(), NOW)
    )
    assert result is snapshot


def _batch() -> ArtifactTopologyBatch:
    artifact = _scoped_artifact()
    return DependencyManifestParser().parse(artifact)


def _scoped_artifact() -> ArtifactTopologySourceArtifact:
    artifact = _artifact("package.json", '{"dependencies":{"fastify":"5.0.0"}}')
    scope = _register_scope()
    evidence = replace(
        artifact.evidence,
        brain_id=scope.brain_id.value,
        project_id=scope.members[0].project_id.value,
        repository_id=scope.members[0].repository_ids[0].value,
    )
    return replace(artifact, evidence=evidence)


def _foreign_batch() -> ArtifactTopologyBatch:
    batch = _batch()
    foreign = replace(
        batch.candidates[0].evidence,
        brain_id="018f0000-0000-7000-8000-000000000099",
    )
    candidates = tuple(replace(item, evidence=foreign) for item in batch.candidates)
    relations = tuple(replace(item, evidence=foreign) for item in batch.relations)
    return replace(batch, candidates=candidates, relations=relations)


def _repository_foreign_batch() -> ArtifactTopologyBatch:
    batch = _batch()
    foreign_repository = "018f0000-0000-7000-8000-000000000099"
    foreign = replace(batch.candidates[0].evidence, repository_id=foreign_repository)
    candidates = tuple(replace(item, evidence=foreign) for item in batch.candidates)
    relations = tuple(
        replace(item, evidence=foreign, subject_entity_id=foreign_repository)
        for item in batch.relations
    )
    return replace(batch, candidates=candidates, relations=relations)


def _register_scope() -> AuthorizedScope:
    return _scope("indexing.artifact_topology.register")


def _read_scope() -> AuthorizedScope:
    return _scope("indexing.artifact_topology.read")
