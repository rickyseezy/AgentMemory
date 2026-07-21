"""TDD specifications for IDX-002 planning, worker bounds, and cancellation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import TreeSitterLanguagePlugin
from agentmemory.indexing.application.incremental_index import (
    CancelIndexRunCommand,
    CancelIndexRunHandler,
    GetIndexRunHandler,
    GetIndexRunQuery,
    IncrementalIndexWorker,
    IndexProjectionWorker,
    StartIndexRunCommand,
    StartIndexRunHandler,
)
from agentmemory.indexing.domain.code_entities import SourceSnapshot
from agentmemory.indexing.domain.errors import IndexingAuthorizationError
from agentmemory.indexing.domain.incremental import (
    IndexFingerprint,
    IndexOperationKind,
    IndexPlan,
    IndexProjectionEvent,
    IndexRevisionContext,
    IndexRun,
    IndexRunState,
    PriorIndexedUnit,
    VcsDelta,
    VcsDeltaKind,
)
from agentmemory.indexing.domain.incremental_ports import (
    CompletedIndexManifest,
    IndexOperationCommit,
    IndexWork,
    ProjectionImpact,
    RepositoryInspection,
    RepositoryManifestEntry,
)
from agentmemory.indexing.domain.ports import SourceArtifact
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(slots=True)
class _Clock:
    value: datetime = NOW

    def now(self) -> datetime:
        self.value += timedelta(milliseconds=1)
        return self.value


@dataclass(frozen=True, slots=True)
class _Fingerprints:
    version: str = "tree-sitter-0.26.0"

    @property
    def implementation_digest(self) -> str:
        return _digest(f"implementation:{self.version}")

    def for_path(self, relative_path: str) -> IndexFingerprint:
        del relative_path
        return IndexFingerprint(
            self.version,
            "grammar-1",
            _digest("queries"),
            _digest("extractor"),
            "privacy-v1",
        )


@dataclass(slots=True)
class _Source:
    inspection: RepositoryInspection
    content: dict[str, bytes]
    reads: list[str] = field(default_factory=list[str])

    async def inspect(
        self,
        repository_id: str,
        base_commit_id: str | None,
        target_commit_id: str | None,
        previous: tuple[PriorIndexedUnit, ...],
    ) -> RepositoryInspection:
        del repository_id, base_commit_id, target_commit_id, previous
        return self.inspection

    async def read(
        self,
        repository_id: str,
        target_commit_id: str | None,
        relative_path: str,
        expected_digest: str,
    ) -> SourceArtifact:
        del repository_id, target_commit_id
        value = self.content[relative_path]
        assert hashlib.sha256(value).hexdigest() == expected_digest
        self.reads.append(relative_path)
        return SourceArtifact(relative_path, value)


@dataclass(slots=True)
class _Repository:
    previous: CompletedIndexManifest | None = None
    work: IndexWork | None = None
    commits: list[IndexOperationCommit] = field(default_factory=list[IndexOperationCommit])
    states: list[IndexRun] = field(default_factory=list[IndexRun])
    impact_value: ProjectionImpact = field(default_factory=lambda: ProjectionImpact((), ()))
    pending_events: list[IndexProjectionEvent] = field(default_factory=list[IndexProjectionEvent])
    delivered: list[str] = field(default_factory=list[str])

    async def latest_completed(self, scope: AuthorizedScope) -> CompletedIndexManifest | None:
        del scope
        return self.previous

    async def find_by_operation(self, scope: AuthorizedScope, operation_id: str) -> IndexRun | None:
        del scope
        if self.work is not None and self.work.run.operation_id == operation_id:
            return self.work.run
        return None

    async def start(
        self,
        scope: AuthorizedScope,
        run: IndexRun,
        snapshot: SourceSnapshot,
        plan: IndexPlan,
    ) -> IndexRun:
        del scope
        if self.work is None:
            self.work = IndexWork(run, snapshot, plan)
            self.states.append(run)
        return self.work.run

    async def get(self, scope: AuthorizedScope, run_id: str) -> IndexRun | None:
        del scope
        if self.work is None or self.work.run.id != run_id:
            return None
        return self.work.run

    async def request_cancel(
        self,
        scope: AuthorizedScope,
        run_id: str,
        operation_id: str,
        requested_at: datetime,
    ) -> IndexRun:
        del scope, operation_id
        current = await self.current(run_id)
        updated = current.request_cancel(requested_at)
        self._replace(updated)
        return updated

    async def claim_next(self, claimed_at: datetime) -> IndexWork | None:
        if self.work is None or self.work.run.state is not IndexRunState.QUEUED:
            return None
        claimed = self.work.run.begin(claimed_at)
        self._replace(claimed)
        return self.work

    async def current(self, run_id: str) -> IndexRun:
        assert self.work is not None
        assert self.work.run.id == run_id
        return self.work.run

    async def impact(self, semantic_ids: tuple[str, ...]) -> ProjectionImpact:
        del semantic_ids
        return self.impact_value

    async def commit_operation(
        self,
        previous: IndexRun,
        current: IndexRun,
        commit: IndexOperationCommit,
    ) -> IndexRun:
        assert self.work is not None
        assert self.work.run == previous
        self.commits.append(commit)
        if commit.projection_event is not None:
            self.pending_events.append(commit.projection_event)
        self._replace(current)
        return current

    async def save_state(self, previous: IndexRun, current: IndexRun) -> IndexRun:
        assert self.work is not None
        assert self.work.run == previous
        self._replace(current)
        return current

    async def next_projection(self, claimed_at: datetime) -> IndexProjectionEvent | None:
        del claimed_at
        return next(
            (item for item in self.pending_events if item.id not in self.delivered),
            None,
        )

    async def projection_succeeded(self, event_id: str, delivered_at: datetime) -> None:
        del delivered_at
        if event_id not in self.delivered:
            self.delivered.append(event_id)

    def _replace(self, run: IndexRun) -> None:
        assert self.work is not None
        self.work = replace(self.work, run=run)
        self.states.append(run)


@dataclass(slots=True)
class _Consumer:
    events: list[IndexProjectionEvent] = field(default_factory=list[IndexProjectionEvent])

    async def consume(self, event: IndexProjectionEvent) -> None:
        if event.id not in {item.id for item in self.events}:
            self.events.append(event)


def _previous(path_to_content: dict[str, bytes]) -> CompletedIndexManifest:
    scope = _scope("indexing.run.read")
    repository_id = scope.repository_ids[0].value
    project_id = scope.project_ids[0].value
    snapshot = SourceSnapshot.create(
        brain_id=scope.brain_id.value,
        project_id=project_id,
        repository_id=repository_id,
        commit_id="base-commit",
        working_digest=_digest("base-working"),
        created_at=NOW - timedelta(minutes=1),
    )
    fingerprints = _Fingerprints()
    units: list[PriorIndexedUnit] = []
    for path, content in sorted(path_to_content.items()):
        digest = hashlib.sha256(content).hexdigest()
        units.append(
            PriorIndexedUnit(
                path,
                _digest(f"file:{path}"),
                _digest(f"revision:{path}:{digest}"),
                digest,
                fingerprints.for_path(path).cache_key(path, digest),
                (_digest(f"semantic:{path}"),),
            )
        )
    return CompletedIndexManifest(snapshot, tuple(units))


def _inspection(content: dict[str, bytes], deltas: tuple[VcsDelta, ...]) -> RepositoryInspection:
    return RepositoryInspection(
        "target-commit",
        _digest("target-working"),
        tuple(
            RepositoryManifestEntry(
                path,
                hashlib.sha256(value).hexdigest(),
                len(value),
                generated=False,
            )
            for path, value in sorted(content.items())
        ),
        deltas,
        IndexRevisionContext.COMMITTED,
    )


@pytest.mark.asyncio
async def test_start_and_worker_read_parse_and_reembed_only_changed_file() -> None:
    old = {"src/a.py": b"def a(): return 1\n", "src/b.py": b"def b(): return 1\n"}
    current = {**old, "src/b.py": b"def b(): return 2\n"}
    source = _Source(
        _inspection(current, (VcsDelta(VcsDeltaKind.MODIFY, "src/b.py"),)),
        current,
    )
    repository = _Repository(
        previous=_previous(old),
        impact_value=ProjectionImpact(
            (_digest("dependent-topology-fact"),),
            (_digest("assertion-evidence"),),
        ),
    )
    scope = _scope("indexing.run.start")
    run = await StartIndexRunHandler(source, _Fingerprints(), repository).execute(
        StartIndexRunCommand(
            "run-1",
            scope,
            "target-commit",
            include_generated=True,
            detected_at=NOW,
        )
    )

    assert run.state is IndexRunState.QUEUED
    assert repository.work is not None
    assert repository.work.plan.changed_count == 1
    assert [item.kind for item in repository.work.plan.operations] == [
        IndexOperationKind.REUSE,
        IndexOperationKind.MODIFY,
    ]
    assert await IncrementalIndexWorker(
        source, TreeSitterLanguagePlugin(), repository, _Clock()
    ).run_once()

    assert source.reads == ["src/b.py"]
    assert repository.work.run.state is IndexRunState.COMPLETED
    assert repository.work.run.indexed_count == 1
    assert repository.work.run.reused_count == 1
    changed = repository.commits[1]
    assert changed.indexed_file is not None
    assert changed.projection_event is not None
    assert changed.projection_event.dependent_fact_ids == (_digest("dependent-topology-fact"),)
    assert changed.projection_event.assertion_evidence_ids == (_digest("assertion-evidence"),)
    assert changed.projection_event.reembed_semantic_ids


@pytest.mark.asyncio
async def test_delete_emits_invalidation_without_reading_source_and_projection_is_idempotent() -> (
    None
):
    old = {"src/deleted.py": b"def gone(): pass\n"}
    source = _Source(
        _inspection({}, (VcsDelta(VcsDeltaKind.DELETE, "src/deleted.py"),)),
        {},
    )
    repository = _Repository(
        previous=_previous(old),
        impact_value=ProjectionImpact(
            (_digest("dependent"),),
            (_digest("evidence"),),
        ),
    )
    run = await StartIndexRunHandler(source, _Fingerprints(), repository).execute(
        StartIndexRunCommand(
            "delete-run",
            _scope("indexing.run.start"),
            "target-commit",
            include_generated=True,
            detected_at=NOW,
        )
    )
    await IncrementalIndexWorker(
        source, TreeSitterLanguagePlugin(), repository, _Clock()
    ).run_once()
    event = repository.pending_events[0]
    consumer = _Consumer()
    projection = IndexProjectionWorker(repository, consumer, _Clock())

    assert source.reads == []
    assert run.changed_operations == 1
    assert event.previous_file_revision_ids
    assert event.current_file_revision_ids == ()
    assert await projection.run_once()
    assert not await projection.run_once()
    assert consumer.events == [event]


@pytest.mark.asyncio
async def test_status_and_cancel_revalidate_action_and_preserve_operation_boundary() -> None:
    content = {"src/a.py": b"def a(): pass\n"}
    repository = _Repository()
    run = await StartIndexRunHandler(
        _Source(_inspection(content, ()), content),
        _Fingerprints(),
        repository,
    ).execute(
        StartIndexRunCommand(
            "cancel-run",
            _scope("indexing.run.start"),
            "target-commit",
            include_generated=True,
            detected_at=NOW,
        )
    )
    queried = await GetIndexRunHandler(repository).execute(
        GetIndexRunQuery(_scope("indexing.run.read"), run.id)
    )
    cancelled = await CancelIndexRunHandler(repository).execute(
        CancelIndexRunCommand(
            "cancel-request",
            _scope("indexing.run.cancel"),
            run.id,
            NOW + timedelta(seconds=1),
        )
    )

    assert queried == run
    assert cancelled.state is IndexRunState.CANCELLING
    await repository.save_state(cancelled, cancelled.cancel(NOW + timedelta(seconds=2)))
    assert repository.work is not None
    assert repository.work.run.cursor == 0

    with pytest.raises(IndexingAuthorizationError, match="action is not authorized"):
        await GetIndexRunHandler(repository).execute(
            GetIndexRunQuery(_scope("indexing.search"), run.id)
        )
