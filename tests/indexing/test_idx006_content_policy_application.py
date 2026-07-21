"""IDX-006 policy application authorization, gate, and worker tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.identity.domain.retrieval_scope import ScopeMember
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.indexing.application.content_policy import (
    ActivateIndexPolicyCommand,
    ActivateIndexPolicyHandler,
    GetIndexPolicyChangeHandler,
    GetIndexPolicyChangeQuery,
    IndexContentPolicyGate,
    PolicyReconciliationWorker,
)
from agentmemory.indexing.domain.content_policy import (
    IndexPolicyRevision,
    PolicyDecision,
    PolicyLayer,
    PolicyRuleSource,
    ReconciliationAction,
)
from agentmemory.indexing.domain.content_policy_ports import (
    PolicyChangeResult,
    PolicyReconciliationWork,
    PolicySourceDocuments,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingValidationError,
)
from tests.core.support import BRAIN_ID, NOW, FixedClock
from tests.indexing.test_idx001_sqlite_code_index import REPOSITORY_ID
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope as indexing_scope,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope

CHANGE_ID = "a" * 64


def _revision() -> IndexPolicyRevision:
    return IndexPolicyRevision.production_default(BRAIN_ID, REPOSITORY_ID, NOW)


def _result() -> PolicyChangeResult:
    revision = _revision()
    return PolicyChangeResult(
        CHANGE_ID,
        "idx006-operation",
        BRAIN_ID,
        REPOSITORY_ID,
        None,
        revision.digest,
        0,
        0,
        NOW,
    )


@dataclass(slots=True)
class _Repository:
    result: PolicyChangeResult = field(default_factory=_result)
    missing: bool = False
    decisions: list[PolicyDecision] = field(default_factory=list[PolicyDecision])
    sources: list[PolicyRuleSource] = field(default_factory=list[PolicyRuleSource])
    activations: list[tuple[str, IndexPolicyRevision]] = field(
        default_factory=list[tuple[str, IndexPolicyRevision]]
    )

    async def resolve_revision(
        self, repository_id: str, resolved_at: datetime
    ) -> IndexPolicyRevision:
        del resolved_at
        assert repository_id == REPOSITORY_ID
        return _revision()

    async def observe_source(
        self,
        repository_id: str,
        layer: PolicyLayer,
        content: bytes,
        observed_at: datetime,
    ) -> PolicyRuleSource:
        del observed_at
        assert repository_id == REPOSITORY_ID
        source = PolicyRuleSource.from_ignore_bytes(layer, len(self.sources) + 1, content)
        self.sources.append(source)
        return source

    async def record_decision(self, decision: PolicyDecision) -> None:
        self.decisions.append(decision)

    async def activate(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        revision: IndexPolicyRevision,
        activated_at: datetime,
    ) -> PolicyChangeResult:
        del scope, activated_at
        self.activations.append((operation_id, revision))
        return self.result

    async def get_change(self, scope: AuthorizedScope, change_id: str) -> PolicyChangeResult | None:
        del scope
        assert change_id == CHANGE_ID
        return None if self.missing else self.result


@pytest.mark.asyncio
async def test_gate_resolves_empty_and_observed_sources_then_records_decisions() -> None:
    repository = _Repository()
    gate = IndexContentPolicyGate(repository)
    empty = await gate.prepare(REPOSITORY_ID, PolicySourceDocuments(None, None), NOW)
    assert empty.agentmemoryignore == PolicyRuleSource.empty(PolicyLayer.AGENTMEMORY_IGNORE)
    assert empty.gitignore == PolicyRuleSource.empty(PolicyLayer.GITIGNORE)

    policy = await gate.prepare(
        REPOSITORY_ID,
        PolicySourceDocuments(b"private/**\n", b"*.log\n"),
        NOW,
    )
    decision = policy.evaluate_path("private/key.txt", symlink=False, byte_length=1, decided_at=NOW)
    await gate.record(decision)
    assert [source.layer for source in repository.sources] == [
        PolicyLayer.AGENTMEMORY_IGNORE,
        PolicyLayer.GITIGNORE,
    ]
    assert repository.decisions == [decision]


@pytest.mark.asyncio
async def test_handlers_require_exact_action_scope_revision_and_existing_change() -> None:
    repository = _Repository()
    revision = _revision()
    with pytest.raises(IndexingAuthorizationError, match="not authorized"):
        await ActivateIndexPolicyHandler(repository).execute(
            ActivateIndexPolicyCommand(
                "idx006-operation",
                indexing_scope("indexing.search"),
                revision,
                NOW,
            )
        )
    wrong_scope_revision = replace(revision, repository_id=None)
    with pytest.raises(IndexingValidationError, match="request is invalid"):
        await ActivateIndexPolicyHandler(repository).execute(
            ActivateIndexPolicyCommand(
                "idx006-operation",
                indexing_scope("indexing.policy.activate"),
                wrong_scope_revision,
                NOW,
            )
        )
    with pytest.raises(IndexingValidationError, match="request is invalid"):
        ActivateIndexPolicyCommand(
            "bad operation",
            indexing_scope("indexing.policy.activate"),
            revision,
            NOW,
        )

    repository.missing = True
    with pytest.raises(IndexingValidationError, match="was not found"):
        await GetIndexPolicyChangeHandler(repository).execute(
            GetIndexPolicyChangeQuery(indexing_scope("indexing.policy.read"), CHANGE_ID)
        )
    with pytest.raises(IndexingAuthorizationError, match="not authorized"):
        await GetIndexPolicyChangeHandler(repository).execute(
            GetIndexPolicyChangeQuery(indexing_scope("indexing.search"), CHANGE_ID)
        )
    with pytest.raises(IndexingValidationError, match="request is invalid"):
        GetIndexPolicyChangeQuery(indexing_scope("indexing.policy.read"), "invalid")


@pytest.mark.asyncio
async def test_activation_handler_delegates_exact_valid_revision() -> None:
    repository = _Repository()
    revision = _revision()
    result = await ActivateIndexPolicyHandler(repository).execute(
        ActivateIndexPolicyCommand(
            "idx006-operation",
            indexing_scope("indexing.policy.activate"),
            revision,
            NOW,
        )
    )
    assert result == repository.result
    assert repository.activations == [("idx006-operation", revision)]


@pytest.mark.asyncio
async def test_activation_rejects_each_independently_non_exact_scope_shape() -> None:
    repository = _Repository()
    revision = _revision()
    base = indexing_scope("indexing.policy.activate")
    second_project = ScopeMember(
        StableId("018f0000-0000-7000-8000-000000000011"),
        (StableId(REPOSITORY_ID),),
        (),
    )
    two_projects_one_repository = replace(base, members=(*base.members, second_project))
    one_project_two_repositories = replace(
        base,
        members=(
            ScopeMember(
                base.members[0].project_id,
                (
                    StableId(REPOSITORY_ID),
                    StableId("018f0000-0000-7000-8000-000000000021"),
                ),
                (),
            ),
        ),
    )

    for scope in (two_projects_one_repository, one_project_two_repositories):
        with pytest.raises(IndexingAuthorizationError, match="exact project and repository"):
            await ActivateIndexPolicyHandler(repository).execute(
                ActivateIndexPolicyCommand("idx006-operation", scope, revision, NOW)
            )


@dataclass(slots=True)
class _WorkRepository:
    work: list[PolicyReconciliationWork]
    completed: list[str] = field(default_factory=list[str])

    async def claim_next(self, claimed_at: datetime) -> PolicyReconciliationWork | None:
        del claimed_at
        return None if not self.work else self.work.pop(0)

    async def complete(self, item_id: str, completed_at: datetime) -> None:
        del completed_at
        self.completed.append(item_id)


@dataclass(slots=True)
class _Projection:
    applied: list[PolicyReconciliationWork] = field(default_factory=list[PolicyReconciliationWork])

    async def apply(self, work: PolicyReconciliationWork) -> None:
        self.applied.append(work)


@pytest.mark.asyncio
async def test_worker_delivers_once_and_idle_run_stops_cleanly() -> None:
    work = PolicyReconciliationWork(
        "d" * 64,
        CHANGE_ID,
        REPOSITORY_ID,
        "src/a.py",
        ReconciliationAction.DELETE,
        "e" * 64,
        NOW,
    )
    repository = _WorkRepository([work])
    projection = _Projection()
    worker = PolicyReconciliationWorker(repository, projection, FixedClock(NOW))
    assert await worker.run_once()
    assert not await worker.run_once()
    assert projection.applied == [work]
    assert repository.completed == [work.item_id]

    stop = asyncio.Event()
    task = asyncio.create_task(worker.run(stop, idle_seconds=0.001))
    await asyncio.sleep(0.002)
    stop.set()
    await asyncio.wait_for(task, timeout=1)


def test_work_and_change_values_remain_content_free() -> None:
    result = _result()
    assert result.delete_count == 0
    assert result.reindex_count == 0
    assert RAW_PATH_FRAGMENT not in repr(result)


RAW_PATH_FRAGMENT = "raw-secret-value"
