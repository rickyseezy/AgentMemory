"""MEM-006 production briefing policy and orchestration TDD tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from agentmemory.retrieval.application.start_session_briefing import (
    DeterministicBriefingRetrievalPipeline,
    StartSessionBriefingHandler,
)
from agentmemory.retrieval.domain.continuity import (
    BriefingBudget,
    BriefingCategory,
    BriefingStatus,
    CodeRevision,
    ContextSelection,
    ContinuityFreshness,
    ContinuityItem,
    ContinuityKind,
    ExcludedContinuityItem,
    ItemProvenance,
    ProcedureEnvironment,
    StartSessionBriefingQuery,
)
from agentmemory.retrieval.domain.errors import RetrievalValidationError
from tests.retrieval.support import FakeProcedureRepository, scope

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.retrieval.domain.continuity import ContextInjectedEvent

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
OPERATION_ID = "018f0000-0000-7000-8000-000000000701"
EVENT_ID = "018f0000-0000-7000-8000-000000000702"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000030"
TASK_ID = "018f0000-0000-7000-8000-000000000703"
MEMORY_ID = "018f0000-0000-7000-8000-000000000704"
SESSION_ID = "018f0000-0000-7000-8000-000000000707"
OTHER_SESSION_ID = "018f0000-0000-7000-8000-000000000708"
OTHER_PROJECT_ID = "018f0000-0000-7000-8000-000000000709"


@pytest.mark.asyncio
async def test_briefing_composes_task_memory_revision_and_pipeline_by_fixed_priority() -> None:
    records = (
        _item("change", ContinuityKind.CHANGE, "Changed API client."),
        _item(
            "validation",
            ContinuityKind.FACT,
            "The API contract test passed.",
            source_event_type="agentmemory.test.completed.v1",
        ),
        _item(
            "blocker",
            ContinuityKind.FAILURE,
            "The dependency is unavailable.",
            source_event_type="agentmemory.tool.failed.v1",
        ),
    )
    memories = (
        _item(
            "constraint",
            ContinuityKind.FACT,
            "Never send repository content to an unapproved provider.",
            source_memory_class="constraint",
            source_memory_id=MEMORY_ID,
        ),
        _item(
            "decision",
            ContinuityKind.DECISION,
            "Use the repository boundary.",
            source_memory_class="decision",
            source_memory_id="018f0000-0000-7000-8000-000000000705",
        ),
        _item(
            "next",
            ContinuityKind.NEXT_STEP,
            "Finish the frontend integration.",
            source_memory_class="unresolved_work",
            source_memory_id="018f0000-0000-7000-8000-000000000706",
        ),
    )
    recorder = _Recorder()
    handler = _handler(records, memories, recorder=recorder)

    briefing = await handler.execute(_query())

    assert [item.category for item in briefing.items] == [
        BriefingCategory.SAFETY_CONSTRAINT,
        BriefingCategory.BLOCKER,
        BriefingCategory.UNRESOLVED_WORK,
        BriefingCategory.DECISION,
        BriefingCategory.VALIDATION,
        BriefingCategory.CHANGE,
    ]
    assert [item.rank for item in briefing.items] == [1, 2, 3, 4, 5, 6]
    assert briefing.status is BriefingStatus.READY
    assert briefing.context_event_id == EVENT_ID
    assert recorder.event is not None


@pytest.mark.asyncio
async def test_stale_and_branch_incompatible_work_is_labeled_or_excluded() -> None:
    stale_decision = replace(
        _item("stale-decision", ContinuityKind.DECISION, "Keep the API stable."),
        occurred_at=NOW - timedelta(days=31),
    )
    incompatible_next = replace(
        _item("wrong-branch", ContinuityKind.NEXT_STEP, "Continue the old branch."),
        branch_name="release/old",
        commit_sha="b" * 40,
    )
    ancient_change = replace(
        _item("ancient-change", ContinuityKind.CHANGE, "Old generated output."),
        occurred_at=NOW - timedelta(days=181),
    )
    constraint = replace(
        _item(
            "old-constraint",
            ContinuityKind.FACT,
            "Do not disclose secrets.",
            source_memory_class="constraint",
            source_memory_id=MEMORY_ID,
        ),
        occurred_at=NOW - timedelta(days=365),
    )

    briefing = await _handler(
        (stale_decision, incompatible_next, ancient_change),
        (constraint,),
    ).execute(_query())

    assert [item.item_id for item in briefing.items] == ["old-constraint", "stale-decision"]
    assert all(item.freshness is ContinuityFreshness.STALE for item in briefing.items)
    assert [item.reason for item in briefing.excluded_items] == [
        "stale_beyond_horizon",
        "branch_incompatible",
    ]
    assert {item.item_id for item in briefing.excluded_items} == {
        "ancient-change",
        "wrong-branch",
    }


@pytest.mark.asyncio
async def test_empty_sources_return_explicit_no_answer_and_still_record_injection() -> None:
    recorder = _Recorder()
    result = await _handler((), (), recorder=recorder).execute(_query())

    assert result.status is BriefingStatus.NO_ANSWER
    assert result.items == ()
    assert result.used_items == 0
    assert result.context_event_id == EVENT_ID
    assert recorder.event is not None
    assert recorder.event.selections == ()


@pytest.mark.asyncio
async def test_context_injected_event_contains_ids_ranks_and_budget_but_no_content() -> None:
    recorder = _Recorder()
    briefing = await _handler(
        (_item("next", ContinuityKind.NEXT_STEP, "Private unresolved work."),),
        (),
        recorder=recorder,
    ).execute(_query())

    assert briefing.context_event_id == EVENT_ID
    assert recorder.event is not None
    document = json.loads(recorder.event.event_json)
    assert document["selected"] == [
        {
            "category": "unresolved_work",
            "evidence_event_ids": ["018f0000-0000-7000-8000-000000000101"],
            "item_id": "next",
            "rank": 1,
            "semantic_id": "next",
        }
    ]
    assert document["budget"] == {
        "max_bytes": 20_480,
        "max_items": 12,
        "max_tokens": 1_200,
    }
    assert document == {
        "brain_id": "018f0000-0000-7000-8000-000000000004",
        "budget": {
            "max_bytes": 20_480,
            "max_items": 12,
            "max_tokens": 1_200,
        },
        "event_id": EVENT_ID,
        "event_type": "ContextInjected",
        "operation_id": OPERATION_ID,
        "occurred_at": "2026-07-21T12:00:00.000000Z",
        "policy_version": "session-briefing.v1",
        "principal_id": "018f0000-0000-7000-8000-000000000002",
        "request_sha256": recorder.event.request_sha256,
        "schema_version": 1,
        "scope_fingerprint": recorder.event.scope_fingerprint,
        "selected": [
            {
                "category": "unresolved_work",
                "evidence_event_ids": ["018f0000-0000-7000-8000-000000000101"],
                "item_id": "next",
                "rank": 1,
                "semantic_id": "next",
            }
        ],
        "status": "ready",
        "truncated": False,
        "used": {
            "bytes": briefing.used_bytes,
            "items": 1,
            "tokens": briefing.used_tokens,
        },
    }
    expected_json = json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert recorder.event.event_json == expected_json
    serialized = recorder.event.event_json.lower()
    assert "private unresolved work" not in serialized
    assert "content" not in document
    assert recorder.event.event_sha256 == recorder.event.recompute_sha256()
    with pytest.raises(RetrievalValidationError, match="event digest"):
        replace(recorder.event, event_sha256="0" * 64)
    for changes in (
        {"operation_id": "*invalid"},
        {"scope_fingerprint": "0"},
        {"request_sha256": "0"},
        {"used_tokens": -1},
        {"used_items": 0},
    ):
        with pytest.raises(RetrievalValidationError):
            replace(recorder.event, **changes)


@pytest.mark.asyncio
async def test_selection_is_deterministic_and_never_splits_an_atomic_item() -> None:
    large = _item("large", ContinuityKind.NEXT_STEP, "x" * 8_000)
    small = _item("small", ContinuityKind.DECISION, "Keep the boundary.")
    query = replace(_query(), budget=BriefingBudget(400, 2, 2_000))
    handler = _handler((large, small), ())

    first = await handler.execute(query)
    second = await handler.execute(query)

    assert [item.item_id for item in first.items] == ["small"]
    assert first.items == second.items
    assert first.used_tokens <= query.budget.max_tokens
    assert first.used_bytes <= query.budget.max_bytes
    assert first.truncated


def test_selection_enforces_category_project_and_session_diversity() -> None:
    dominant = tuple(
        replace(
            _item(f"change-{index}", ContinuityKind.CHANGE, f"Change {index}."),
            source_session_id=SESSION_ID,
        )
        for index in range(3)
    )
    alternatives = tuple(
        replace(
            _item(f"fact-{index}", ContinuityKind.FACT, f"Supporting fact {index}."),
            project_id=OTHER_PROJECT_ID,
            source_session_id=OTHER_SESSION_ID,
        )
        for index in range(3)
    )

    briefing = DeterministicBriefingRetrievalPipeline.production().select(
        _query(),
        (*dominant, *alternatives),
        (),
        (),
        (),
    )

    assert briefing.items[0].category is BriefingCategory.CHANGE
    assert len(briefing.items) == 6
    assert (
        max(
            sum(item.category is category for item in briefing.items)
            for category in BriefingCategory
        )
        <= 3
    )
    assert (
        max(
            sum(item.project_id == project for item in briefing.items)
            for project in {item.project_id for item in briefing.items}
        )
        <= 3
    )
    assert (
        max(
            sum(item.source_session_id == session for item in briefing.items)
            for session in {item.source_session_id for item in briefing.items}
        )
        <= 3
    )


def test_mem006_enrichment_and_revision_values_fail_closed() -> None:
    item = _item("invariant", ContinuityKind.FACT, "Evidence-backed fact.")
    with pytest.raises(RetrievalValidationError):
        replace(item, rank=1)
    with pytest.raises(RetrievalValidationError):
        replace(item, source_event_type="Invalid Type")
    with pytest.raises(RetrievalValidationError):
        replace(item, source_memory_class="unknown")
    with pytest.raises(RetrievalValidationError):
        ContextSelection.from_item(item)
    with pytest.raises(RetrievalValidationError):
        ExcludedContinuityItem("item", "Invalid Reason")
    with pytest.raises(RetrievalValidationError):
        CodeRevision(
            "018f0000-0000-7000-8000-000000000020",
            CHECKOUT_ID,
            "main",
            "invalid",
            NOW,
        )
    with pytest.raises(RetrievalValidationError):
        replace(_query(), operation_id="*invalid")


def _query() -> StartSessionBriefingQuery:
    return StartSessionBriefingQuery(
        scope(),
        BriefingBudget(),
        ProcedureEnvironment("darwin", ("mcp", "shell")),
        OPERATION_ID,
        NOW,
    )


def _item(  # noqa: PLR0913 -- Test builder exposes the source fields under test.
    identifier: str,
    kind: ContinuityKind,
    content: str,
    *,
    source_event_type: str = "agentmemory.task.checkpointed.v1",
    source_memory_class: str | None = None,
    source_memory_id: str | None = None,
) -> ContinuityItem:
    return ContinuityItem(
        item_id=identifier,
        semantic_id=identifier,
        kind=kind,
        content=content,
        brain_id="018f0000-0000-7000-8000-000000000004",
        project_id="018f0000-0000-7000-8000-000000000010",
        repository_id="018f0000-0000-7000-8000-000000000020",
        checkout_id=CHECKOUT_ID,
        branch_name="main",
        commit_sha="a" * 40,
        occurred_at=NOW - timedelta(days=1),
        ingested_at=NOW - timedelta(days=1) + timedelta(seconds=1),
        classification="internal",
        evidence_event_id="018f0000-0000-7000-8000-000000000101",
        provenance=ItemProvenance(
            "claude_code",
            "claude-sonnet",
            "agentmemory.claude-code",
            "1.0.0",
            "native",
        ),
        source_event_type=source_event_type,
        source_task_id=TASK_ID,
        source_memory_class=source_memory_class,
        source_memory_id=source_memory_id,
    )


def _handler(
    tasks: tuple[ContinuityItem, ...],
    memories: tuple[ContinuityItem, ...],
    *,
    recorder: _Recorder | None = None,
) -> StartSessionBriefingHandler:
    return StartSessionBriefingHandler(
        _Items(tasks),
        _Items(memories),
        _Revisions(
            (
                CodeRevision(
                    "018f0000-0000-7000-8000-000000000020",
                    CHECKOUT_ID,
                    "main",
                    "a" * 40,
                    NOW,
                ),
            )
        ),
        DeterministicBriefingRetrievalPipeline.production(),
        FakeProcedureRepository(()),
        recorder or _Recorder(),
        lambda: UUID(EVENT_ID),
    )


@dataclass
class _Items:
    items: tuple[ContinuityItem, ...]

    async def list_items(
        self,
        authorized_scope: AuthorizedScope,
        candidate_limit: int,
    ) -> tuple[ContinuityItem, ...]:
        del authorized_scope
        return self.items[:candidate_limit]


@dataclass
class _Revisions:
    revisions: tuple[CodeRevision, ...]

    async def current_revisions(
        self,
        authorized_scope: AuthorizedScope,
    ) -> tuple[CodeRevision, ...]:
        del authorized_scope
        return self.revisions


@dataclass
class _Recorder:
    event: ContextInjectedEvent | None = None

    async def record(
        self,
        authorized_scope: AuthorizedScope,
        event: ContextInjectedEvent,
    ) -> str:
        del authorized_scope
        self.event = event
        return event.event_id
