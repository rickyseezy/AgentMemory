"""ADP-006 host-neutral continuity domain and selection tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from uuid import uuid4

import pytest

from agentmemory.identity.domain.retrieval_scope import (
    Classification as ScopeClassification,
)
from agentmemory.identity.domain.retrieval_scope import (
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.retrieval.domain.continuity import (
    AgentHost,
    BriefingBudget,
    ContinuityItem,
    ContinuityKind,
    ItemProvenance,
    ProcedureApplicability,
    ProcedureCandidate,
    ProcedureEnvironment,
    classification_permitted,
    conservative_tokens,
)
from agentmemory.retrieval.domain.errors import (
    RetrievalAuthorizationError,
    RetrievalValidationError,
)
from tests.retrieval.support import (
    FakeContinuityRepository,
    FakeProcedureRepository,
    briefing_handler,
    briefing_query,
    scope,
)


def _item(identifier: str, kind: ContinuityKind, content: str) -> ContinuityItem:
    return ContinuityItem(
        item_id=identifier,
        semantic_id=identifier,
        kind=kind,
        content=content,
        brain_id="018f0000-0000-7000-8000-000000000004",
        project_id="018f0000-0000-7000-8000-000000000010",
        repository_id="018f0000-0000-7000-8000-000000000020",
        checkout_id=None,
        branch_name="main",
        commit_sha="a" * 40,
        occurred_at=datetime(2026, 7, 20, 10, tzinfo=UTC),
        ingested_at=datetime(2026, 7, 20, 10, 1, tzinfo=UTC),
        classification="internal",
        evidence_event_id="018f0000-0000-7000-8000-000000000101",
        provenance=ItemProvenance(
            producer_host="claude_code",
            model_id="claude-sonnet",
            adapter_id="agentmemory.claude-code",
            adapter_version="1.0.0",
            capture_method="native",
        ),
    )


def test_domain_rejects_invalid_or_unbounded_values() -> None:
    with pytest.raises(RetrievalValidationError):
        BriefingBudget(max_tokens=0, max_items=12, max_bytes=20_480)
    with pytest.raises(RetrievalValidationError):
        _item("bad id", ContinuityKind.FACT, "valid")
    with pytest.raises(RetrievalValidationError):
        ProcedureEnvironment(platform="darwin", capabilities=("shell", "shell"))


def test_domain_rejects_malformed_provenance_item_and_budget_dimensions() -> None:
    provenance = ItemProvenance(
        "claude_code", "model", "agentmemory.claude-code", "1.0.0", "native"
    )
    with pytest.raises(RetrievalValidationError):
        replace(provenance, producer_host="Bad Host")
    with pytest.raises(RetrievalValidationError):
        replace(provenance, adapter_version="latest")
    baseline = _item("valid", ContinuityKind.FACT, "valid")
    for replacement in (
        {"checkout_id": "not-a-uuid"},
        {"commit_sha": "bad"},
        {"classification": "secret"},
        {"occurred_at": datetime(2026, 7, 20, 10, tzinfo=UTC).replace(tzinfo=None)},
        {"occurred_at": datetime(2026, 7, 20, 10, tzinfo=timezone(timedelta(hours=4)))},
        {"content": "contains\x00control"},
        {"content": "contains\x7fdelete"},
        {"content": ""},
        {"brain_id": str(uuid4())},
    ):
        with pytest.raises(RetrievalValidationError):
            replace(baseline, **replacement)
    with pytest.raises(RetrievalValidationError):
        BriefingBudget(max_tokens=1_200, max_items=0, max_bytes=20_480)
    with pytest.raises(RetrievalValidationError):
        BriefingBudget(max_tokens=1_200, max_items=12, max_bytes=511)


def test_context_serialization_token_counter_and_classification_are_exact() -> None:
    item = _item("exact", ContinuityKind.DECISION, "café decision")
    assert item.context_bytes() == (
        b'{"category":null,"classification":"internal","content":"caf\xc3\xa9 decision",'
        b'"evidence_event_id":"018f0000-0000-7000-8000-000000000101",'
        b'"freshness":"current","item_id":"exact","kind":"decision","provenance":{'
        b'"adapter_id":"agentmemory.claude-code","adapter_version":"1.0.0",'
        b'"capture_method":"native","model_id":"claude-sonnet",'
        b'"producer_host":"claude_code"},"rank":0,'
        b'"revision_compatibility":"unknown","semantic_id":"exact"}'
    )
    procedure = ProcedureCandidate(
        "exact-procedure",
        "verify",
        ProcedureApplicability(platforms=("darwin",), required_capabilities=("mcp",)),
    )
    assert procedure.context_bytes() == (
        b'{"content":"verify","procedure_id":"exact-procedure","type":"procedure"}'
    )
    assert [conservative_tokens(value) for value in (b"", b"a", b"aaa", b"aaaa")] == [
        1,
        1,
        1,
        2,
    ]
    assert classification_permitted(replace(item, classification="public"), "internal") is True
    assert classification_permitted(replace(item, classification="restricted"), "internal") is False


def test_procedure_and_query_validation_cover_platform_scope_and_identity() -> None:
    with pytest.raises(RetrievalValidationError):
        ProcedureEnvironment(platform="Bad Platform", capabilities=("mcp",))
    with pytest.raises(RetrievalValidationError):
        ProcedureApplicability(platforms=("linux", "darwin"), required_capabilities=("mcp",))
    applicability = ProcedureApplicability(platforms=("darwin",), required_capabilities=("mcp",))
    assert (
        applicability.exclusion_reason(
            ProcedureEnvironment(platform="linux", capabilities=("mcp",))
        )
        == "platform_mismatch:linux"
    )
    with pytest.raises(RetrievalValidationError):
        ProcedureCandidate("bad id", "content", applicability)
    with pytest.raises(RetrievalValidationError):
        briefing_query(
            replace(scope(), action="memory.write"),
            BriefingBudget(),
            ProcedureEnvironment(platform="darwin", capabilities=("mcp",)),
        )


@pytest.mark.asyncio
async def test_selection_is_atomic_deterministic_deduplicated_and_priority_ordered() -> None:
    duplicate = _item("duplicate", ContinuityKind.NEXT_STEP, "same next action")
    records = (
        _item("fact", ContinuityKind.FACT, "supporting fact"),
        _item("change", ContinuityKind.CHANGE, "changed file"),
        _item("failure", ContinuityKind.FAILURE, "failed test"),
        _item("decision", ContinuityKind.DECISION, "chosen design"),
        _item("next", ContinuityKind.NEXT_STEP, "same next action"),
        duplicate,
    )
    handler = briefing_handler(
        FakeContinuityRepository(tuple(reversed(records))), FakeProcedureRepository(())
    )
    query = briefing_query(
        scope(),
        BriefingBudget(max_tokens=1_200, max_items=5, max_bytes=20_480),
        ProcedureEnvironment(platform="darwin", capabilities=("mcp", "shell")),
    )
    first = await handler.execute(query)
    second = await handler.execute(query)
    assert first == second
    assert [item.kind for item in first.items] == [
        ContinuityKind.NEXT_STEP,
        ContinuityKind.DECISION,
        ContinuityKind.FAILURE,
        ContinuityKind.CHANGE,
        ContinuityKind.FACT,
    ]
    assert len({item.content for item in first.items}) == 5
    assert first.used_items == 5
    assert first.used_tokens <= query.budget.max_tokens
    assert first.used_bytes <= query.budget.max_bytes


@pytest.mark.asyncio
async def test_oversized_item_is_skipped_without_cutting_and_later_item_can_fit() -> None:
    records = (
        _item("large", ContinuityKind.NEXT_STEP, "x" * 8_000),
        _item("small", ContinuityKind.DECISION, "keep the repository boundary"),
    )
    result = await briefing_handler(
        FakeContinuityRepository(records), FakeProcedureRepository(())
    ).execute(
        briefing_query(
            scope(),
            BriefingBudget(max_tokens=400, max_items=2, max_bytes=2_000),
            ProcedureEnvironment(platform="darwin", capabilities=("mcp",)),
        )
    )
    assert [item.item_id for item in result.items] == ["small"]
    assert result.truncated is True
    assert result.items[0].content == "keep the repository boundary"


@pytest.mark.asyncio
async def test_procedure_applicability_is_separate_from_memory_access() -> None:
    memory = _item("decision", ContinuityKind.DECISION, "use a local database")
    procedures = (
        ProcedureCandidate(
            "portable",
            "Run the portable verification command.",
            ProcedureApplicability(platforms=("darwin", "linux"), required_capabilities=("shell",)),
        ),
        ProcedureCandidate(
            "incompatible",
            "Apply the host-only patch primitive.",
            ProcedureApplicability(platforms=("darwin",), required_capabilities=("patch.apply",)),
        ),
    )
    result = await briefing_handler(
        FakeContinuityRepository((memory,)), FakeProcedureRepository(procedures)
    ).execute(
        briefing_query(
            scope(),
            BriefingBudget(max_tokens=1_200, max_items=12, max_bytes=20_480),
            ProcedureEnvironment(platform="darwin", capabilities=("mcp", "shell")),
        )
    )
    assert [item.item_id for item in result.items] == [memory.item_id]
    assert [item.content for item in result.items] == [memory.content]
    assert [item.procedure_id for item in result.procedures] == ["portable"]
    assert [(item.procedure_id, item.reason) for item in result.excluded_procedures] == [
        ("incompatible", "missing_capability:patch.apply")
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["brain", "project", "repository", "classification", "temporal_from", "temporal_to"],
)
async def test_repository_scope_leaks_fail_closed(case: str) -> None:
    leaked = _item("leak", ContinuityKind.FACT, "leaked")
    authorized = scope()
    if case == "brain":
        leaked = replace(leaked, brain_id="018f0000-0000-7000-8000-000000000099")
    elif case == "project":
        leaked = replace(leaked, project_id="018f0000-0000-7000-8000-000000000099")
    elif case == "repository":
        leaked = replace(leaked, repository_id="018f0000-0000-7000-8000-000000000099")
    elif case == "classification":
        leaked = replace(leaked, classification="restricted")
        authorized = replace(authorized, classification_ceiling=ScopeClassification.INTERNAL)
    elif case == "temporal_from":
        start = round(datetime(2026, 7, 21, tzinfo=UTC).timestamp() * 1_000_000)
        authorized = replace(authorized, temporal_scope=TemporalScope(start, None))
    else:
        end = round(datetime(2026, 7, 19, tzinfo=UTC).timestamp() * 1_000_000)
        authorized = replace(authorized, temporal_scope=TemporalScope(None, end))
    handler = briefing_handler(FakeContinuityRepository((leaked,)), FakeProcedureRepository(()))
    with pytest.raises(
        RetrievalAuthorizationError, match="continuity repository crossed authorized scope"
    ):
        await handler.execute(
            briefing_query(
                authorized,
                BriefingBudget(),
                ProcedureEnvironment(platform="darwin", capabilities=("mcp",)),
            )
        )


@pytest.mark.asyncio
async def test_temporal_boundaries_and_checkout_membership_are_exact() -> None:
    checkout_id = StableId("018f0000-0000-7000-8000-000000000030")
    baseline = _item("boundary", ContinuityKind.FACT, "boundary")
    checked_out = replace(baseline, checkout_id=checkout_id.value)
    authorized = scope()
    member = authorized.members[0]
    checkout_scope = replace(
        authorized,
        members=(
            ScopeMember(
                member.project_id,
                member.repository_ids,
                (checkout_id,),
                member.rank_boost_micros,
            ),
        ),
    )
    occurred = round(baseline.occurred_at.timestamp() * 1_000_000)
    inclusive = replace(checkout_scope, temporal_scope=TemporalScope(occurred, occurred + 1))
    result = await briefing_handler(
        FakeContinuityRepository((checked_out,)), FakeProcedureRepository(())
    ).execute(
        briefing_query(
            inclusive,
            BriefingBudget(),
            ProcedureEnvironment(platform="darwin", capabilities=("mcp",)),
        )
    )
    assert [item.item_id for item in result.items] == [checked_out.item_id]
    with pytest.raises(RetrievalAuthorizationError):
        await briefing_handler(
            FakeContinuityRepository((baseline,)), FakeProcedureRepository(())
        ).execute(
            briefing_query(
                checkout_scope,
                BriefingBudget(),
                ProcedureEnvironment(platform="darwin", capabilities=("mcp",)),
            )
        )
    with pytest.raises(RetrievalAuthorizationError):
        await briefing_handler(
            FakeContinuityRepository((checked_out,)), FakeProcedureRepository(())
        ).execute(
            briefing_query(
                replace(checkout_scope, temporal_scope=TemporalScope(None, occurred)),
                BriefingBudget(),
                ProcedureEnvironment(platform="darwin", capabilities=("mcp",)),
            )
        )


@pytest.mark.asyncio
async def test_compatible_procedure_that_does_not_fit_is_atomically_omitted() -> None:
    procedure = ProcedureCandidate(
        "large-procedure",
        "x" * 2_000,
        ProcedureApplicability(platforms=("darwin",), required_capabilities=("mcp",)),
    )
    result = await briefing_handler(
        FakeContinuityRepository(()), FakeProcedureRepository((procedure,))
    ).execute(
        briefing_query(
            scope(),
            BriefingBudget(max_tokens=200, max_items=1, max_bytes=1_000),
            ProcedureEnvironment(platform="darwin", capabilities=("mcp",)),
        )
    )
    assert result.procedures == ()
    assert result.truncated is True


@pytest.mark.parametrize("host", tuple(AgentHost))
def test_certified_host_set_is_closed_and_complete(host: AgentHost) -> None:
    assert host.value in {
        "claude_code",
        "codex",
        "gemini_cli",
        "cursor_compatible",
        "generic",
    }
