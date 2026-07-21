"""MEM-006 deterministic multi-source session briefing query."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING
from uuid import UUID, uuid7

from agentmemory.retrieval.domain.continuity import (
    BriefingCategory,
    BriefingStatus,
    ContextInjectedEvent,
    ContinuityFreshness,
    ContinuityKind,
    ExcludedContinuityItem,
    ExcludedProcedure,
    RevisionCompatibility,
    SessionBriefing,
    classification_permitted,
    conservative_tokens,
)
from agentmemory.retrieval.domain.errors import RetrievalAuthorizationError

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, ScopeMember
    from agentmemory.retrieval.domain.continuity import (
        CodeRevision,
        ContinuityItem,
        ProcedureCandidate,
        StartSessionBriefingQuery,
    )
    from agentmemory.retrieval.domain.ports import (
        CodeRevisionQuery,
        ContextInjectionRepository,
        MemoryQueryRepository,
        ProcedureReadRepository,
        RetrievalPipeline,
        TaskReadRepository,
    )

_CANDIDATE_LIMIT = 200
_ENVELOPE_RESERVE_BYTES = 512
_ENVELOPE_RESERVE_TOKENS = 64
_DEFAULT_STALE_AFTER_DAYS = 30
_DEFAULT_EXCLUDE_AFTER_DAYS = 180
_SECONDS_PER_DAY = 86_400
_PRIORITY = {
    BriefingCategory.SAFETY_CONSTRAINT: 0,
    BriefingCategory.BLOCKER: 1,
    BriefingCategory.UNRESOLVED_WORK: 1,
    BriefingCategory.DECISION: 2,
    BriefingCategory.FAILURE: 3,
    BriefingCategory.VALIDATION: 4,
    BriefingCategory.CHANGE: 5,
    BriefingCategory.SUPPORTING: 6,
}
_BRANCH_SENSITIVE = frozenset(
    {
        BriefingCategory.BLOCKER,
        BriefingCategory.UNRESOLVED_WORK,
        BriefingCategory.FAILURE,
        BriefingCategory.VALIDATION,
        BriefingCategory.CHANGE,
    }
)
_ERR_REPOSITORY_SCOPE = "continuity repository crossed authorized scope"


@dataclass(frozen=True, slots=True)
class StartSessionBriefingHandler:
    """Compose task, memory, code-revision, retrieval, procedure, and event ports."""

    tasks: TaskReadRepository
    memories: MemoryQueryRepository
    revisions: CodeRevisionQuery
    pipeline: RetrievalPipeline
    procedures: ProcedureReadRepository
    context_events: ContextInjectionRepository
    identity: Callable[[], UUID] = uuid7

    async def execute(self, query: StartSessionBriefingQuery) -> SessionBriefing:
        """Select an authorized briefing and durably emit its content-free trace event."""
        task_items, memory_items, revisions, procedures = await asyncio.gather(
            self.tasks.list_items(query.scope, _CANDIDATE_LIMIT),
            self.memories.list_items(query.scope, _CANDIDATE_LIMIT),
            self.revisions.current_revisions(query.scope),
            self.procedures.list_candidates(query.scope, _CANDIDATE_LIMIT),
        )
        for item in (*task_items, *memory_items):
            _require_item_in_scope(item, query.scope)
        briefing = self.pipeline.select(
            query,
            task_items,
            memory_items,
            revisions,
            procedures,
        )
        event = ContextInjectedEvent.create(str(self.identity()), query, briefing)
        canonical_event_id = await self.context_events.record(query.scope, event)
        return replace(briefing, context_event_id=canonical_event_id)


@dataclass(frozen=True, slots=True)
class DeterministicBriefingRetrievalPipeline:
    """Pure MEM-006 filtering, labeling, deduplication, ordering, and budgeting policy."""

    stale_after_days: int
    exclude_after_days: int

    @classmethod
    def production(cls) -> DeterministicBriefingRetrievalPipeline:
        """Return the reviewed initial freshness policy."""
        return cls(_DEFAULT_STALE_AFTER_DAYS, _DEFAULT_EXCLUDE_AFTER_DAYS)

    def __post_init__(self) -> None:
        """Require one ordered positive freshness policy."""
        if self.stale_after_days < 1 or self.exclude_after_days <= self.stale_after_days:
            msg = "briefing freshness policy is invalid"
            raise ValueError(msg)

    def select(
        self,
        query: StartSessionBriefingQuery,
        task_items: tuple[ContinuityItem, ...],
        memory_items: tuple[ContinuityItem, ...],
        revisions: tuple[CodeRevision, ...],
        procedures: tuple[ProcedureCandidate, ...],
    ) -> SessionBriefing:
        """Return deterministic atomic selections under every configured budget dimension."""
        eligible: list[ContinuityItem] = []
        excluded: list[ExcludedContinuityItem] = []
        seen: set[str] = set()
        for source in (*memory_items, *task_items):
            category = _category(source)
            compatibility = _compatibility(source, revisions)
            age_days = max(
                0,
                int((query.requested_at - source.occurred_at).total_seconds()) // _SECONDS_PER_DAY,
            )
            freshness = (
                ContinuityFreshness.STALE
                if age_days > self.stale_after_days
                else ContinuityFreshness.CURRENT
            )
            if (
                age_days > self.exclude_after_days
                and category is not BriefingCategory.SAFETY_CONSTRAINT
            ):
                excluded.append(ExcludedContinuityItem(source.item_id, "stale_beyond_horizon"))
                continue
            if (
                compatibility is RevisionCompatibility.BRANCH_INCOMPATIBLE
                and category in _BRANCH_SENSITIVE
            ):
                excluded.append(ExcludedContinuityItem(source.item_id, "branch_incompatible"))
                continue
            dedupe_key = hashlib.sha256(
                f"{category.value}\x00{source.content}".encode()
            ).hexdigest()
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            eligible.append(
                replace(
                    source,
                    category=category,
                    freshness=freshness,
                    revision_compatibility=compatibility,
                )
            )
        eligible.sort(
            key=lambda item: (
                _PRIORITY[_required_category(item)],
                -round(item.occurred_at.timestamp() * 1_000_000),
                item.item_id,
            )
        )

        selected, used_tokens, used_bytes, truncated = _select_diverse_items(query, eligible)

        applicable: list[ProcedureCandidate] = []
        excluded_procedures: list[ExcludedProcedure] = []
        for procedure in sorted(procedures, key=lambda item: item.procedure_id):
            reason = procedure.applicability.exclusion_reason(query.procedure_environment)
            if reason is not None:
                excluded_procedures.append(ExcludedProcedure(procedure.procedure_id, reason))
                continue
            encoded = procedure.context_bytes()
            tokens = conservative_tokens(encoded)
            if (
                len(selected) + len(applicable) + 1 > query.budget.max_items
                or used_tokens + tokens > query.budget.max_tokens
                or used_bytes + len(encoded) > query.budget.max_bytes
            ):
                truncated = True
                continue
            applicable.append(procedure)
            used_tokens += tokens
            used_bytes += len(encoded)

        return SessionBriefing(
            items=tuple(selected),
            procedures=tuple(applicable),
            excluded_procedures=tuple(excluded_procedures),
            excluded_items=tuple(sorted(excluded, key=lambda item: item.item_id)),
            used_tokens=used_tokens,
            used_items=len(selected) + len(applicable),
            used_bytes=used_bytes,
            truncated=truncated,
            scope_fingerprint=query.scope.scope_fingerprint,
            status=BriefingStatus.READY if selected else BriefingStatus.NO_ANSWER,
        )


def _category(item: ContinuityItem) -> BriefingCategory:
    if item.source_memory_class == "constraint":
        return BriefingCategory.SAFETY_CONSTRAINT
    if item.source_memory_class == "unresolved_work":
        return BriefingCategory.UNRESOLVED_WORK
    if item.source_memory_class == "decision":
        return BriefingCategory.DECISION
    if item.source_event_type == "agentmemory.tool.failed.v1":
        return BriefingCategory.BLOCKER
    if item.source_event_type in {
        "agentmemory.command.completed.v1",
        "agentmemory.test.completed.v1",
    }:
        return BriefingCategory.VALIDATION
    return {
        ContinuityKind.NEXT_STEP: BriefingCategory.UNRESOLVED_WORK,
        ContinuityKind.DECISION: BriefingCategory.DECISION,
        ContinuityKind.FAILURE: BriefingCategory.FAILURE,
        ContinuityKind.CHANGE: BriefingCategory.CHANGE,
        ContinuityKind.FACT: BriefingCategory.SUPPORTING,
    }[item.kind]


def _compatibility(
    item: ContinuityItem,
    revisions: tuple[CodeRevision, ...],
) -> RevisionCompatibility:
    current = next(
        (revision for revision in revisions if revision.checkout_id == item.checkout_id),
        None,
    )
    if current is None:
        matching = tuple(
            revision for revision in revisions if revision.repository_id == item.repository_id
        )
        current = matching[0] if len(matching) == 1 else None
    if current is None or item.branch_name is None or current.branch_name is None:
        return RevisionCompatibility.UNKNOWN
    if item.branch_name != current.branch_name:
        return RevisionCompatibility.BRANCH_INCOMPATIBLE
    return RevisionCompatibility.COMPATIBLE


def _required_category(item: ContinuityItem) -> BriefingCategory:
    if item.category is None:
        msg = "briefing item was not categorized"
        raise ValueError(msg)
    return item.category


def _select_diverse_items(
    query: StartSessionBriefingQuery,
    eligible: list[ContinuityItem],
) -> tuple[list[ContinuityItem], int, int, bool]:
    """Select whole atoms while enforcing ADR-012 category/project/session diversity."""
    selected: list[ContinuityItem] = []
    remaining = list(eligible)
    used_tokens = _ENVELOPE_RESERVE_TOKENS
    used_bytes = _ENVELOPE_RESERVE_BYTES
    truncated = False
    while remaining:
        fitting: list[tuple[ContinuityItem, ContinuityItem, bytes, int]] = []
        for item in remaining:
            ranked = replace(item, rank=len(selected) + 1)
            encoded = ranked.context_bytes()
            tokens = conservative_tokens(encoded)
            if (
                len(selected) + 1 <= query.budget.max_items
                and used_tokens + tokens <= query.budget.max_tokens
                and used_bytes + len(encoded) <= query.budget.max_bytes
            ):
                fitting.append((item, ranked, encoded, tokens))
            else:
                truncated = True
        if not fitting:
            break
        choice = next(
            (candidate for candidate in fitting if _preserves_diversity(selected, candidate[1])),
            fitting[0],
        )
        original, ranked, encoded, tokens = choice
        remaining.remove(original)
        selected.append(ranked)
        used_tokens += tokens
        used_bytes += len(encoded)
    return selected, used_tokens, used_bytes, truncated


def _preserves_diversity(selected: list[ContinuityItem], candidate: ContinuityItem) -> bool:
    maximum = (len(selected) + 2) // 2
    values: tuple[tuple[object, ...], ...] = (
        tuple(_required_category(item) for item in (*selected, candidate)),
        tuple(item.project_id for item in (*selected, candidate)),
        tuple(_session_group(item) for item in (*selected, candidate)),
    )
    return all(
        values_for_dimension.count(values_for_dimension[-1]) <= maximum
        for values_for_dimension in values
    )


def _session_group(item: ContinuityItem) -> str:
    return item.source_session_id or f"unknown:{item.item_id}"


def _require_item_in_scope(item: ContinuityItem, scope: AuthorizedScope) -> None:
    if item.brain_id != scope.brain_id.value:
        raise RetrievalAuthorizationError(_ERR_REPOSITORY_SCOPE)
    member = next(
        (candidate for candidate in scope.members if candidate.project_id.value == item.project_id),
        None,
    )
    if member is None or not _member_permits(item, member):
        raise RetrievalAuthorizationError(_ERR_REPOSITORY_SCOPE)
    if not classification_permitted(item, scope.classification_ceiling.value):
        raise RetrievalAuthorizationError(_ERR_REPOSITORY_SCOPE)
    occurred = round(item.occurred_at.timestamp() * 1_000_000)
    temporal = scope.temporal_scope
    if temporal.valid_from is not None and occurred < temporal.valid_from:
        raise RetrievalAuthorizationError(_ERR_REPOSITORY_SCOPE)
    if temporal.valid_to is not None and occurred >= temporal.valid_to:
        raise RetrievalAuthorizationError(_ERR_REPOSITORY_SCOPE)


def _member_permits(item: ContinuityItem, member: ScopeMember) -> bool:
    if item.repository_id not in {value.value for value in member.repository_ids}:
        return False
    return not member.checkout_ids or item.checkout_id in {
        value.value for value in member.checkout_ids
    }
