"""ADP-006 deterministic host-neutral session briefing query."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.retrieval.domain.continuity import (
    ContinuityKind,
    ExcludedProcedure,
    SessionBriefing,
    classification_permitted,
    conservative_tokens,
)
from agentmemory.retrieval.domain.errors import RetrievalAuthorizationError

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, ScopeMember
    from agentmemory.retrieval.domain.continuity import (
        ContinuityItem,
        ProcedureCandidate,
        StartSessionBriefingQuery,
    )
    from agentmemory.retrieval.domain.ports import (
        ContinuityReadRepository,
        ProcedureReadRepository,
    )

_CANDIDATE_LIMIT = 200
_ENVELOPE_RESERVE_BYTES = 512
_ENVELOPE_RESERVE_TOKENS = 64
_PRIORITY = {
    ContinuityKind.NEXT_STEP: 0,
    ContinuityKind.DECISION: 1,
    ContinuityKind.FAILURE: 2,
    ContinuityKind.CHANGE: 3,
    ContinuityKind.FACT: 4,
}
_ERR_REPOSITORY_SCOPE = "continuity repository crossed authorized scope"


@dataclass(frozen=True, slots=True)
class StartSessionBriefingHandler:
    """Select memories first and evaluate procedure applicability separately."""

    continuity: ContinuityReadRepository
    procedures: ProcedureReadRepository

    async def execute(self, query: StartSessionBriefingQuery) -> SessionBriefing:
        """Return the same memory selection for every equivalent host budget."""
        candidates = await self.continuity.list_items(query.scope, _CANDIDATE_LIMIT)
        for item in candidates:
            _require_item_in_scope(item, query.scope)
        ordered = sorted(
            candidates,
            key=lambda item: (
                _PRIORITY[item.kind],
                -round(item.occurred_at.timestamp() * 1_000_000),
                item.item_id,
            ),
        )
        selected: list[ContinuityItem] = []
        seen: set[str] = set()
        used_tokens = _ENVELOPE_RESERVE_TOKENS
        used_bytes = _ENVELOPE_RESERVE_BYTES
        truncated = False
        for item in ordered:
            dedupe_key = hashlib.sha256(f"{item.kind.value}\x00{item.content}".encode()).hexdigest()
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            encoded = item.context_bytes()
            tokens = conservative_tokens(encoded)
            if (
                len(selected) + 1 > query.budget.max_items
                or used_tokens + tokens > query.budget.max_tokens
                or used_bytes + len(encoded) > query.budget.max_bytes
            ):
                truncated = True
                continue
            selected.append(item)
            used_tokens += tokens
            used_bytes += len(encoded)

        procedure_candidates = await self.procedures.list_candidates(query.scope, _CANDIDATE_LIMIT)
        applicable: list[ProcedureCandidate] = []
        excluded: list[ExcludedProcedure] = []
        for procedure in sorted(procedure_candidates, key=lambda item: item.procedure_id):
            reason = procedure.applicability.exclusion_reason(query.procedure_environment)
            if reason is not None:
                excluded.append(ExcludedProcedure(procedure.procedure_id, reason))
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
            tuple(selected),
            tuple(applicable),
            tuple(excluded),
            used_tokens,
            len(selected) + len(applicable),
            used_bytes,
            truncated,
            query.scope.scope_fingerprint,
        )


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
