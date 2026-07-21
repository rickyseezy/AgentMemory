"""GRA-002 application authorization, evidence, event, and idempotency tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.graph.application.assertions import (
    ActivateAssertionCommand,
    ActivateAssertionHandler,
    ProposeAssertionCommand,
    ProposeAssertionHandler,
    ReconcileAssertionEvidenceCommand,
    ReconcileAssertionEvidenceHandler,
)
from agentmemory.graph.domain.assertions import (
    Assertion,
    AssertionCandidate,
    AssertionConfidence,
    AssertionEventType,
    AssertionExtractor,
    AssertionLifecycleEvent,
    AssertionPredicate,
    AssertionScope,
    AssertionStatus,
    AssertionTemporal,
    EvidenceKind,
    ResolvedAssertionEvidence,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphConflictError
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId

if TYPE_CHECKING:
    from agentmemory.graph.domain.assertion_ports import (
        AssertionEvidenceRepository,
        AssertionRepository,
    )

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
OTHER_BRAIN_ID = "018f0000-0000-7000-8000-000000000005"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000006"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
SUBJECT_ID = "018f0000-0000-7000-8000-000000000030"
OBJECT_ID = "018f0000-0000-7000-8000-000000000031"
CANDIDATE_ID = "018f0000-0000-7000-8000-000000000040"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000050"
SOURCE_ID = "018f0000-0000-7000-8000-000000000060"
ACTIVATED_EVENT_ID = "018f0000-0000-7000-8000-000000000070"
DISPUTED_EVENT_ID = "018f0000-0000-7000-8000-000000000071"


@pytest.mark.asyncio
async def test_propose_stores_candidate_without_activation() -> None:
    factory = _Factory(candidate=_candidate(), evidence_result=(_evidence(),))
    result = await ProposeAssertionHandler(factory).execute(
        ProposeAssertionCommand(
            "assertion-propose-1", _scope("graph.assertion.propose"), _candidate()
        )
    )
    assert result.status is AssertionStatus.CANDIDATE
    assert factory.proposals == [("assertion-propose-1", _candidate())]
    assert factory.activations == []


@pytest.mark.asyncio
async def test_activate_resolves_evidence_and_appends_content_free_event_atomically() -> None:
    factory = _Factory(candidate=_candidate(), evidence_result=(_evidence(),))
    assertion = await ActivateAssertionHandler(factory).execute(
        ActivateAssertionCommand(
            "assertion-activate-1",
            ACTIVATED_EVENT_ID,
            CANDIDATE_ID,
            _scope("graph.assertion.activate"),
            NOW + timedelta(seconds=1),
        )
    )
    assert assertion.status is AssertionStatus.ACTIVE
    operation_id, persisted, event = factory.activations[0]
    assert operation_id == "assertion-activate-1"
    assert persisted == assertion
    assert event.event_type is AssertionEventType.ACTIVATED
    assert event.evidence_ids == (EVIDENCE_ID,)
    assert len(event.digest) == 64


@pytest.mark.asyncio
async def test_evidence_revocation_disputes_active_assertion() -> None:
    active = _candidate().activate((_evidence(),), NOW)
    factory = _Factory(
        candidate=_candidate(),
        assertion=active,
        evidence_result=(replace(_evidence(), deleted=True),),
    )
    command = ReconcileAssertionEvidenceCommand(
        "assertion-reconcile-1",
        DISPUTED_EVENT_ID,
        CANDIDATE_ID,
        _scope("graph.assertion.reconcile"),
        NOW + timedelta(seconds=1),
    )
    handler = ReconcileAssertionEvidenceHandler(factory)
    result = await handler.execute(command)
    assert result.status is AssertionStatus.DISPUTED
    assert factory.disputes[0][2].event_type is AssertionEventType.DISPUTED
    assert await handler.execute(command) == result
    assert len(factory.disputes) == 2


@pytest.mark.asyncio
async def test_cross_brain_and_wrong_action_fail_before_repository_access() -> None:
    factory = _Factory(candidate=_candidate(), evidence_result=(_evidence(),))
    for scope, candidate in (
        (
            _scope("graph.assertion.activate"),
            _candidate(brain_id=OTHER_BRAIN_ID),
        ),
        (_scope("graph.assertion.propose"), _candidate()),
    ):
        factory.candidate = candidate
        with pytest.raises(GraphAuthorizationError):
            await ActivateAssertionHandler(factory).execute(
                ActivateAssertionCommand(
                    "assertion-activate-2",
                    ACTIVATED_EVENT_ID,
                    CANDIDATE_ID,
                    scope,
                    NOW,
                )
            )
    assert factory.activations == []


@pytest.mark.asyncio
async def test_missing_and_still_supported_reconciliation_paths_are_explicit() -> None:
    missing = _Factory(candidate=_candidate(), evidence_result=(_evidence(),))
    missing.assertion = None
    with pytest.raises(GraphConflictError, match="not found"):
        await ReconcileAssertionEvidenceHandler(missing).execute(
            ReconcileAssertionEvidenceCommand(
                "assertion-reconcile-missing",
                DISPUTED_EVENT_ID,
                CANDIDATE_ID,
                _scope("graph.assertion.reconcile"),
                NOW,
            )
        )
    missing.candidate = cast("AssertionCandidate", None)
    with pytest.raises(GraphConflictError, match="not found"):
        await ActivateAssertionHandler(missing).execute(
            ActivateAssertionCommand(
                "assertion-activate-missing",
                ACTIVATED_EVENT_ID,
                CANDIDATE_ID,
                _scope("graph.assertion.activate"),
                NOW,
            )
        )

    active = _candidate().activate((_evidence(),), NOW)
    supported = _Factory(
        candidate=_candidate(),
        assertion=active,
        evidence_result=(_evidence(),),
    )
    result = await ReconcileAssertionEvidenceHandler(supported).execute(
        ReconcileAssertionEvidenceCommand(
            "assertion-reconcile-supported",
            DISPUTED_EVENT_ID,
            CANDIDATE_ID,
            _scope("graph.assertion.reconcile"),
            NOW + timedelta(seconds=1),
        )
    )
    assert result is active
    assert supported.disputes == []


@pytest.mark.asyncio
async def test_project_checkout_and_classification_scope_mismatches_fail_closed() -> None:
    checkout_id = "018f0000-0000-7000-8000-000000000090"
    other_project = "018f0000-0000-7000-8000-000000000091"
    cases = (
        (_candidate(project_id=other_project), _scope("graph.assertion.propose")),
        (
            _candidate(classification="restricted"),
            _scope("graph.assertion.propose"),
        ),
        (
            _candidate(checkout_id=checkout_id),
            _scope(
                "graph.assertion.propose",
                checkout_ids=("018f0000-0000-7000-8000-000000000092",),
            ),
        ),
    )
    for candidate, scope in cases:
        factory = _Factory(candidate=candidate, evidence_result=(_evidence(),))
        with pytest.raises(GraphAuthorizationError, match="outside authorized scope"):
            await ProposeAssertionHandler(factory).execute(
                ProposeAssertionCommand(
                    "assertion-propose-scope",
                    scope,
                    candidate,
                )
            )

    active = _candidate().activate((_evidence(),), NOW)
    invalidated = replace(active, status=AssertionStatus.INVALIDATED)
    factory = _Factory(
        candidate=_candidate(),
        assertion=invalidated,
        evidence_result=(_evidence(),),
    )
    with pytest.raises(GraphConflictError, match="not found"):
        await ReconcileAssertionEvidenceHandler(factory).execute(
            ReconcileAssertionEvidenceCommand(
                "assertion-invalidated",
                DISPUTED_EVENT_ID,
                CANDIDATE_ID,
                _scope("graph.assertion.reconcile"),
                NOW,
            )
        )


def test_lifecycle_event_rejects_forged_digest() -> None:
    assertion = _candidate().activate((_evidence(),), NOW)
    event = AssertionLifecycleEvent.create(
        event_id=ACTIVATED_EVENT_ID,
        operation_id="assertion-activate-1",
        assertion=assertion,
        event_type=AssertionEventType.ACTIVATED,
        occurred_at=NOW,
    )
    with pytest.raises(ValueError, match="event is invalid"):
        replace(event, digest="b" * 64)


def _candidate(
    *,
    brain_id: str = BRAIN_ID,
    project_id: str = PROJECT_ID,
    checkout_id: str | None = None,
    classification: str = "internal",
) -> AssertionCandidate:
    return AssertionCandidate.create(
        candidate_id=CANDIDATE_ID,
        subject_id=SUBJECT_ID,
        predicate=AssertionPredicate.CONSUMES,
        object_id=OBJECT_ID,
        scope=AssertionScope(
            brain_id,
            project_id,
            REPOSITORY_ID,
            checkout_id,
            classification,
        ),
        temporal=AssertionTemporal(NOW, None, NOW, None),
        confidence=AssertionConfidence(9_000, 9_000, 9_000),
        extractor=AssertionExtractor("graph.extractor", "1.0.0", "qwen3", "revision-1"),
        evidence_ids=(EVIDENCE_ID,),
    )


def _scope_value(brain_id: str) -> AssertionScope:
    return AssertionScope(brain_id, PROJECT_ID, REPOSITORY_ID, None, "internal")


def _evidence() -> ResolvedAssertionEvidence:
    return ResolvedAssertionEvidence(
        evidence_id=EVIDENCE_ID,
        source_id=SOURCE_ID,
        kind=EvidenceKind.USER_STATEMENT,
        scope=_scope_value(BRAIN_ID),
        source_digest="a" * 64,
        occurred_at=NOW,
        accessible=True,
        deleted=False,
        immutable=True,
    )


def _scope(action: str, *, checkout_ids: tuple[str, ...] = ()) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(PRINCIPAL_ID),
        role=RetrievalRole.WORKER,
        mode=RetrievalScopeMode.SELECTED,
        members=(
            ScopeMember(
                StableId(PROJECT_ID),
                (StableId(REPOSITORY_ID),),
                tuple(StableId(value) for value in checkout_ids),
            ),
        ),
        classification_ceiling=Classification.INTERNAL,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action=action,
        purpose="assertion_test",
    )


@dataclass
class _Factory:
    candidate: AssertionCandidate
    evidence_result: tuple[ResolvedAssertionEvidence, ...]
    assertion: Assertion | None = None
    proposals: list[tuple[str, AssertionCandidate]] = field(
        default_factory=list[tuple[str, AssertionCandidate]]
    )
    activations: list[tuple[str, Assertion, AssertionLifecycleEvent]] = field(
        default_factory=list[tuple[str, Assertion, AssertionLifecycleEvent]]
    )
    disputes: list[tuple[str, Assertion, AssertionLifecycleEvent]] = field(
        default_factory=list[tuple[str, Assertion, AssertionLifecycleEvent]]
    )

    def assertions(self, scope: AuthorizedScope) -> AssertionRepository:
        del scope
        return cast("AssertionRepository", self)

    def evidence(self, scope: AuthorizedScope) -> AssertionEvidenceRepository:
        del scope
        return cast("AssertionEvidenceRepository", self)

    async def propose(self, operation_id: str, candidate: AssertionCandidate) -> AssertionCandidate:
        self.proposals.append((operation_id, candidate))
        return candidate

    async def get_candidate(self, candidate_id: str) -> AssertionCandidate | None:
        del candidate_id
        return self.candidate

    async def get_assertion(self, assertion_id: str) -> Assertion | None:
        del assertion_id
        return self.assertion

    async def activate(
        self,
        operation_id: str,
        assertion: Assertion,
        event: AssertionLifecycleEvent,
    ) -> Assertion:
        self.activations.append((operation_id, assertion, event))
        self.assertion = assertion
        return assertion

    async def dispute(
        self,
        operation_id: str,
        assertion: Assertion,
        event: AssertionLifecycleEvent,
    ) -> Assertion:
        self.disputes.append((operation_id, assertion, event))
        self.assertion = assertion
        return assertion

    async def resolve(
        self,
        evidence_ids: tuple[str, ...],
        resolved_at: datetime,
    ) -> tuple[ResolvedAssertionEvidence, ...]:
        del evidence_ids, resolved_at
        return self.evidence_result
