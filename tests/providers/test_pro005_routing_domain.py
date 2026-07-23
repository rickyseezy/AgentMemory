"""PRO-005 deterministic routing, policy-lattice, and cache acceptance tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.domain.errors import (
    ProviderRoutingCapabilityError,
    ProviderRoutingDeniedError,
    ProviderRoutingValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    ProviderOperation,
    ProviderProfileStatus,
)
from agentmemory.providers.domain.routing import (
    ProviderCorpus,
    ProviderRouteDraft,
    ProviderRouteRequest,
    ProviderRouteRule,
    ProviderRouteSelector,
    ProviderRoutingGuard,
    ProviderRoutingPolicy,
    ProviderWorkload,
    RepositoryRoutingRestriction,
    RoutableProviderProfile,
    routing_cache_key,
)
from tests.core.support import BRAIN_ID, NOW, digest

POLICY_ID = "018f0000-0000-7000-8000-000000000501"
RULE_ID = "018f0000-0000-7000-8000-000000000502"
PROFILE_ID = "018f0000-0000-7000-8000-000000000503"
OTHER_PROFILE_ID = "018f0000-0000-7000-8000-000000000504"
PROJECT_ID = "018f0000-0000-7000-8000-000000000505"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000506"
RESTRICTION_ID = "018f0000-0000-7000-8000-000000000507"


def guard() -> ProviderRoutingGuard:
    return ProviderRoutingGuard(
        allow_remote=True,
        allowed_remote_residencies=("AE", "global"),
        remote_classification_ceiling=Classification.CONFIDENTIAL,
    )


def request(**changes: object) -> ProviderRouteRequest:
    values: dict[str, object] = {
        "brain_id": BRAIN_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
        "operation": ProviderOperation.EMBEDDING,
        "corpus": ProviderCorpus.CODE,
        "language": "python",
        "classification": Classification.INTERNAL,
        "purpose": CanonicalPurpose.CODE_QUERY,
        "workload": ProviderWorkload.INTERACTIVE,
    }
    values.update(changes)
    return ProviderRouteRequest(**values)  # type: ignore[arg-type]


def profile(**changes: object) -> RoutableProviderProfile:
    values: dict[str, object] = {
        "profile_id": PROFILE_ID,
        "version": 2,
        "snapshot_digest": digest("profile").value,
        "status": ProviderProfileStatus.ACTIVE,
        "operation": ProviderOperation.EMBEDDING,
        "purposes": (CanonicalPurpose.CODE_QUERY,),
        "execution_class": ProviderExecutionClass.REMOTE,
        "residency": "AE",
    }
    values.update(changes)
    return RoutableProviderProfile(**values)  # type: ignore[arg-type]


def rule(
    *,
    rule_id: str = RULE_ID,
    profile_value: RoutableProviderProfile | None = None,
    selector: ProviderRouteSelector | None = None,
    enabled: bool = True,
    reason: str = "code.interactive",
) -> ProviderRouteRule:
    selected = profile_value or profile()
    return ProviderRouteRule(
        rule_id=rule_id,
        profile_id=selected.profile_id,
        profile_version=selected.version,
        profile_snapshot_digest=selected.snapshot_digest,
        operation=selected.operation,
        selector=selector or ProviderRouteSelector(),
        enabled=enabled,
        reason=reason,
    )


def policy(*rules: ProviderRouteRule) -> ProviderRoutingPolicy:
    return ProviderRoutingPolicy(
        policy_id=POLICY_ID,
        brain_id=BRAIN_ID,
        version=3,
        guard=guard(),
        rules=tuple(sorted(rules or (rule(),), key=lambda item: item.rule_id)),
        created_at=NOW,
    )


def restriction(**changes: object) -> RepositoryRoutingRestriction:
    values: dict[str, object] = {
        "restriction_id": RESTRICTION_ID,
        "brain_id": BRAIN_ID,
        "repository_id": REPOSITORY_ID,
        "version": 1,
        "allow_remote": True,
        "allowed_remote_residencies": ("AE",),
        "remote_classification_ceiling": Classification.INTERNAL,
        "allowed_profile_ids": (PROFILE_ID,),
        "allowed_purposes": (CanonicalPurpose.CODE_QUERY,),
        "allowed_workloads": (ProviderWorkload.INTERACTIVE,),
    }
    values.update(changes)
    return RepositoryRoutingRestriction(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("selectors", "winning_reason", "precedence"),
    [
        (
            (
                ProviderRouteSelector(),
                ProviderRouteSelector(corpus=ProviderCorpus.CODE),
            ),
            "specific",
            (0, 1),
        ),
        (
            (
                ProviderRouteSelector(
                    corpus=ProviderCorpus.CODE,
                    workload=ProviderWorkload.INTERACTIVE,
                ),
                ProviderRouteSelector(project_id=PROJECT_ID),
            ),
            "specific",
            (1, 0),
        ),
        (
            (
                ProviderRouteSelector(project_id=PROJECT_ID),
                ProviderRouteSelector(
                    project_id=PROJECT_ID,
                    corpus=ProviderCorpus.CODE,
                    language="python",
                    classification=Classification.INTERNAL,
                    purpose=CanonicalPurpose.CODE_QUERY,
                    workload=ProviderWorkload.INTERACTIVE,
                ),
            ),
            "specific",
            (1, 5),
        ),
    ],
)
def test_documented_precedence_tuple_selects_the_most_specific_enabled_route(
    selectors: tuple[ProviderRouteSelector, ProviderRouteSelector],
    winning_reason: str,
    precedence: tuple[int, int],
) -> None:
    routes = (
        rule(
            rule_id=RULE_ID,
            selector=selectors[0],
            reason="general",
        ),
        rule(
            rule_id="018f0000-0000-7000-8000-000000000599",
            selector=selectors[1],
            reason=winning_reason,
        ),
    )
    decision = policy(*routes).decide(request(), (profile(),))

    assert decision.reason == winning_reason
    assert decision.precedence == precedence
    assert decision.profile_version == 2


def test_disabled_and_nonmatching_routes_do_not_enter_precedence() -> None:
    ignored = rule(
        rule_id="018f0000-0000-7000-8000-000000000598",
        selector=ProviderRouteSelector(
            project_id=PROJECT_ID,
            corpus=ProviderCorpus.CODE,
        ),
        enabled=False,
        reason="disabled",
    )
    decision = policy(ignored, rule()).decide(request(), (profile(),))
    assert decision.rule_id == RULE_ID


def test_equal_precedence_overlap_is_rejected_before_publication() -> None:
    corpus = rule(
        selector=ProviderRouteSelector(corpus=ProviderCorpus.CODE),
    )
    workload = rule(
        rule_id="018f0000-0000-7000-8000-000000000599",
        selector=ProviderRouteSelector(workload=ProviderWorkload.INTERACTIVE),
    )
    with pytest.raises(ProviderRoutingValidationError, match="ambiguous"):
        policy(corpus, workload)


@pytest.mark.parametrize(
    "changed",
    [
        {"status": ProviderProfileStatus.REPROBE_REQUIRED},
        {"version": 3},
        {"snapshot_digest": digest("changed").value},
        {"operation": ProviderOperation.RERANKING},
        {"purposes": (CanonicalPurpose.RETRIEVAL_DOCUMENT,)},
    ],
)
def test_selected_route_fails_closed_on_profile_capability_or_snapshot_drift(
    changed: dict[str, object],
) -> None:
    with pytest.raises(ProviderRoutingCapabilityError):
        policy().decide(request(), (profile(**changed),))


@pytest.mark.parametrize(
    ("request_changes", "profile_changes"),
    [
        ({"classification": Classification.RESTRICTED}, {}),
        ({"classification": Classification.LOCAL_ONLY}, {}),
        ({}, {"residency": "US"}),
    ],
)
def test_remote_route_enforces_classification_and_residency(
    request_changes: dict[str, object],
    profile_changes: dict[str, object],
) -> None:
    with pytest.raises(ProviderRoutingDeniedError):
        policy().decide(request(**request_changes), (profile(**profile_changes),))


def test_local_route_never_requires_or_uses_an_egress_grant() -> None:
    local = profile(
        execution_class=ProviderExecutionClass.LOCAL,
        residency="local",
    )
    no_egress = ProviderRoutingPolicy(
        policy_id=POLICY_ID,
        brain_id=BRAIN_ID,
        version=1,
        guard=ProviderRoutingGuard(
            allow_remote=False,
            allowed_remote_residencies=(),
            remote_classification_ceiling=Classification.PUBLIC,
        ),
        rules=(rule(profile_value=local),),
        created_at=NOW,
    )
    assert no_egress.decide(request(), (local,)).profile_id == PROFILE_ID


def test_repository_restriction_can_narrow_but_never_broaden() -> None:
    restricted = restriction()
    assert policy().decide(request(), (profile(),), restricted).profile_id == PROFILE_ID
    with pytest.raises(ProviderRoutingDeniedError):
        policy().decide(
            request(classification=Classification.CONFIDENTIAL),
            (profile(),),
            restricted,
        )
    with pytest.raises(ProviderRoutingValidationError):
        restriction(
            allowed_remote_residencies=("AE", "US"),
        ).validate_narrows(guard())
    with pytest.raises(ProviderRoutingValidationError):
        restriction(
            remote_classification_ceiling=Classification.RESTRICTED,
        ).validate_narrows(guard())


def test_repository_allowlists_only_filter_selected_routes() -> None:
    with pytest.raises(ProviderRoutingDeniedError):
        policy().decide(
            request(),
            (profile(),),
            restriction(allowed_profile_ids=(OTHER_PROFILE_ID,)),
        )
    with pytest.raises(ProviderRoutingDeniedError):
        policy().decide(
            request(),
            (profile(),),
            restriction(allowed_workloads=(ProviderWorkload.BACKFILL,)),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("grant_version", 2),
        ("authorization_policy_version", 5),
        ("security_epoch", 4),
    ],
)
def test_cache_key_invalidates_on_every_authorization_version(
    field: str,
    value: int,
) -> None:
    baseline = {
        "request": request(),
        "policy": policy(),
        "grant_version": 1,
        "authorization_policy_version": 1,
        "security_epoch": 1,
        "profiles": (profile(),),
        "restriction": restriction(),
    }
    original = routing_cache_key(**baseline)  # type: ignore[arg-type]
    baseline[field] = value
    assert routing_cache_key(**baseline) != original  # type: ignore[arg-type]


def test_cache_key_invalidates_on_policy_profile_and_restriction_version() -> None:
    values = {
        "request": request(),
        "policy": policy(),
        "grant_version": 1,
        "authorization_policy_version": 1,
        "security_epoch": 1,
        "profiles": (profile(),),
        "restriction": restriction(),
    }
    original = routing_cache_key(**values)  # type: ignore[arg-type]
    variants = (
        {**values, "policy": replace(policy(), version=4)},
        {**values, "profiles": (profile(version=3),)},
        {**values, "restriction": replace(restriction(), version=2)},
    )
    assert all(
        routing_cache_key(**variant) != original  # type: ignore[arg-type]
        for variant in variants
    )


def test_routing_contract_rejects_noncanonical_and_empty_documents() -> None:
    with pytest.raises(ProviderRoutingValidationError):
        request(language="Python")
    with pytest.raises(ProviderRoutingValidationError):
        ProviderRoutingGuard(
            allow_remote=False,
            allowed_remote_residencies=("AE",),
            remote_classification_ceiling=Classification.INTERNAL,
        )
    with pytest.raises(ProviderRoutingValidationError):
        ProviderRoutingPolicy(
            policy_id=POLICY_ID,
            brain_id=BRAIN_ID,
            version=1,
            guard=guard(),
            rules=(),
            created_at=datetime(2026, 1, 1, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "build",
    [
        lambda: restriction(version=0),
        lambda: ProviderRouteSelector(
            project_id=PROJECT_ID,
            language="Python",
        ),
        lambda: replace(rule(), profile_version=0),
        lambda: ProviderRouteDraft(
            draft_key="INVALID KEY",
            profile_id=PROFILE_ID,
            operation=ProviderOperation.EMBEDDING,
            selector=ProviderRouteSelector(),
            enabled=True,
            reason="valid.reason",
        ),
        lambda: profile(version=0),
        lambda: replace(
            policy().decide(request(), (profile(),)),
            policy_version=0,
        ),
        lambda: ProviderRouteSelector(project_id="00000000-0000-4000-8000-000000000001"),
    ],
)
def test_closed_routing_values_reject_each_invalid_shape(build: object) -> None:
    with pytest.raises(ProviderRoutingValidationError):
        build()  # type: ignore[operator]


def test_optional_request_scope_and_fail_closed_decision_branches() -> None:
    unscoped = request(
        project_id=None,
        repository_id=None,
        language=None,
    )
    assert unscoped.project_id is None
    assert unscoped.repository_id is None
    with pytest.raises(ProviderRoutingValidationError):
        policy().decide(
            replace(
                request(),
                brain_id="018f0000-0000-7000-8000-000000000599",
            ),
            (profile(),),
        )
    with pytest.raises(ProviderRoutingValidationError):
        policy().decide(
            request(repository_id=None),
            (profile(),),
            restriction(),
        )
    with pytest.raises(ProviderRoutingCapabilityError, match="no provider route"):
        policy().decide(
            request(operation=ProviderOperation.RERANKING),
            (profile(),),
        )
    with pytest.raises(ProviderRoutingValidationError):
        routing_cache_key(
            request=request(),
            policy=policy(),
            grant_version=0,
            authorization_policy_version=1,
            security_epoch=1,
            profiles=(profile(),),
            restriction=None,
        )
