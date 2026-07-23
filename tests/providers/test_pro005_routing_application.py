"""PRO-005 application orchestration and bounded-cache acceptance tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, Classification
from agentmemory.providers.adapters.routing_cache import BoundedProviderRouteCache
from agentmemory.providers.application.routing import (
    CreateProviderRouteCommand,
    CreateProviderRouteHandler,
    ResolveProviderRouteHandler,
    ResolveProviderRouteQuery,
    RestrictProviderRoutingCommand,
    RestrictProviderRoutingHandler,
)
from agentmemory.providers.domain.errors import (
    ProviderRoutingAuthorizationError,
    ProviderRoutingCapabilityError,
    ProviderRoutingValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderOperation,
    ProviderProfileStatus,
)
from agentmemory.providers.domain.routing import (
    ProviderRouteDraft,
    ProviderRouteSelector,
    ProviderRoutingPolicy,
    ProviderWorkload,
    RepositoryRoutingRestriction,
    RoutableProviderProfile,
    RouteDecision,
)
from tests.core.support import NOW
from tests.providers.test_pro001_profiles_domain_application import (
    PROJECT_ID as SCOPE_PROJECT_ID,
)
from tests.providers.test_pro001_profiles_domain_application import (
    REPOSITORY_ID as SCOPE_REPOSITORY_ID,
)
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro005_routing_domain import (
    POLICY_ID,
    PROFILE_ID,
    RESTRICTION_ID,
    RULE_ID,
    guard,
    policy,
    profile,
    request,
    restriction,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable
    from datetime import datetime


def _profile_calls() -> list[tuple[tuple[str, ...], datetime]]:
    return []


def _policy_publications() -> list[tuple[str, str, int, ProviderRoutingPolicy]]:
    return []


def _restriction_publications() -> list[
    tuple[str, str, int, RepositoryRoutingRestriction, datetime]
]:
    return []


def _decision_calls() -> list[tuple[str, str, RouteDecision, datetime]]:
    return []


@dataclass(slots=True)
class _Identities:
    values: list[str]

    def new(self) -> str:
        return self.values.pop(0)


@dataclass(slots=True)
class _Repository:
    profile_values: tuple[RoutableProviderProfile, ...] = field(
        default_factory=lambda: (profile(),)
    )
    policy_value: ProviderRoutingPolicy | None = None
    restriction_value: RepositoryRoutingRestriction | None = None
    profile_calls: list[tuple[tuple[str, ...], datetime]] = field(default_factory=_profile_calls)
    policy_publications: list[tuple[str, str, int, ProviderRoutingPolicy]] = field(
        default_factory=_policy_publications
    )
    restriction_publications: list[tuple[str, str, int, RepositoryRoutingRestriction, datetime]] = (
        field(default_factory=_restriction_publications)
    )
    decision_calls: list[tuple[str, str, RouteDecision, datetime]] = field(
        default_factory=_decision_calls
    )

    async def current_policy(
        self,
        scope: AuthorizedScope,
        requested_at: datetime,
    ) -> ProviderRoutingPolicy | None:
        del scope, requested_at
        return self.policy_value

    async def profiles(
        self,
        scope: AuthorizedScope,
        profile_ids: tuple[str, ...],
        requested_at: datetime,
    ) -> tuple[RoutableProviderProfile, ...]:
        del scope
        self.profile_calls.append((profile_ids, requested_at))
        return self.profile_values

    async def publish_policy(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        expected_current_version: int,
        policy: ProviderRoutingPolicy,
    ) -> ProviderRoutingPolicy:
        del scope
        self.policy_publications.append(
            (operation_id, request_digest, expected_current_version, policy)
        )
        self.policy_value = policy
        return policy

    async def current_restriction(
        self,
        scope: AuthorizedScope,
        repository_id: str,
        requested_at: datetime,
    ) -> RepositoryRoutingRestriction | None:
        del scope, repository_id, requested_at
        return self.restriction_value

    async def publish_restriction(  # noqa: PLR0913 -- Fake mirrors production port.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        expected_current_version: int,
        restriction: RepositoryRoutingRestriction,
        created_at: datetime,
    ) -> RepositoryRoutingRestriction:
        del scope
        self.restriction_publications.append(
            (
                operation_id,
                request_digest,
                expected_current_version,
                restriction,
                created_at,
            )
        )
        self.restriction_value = restriction
        return restriction

    async def record_decision(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        cache_key: str,
        decision: RouteDecision,
        decided_at: datetime,
    ) -> RouteDecision:
        del scope
        self.decision_calls.append((operation_id, cache_key, decision, decided_at))
        return decision


def route_command(
    *,
    authorized_scope: AuthorizedScope | None = None,
) -> CreateProviderRouteCommand:
    return CreateProviderRouteCommand(
        operation_id="publish-route-0001",
        scope=authorized_scope or scope("provider.route.publish"),
        expected_current_version=0,
        guard=guard(),
        routes=(
            ProviderRouteDraft(
                draft_key="code.interactive",
                profile_id=PROFILE_ID,
                operation=ProviderOperation.EMBEDDING,
                selector=ProviderRouteSelector(
                    purpose=CanonicalPurpose.CODE_QUERY,
                    workload=ProviderWorkload.INTERACTIVE,
                ),
                enabled=True,
                reason="code.interactive",
            ),
        ),
        created_at=NOW,
    )


def restriction_command(
    *,
    authorized_scope: AuthorizedScope | None = None,
) -> RestrictProviderRoutingCommand:
    return RestrictProviderRoutingCommand(
        operation_id="restrict-route-0001",
        scope=authorized_scope or scope("provider.route.restrict"),
        repository_id=SCOPE_REPOSITORY_ID,
        expected_current_version=0,
        allow_remote=True,
        allowed_remote_residencies=("AE",),
        remote_classification_ceiling=Classification.INTERNAL,
        allowed_profile_ids=(PROFILE_ID,),
        allowed_purposes=(CanonicalPurpose.CODE_QUERY,),
        allowed_workloads=(ProviderWorkload.INTERACTIVE,),
        created_at=NOW,
    )


@pytest.mark.asyncio
async def test_create_route_binds_exact_active_profile_and_publishes_next_version() -> None:
    repository = _Repository()
    identities = _Identities([RULE_ID, POLICY_ID])
    result = await CreateProviderRouteHandler(repository, identities).execute(route_command())

    assert result.version == 1
    assert result.rules[0].profile_version == profile().version
    assert result.rules[0].profile_snapshot_digest == profile().snapshot_digest
    assert repository.profile_calls == [((PROFILE_ID,), NOW)]
    publication = repository.policy_publications[0]
    assert publication[:3] == (
        "publish-route-0001",
        route_command().request_digest,
        0,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "profile_value",
    [
        profile(status=ProviderProfileStatus.REPROBE_REQUIRED),
        profile(operation=ProviderOperation.RERANKING),
        profile(purposes=(CanonicalPurpose.RETRIEVAL_DOCUMENT,)),
    ],
)
async def test_create_route_rejects_inactive_or_incompatible_profiles(
    profile_value: RoutableProviderProfile,
) -> None:
    repository = _Repository(profile_values=(profile_value,))
    with pytest.raises(ProviderRoutingCapabilityError):
        await CreateProviderRouteHandler(
            repository,
            _Identities([RULE_ID, POLICY_ID]),
        ).execute(route_command())
    assert repository.policy_publications == []


@pytest.mark.asyncio
async def test_create_route_rejects_ambiguity_before_repository_publication() -> None:
    first = route_command().routes[0]
    second = replace(
        first,
        draft_key="code.python",
        selector=ProviderRouteSelector(corpus=request().corpus),
    )
    ambiguous_first = replace(
        first,
        selector=ProviderRouteSelector(workload=request().workload),
    )
    command = replace(
        route_command(),
        routes=tuple(sorted((second, ambiguous_first), key=lambda item: item.draft_key)),
    )
    repository = _Repository()
    with pytest.raises(ProviderRoutingValidationError, match="ambiguous"):
        await CreateProviderRouteHandler(
            repository,
            _Identities(
                [
                    RULE_ID,
                    "018f0000-0000-7000-8000-000000000599",
                    POLICY_ID,
                ]
            ),
        ).execute(command)
    assert repository.policy_publications == []


@pytest.mark.asyncio
async def test_repository_restriction_is_validated_against_current_policy() -> None:
    repository = _Repository(policy_value=policy())
    result = await RestrictProviderRoutingHandler(
        repository,
        _Identities([RESTRICTION_ID]),
    ).execute(restriction_command())
    assert result.version == 1
    assert repository.restriction_publications[0][0] == "restrict-route-0001"

    broadened = replace(
        restriction_command(),
        allowed_remote_residencies=("AE", "US"),
    )
    with pytest.raises(ProviderRoutingValidationError):
        await RestrictProviderRoutingHandler(
            repository,
            _Identities([RESTRICTION_ID]),
        ).execute(broadened)


@pytest.mark.asyncio
async def test_handlers_fail_closed_when_no_routing_policy_exists() -> None:
    repository = _Repository()
    with pytest.raises(ProviderRoutingValidationError, match="not found"):
        await RestrictProviderRoutingHandler(
            repository,
            _Identities([RESTRICTION_ID]),
        ).execute(restriction_command())
    with pytest.raises(ProviderRoutingCapabilityError, match="not found"):
        await ResolveProviderRouteHandler(
            repository,
            BoundedProviderRouteCache(),
        ).execute(
            ResolveProviderRouteQuery(
                operation_id="resolve-route-missing",
                scope=scope("provider.route.resolve"),
                request=replace(
                    request(),
                    project_id=SCOPE_PROJECT_ID,
                    repository_id=SCOPE_REPOSITORY_ID,
                ),
                requested_at=NOW,
            )
        )


@pytest.mark.asyncio
async def test_resolution_uses_complete_version_cache_but_journals_every_call() -> None:
    repository = _Repository(
        policy_value=policy(),
        restriction_value=replace(
            restriction(),
            repository_id=SCOPE_REPOSITORY_ID,
        ),
    )
    cache = BoundedProviderRouteCache(maximum_entries=2)
    handler = ResolveProviderRouteHandler(repository, cache)
    query = ResolveProviderRouteQuery(
        operation_id="resolve-route-0001",
        scope=scope("provider.route.resolve"),
        request=replace(
            request(),
            project_id=SCOPE_PROJECT_ID,
            repository_id=SCOPE_REPOSITORY_ID,
        ),
        requested_at=NOW,
    )
    first = await handler.execute(query)
    second = await handler.execute(replace(query, operation_id="resolve-route-0002"))
    assert first == second
    assert len(repository.decision_calls) == 2
    assert repository.decision_calls[0][1] == repository.decision_calls[1][1]


@pytest.mark.asyncio
async def test_profile_version_change_invalidates_resolution_cache() -> None:
    original = profile()
    repository = _Repository(policy_value=policy(), profile_values=(original,))
    cache = BoundedProviderRouteCache(maximum_entries=2)
    handler = ResolveProviderRouteHandler(repository, cache)
    query = ResolveProviderRouteQuery(
        operation_id="resolve-route-0001",
        scope=scope("provider.route.resolve"),
        request=replace(
            request(),
            project_id=SCOPE_PROJECT_ID,
            repository_id=SCOPE_REPOSITORY_ID,
        ),
        requested_at=NOW,
    )
    await handler.execute(query)
    repository.profile_values = (replace(original, version=3),)
    with pytest.raises(ProviderRoutingCapabilityError):
        await handler.execute(replace(query, operation_id="resolve-route-0002"))


@pytest.mark.asyncio
async def test_resolution_and_restriction_cannot_escape_authorized_workspace() -> None:
    repository = _Repository(policy_value=policy())
    resolve = ResolveProviderRouteHandler(
        repository,
        BoundedProviderRouteCache(),
    )
    with pytest.raises(ProviderRoutingAuthorizationError):
        await resolve.execute(
            ResolveProviderRouteQuery(
                operation_id="resolve-outside-scope",
                scope=scope("provider.route.resolve"),
                request=request(),
                requested_at=NOW,
            )
        )
    with pytest.raises(ProviderRoutingAuthorizationError):
        await RestrictProviderRoutingHandler(
            repository,
            _Identities([RESTRICTION_ID]),
        ).execute(
            replace(
                restriction_command(),
                repository_id="018f0000-0000-7000-8000-000000000599",
            )
        )


@pytest.mark.asyncio
async def test_bounded_cache_evicts_lru_and_validates_capacity() -> None:
    cache = BoundedProviderRouteCache(maximum_entries=1)
    first = policy().decide(request(), (profile(),))
    second = replace(first, request_digest="a" * 64)
    await cache.put("one", first)
    await cache.put("two", second)
    assert await cache.get("one") is None
    assert await cache.get("two") == second
    with pytest.raises(ProviderRoutingValidationError):
        BoundedProviderRouteCache(maximum_entries=0)


@pytest.mark.asyncio
async def test_bounded_cache_overwrite_preserves_capacity_and_refreshes_lru() -> None:
    cache = BoundedProviderRouteCache(maximum_entries=2)
    first = policy().decide(request(), (profile(),))
    refreshed = replace(first, request_digest="b" * 64)
    other = replace(first, request_digest="c" * 64)
    final = replace(first, request_digest="d" * 64)
    await cache.put("first", first)
    await cache.put("other", other)
    await cache.put("first", refreshed)
    await cache.put("final", final)
    assert await cache.get("first") == refreshed
    assert await cache.get("other") is None
    assert await cache.get("final") == final


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("command", "handler"),
    [
        (
            route_command(authorized_scope=scope("provider.route.read")),
            "create",
        ),
        (
            restriction_command(
                authorized_scope=scope("provider.route.read"),
            ),
            "restrict",
        ),
    ],
)
async def test_mutation_handlers_require_exact_administrator_action(
    command: object,
    handler: str,
) -> None:
    repository = _Repository(policy_value=policy())
    invocation: Awaitable[object]
    if handler == "create":
        invocation = CreateProviderRouteHandler(
            repository,
            _Identities([RULE_ID, POLICY_ID]),
        ).execute(command)  # type: ignore[arg-type]
    else:
        invocation = RestrictProviderRoutingHandler(
            repository,
            _Identities([RESTRICTION_ID]),
        ).execute(command)  # type: ignore[arg-type]
    with pytest.raises(ProviderRoutingAuthorizationError):
        await invocation


@pytest.mark.parametrize(
    "build",
    [
        lambda: replace(route_command(), operation_id="invalid operation"),
        lambda: replace(
            restriction_command(),
            created_at=NOW.replace(tzinfo=None),
        ),
        lambda: ResolveProviderRouteQuery(
            operation_id="resolve-route-invalid",
            scope=scope("provider.route.resolve"),
            request=replace(
                request(),
                brain_id="018f0000-0000-7000-8000-000000000599",
            ),
            requested_at=NOW,
        ),
    ],
)
def test_application_commands_reject_invalid_coordinates(build: object) -> None:
    with pytest.raises(ProviderRoutingValidationError):
        build()  # type: ignore[operator]
