"""PRO-005 provider route publication, restriction, and resolution use cases."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import Classification, RetrievalRole
from agentmemory.providers.domain.errors import (
    ProviderRoutingAuthorizationError,
    ProviderRoutingCapabilityError,
    ProviderRoutingValidationError,
)
from agentmemory.providers.domain.profiles import CanonicalPurpose, ProviderProfileStatus
from agentmemory.providers.domain.routing import (
    ProviderRouteRule,
    ProviderRoutingPolicy,
    ProviderWorkload,
    RepositoryRoutingRestriction,
    routing_cache_key,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.routing import (
        ProviderRouteDraft,
        ProviderRouteRequest,
        ProviderRoutingGuard,
        RoutableProviderProfile,
        RouteDecision,
    )
    from agentmemory.providers.domain.routing_ports import (
        ProviderRouteCache,
        ProviderRoutingIdentityGenerator,
        ProviderRoutingRepository,
    )

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_WRITE_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})
_RESOLVE_ROLES = frozenset(
    {
        RetrievalRole.OWNER,
        RetrievalRole.ADMIN,
        RetrievalRole.EDITOR,
        RetrievalRole.ADAPTER,
        RetrievalRole.WORKER,
    }
)
_ERR_REQUEST = "provider routing request is invalid"
_ERR_ACTION = "provider routing action is not authorized"
_ERR_PROFILE = "provider routing profile is not active or capable"
_ERR_POLICY = "provider routing policy was not found"


@dataclass(frozen=True, slots=True, kw_only=True)
class CreateProviderRouteCommand:
    """Publish a complete replacement policy bound to current profile snapshots."""

    operation_id: str
    scope: AuthorizedScope
    expected_current_version: int
    guard: ProviderRoutingGuard
    routes: tuple[ProviderRouteDraft, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        """Require canonical command coordinates and deterministic draft ordering."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or not 0 <= self.expected_current_version <= 2**31 - 2
            or not self.routes
            or tuple(sorted(self.routes, key=lambda item: item.draft_key)) != self.routes
            or len({item.draft_key for item in self.routes}) != len(self.routes)
            or not _is_utc(self.created_at)
        ):
            raise ProviderRoutingValidationError(_ERR_REQUEST)

    @property
    def request_digest(self) -> str:
        """Bind idempotency to all administrator-authored policy input."""
        return _digest(
            {
                "brain_id": self.scope.brain_id.value,
                "expected_current_version": self.expected_current_version,
                "guard": self.guard.document,
                "routes": [route.document for route in self.routes],
            }
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RestrictProviderRoutingCommand:
    """Publish one repository filter that cannot broaden the Brain policy."""

    operation_id: str
    scope: AuthorizedScope
    repository_id: str
    expected_current_version: int
    allow_remote: bool
    allowed_remote_residencies: tuple[str, ...]
    remote_classification_ceiling: Classification
    allowed_profile_ids: tuple[str, ...]
    allowed_purposes: tuple[CanonicalPurpose, ...]
    allowed_workloads: tuple[ProviderWorkload, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        """Validate shared command coordinates before domain construction."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or not 0 <= self.expected_current_version <= 2**31 - 2
            or not _is_utc(self.created_at)
        ):
            raise ProviderRoutingValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True, kw_only=True)
class ResolveProviderRouteQuery:
    """Resolve and journal one route under current authorization versions."""

    operation_id: str
    scope: AuthorizedScope
    request: ProviderRouteRequest
    requested_at: datetime

    def __post_init__(self) -> None:
        """Require a stable evidence identity and matching Brain."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or self.request.brain_id != self.scope.brain_id.value
            or not _is_utc(self.requested_at)
        ):
            raise ProviderRoutingValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class CreateProviderRouteHandler:
    """Resolve exact capabilities, reject ambiguity, and publish atomically."""

    repository: ProviderRoutingRepository
    identities: ProviderRoutingIdentityGenerator

    async def execute(self, command: CreateProviderRouteCommand) -> ProviderRoutingPolicy:
        """Create one immutable policy revision with no implicit fallback."""
        _authorize(command.scope, "provider.route.publish", _WRITE_ROLES)
        profile_ids = tuple(sorted({route.profile_id for route in command.routes}))
        profiles = await self.repository.profiles(
            command.scope,
            profile_ids,
            command.created_at,
        )
        by_id = {profile.profile_id: profile for profile in profiles}
        rules: list[ProviderRouteRule] = []
        for draft in command.routes:
            profile = _validate_draft_capability(draft, by_id.get(draft.profile_id))
            rules.append(
                ProviderRouteRule(
                    rule_id=self.identities.new(),
                    profile_id=profile.profile_id,
                    profile_version=profile.version,
                    profile_snapshot_digest=profile.snapshot_digest,
                    operation=draft.operation,
                    selector=draft.selector,
                    enabled=draft.enabled,
                    reason=draft.reason,
                )
            )
        policy = ProviderRoutingPolicy(
            policy_id=self.identities.new(),
            brain_id=command.scope.brain_id.value,
            version=command.expected_current_version + 1,
            guard=command.guard,
            rules=tuple(sorted(rules, key=lambda item: item.rule_id)),
            created_at=command.created_at,
        )
        return await self.repository.publish_policy(
            command.scope,
            command.operation_id,
            command.request_digest,
            command.expected_current_version,
            policy,
        )


@dataclass(frozen=True, slots=True)
class RestrictProviderRoutingHandler:
    """Validate a repository filter against the current Brain lattice."""

    repository: ProviderRoutingRepository
    identities: ProviderRoutingIdentityGenerator

    async def execute(
        self,
        command: RestrictProviderRoutingCommand,
    ) -> RepositoryRoutingRestriction:
        """Publish one immutable restriction revision."""
        _authorize(command.scope, "provider.route.restrict", _WRITE_ROLES)
        if command.repository_id not in {value.value for value in command.scope.repository_ids}:
            raise ProviderRoutingAuthorizationError(_ERR_ACTION)
        policy = await self.repository.current_policy(command.scope, command.created_at)
        if policy is None:
            raise ProviderRoutingValidationError(_ERR_POLICY)
        restriction = RepositoryRoutingRestriction(
            restriction_id=self.identities.new(),
            brain_id=command.scope.brain_id.value,
            repository_id=command.repository_id,
            version=command.expected_current_version + 1,
            allow_remote=command.allow_remote,
            allowed_remote_residencies=command.allowed_remote_residencies,
            remote_classification_ceiling=command.remote_classification_ceiling,
            allowed_profile_ids=command.allowed_profile_ids,
            allowed_purposes=command.allowed_purposes,
            allowed_workloads=command.allowed_workloads,
        )
        restriction.validate_narrows(policy.guard)
        request_digest = _digest(
            {
                "expected_current_version": command.expected_current_version,
                "restriction": restriction.document | {"restriction_id": None, "version": None},
            }
        )
        return await self.repository.publish_restriction(
            command.scope,
            command.operation_id,
            request_digest,
            command.expected_current_version,
            restriction,
            command.created_at,
        )


@dataclass(frozen=True, slots=True)
class ResolveProviderRouteHandler:
    """Resolve through a complete version cache and journal every response."""

    repository: ProviderRoutingRepository
    cache: ProviderRouteCache

    async def execute(self, query: ResolveProviderRouteQuery) -> RouteDecision:
        """Return a deterministic decision under fresh policy and capability state."""
        _authorize(query.scope, "provider.route.resolve", _RESOLVE_ROLES)
        if (
            query.request.project_id is not None
            and query.request.project_id not in {value.value for value in query.scope.project_ids}
        ) or (
            query.request.repository_id is not None
            and query.request.repository_id
            not in {value.value for value in query.scope.repository_ids}
        ):
            raise ProviderRoutingAuthorizationError(_ERR_ACTION)
        policy = await self.repository.current_policy(query.scope, query.requested_at)
        if policy is None:
            raise ProviderRoutingCapabilityError(_ERR_POLICY)
        profile_ids = tuple(sorted({rule.profile_id for rule in policy.rules if rule.enabled}))
        profiles = await self.repository.profiles(
            query.scope,
            profile_ids,
            query.requested_at,
        )
        restriction = (
            None
            if query.request.repository_id is None
            else await self.repository.current_restriction(
                query.scope,
                query.request.repository_id,
                query.requested_at,
            )
        )
        key = routing_cache_key(
            request=query.request,
            policy=policy,
            grant_version=query.scope.grant_version,
            authorization_policy_version=query.scope.policy_version,
            security_epoch=query.scope.security_epoch,
            profiles=profiles,
            restriction=restriction,
        )
        decision = await self.cache.get(key)
        if decision is None:
            decision = policy.decide(query.request, profiles, restriction)
            await self.cache.put(key, decision)
        return await self.repository.record_decision(
            query.scope,
            query.operation_id,
            key,
            decision,
            query.requested_at,
        )


def _validate_draft_capability(
    draft: ProviderRouteDraft,
    profile: RoutableProviderProfile | None,
) -> RoutableProviderProfile:
    if (
        profile is None
        or profile.status is not ProviderProfileStatus.ACTIVE
        or profile.operation is not draft.operation
        or (draft.selector.purpose is not None and draft.selector.purpose not in profile.purposes)
    ):
        raise ProviderRoutingCapabilityError(_ERR_PROFILE)
    return profile


def _authorize(
    scope: AuthorizedScope,
    action: str,
    roles: frozenset[RetrievalRole],
) -> None:
    if scope.action != action or scope.role not in roles:
        raise ProviderRoutingAuthorizationError(_ERR_ACTION)


def _digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderRoutingValidationError(_ERR_REQUEST) from error
    result = hashlib.sha256(payload).hexdigest()
    if _DIGEST.fullmatch(result) is None:
        raise ProviderRoutingValidationError(_ERR_REQUEST)
    return result


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)
