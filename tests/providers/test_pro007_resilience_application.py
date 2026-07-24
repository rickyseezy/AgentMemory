"""PRO-007 endpoint-equivalence application authorization and idempotency tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import timedelta, timezone
from typing import TYPE_CHECKING, Any, cast

import pytest

from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.providers.application.resilience import (
    GetEquivalentEndpointSetHandler,
    GetEquivalentEndpointSetQuery,
    PublishEquivalentEndpointSetCommand,
    PublishEquivalentEndpointSetHandler,
)
from agentmemory.providers.domain.errors import (
    ProviderResilienceAuthorizationError,
    ProviderResilienceValidationError,
)
from tests.core.support import NOW
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro007_resilience_domain import equivalent_endpoints

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.resilience import EquivalentEndpointSet


def _empty_puts() -> list[tuple[AuthorizedScope, str, str, EquivalentEndpointSet, int]]:
    return []


def _empty_gets() -> list[tuple[AuthorizedScope, str]]:
    return []


@dataclass(slots=True)
class _Repository:
    value: EquivalentEndpointSet | None = None
    puts: list[tuple[AuthorizedScope, str, str, EquivalentEndpointSet, int]] = field(
        default_factory=_empty_puts
    )
    gets: list[tuple[AuthorizedScope, str]] = field(default_factory=_empty_gets)

    async def put(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        endpoints: EquivalentEndpointSet,
        created_at_microseconds: int,
    ) -> EquivalentEndpointSet:
        self.puts.append(
            (
                scope,
                operation_id,
                request_digest,
                endpoints,
                created_at_microseconds,
            )
        )
        self.value = endpoints
        return endpoints

    async def get(
        self,
        scope: AuthorizedScope,
        set_id: str,
    ) -> EquivalentEndpointSet | None:
        self.gets.append((scope, set_id))
        return self.value

    async def resolve(
        self,
        brain_id: str,
        primary_profile_id: str,
        primary_profile_version: int,
        space_id: str,
    ) -> EquivalentEndpointSet | None:
        del brain_id, primary_profile_id, primary_profile_version, space_id
        return self.value


def _command(
    *,
    action: str = "provider.resilience.publish",
    role: RetrievalRole = RetrievalRole.OWNER,
) -> PublishEquivalentEndpointSetCommand:
    return PublishEquivalentEndpointSetCommand(
        operation_id="publish-equivalent-endpoints-1",
        scope=scope(action, role=role),
        endpoints=equivalent_endpoints(),
        created_at=NOW,
    )


@pytest.mark.asyncio
async def test_publish_authorizes_exact_action_and_binds_idempotency_to_brain_and_set() -> None:
    repository = _Repository()
    command = _command()

    result = await PublishEquivalentEndpointSetHandler(repository).execute(command)

    assert result == command.endpoints
    assert repository.puts == [
        (
            command.scope,
            command.operation_id,
            command.request_digest,
            command.endpoints,
            round(NOW.timestamp() * 1_000_000),
        )
    ]
    expected = json.dumps(
        {
            "brain_id": command.scope.brain_id.value,
            "set_id": command.endpoints.set_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    assert command.request_digest == hashlib.sha256(expected).hexdigest()


@pytest.mark.parametrize(
    ("action", "role"),
    [
        ("provider.resilience.read", RetrievalRole.OWNER),
        ("provider.resilience.publish", RetrievalRole.EDITOR),
        ("provider.resilience.publish", RetrievalRole.AUDITOR),
    ],
)
@pytest.mark.asyncio
async def test_publish_rejects_wrong_action_or_role_before_repository(
    action: str,
    role: RetrievalRole,
) -> None:
    repository = _Repository()

    with pytest.raises(ProviderResilienceAuthorizationError, match="not authorized"):
        await PublishEquivalentEndpointSetHandler(repository).execute(
            _command(action=action, role=role)
        )

    assert repository.puts == []


@pytest.mark.parametrize("role", [RetrievalRole.OWNER, RetrievalRole.ADMIN, RetrievalRole.AUDITOR])
@pytest.mark.asyncio
async def test_read_allows_governed_roles_and_preserves_brain_scope(
    role: RetrievalRole,
) -> None:
    endpoints = equivalent_endpoints()
    repository = _Repository(value=endpoints)
    query = GetEquivalentEndpointSetQuery(
        scope=scope("provider.resilience.read", role=role),
        set_id=endpoints.set_id,
    )

    assert await GetEquivalentEndpointSetHandler(repository).execute(query) == endpoints
    assert repository.gets == [(query.scope, endpoints.set_id)]


@pytest.mark.asyncio
async def test_read_rejects_non_governance_role_before_repository() -> None:
    repository = _Repository(value=equivalent_endpoints())
    query = GetEquivalentEndpointSetQuery(
        scope=scope("provider.resilience.read", role=RetrievalRole.READER),
        set_id=equivalent_endpoints().set_id,
    )

    with pytest.raises(ProviderResilienceAuthorizationError, match="not authorized"):
        await GetEquivalentEndpointSetHandler(repository).execute(query)

    assert repository.gets == []


@pytest.mark.parametrize(
    "changed",
    [
        {"operation_id": ""},
        {"operation_id": "x" * 129},
        {"created_at": NOW.replace(tzinfo=None)},
        {"created_at": NOW.astimezone(timezone(timedelta(hours=4)))},
    ],
)
def test_publish_command_rejects_invalid_identity_or_non_utc_time(
    changed: dict[str, object],
) -> None:
    command = _command()
    with pytest.raises(ProviderResilienceValidationError, match="request is invalid"):
        replace(command, **cast("Any", changed))


@pytest.mark.parametrize("set_id", ["", "A" * 64, "0" * 63, "not-a-digest"])
def test_read_query_requires_exact_content_address(set_id: str) -> None:
    with pytest.raises(ProviderResilienceValidationError, match="request is invalid"):
        GetEquivalentEndpointSetQuery(
            scope=scope("provider.resilience.read"),
            set_id=set_id,
        )
