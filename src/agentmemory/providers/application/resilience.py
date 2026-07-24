"""PRO-007 authorized endpoint-equivalence publication and lookup."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.providers.domain.errors import (
    ProviderResilienceAuthorizationError,
    ProviderResilienceValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.resilience import EquivalentEndpointSet
    from agentmemory.providers.domain.resilience_ports import EquivalentEndpointRepository

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PUBLISH_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})
_READ_ROLES = _PUBLISH_ROLES | frozenset({RetrievalRole.AUDITOR})
_ERR_INPUT = "provider equivalence request is invalid"
_ERR_ACTION = "provider equivalence action is not authorized"


@dataclass(frozen=True, slots=True, kw_only=True)
class PublishEquivalentEndpointSetCommand:
    """Publish one immutable current-attestation endpoint set."""

    operation_id: str
    scope: AuthorizedScope
    endpoints: EquivalentEndpointSet
    created_at: datetime

    def __post_init__(self) -> None:
        """Require stable idempotency and a trusted UTC operation time."""
        if _OPERATION.fullmatch(self.operation_id) is None or not _is_utc(self.created_at):
            raise ProviderResilienceValidationError(_ERR_INPUT)

    @property
    def request_digest(self) -> str:
        """Bind idempotency to Brain and exact ordered equivalence evidence."""
        payload = json.dumps(
            {
                "brain_id": self.scope.brain_id.value,
                "set_id": self.endpoints.set_id,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True, kw_only=True)
class GetEquivalentEndpointSetQuery:
    """Read one Brain-scoped content-free equivalence attestation."""

    scope: AuthorizedScope
    set_id: str

    def __post_init__(self) -> None:
        """Require one exact content-addressed set identity."""
        if _DIGEST.fullmatch(self.set_id) is None:
            raise ProviderResilienceValidationError(_ERR_INPUT)


@dataclass(frozen=True, slots=True)
class PublishEquivalentEndpointSetHandler:
    """Authorize and persist one exact current equivalence set."""

    repository: EquivalentEndpointRepository

    async def execute(
        self,
        command: PublishEquivalentEndpointSetCommand,
    ) -> EquivalentEndpointSet:
        """Publish only with Brain-wide provider administration authority."""
        _authorize(
            command.scope,
            "provider.resilience.publish",
            _PUBLISH_ROLES,
        )
        return await self.repository.put(
            command.scope,
            command.operation_id,
            command.request_digest,
            command.endpoints,
            _microseconds(command.created_at),
        )


@dataclass(frozen=True, slots=True)
class GetEquivalentEndpointSetHandler:
    """Read one exact Brain-scoped endpoint set."""

    repository: EquivalentEndpointRepository

    async def execute(
        self,
        query: GetEquivalentEndpointSetQuery,
    ) -> EquivalentEndpointSet | None:
        """Return content-free equivalence evidence under current authority."""
        _authorize(query.scope, "provider.resilience.read", _READ_ROLES)
        return await self.repository.get(query.scope, query.set_id)


def _authorize(
    scope: AuthorizedScope,
    action: str,
    roles: frozenset[RetrievalRole],
) -> None:
    if scope.action != action or scope.role not in roles:
        raise ProviderResilienceAuthorizationError(_ERR_ACTION)


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)


def _microseconds(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)
