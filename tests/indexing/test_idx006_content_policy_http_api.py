"""IDX-006 authenticated policy activation and content-free status HTTP tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution, ScopeExplanation
from agentmemory.indexing.adapters.inbound.content_policy_http_api import (
    create_content_policy_router,
    create_contract_content_policy_router,
)
from agentmemory.indexing.application.content_policy import (
    ActivateIndexPolicyCommand,
    GetIndexPolicyChangeQuery,
)
from agentmemory.indexing.domain.content_policy_ports import PolicyChangeResult
from agentmemory.indexing.domain.errors import IndexingAuthorizationError
from agentmemory.operations.bootstrap import export_core_openapi_schema
from tests.core.support import BRAIN_ID, NOW, OWNER_ID, FixedClock
from tests.indexing.test_idx001_sqlite_code_index import (
    PROJECT_ID,
    REPOSITORY_ID,
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope as indexing_scope,  # pyright: ignore[reportPrivateUsage]
)

GRANT_ID = "018f0000-0000-7000-8000-000000000003"
CHANGE_ID = "a" * 64
POLICY_DIGEST = "b" * 64
PREVIOUS_DIGEST = "c" * 64
POLICY_ID = "018f0000-0000-7000-8000-000000000601"
_ERR_CREDENTIAL = "credential is not authorized"


@dataclass(slots=True)
class _Authenticator:
    reject: bool = False

    async def authenticate(self, authorization: str | None) -> None:
        if self.reject or authorization != "Bearer local":
            raise IndexingAuthorizationError(_ERR_CREDENTIAL)


@dataclass(slots=True)
class _Resolver:
    requests: list[object] = field(default_factory=list[object])

    async def execute(self, query: object) -> RetrievalScopeResolution:
        self.requests.append(query)
        scope = indexing_scope("indexing.search")
        return RetrievalScopeResolution(scope, ScopeExplanation(scope.mode, ("project",)))


@dataclass(slots=True)
class _Activate:
    commands: list[ActivateIndexPolicyCommand] = field(
        default_factory=list[ActivateIndexPolicyCommand]
    )

    async def execute(self, command: ActivateIndexPolicyCommand) -> PolicyChangeResult:
        self.commands.append(command)
        return _result(command.operation_id)


@dataclass(slots=True)
class _Get:
    queries: list[GetIndexPolicyChangeQuery] = field(
        default_factory=list[GetIndexPolicyChangeQuery]
    )

    async def execute(self, query: GetIndexPolicyChangeQuery) -> PolicyChangeResult:
        self.queries.append(query)
        return _result("idx006-http")


def _result(operation_id: str) -> PolicyChangeResult:
    return PolicyChangeResult(
        CHANGE_ID,
        operation_id,
        BRAIN_ID,
        REPOSITORY_ID,
        PREVIOUS_DIGEST,
        POLICY_DIGEST,
        2,
        3,
        NOW,
    )


def _scope_fields() -> dict[str, str]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def _body(operation_id: str) -> dict[str, object]:
    return {
        **_scope_fields(),
        "operation_id": operation_id,
        "policy_id": POLICY_ID,
        "version": 2,
        "rules": [
            {"rule_id": "brain.exclude_secrets", "pattern": "secrets/**", "action": "exclude"}
        ],
        "max_file_bytes": 1048576,
        "private_blocks": [{"start": "<private>", "end": "</private>"}],
        "exclude_binary": True,
        "exclude_generated": True,
        "exclude_encrypted": True,
    }


@pytest.mark.asyncio
@pytest.mark.security
async def test_activation_authenticates_resolves_admin_scope_and_returns_no_rules() -> None:
    application = FastAPI()
    resolver = _Resolver()
    activate = _Activate()
    get = _Get()
    application.include_router(
        create_content_policy_router(_Authenticator(), resolver, activate, get, FixedClock(NOW))
    )
    operation = "idx006-http"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/indexing/content-policies/revisions",
            json=_body(operation),
            headers={"Authorization": "Bearer local", "Idempotency-Key": operation},
        )
        status = await client.get(
            f"/v1/indexing/content-policies/changes/{CHANGE_ID}",
            params=_scope_fields(),
            headers={"Authorization": "Bearer local"},
        )

    assert response.status_code == 202, response.text
    assert status.status_code == 200, status.text
    assert response.json()["delete_count"] == 2
    assert response.json()["reindex_count"] == 3
    assert "secrets/**" not in response.text
    assert activate.commands[0].scope.action == "indexing.policy.activate"
    assert activate.commands[0].revision.brain_rules.rules[0].pattern == "secrets/**"
    assert get.queries[0].scope.action == "indexing.policy.read"
    assert len(resolver.requests) == 2


@pytest.mark.asyncio
async def test_authentication_and_idempotency_fail_before_policy_handler() -> None:
    application = FastAPI()
    resolver = _Resolver()
    activate = _Activate()
    application.include_router(
        create_content_policy_router(
            _Authenticator(reject=True), resolver, activate, _Get(), FixedClock(NOW)
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        forbidden = await client.post(
            "/v1/indexing/content-policies/revisions",
            json=_body("idx006-forbidden"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "idx006-forbidden"},
        )
    assert forbidden.status_code == 403
    assert resolver.requests == []
    assert activate.commands == []

    application = FastAPI()
    application.include_router(
        create_content_policy_router(_Authenticator(), resolver, activate, _Get(), FixedClock(NOW))
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        invalid = await client.post(
            "/v1/indexing/content-policies/revisions",
            json=_body("idx006-key"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "wrong"},
        )
    assert invalid.status_code == 422
    assert activate.commands == []


def test_contract_and_complete_openapi_export_both_idx006_operations() -> None:
    application = FastAPI()
    application.include_router(create_contract_content_policy_router())
    paths = cast("dict[str, object]", application.openapi()["paths"])
    assert "/v1/indexing/content-policies/revisions" in paths
    assert "/v1/indexing/content-policies/changes/{change_id}" in paths

    complete = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    assert "/v1/indexing/content-policies/revisions" in complete
    assert "/v1/indexing/content-policies/changes/{change_id}" in complete
