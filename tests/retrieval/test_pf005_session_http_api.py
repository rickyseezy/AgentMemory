"""PF-005 session-derived cross-agent briefing transport tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
    IdentityValidationError,
)
from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSession,
    McpSessionRegistration,
)
from agentmemory.operations.domain.value_objects import Uuid7Id
from agentmemory.retrieval.adapters.inbound.host_delivery import (
    CertifiedDeliveryAdapterRegistry,
)
from agentmemory.retrieval.adapters.inbound.session_http_api import (
    SessionAuthenticatorPort,
    SessionScopeResolverPort,
    create_contract_session_retrieval_router,
    create_session_retrieval_router,
)
from agentmemory.retrieval.domain.continuity import (
    ContinuityItem,
    ContinuityKind,
    ItemProvenance,
)
from agentmemory.retrieval.domain.errors import (
    RetrievalAuthorizationError,
    RetrievalConflictError,
    RetrievalDependencyError,
    RetrievalIntegrityError,
    RetrievalValidationError,
)
from tests.core.support import FixedClock, digest
from tests.retrieval.support import (
    FakeContinuityRepository,
    FakeProcedureRepository,
    briefing_handler,
    scope,
)

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )

_NOW = datetime(2026, 7, 20, 10, 12, 13, tzinfo=UTC)
_SESSION_ID = "018f0000-0000-7000-8000-000000000050"


def _queries() -> list[ResolveRetrievalScopeQuery]:
    return []


def _auth_calls() -> list[tuple[str | None, str]]:
    return []


@dataclass(slots=True)
class _Authenticator:
    denied: bool = False
    calls: list[tuple[str | None, str]] = field(default_factory=_auth_calls)

    async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
        self.calls.append((authorization, session_id))
        if self.denied:
            raise OperationError(ErrorCode.UNAUTHENTICATED, "private")
        return _session()


@dataclass(slots=True)
class _ScopeResolver:
    queries: list[ResolveRetrievalScopeQuery] = field(default_factory=_queries)
    error: Exception | None = None

    async def execute_session_scoped(
        self,
        query: ResolveRetrievalScopeQuery,
    ) -> RetrievalScopeResolution:
        self.queries.append(query)
        if self.error is not None:
            raise self.error
        authorized = scope()
        return RetrievalScopeResolution(
            authorized,
            ScopeExplanation(authorized.mode, ("current:project",)),
        )


def _session() -> McpSession:
    registration = McpSessionRegistration(
        session_id=Uuid7Id(_SESSION_ID),
        installation_id=Uuid7Id("018f0000-0000-7000-8000-000000000001"),
        brain_id=Uuid7Id("018f0000-0000-7000-8000-000000000004"),
        actor_id=Uuid7Id("018f0000-0000-7000-8000-000000000002"),
        grant_id=Uuid7Id("018f0000-0000-7000-8000-000000000003"),
        agent_id="gemini",
        workspace_fingerprint=digest("pf005-session-recall"),
        device_identity="device:local",
        git_repository_id=None,
        git_worktree_id=None,
        git_coverage=McpGitCoverage.NONE,
        security_epoch=1,
        credential_digest=digest("pf005-session-recall-credential"),
        issued_at=_NOW - timedelta(minutes=1),
        expires_at=_NOW + timedelta(hours=1),
        project_id=Uuid7Id("018f0000-0000-7000-8000-000000000010"),
        repository_id=Uuid7Id("018f0000-0000-7000-8000-000000000020"),
    )
    return McpSession.register(registration).begin(_NOW, timedelta(seconds=120))


def _item() -> ContinuityItem:
    return ContinuityItem(
        item_id="cross-agent-decision",
        semantic_id="cross-agent-decision",
        kind=ContinuityKind.DECISION,
        content="The frontend consumes the shared user API.",
        brain_id="018f0000-0000-7000-8000-000000000004",
        project_id="018f0000-0000-7000-8000-000000000010",
        repository_id="018f0000-0000-7000-8000-000000000020",
        checkout_id=None,
        branch_name=None,
        commit_sha=None,
        occurred_at=_NOW,
        ingested_at=_NOW,
        classification="internal",
        evidence_event_id="018f0000-0000-7000-8000-000000000101",
        provenance=ItemProvenance(
            "claude_code",
            "claude-sonnet",
            "agentmemory.claude-code",
            "1.0.0",
            "native",
        ),
    )


def _app(
    authenticator: SessionAuthenticatorPort,
    resolver: SessionScopeResolverPort,
) -> FastAPI:
    application = FastAPI()
    handler = briefing_handler(
        FakeContinuityRepository((_item(),)),
        FakeProcedureRepository(()),
    )
    application.include_router(
        create_session_retrieval_router(
            authenticator,
            resolver,
            CertifiedDeliveryAdapterRegistry(handler),
            FixedClock(_NOW),
        )
    )
    return application


@pytest.mark.asyncio
async def test_session_recall_derives_scope_and_preserves_foreign_agent_provenance() -> None:
    authenticator = _Authenticator()
    resolver = _ScopeResolver()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(authenticator, resolver)),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post(
            "/v1/session/recall:brief",
            json={"operation_id": "turn-42", "mode": "global"},
            headers={
                "Authorization": "Bearer session-secret",
                "X-AgentMemory-Session-ID": _SESSION_ID,
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["consumer_host"] == "generic"
    assert body["media_type"] == "application/json"
    assert body["items"][0]["content"] == "The frontend consumes the shared user API."
    assert body["items"][0]["provenance"]["producer_host"] == "claude_code"
    assert authenticator.calls == [("Bearer session-secret", _SESSION_ID)]
    query = resolver.queries[0]
    assert query.brain_id.value == _session().registration.brain_id.value
    assert query.actor_id.value == _session().registration.actor_id.value
    assert query.current_project_id is not None
    assert query.current_project_id.value == "018f0000-0000-7000-8000-000000000010"
    assert query.selected_project_ids == ()
    assert query.operation_id.startswith("pf005-recall-")
    assert "turn-42" not in query.operation_id


@pytest.mark.asyncio
async def test_session_recall_rejects_identity_injection_and_bad_scope_mode() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Authenticator(), _ScopeResolver())),
        base_url="http://127.0.0.1:9411",
    ) as client:
        injected = await client.post(
            "/v1/session/recall:brief",
            json={"operation_id": "turn-42", "brain_id": "foreign"},
        )
        selected = await client.post(
            "/v1/session/recall:brief",
            json={"operation_id": "turn-42", "mode": "selected"},
        )
    assert injected.status_code == 422
    assert selected.status_code == 422


@pytest.mark.asyncio
async def test_session_recall_authentication_failure_is_content_free() -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Authenticator(denied=True), _ScopeResolver())),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post(
            "/v1/session/recall:brief",
            json={"operation_id": "turn-42"},
        )
    assert response.status_code == 401
    assert response.json() == {
        "code": "AM_UNAUTHENTICATED",
        "detail": "session authentication is required",
        "retryable": False,
    }
    assert "private" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status", "expected"),
    [
        (OperationError(ErrorCode.FORBIDDEN, "private"), 403, ("AM_FORBIDDEN", False)),
        (IdentityAuthorizationError("private"), 403, ("AM_FORBIDDEN", False)),
        (RetrievalAuthorizationError("private"), 403, ("AM_FORBIDDEN", False)),
        (IdentityConflictError("private"), 409, ("AM_CONFLICT", False)),
        (RetrievalConflictError("private"), 409, ("AM_CONFLICT", False)),
        (IdentityValidationError("private"), 422, ("AM_VALIDATION", False)),
        (RetrievalValidationError("private"), 422, ("AM_VALIDATION", False)),
        (
            IdentityDependencyError("private"),
            503,
            ("AM_DEPENDENCY_UNAVAILABLE", True),
        ),
        (
            RetrievalDependencyError("private"),
            503,
            ("AM_DEPENDENCY_UNAVAILABLE", True),
        ),
        (RetrievalIntegrityError("private"), 500, ("AM_INTEGRITY_VIOLATION", False)),
    ],
)
async def test_session_recall_maps_closed_error_taxonomy_without_leaking_content(
    error: Exception,
    status: int,
    expected: tuple[str, bool],
) -> None:
    resolver = _ScopeResolver(error=error)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Authenticator(), resolver)),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post(
            "/v1/session/recall:brief",
            json={"operation_id": "turn-errors"},
            headers={"X-AgentMemory-Session-ID": _SESSION_ID},
        )

    assert response.status_code == status
    assert (response.json()["code"], response.json()["retryable"]) == expected
    assert "private" not in response.text


@pytest.mark.asyncio
async def test_session_recall_rejects_registration_without_canonical_workspace_scope() -> None:
    session = _session()
    session = replace(
        session,
        registration=replace(
            session.registration,
            project_id=None,
            repository_id=None,
            checkout_id=None,
        ),
    )

    @dataclass(slots=True)
    class _UnscopedAuthenticator:
        async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
            del authorization, session_id
            return session

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_UnscopedAuthenticator(), _ScopeResolver())),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.post(
            "/v1/session/recall:brief",
            json={"operation_id": "turn-unscoped"},
        )
    assert response.status_code == 500
    assert response.json()["code"] == "AM_INTEGRITY_VIOLATION"


def test_complete_contract_exposes_scope_free_session_recall() -> None:
    application = FastAPI()
    application.include_router(create_contract_session_retrieval_router())
    operation = application.openapi()["paths"]["/v1/session/recall:brief"]["post"]
    assert operation["operationId"] == "StartMcpSessionBriefingQuery"
    schema_ref = operation["requestBody"]["content"]["application/json"]["schema"]["$ref"]
    schema_name = schema_ref.rsplit("/", maxsplit=1)[-1]
    schema = application.openapi()["components"]["schemas"][schema_name]
    assert set(schema["properties"]) == {
        "operation_id",
        "mode",
        "max_related_depth",
        "max_related_cost",
        "temporal_from",
        "temporal_to",
        "budget",
    }
