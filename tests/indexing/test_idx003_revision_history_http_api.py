"""IDX-003 authenticated source-history and lineage HTTP contract tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution, ScopeExplanation
from agentmemory.indexing.adapters.inbound.revision_history_http_api import (
    create_contract_revision_history_router,
    create_revision_history_router,
)
from agentmemory.indexing.application.revision_history import (
    QuerySourceRevisionHistoryQuery,
    RegisterEvidenceLineageCommand,
)
from agentmemory.indexing.domain.errors import IndexingAuthorizationError
from agentmemory.indexing.domain.revision_history import (
    SourceRevisionApplicability,
    SourceRevisionChangeKind,
    SourceRevisionHistoryCandidate,
    SourceRevisionHistoryEntry,
)
from tests.core.support import BRAIN_ID, NOW, FixedClock
from tests.indexing.test_idx001_sqlite_code_index import (
    PROJECT_ID,
    REPOSITORY_ID,
    _scope,  # pyright: ignore[reportPrivateUsage]
)

_ERR_CREDENTIAL = "credential is not authorized"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(slots=True)
class _Authenticator:
    reject: bool = False
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if self.reject or authorization != "Bearer local":
            raise IndexingAuthorizationError(_ERR_CREDENTIAL)


@dataclass(slots=True)
class _Resolver:
    calls: int = 0

    async def execute(self, query: object) -> RetrievalScopeResolution:
        del query
        self.calls += 1
        scope = _scope("indexing.revision.history.read")
        return RetrievalScopeResolution(scope, ScopeExplanation(scope.mode, ("repository",)))


@dataclass(slots=True)
class _History:
    entries: tuple[SourceRevisionHistoryEntry, ...]
    queries: list[QuerySourceRevisionHistoryQuery] = field(
        default_factory=list[QuerySourceRevisionHistoryQuery]
    )

    async def execute(
        self, query: QuerySourceRevisionHistoryQuery
    ) -> tuple[SourceRevisionHistoryEntry, ...]:
        self.queries.append(query)
        return self.entries


@dataclass(slots=True)
class _Lineage:
    commands: list[RegisterEvidenceLineageCommand] = field(
        default_factory=list[RegisterEvidenceLineageCommand]
    )

    async def execute(self, command: RegisterEvidenceLineageCommand) -> str:
        self.commands.append(command)
        return _digest("registration")


def _entry() -> SourceRevisionHistoryEntry:
    candidate = SourceRevisionHistoryCandidate(
        _digest("context"),
        _digest("file"),
        _digest("revision"),
        _digest("snapshot"),
        "src/service.py",
        "2" * 40,
        _digest("content"),
        SourceRevisionChangeKind.MODIFY,
        ("3" * 40,),
        (),
        (),
        None,
        NOW,
    )
    return SourceRevisionHistoryEntry(
        candidate,
        SourceRevisionApplicability.STALE,
        ("3" * 40,),
        _digest("graph"),
        (_digest("answer"),),
    )


def _application(
    *, reject_authentication: bool = False
) -> tuple[FastAPI, _Authenticator, _Resolver, _History, _Lineage]:
    application = FastAPI()
    authenticator = _Authenticator(reject_authentication)
    resolver = _Resolver()
    history = _History((_entry(),))
    lineage = _Lineage()
    application.include_router(
        create_revision_history_router(
            authenticator,
            resolver,
            history,
            lineage,
            FixedClock(),
        )
    )
    return application, authenticator, resolver, history, lineage


def _scope_fields() -> dict[str, str]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": _scope("indexing.revision.history.read").principal_id.value,
        "grant_id": "018f0000-0000-7000-8000-000000000003",
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


@pytest.mark.asyncio
async def test_history_authenticates_resolves_current_scope_and_returns_graph_proofs() -> None:
    application, authenticator, resolver, history, _lineage = _application()
    params = {
        **_scope_fields(),
        "operation_id": "idx003-history-http",
        "relative_path": "src/service.py",
        "recorded_at": NOW.isoformat(),
        "branch_name": "main",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.get(
            "/v1/indexing/source-revisions/history",
            params=params,
            headers={"Authorization": "Bearer local"},
        )

    assert response.status_code == 200
    assert response.json()[0]["applicability"] == "stale"
    assert response.json()[0]["graph_answer_ids"] == [_digest("answer")]
    assert history.queries[0].scope.action == "indexing.revision.history.read"
    assert history.queries[0].branch_name == "main"
    assert authenticator.calls == resolver.calls == 1


@pytest.mark.asyncio
async def test_lineage_requires_matching_idempotency_and_authentication_precedes_scope() -> None:
    application, _authenticator, resolver, _history, lineage = _application()
    body = {
        **_scope_fields(),
        "operation_id": "idx003-lineage-http",
        "context_id": _digest("context"),
        "evidence_id": "018f0000-0000-7000-8000-000000000160",
        "assertion_id": "018f0000-0000-7000-8000-000000000170",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        mismatch = await client.post(
            "/v1/indexing/source-revisions/lineage",
            json=body,
            headers={"Authorization": "Bearer local", "Idempotency-Key": "wrong"},
        )
        accepted = await client.post(
            "/v1/indexing/source-revisions/lineage",
            json=body,
            headers={
                "Authorization": "Bearer local",
                "Idempotency-Key": "idx003-lineage-http",
            },
        )

    assert mismatch.status_code == 422
    assert "context" not in mismatch.text
    assert accepted.status_code == 201
    assert accepted.json()["registration_digest"] == _digest("registration")
    assert lineage.commands[0].scope.action == "indexing.revision.lineage.register"
    assert resolver.calls == 1

    rejected, authenticator, rejected_resolver, _history, _lineage = _application(
        reject_authentication=True
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=rejected), base_url="http://test"
    ) as client:
        forbidden = await client.post(
            "/v1/indexing/source-revisions/lineage",
            json=body,
            headers={
                "Authorization": "Bearer invalid",
                "Idempotency-Key": "idx003-lineage-http",
            },
        )
    assert forbidden.status_code == 403
    assert authenticator.calls == 1
    assert rejected_resolver.calls == 0


def test_contract_openapi_has_history_and_lineage_use_case_operation_ids() -> None:
    application = FastAPI()
    application.include_router(create_contract_revision_history_router())
    schema = application.openapi()

    assert (
        schema["paths"]["/v1/indexing/source-revisions/history"]["get"]["operationId"]
        == "QuerySourceRevisionHistoryQuery"
    )
    assert (
        schema["paths"]["/v1/indexing/source-revisions/lineage"]["post"]["operationId"]
        == "RegisterEvidenceLineageCommand"
    )
