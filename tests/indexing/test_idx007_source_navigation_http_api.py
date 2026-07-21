"""IDX-007 authenticated source-link HTTP and deterministic OpenAPI tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution, ScopeExplanation
from agentmemory.indexing.adapters.inbound.source_navigation_http_api import (
    create_contract_source_navigation_router,
    create_source_navigation_router,
)
from agentmemory.indexing.application.source_navigation import ResolveSourceEvidenceQuery
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.source_navigation import (
    CheckoutResolution,
    CurrentWorktreeMapping,
    SourceLink,
    WorktreeMappingKind,
)
from agentmemory.operations.bootstrap import export_core_openapi_schema
from tests.core.support import BRAIN_ID, NOW, OWNER_ID, FixedClock
from tests.indexing.test_idx001_sqlite_code_index import PROJECT_ID, REPOSITORY_ID
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope as indexing_scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.indexing.test_idx007_source_navigation_application import (
    OLD_COMMIT,
    _evidence,  # pyright: ignore[reportPrivateUsage]
)

GRANT_ID = "018f0000-0000-7000-8000-000000000003"
_ERR_AUTH = "credential is not authorized"


@dataclass(slots=True)
class _Authenticator:
    reject: bool = False
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if self.reject or authorization != "Bearer local":
            raise IndexingAuthorizationError(_ERR_AUTH)


@dataclass(slots=True)
class _Resolver:
    requests: list[object] = field(default_factory=list[object])

    async def execute(self, query: object) -> RetrievalScopeResolution:
        self.requests.append(query)
        scope = indexing_scope("indexing.search")
        return RetrievalScopeResolution(scope, ScopeExplanation(scope.mode, ("project",)))


@dataclass(slots=True)
class _Handler:
    error: Exception | None = None
    queries: list[ResolveSourceEvidenceQuery] = field(
        default_factory=list[ResolveSourceEvidenceQuery]
    )

    async def execute(self, query: ResolveSourceEvidenceQuery) -> SourceLink:
        self.queries.append(query)
        if self.error is not None:
            raise self.error
        evidence = _evidence()
        mapping = CurrentWorktreeMapping(
            evidence.relative_path,
            evidence.span,
            evidence.content_digest,
            WorktreeMappingKind.EXACT,
        )
        return SourceLink(
            evidence=evidence,
            immutable_revision_uri=evidence.immutable_revision_uri,
            checkout_resolution=CheckoutResolution.EXACT,
            checkout_commit_id=OLD_COMMIT,
            checkout_dirty=False,
            checkout_mismatch=False,
            historical_blob_available=True,
            current_mapping=mapping,
        )


def _params() -> dict[str, str]:
    return {
        "operation_id": "idx007-http",
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


@pytest.mark.asyncio
@pytest.mark.security
async def test_route_authenticates_resolves_scope_and_returns_complete_revision_link() -> None:
    application = FastAPI()
    resolver = _Resolver()
    handler = _Handler()
    application.include_router(
        create_source_navigation_router(_Authenticator(), resolver, handler, FixedClock(NOW))
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.get(
            f"/v1/indexing/source-evidence/{'1' * 64}",
            params=_params(),
            headers={"Authorization": "Bearer local"},
        )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["repository_id"] == REPOSITORY_ID
    assert body["commit_id"] == OLD_COMMIT
    assert body["relative_path"] == "src/old.py"
    assert body["symbol_display_name"] == "café"
    assert body["span"]["start_byte"] == 4
    assert body["content_digest"] == _evidence().content_digest
    assert body["parser_version"] == "parser@1"
    assert body["checkout_mismatch"] is False
    assert body["current_mapping"]["kind"] == "exact"
    assert handler.queries[0].scope.action == "indexing.source.navigate"
    assert len(resolver.requests) == 1


@pytest.mark.asyncio
async def test_authentication_precedes_resolution_and_safe_problems_never_echo_evidence() -> None:
    application = FastAPI()
    resolver = _Resolver()
    handler = _Handler()
    application.include_router(
        create_source_navigation_router(
            _Authenticator(reject=True), resolver, handler, FixedClock(NOW)
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        forbidden = await client.get(
            f"/v1/indexing/source-evidence/{'1' * 64}",
            params=_params(),
            headers={"Authorization": "Bearer local"},
        )
    assert forbidden.status_code == 403
    assert resolver.requests == []
    assert handler.queries == []

    cases = (
        (IndexingValidationError("secret-validation"), 422),
        (IndexingConflictError("secret-conflict"), 409),
        (IndexingUnavailableError("secret-unavailable"), 503),
    )
    for error, status in cases:
        candidate = FastAPI()
        candidate.include_router(
            create_source_navigation_router(
                _Authenticator(), _Resolver(), _Handler(error), FixedClock(NOW)
            )
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=candidate), base_url="http://test"
        ) as client:
            response = await client.get(
                f"/v1/indexing/source-evidence/{'1' * 64}",
                params=_params(),
                headers={"Authorization": "Bearer local"},
            )
        assert response.status_code == status
        assert "secret" not in response.text


def test_contract_and_complete_openapi_export_idx007_resolution() -> None:
    application = FastAPI()
    application.include_router(create_contract_source_navigation_router())
    paths = cast("dict[str, object]", application.openapi()["paths"])
    assert "/v1/indexing/source-evidence/{evidence_id}" in paths

    complete = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    assert "/v1/indexing/source-evidence/{evidence_id}" in complete
