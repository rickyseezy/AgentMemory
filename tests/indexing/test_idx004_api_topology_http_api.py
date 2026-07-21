"""IDX-004 authenticated extraction and explainable topology-link HTTP tests."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution, ScopeExplanation
from agentmemory.indexing.adapters.inbound.api_topology_http_api import (
    create_api_topology_router,
    create_contract_api_topology_router,
)
from agentmemory.indexing.application.api_topology import (
    ExtractAndRegisterApiTopologyCommand,
    LinkApiTopologyCommand,
)
from agentmemory.indexing.domain.api_topology import (
    ApiMatchDisposition,
    ApiMatchRule,
    ApiTopologyCandidateBatch,
    ApiTopologyLinkDecision,
    ApiTopologyMatch,
    ApiTopologyPluginKind,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
)
from tests.core.support import BRAIN_ID, NOW, FixedClock
from tests.indexing.test_idx001_sqlite_code_index import (
    PROJECT_ID,
    REPOSITORY_ID,
    _scope,  # pyright: ignore[reportPrivateUsage]
)

CLIENT_ID = hashlib.sha256(b"client").hexdigest()
ENDPOINT_ID = hashlib.sha256(b"endpoint").hexdigest()
CLIENT_ENTITY = "018f0000-0000-7000-8000-000000000510"
ENDPOINT_ENTITY = "018f0000-0000-7000-8000-000000000511"
CLIENT_EVIDENCE = "018f0000-0000-7000-8000-000000000512"
SERVER_EVIDENCE = "018f0000-0000-7000-8000-000000000513"
_ERR_CREDENTIAL = "credential is not authorized"


@dataclass(slots=True)
class _Authenticator:
    reject: bool = False

    async def authenticate(self, authorization: str | None) -> None:
        if self.reject or authorization != "Bearer local":
            raise IndexingAuthorizationError(_ERR_CREDENTIAL)


@dataclass(slots=True)
class _Resolver:
    queries: list[object] = field(default_factory=list[object])

    async def execute(self, query: object) -> RetrievalScopeResolution:
        self.queries.append(query)
        scope = _scope("indexing.search")
        return RetrievalScopeResolution(scope, ScopeExplanation(scope.mode, ("project",)))


@dataclass(slots=True)
class _Extraction:
    commands: list[ExtractAndRegisterApiTopologyCommand] = field(
        default_factory=list[ExtractAndRegisterApiTopologyCommand]
    )
    error: Exception | None = None

    async def execute(
        self, command: ExtractAndRegisterApiTopologyCommand
    ) -> ApiTopologyCandidateBatch:
        if self.error is not None:
            raise self.error
        self.commands.append(command)
        return ApiTopologyCandidateBatch(
            ApiTopologyPluginKind.OPENAPI,
            "v1.0.0",
            command.artifact.evidence.source_revision_context_id,
            command.artifact.evidence.source_file_id,
            command.artifact.commit_sha,
        )


@dataclass(slots=True)
class _Linking:
    commands: list[LinkApiTopologyCommand] = field(default_factory=list[LinkApiTopologyCommand])
    error: Exception | None = None

    async def execute(self, command: LinkApiTopologyCommand) -> ApiTopologyLinkDecision:
        if self.error is not None:
            raise self.error
        self.commands.append(command)
        match = ApiTopologyMatch(
            CLIENT_ID,
            ENDPOINT_ID,
            CLIENT_ENTITY,
            ENDPOINT_ENTITY,
            ApiMatchRule.CONTRACT_OPERATION,
            "api-topology-linker-1.0.0",
            ApiMatchDisposition.CONFIRMED,
            1,
            9_800,
            CLIENT_EVIDENCE,
            SERVER_EVIDENCE,
            tuple(sorted((CLIENT_ID, ENDPOINT_ID))),
            tuple(sorted((CLIENT_EVIDENCE, SERVER_EVIDENCE))),
            (),
        )
        return ApiTopologyLinkDecision(CLIENT_ID, hashlib.sha256(b"universe").hexdigest(), (match,))


def _application() -> tuple[FastAPI, _Resolver, _Extraction, _Linking]:
    application = FastAPI()
    resolver = _Resolver()
    extraction = _Extraction()
    linking = _Linking()
    application.include_router(
        create_api_topology_router(_Authenticator(), resolver, extraction, linking, FixedClock(NOW))
    )
    return application, resolver, extraction, linking


@pytest.mark.asyncio
async def test_extraction_decodes_ephemeral_source_and_returns_content_free_receipt() -> None:
    application, _resolver, extraction, _linking = _application()
    operation = "idx004-extract-http"
    body = {
        **_scope_fields(),
        "operation_id": operation,
        "source_file_id": "1" * 64,
        "source_revision_context_id": "2" * 64,
        "source_semantic_id": "3" * 64,
        "evidence_id": CLIENT_EVIDENCE,
        "relative_path": "openapi.yaml",
        "classification": "internal",
        "commit_sha": "4" * 40,
        "content_base64": base64.b64encode(b"openapi: 3.1.0\npaths: {}").decode(),
        "observed_at": NOW.isoformat(),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/indexing/api-topology/extractions",
            json=body,
            headers={"Authorization": "Bearer local", "Idempotency-Key": operation},
        )

    assert response.status_code == 201, response.text
    assert "content_base64" not in response.json()
    assert extraction.commands[0].scope.action == "indexing.api_topology.register"
    assert extraction.commands[0].artifact.content.startswith(b"openapi")


@pytest.mark.asyncio
async def test_link_uses_selected_scope_and_returns_exact_explanation_path() -> None:
    application, resolver, _extraction, linking = _application()
    operation = "idx004-link-http"
    body = {
        **_scope_fields(current=True),
        "operation_id": operation,
        "selected_project_ids": [PROJECT_ID],
        "client_call_id": CLIENT_ID,
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/indexing/api-topology/links",
            json=body,
            headers={"Authorization": "Bearer local", "Idempotency-Key": operation},
        )

    assert response.status_code == 201, response.text
    assert response.json()["matches"][0]["rule"] == "contract_operation"
    assert response.json()["matches"][0]["supporting_evidence_ids"] == sorted(
        (CLIENT_EVIDENCE, SERVER_EVIDENCE)
    )
    assert linking.commands[0].scope.action == "indexing.api_topology.link"
    assert len(resolver.queries) == 1


def test_contract_router_exports_both_idx004_operations() -> None:
    application = FastAPI()
    application.include_router(create_contract_api_topology_router())
    paths = application.openapi()["paths"]
    assert "/v1/indexing/api-topology/extractions" in paths
    assert "/v1/indexing/api-topology/links" in paths


@pytest.mark.asyncio
async def test_authentication_and_idempotency_fail_before_use_case_execution() -> None:
    application = FastAPI()
    resolver = _Resolver()
    extraction = _Extraction()
    application.include_router(
        create_api_topology_router(
            _Authenticator(reject=True), resolver, extraction, _Linking(), FixedClock(NOW)
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        forbidden = await client.post(
            "/v1/indexing/api-topology/extractions",
            json=_extraction_body("idx004-forbidden"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "idx004-forbidden"},
        )
    assert forbidden.status_code == 403
    assert resolver.queries == []
    assert extraction.commands == []

    application, _resolver, extraction, _linking = _application()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        invalid = await client.post(
            "/v1/indexing/api-topology/extractions",
            json=_extraction_body("idx004-idempotency"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "different"},
        )
    assert invalid.status_code == 422
    assert extraction.commands == []


@pytest.mark.asyncio
async def test_invalid_base64_conflict_and_unavailable_errors_are_sanitized() -> None:
    application, _resolver, extraction, linking = _application()
    extraction.error = IndexingConflictError("private conflict")
    linking.error = IndexingUnavailableError("private dependency")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        malformed_body = _extraction_body("idx004-bad-base64")
        malformed_body["content_base64"] = "***"
        malformed = await client.post(
            "/v1/indexing/api-topology/extractions",
            json=malformed_body,
            headers={
                "Authorization": "Bearer local",
                "Idempotency-Key": "idx004-bad-base64",
            },
        )
        conflict = await client.post(
            "/v1/indexing/api-topology/extractions",
            json=_extraction_body("idx004-conflict"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "idx004-conflict"},
        )
        unavailable = await client.post(
            "/v1/indexing/api-topology/links",
            json={
                **_scope_fields(current=True),
                "operation_id": "idx004-unavailable",
                "selected_project_ids": [PROJECT_ID],
                "client_call_id": CLIENT_ID,
            },
            headers={
                "Authorization": "Bearer local",
                "Idempotency-Key": "idx004-unavailable",
            },
        )
    assert malformed.status_code == 422
    assert conflict.status_code == 409
    assert unavailable.status_code == 503
    assert "private" not in conflict.text + unavailable.text


def _scope_fields(*, current: bool = False) -> dict[str, str]:
    common = {
        "brain_id": BRAIN_ID,
        "actor_id": _scope("indexing.search").principal_id.value,
        "grant_id": "018f0000-0000-7000-8000-000000000003",
    }
    if current:
        return {
            **common,
            "current_project_id": PROJECT_ID,
            "current_repository_id": REPOSITORY_ID,
        }
    return {**common, "project_id": PROJECT_ID, "repository_id": REPOSITORY_ID}


def _extraction_body(operation_id: str) -> dict[str, object]:
    return {
        **_scope_fields(),
        "operation_id": operation_id,
        "source_file_id": "1" * 64,
        "source_revision_context_id": "2" * 64,
        "source_semantic_id": "3" * 64,
        "evidence_id": CLIENT_EVIDENCE,
        "relative_path": "openapi.yaml",
        "classification": "internal",
        "commit_sha": "4" * 40,
        "content_base64": base64.b64encode(b"openapi: 3.1.0\npaths: {}").decode(),
        "observed_at": NOW.isoformat(),
    }
