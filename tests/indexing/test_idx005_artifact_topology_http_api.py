"""IDX-005 authenticated, content-free extraction and temporal query HTTP tests."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import RetrievalScopeResolution, ScopeExplanation
from agentmemory.indexing.adapters.inbound.artifact_topology_http_api import (
    create_artifact_topology_router,
    create_contract_artifact_topology_router,
)
from agentmemory.indexing.adapters.outbound.artifact_topology_plugins import (
    EnvironmentTemplateParser,
)
from agentmemory.indexing.application.artifact_topology import (
    ExtractAndRegisterArtifactTopologyCommand,
    QueryArtifactTopologyCommand,
)
from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyBatch,
    ArtifactTopologyEvidence,
    ArtifactTopologySnapshot,
    ArtifactTopologySourceArtifact,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
)
from agentmemory.operations.bootstrap import export_core_openapi_schema
from tests.core.support import BRAIN_ID, NOW, FixedClock
from tests.indexing.test_idx001_sqlite_code_index import (
    PROJECT_ID,
    REPOSITORY_ID,
    _scope,  # pyright: ignore[reportPrivateUsage]
)

_ERR_CREDENTIAL = "credential is not authorized"
_SECRET = "http-secret-never-returned"  # noqa: S105


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
        scope = _scope("indexing.search")
        return RetrievalScopeResolution(scope, ScopeExplanation(scope.mode, ("project",)))


@dataclass(slots=True)
class _Extraction:
    commands: list[ExtractAndRegisterArtifactTopologyCommand] = field(
        default_factory=list[ExtractAndRegisterArtifactTopologyCommand]
    )
    error: Exception | None = None

    async def execute(
        self, command: ExtractAndRegisterArtifactTopologyCommand
    ) -> ArtifactTopologyBatch:
        if self.error is not None:
            raise self.error
        self.commands.append(command)
        return EnvironmentTemplateParser().parse(command.artifact)


@dataclass(slots=True)
class _Query:
    snapshot: ArtifactTopologySnapshot
    commands: list[QueryArtifactTopologyCommand] = field(
        default_factory=list[QueryArtifactTopologyCommand]
    )
    error: Exception | None = None

    async def execute(self, command: QueryArtifactTopologyCommand) -> ArtifactTopologySnapshot:
        if self.error is not None:
            raise self.error
        self.commands.append(command)
        return self.snapshot


def _application() -> tuple[FastAPI, _Resolver, _Extraction, _Query]:
    application = FastAPI()
    resolver = _Resolver()
    extraction = _Extraction()
    empty = ArtifactTopologySnapshot((), (), (), NOW)
    query = _Query(empty)
    application.include_router(
        create_artifact_topology_router(
            _Authenticator(), resolver, extraction, query, FixedClock(NOW)
        )
    )
    return application, resolver, extraction, query


@pytest.mark.asyncio
@pytest.mark.security
async def test_extraction_uses_ephemeral_bytes_and_returns_a_value_free_receipt() -> None:
    application, _resolver, extraction, _query = _application()
    operation = "idx005-http-extract"
    body = _extraction_body(operation)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/indexing/artifact-topology/extractions",
            json=body,
            headers={"Authorization": "Bearer local", "Idempotency-Key": operation},
        )

    assert response.status_code == 201, response.text
    serialized = response.text
    assert "content_base64" not in serialized
    assert _SECRET not in serialized
    assert response.json()["candidate_count"] == 2
    assert extraction.commands[0].scope.action == "indexing.artifact_topology.register"
    assert _SECRET.encode() in extraction.commands[0].artifact.content


@pytest.mark.asyncio
async def test_query_uses_selected_scope_and_serializes_only_normalized_names() -> None:
    application, resolver, extraction, query = _application()
    artifact = _artifact_command()
    batch = EnvironmentTemplateParser().parse(artifact.artifact)
    query.snapshot = ArtifactTopologySnapshot(
        batch.candidates,
        batch.relations,
        batch.unknown_evidence,
        NOW,
    )
    body = {
        **_scope_fields(query=True),
        "operation_id": "idx005-http-query",
        "selected_project_ids": [PROJECT_ID],
        "cutoff": NOW.isoformat(),
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/indexing/artifact-topology/queries",
            json=body,
            headers={"Authorization": "Bearer local"},
        )

    assert response.status_code == 200, response.text
    assert _SECRET not in response.text
    assert {item["environment_reference"] for item in response.json()["candidates"]} == {
        "DATABASE_PASSWORD",
        "PUBLIC_URL",
    }
    assert query.commands[0].scope.action == "indexing.artifact_topology.read"
    assert len(resolver.requests) == 1
    assert extraction.commands == []


def test_contract_router_exports_both_closed_idx005_operations() -> None:
    application = FastAPI()
    application.include_router(create_contract_artifact_topology_router())
    schema = application.openapi()
    paths = schema["paths"]
    assert "/v1/indexing/artifact-topology/extractions" in paths
    assert "/v1/indexing/artifact-topology/queries" in paths
    serialized = str(schema)
    assert "ExtractAndRegisterArtifactTopologyCommand" in serialized
    assert "QueryArtifactTopologyCommand" in serialized


def test_complete_core_openapi_includes_idx005_contract() -> None:
    paths = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    assert "/v1/indexing/artifact-topology/extractions" in paths
    assert "/v1/indexing/artifact-topology/queries" in paths


@pytest.mark.asyncio
async def test_auth_idempotency_base64_and_dependency_errors_are_sanitized() -> None:
    application = FastAPI()
    resolver = _Resolver()
    extraction = _Extraction()
    query = _Query(ArtifactTopologySnapshot((), (), (), NOW))
    application.include_router(
        create_artifact_topology_router(
            _Authenticator(reject=True), resolver, extraction, query, FixedClock(NOW)
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        forbidden = await client.post(
            "/v1/indexing/artifact-topology/extractions",
            json=_extraction_body("idx005-forbidden"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "idx005-forbidden"},
        )
    assert forbidden.status_code == 403
    assert resolver.requests == []
    assert extraction.commands == []

    application, _resolver, extraction, query = _application()
    extraction.error = IndexingConflictError("private conflict")
    query.error = IndexingUnavailableError("private dependency")
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application), base_url="http://test"
    ) as client:
        invalid_key = await client.post(
            "/v1/indexing/artifact-topology/extractions",
            json=_extraction_body("idx005-key"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "different"},
        )
        malformed_body = _extraction_body("idx005-base64")
        malformed_body["content_base64"] = "***"
        malformed = await client.post(
            "/v1/indexing/artifact-topology/extractions",
            json=malformed_body,
            headers={"Authorization": "Bearer local", "Idempotency-Key": "idx005-base64"},
        )
        conflict = await client.post(
            "/v1/indexing/artifact-topology/extractions",
            json=_extraction_body("idx005-conflict"),
            headers={"Authorization": "Bearer local", "Idempotency-Key": "idx005-conflict"},
        )
        unavailable = await client.post(
            "/v1/indexing/artifact-topology/queries",
            json={
                **_scope_fields(query=True),
                "operation_id": "idx005-unavailable",
                "selected_project_ids": [PROJECT_ID],
                "cutoff": NOW.isoformat(),
            },
            headers={"Authorization": "Bearer local"},
        )
    assert invalid_key.status_code == 422
    assert malformed.status_code == 422
    assert conflict.status_code == 409
    assert unavailable.status_code == 503
    assert "private" not in conflict.text + unavailable.text


def _scope_fields(*, query: bool = False) -> dict[str, str]:
    common = {
        "brain_id": BRAIN_ID,
        "actor_id": _scope("indexing.search").principal_id.value,
        "grant_id": "018f0000-0000-7000-8000-000000000003",
    }
    if query:
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
        "evidence_id": "018f0000-0000-7000-8000-000000000512",
        "relative_path": ".env.example",
        "classification": "internal",
        "commit_sha": "4" * 40,
        "content_base64": base64.b64encode(
            f"PUBLIC_URL=https://localhost\nDATABASE_PASSWORD={_SECRET}\n".encode()
        ).decode(),
        "observed_at": NOW.isoformat(),
    }


def _artifact_command() -> ExtractAndRegisterArtifactTopologyCommand:
    evidence = ArtifactTopologyEvidence(
        BRAIN_ID,
        PROJECT_ID,
        REPOSITORY_ID,
        "1" * 64,
        "2" * 64,
        "3" * 64,
        "018f0000-0000-7000-8000-000000000512",
        ".env.example",
        "internal",
        NOW,
    )
    return ExtractAndRegisterArtifactTopologyCommand(
        "idx005-artifact-helper",
        _scope("indexing.artifact_topology.register"),
        ArtifactTopologySourceArtifact(
            evidence,
            "4" * 40,
            f"PUBLIC_URL=https://localhost\nDATABASE_PASSWORD={_SECRET}\n".encode(),
        ),
        NOW,
    )
