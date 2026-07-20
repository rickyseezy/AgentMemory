from __future__ import annotations

import asyncio
import hashlib
from typing import TYPE_CHECKING

import httpx
import pytest

from agentmemory.providers.application.service import ProviderService
from agentmemory.providers.domain.models import EMBEDDING_DIMENSION, ProviderIdentity, ProviderRole
from agentmemory.providers.infrastructure import http_api
from agentmemory.providers.infrastructure.http_api import HttpBoundary, create_app

if TYPE_CHECKING:
    from pathlib import Path

    from tests.providers.conftest import RecordingBackend

REVISION = "b" * 40
CAPABILITY = b"k" * 32


def _identity(role: ProviderRole) -> ProviderIdentity:
    return ProviderIdentity(
        role,
        {
            ProviderRole.EMBEDDING: "Qwen/Qwen3-Embedding-0.6B",
            ProviderRole.RERANKING: "Qwen/Qwen3-Reranker-0.6B",
            ProviderRole.EXTRACTION: "Qwen/Qwen3-4B-GGUF-Q4_K_M",
        }[role],
        REVISION,
        EMBEDDING_DIMENSION if role is ProviderRole.EMBEDDING else None,
    )


def _capability(tmp_path: Path) -> Path:
    path = tmp_path / "capability"
    path.write_bytes(CAPABILITY)
    path.chmod(0o600)
    return path


def _client(role: ProviderRole, backend: RecordingBackend, tmp_path: Path) -> httpx.AsyncClient:
    host = {
        ProviderRole.EMBEDDING: "local-embedding",
        ProviderRole.RERANKING: "local-reranker",
        ProviderRole.EXTRACTION: "local-extractor",
    }[role]
    app = create_app(
        ProviderService(_identity(role), backend),
        HttpBoundary(host, _capability(tmp_path)),
    )
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url=f"http://{host}:8080",
    )


def _headers(**updates: str) -> dict[str, str]:
    headers = {
        "content-type": "application/json",
        "x-agentmemory-capability": CAPABILITY.hex(),
    }
    headers.update(updates)
    return headers


def _probe(role: ProviderRole, *, cancellation: bool = False) -> dict[str, object]:
    identity = _identity(role)
    return {
        "protocol_version": "1.0",
        "role": role.value,
        "model_id": identity.model_id,
        "model_revision": identity.model_revision,
        "test_cancellation": cancellation,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("role", list(ProviderRole))
async def test_probe_returns_exact_identity_and_security_headers(
    role: ProviderRole, backend: RecordingBackend, tmp_path: Path
) -> None:
    async with _client(role, backend, tmp_path) as client:
        response = await client.post("/v1/probe", headers=_headers(), json=_probe(role))
    assert response.status_code == 200
    assert response.json() == {
        "protocol_version": "1.0",
        "role": role.value,
        "model_id": _identity(role).model_id,
        "model_revision": REVISION,
        "dimension": EMBEDDING_DIMENSION if role is ProviderRole.EMBEDDING else None,
        "supports_cancellation": True,
        "local_only": True,
    }
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


@pytest.mark.asyncio
async def test_embedding_route_returns_real_backend_vectors(
    backend: RecordingBackend,
    tmp_path: Path,
) -> None:
    async with _client(ProviderRole.EMBEDDING, backend, tmp_path) as client:
        response = await client.post(
            "/v1/embed",
            headers=_headers(),
            json={
                "protocol_version": "1.0",
                "model_id": _identity(ProviderRole.EMBEDDING).model_id,
                "model_revision": REVISION,
                "purpose": "retrieval_document",
                "classification": "internal",
                "items": [{"content_id": "one", "content": "persistent memory"}],
            },
        )
    assert response.status_code == 200
    assert response.json()["dimension"] == EMBEDDING_DIMENSION
    assert len(response.json()["results"][0]["values"]) == EMBEDDING_DIMENSION


@pytest.mark.asyncio
async def test_reranking_route_is_complete_and_descending(
    backend: RecordingBackend,
    tmp_path: Path,
) -> None:
    backend.scores = (0.1, 0.9)
    async with _client(ProviderRole.RERANKING, backend, tmp_path) as client:
        response = await client.post(
            "/v1/rerank",
            headers=_headers(),
            json={
                "protocol_version": "1.0",
                "model_id": _identity(ProviderRole.RERANKING).model_id,
                "model_revision": REVISION,
                "classification": "internal",
                "query": "what persists?",
                "documents": [
                    {"content_id": "low", "content": "garden"},
                    {"content_id": "high", "content": "persistent memory"},
                ],
            },
        )
    assert response.status_code == 200
    assert [item["content_id"] for item in response.json()["results"]] == ["high", "low"]


@pytest.mark.asyncio
async def test_extraction_route_uses_closed_schema(
    backend: RecordingBackend, tmp_path: Path
) -> None:
    async with _client(ProviderRole.EXTRACTION, backend, tmp_path) as client:
        response = await client.post(
            "/v1/extract",
            headers=_headers(),
            json={
                "protocol_version": "1.0",
                "model_id": _identity(ProviderRole.EXTRACTION).model_id,
                "model_revision": REVISION,
                "classification": "internal",
                "schema": "readiness-subject-v1",
                "content": "AgentMemory preserves persistent memory.",
            },
        )
    assert response.status_code == 200
    assert response.json()["subject"] == "persistent memory"


@pytest.mark.asyncio
async def test_memory_candidate_route_preserves_exact_operation_and_canonical_output(
    backend: RecordingBackend, tmp_path: Path
) -> None:
    input_bytes = b'{"evidence":[]}'
    input_sha = hashlib.sha256(input_bytes).hexdigest()
    expected_output = backend.memory_candidates.replace(b"a" * 64, input_sha.encode())
    async with _client(ProviderRole.EXTRACTION, backend, tmp_path) as client:
        response = await client.post(
            "/v1/extract/memory-candidates",
            headers=_headers(),
            json={
                "protocol_version": "1.0",
                "operation_id": "memory-operation-1",
                "idempotency_key": "b" * 64,
                "task_id": "018f0000-0000-7000-8000-000000000201",
                "model_id": _identity(ProviderRole.EXTRACTION).model_id,
                "model_revision": REVISION,
                "classification": "confidential",
                "schema": "memory-candidates.v1",
                "input_sha256": input_sha,
                "content_base64": "eyJldmlkZW5jZSI6W119",
            },
        )
    assert response.status_code == 200
    assert response.json() == {
        "protocol_version": "1.0",
        "operation_id": "memory-operation-1",
        "idempotency_key": "b" * 64,
        "task_id": "018f0000-0000-7000-8000-000000000201",
        "input_sha256": input_sha,
        "model_id": _identity(ProviderRole.EXTRACTION).model_id,
        "model_revision": REVISION,
        "schema": "memory-candidates.v1",
        "output_json": expected_output.decode(),
        "output_sha256": hashlib.sha256(expected_output).hexdigest(),
    }


@pytest.mark.asyncio
async def test_memory_candidate_route_rejects_bad_base64_or_digest(
    backend: RecordingBackend, tmp_path: Path
) -> None:
    body = {
        "protocol_version": "1.0",
        "operation_id": "memory-operation-1",
        "idempotency_key": "b" * 64,
        "task_id": "018f0000-0000-7000-8000-000000000201",
        "model_id": _identity(ProviderRole.EXTRACTION).model_id,
        "model_revision": REVISION,
        "classification": "internal",
        "schema": "memory-candidates.v1",
        "input_sha256": "a" * 64,
        "content_base64": "not-base64",
    }
    async with _client(ProviderRole.EXTRACTION, backend, tmp_path) as client:
        invalid_base64 = await client.post(
            "/v1/extract/memory-candidates", headers=_headers(), json=body
        )
        mismatched_digest = await client.post(
            "/v1/extract/memory-candidates",
            headers=_headers(),
            json={**body, "content_base64": "e30="},
        )
    assert invalid_base64.status_code == 422
    assert mismatched_digest.status_code == 422


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "header_updates", "body", "expected"),
    [
        ("/unknown", {}, b"{}", 404),
        ("/v1/probe?query=1", {}, b"{}", 404),
        ("/v1/probe", {"host": "attacker:8080"}, b"{}", 403),
        ("/v1/probe", {"origin": "https://example.test"}, b"{}", 403),
        ("/v1/probe", {"sec-fetch-site": "cross-site"}, b"{}", 403),
        ("/v1/probe", {"content-type": "text/plain"}, b"{}", 415),
        ("/v1/probe", {"transfer-encoding": "chunked"}, b"{}", 413),
        ("/v1/probe", {"x-agentmemory-capability": "A" * 64}, b"{}", 401),
        ("/v1/probe", {"x-agentmemory-capability": "a" * 64}, b"{}", 401),
        ("/v1/probe", {}, b'{"a":1,"a":2}', 422),
        ("/v1/probe", {}, b"[]", 422),
    ],
)
async def test_boundary_rejects_untrusted_requests_before_dispatch(  # noqa: PLR0913
    path: str,
    header_updates: dict[str, str],
    body: bytes,
    expected: int,
    backend: RecordingBackend,
    tmp_path: Path,
) -> None:
    async with _client(ProviderRole.EMBEDDING, backend, tmp_path) as client:
        response = await client.post(path, headers=_headers(**header_updates), content=body)
    assert response.status_code == expected
    assert backend.calls == []


@pytest.mark.asyncio
async def test_boundary_rejects_duplicate_framing_and_capability_headers(
    backend: RecordingBackend, tmp_path: Path
) -> None:
    base = [
        ("content-type", "application/json"),
        ("x-agentmemory-capability", CAPABILITY.hex()),
    ]
    async with _client(ProviderRole.EMBEDDING, backend, tmp_path) as client:
        duplicate_length = await client.post(
            "/v1/probe",
            headers=[*base, ("content-length", "2"), ("content-length", "2")],
            content=b"{}",
        )
        duplicate_capability = await client.post(
            "/v1/probe",
            headers=[*base, ("x-agentmemory-capability", CAPABILITY.hex())],
            content=b"{}",
        )
    assert duplicate_length.status_code == 413
    assert duplicate_capability.status_code == 401


@pytest.mark.asyncio
async def test_validation_identity_and_runtime_errors_are_safe(
    backend: RecordingBackend, tmp_path: Path
) -> None:
    payload = _probe(ProviderRole.EMBEDDING)
    payload["model_id"] = "wrong"
    async with _client(ProviderRole.EMBEDDING, backend, tmp_path) as client:
        identity = await client.post("/v1/probe", headers=_headers(), json=payload)
        invalid = await client.post(
            "/v1/probe",
            headers=_headers(),
            json={**_probe(ProviderRole.EMBEDDING), "unknown": True},
        )
        backend.healthy = False
        unavailable = await client.post(
            "/v1/probe", headers=_headers(), json=_probe(ProviderRole.EMBEDDING)
        )
    assert identity.status_code == 422
    assert invalid.status_code == 422
    assert unavailable.status_code == 503
    assert "unhealthy" not in unavailable.text


@pytest.mark.asyncio
async def test_request_timeout_is_bounded(
    backend: RecordingBackend,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def slow_health() -> None:
        await asyncio.Event().wait()

    monkeypatch.setattr(backend, "health", slow_health)
    monkeypatch.setattr(http_api, "_REQUEST_TIMEOUT_SECONDS", 0.001)
    async with _client(ProviderRole.EMBEDDING, backend, tmp_path) as client:
        response = await client.post(
            "/v1/probe", headers=_headers(), json=_probe(ProviderRole.EMBEDDING)
        )
    assert response.status_code == 504
