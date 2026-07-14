"""Pinned local-provider adapters and semantic smoke orchestration tests."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from decimal import Decimal
from typing import TYPE_CHECKING, override

import httpx
import pytest

from agentmemory.operations.adapters.outbound.local_provider import (
    EMBEDDING_DIMENSION,
    MAX_PROVIDER_RESPONSE_BYTES,
    LocalEmbeddingHttpAdapter,
    LocalExtractionHttpAdapter,
    LocalRerankingHttpAdapter,
)
from agentmemory.operations.adapters.outbound.provider_checks import (
    LocalProviderIdentityCheck,
    LocalProviderSetCheck,
    SemanticWriteIndexRecallCheck,
)
from agentmemory.operations.domain.dependency_ports import (
    EmbeddingVector,
    ProviderAttestation,
    RerankItem,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from tests.core.support import binding, write_secret

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from agentmemory.operations.domain.readiness import ReadinessBinding

_EMBED_MODEL = "Qwen/Qwen3-Embedding-0.6B"
_RERANK_MODEL = "Qwen/Qwen3-Reranker-0.6B"
_EXTRACT_MODEL = "Qwen/Qwen3-4B-GGUF-Q4_K_M"
_REVISION = "0123456789abcdef"


def _streaming_json(payload: dict[str, object]) -> httpx.Response:
    content = json.dumps(payload, separators=(",", ":")).encode()
    return httpx.Response(
        200,
        headers={
            "Content-Type": "application/json",
            "Content-Length": str(len(content)),
        },
        stream=_ChunkStream((content,)),
    )


def _provider_response(request: httpx.Request) -> httpx.Response:
    assert request.headers["x-agentmemory-capability"] == (b"c" * 32).hex()
    payload = request.read().decode()
    assert '"classification":"internal"' in payload or request.url.path == "/v1/probe"
    host = request.url.host
    path = request.url.path
    model = {
        "local-embedding": _EMBED_MODEL,
        "local-reranker": _RERANK_MODEL,
        "local-extractor": _EXTRACT_MODEL,
    }[host]
    if path == "/v1/probe":
        role = {
            "local-embedding": "embedding",
            "local-reranker": "reranking",
            "local-extractor": "extraction",
        }[host]
        return _streaming_json(
            {
                "protocol_version": "1.0",
                "role": role,
                "model_id": model,
                "model_revision": _REVISION,
                "dimension": EMBEDDING_DIMENSION if role == "embedding" else None,
                "supports_cancellation": True,
                "local_only": True,
            }
        )
    if path == "/v1/embed":
        content_id = "provider-unknown"
        marker = '"content_id":"'
        start = payload.index(marker) + len(marker)
        content_id = payload[start : payload.index('"', start)]
        return _streaming_json(
            {
                "model_id": model,
                "model_revision": _REVISION,
                "dimension": EMBEDDING_DIMENSION,
                "results": [{"content_id": content_id, "values": [0.25] * EMBEDDING_DIMENSION}],
            }
        )
    if path == "/v1/rerank":
        return _streaming_json(
            {
                "model_id": model,
                "model_revision": _REVISION,
                "results": [
                    {"content_id": "relevant", "score": 0.95},
                    {"content_id": "irrelevant", "score": 0.05},
                ],
            }
        )
    if path == "/v1/extract":
        return _streaming_json(
            {
                "model_id": model,
                "model_revision": _REVISION,
                "subject": "persistent memory",
            }
        )
    return httpx.Response(404)


def _adapters(
    client: httpx.AsyncClient,
    capability: Path,
) -> tuple[LocalEmbeddingHttpAdapter, LocalRerankingHttpAdapter, LocalExtractionHttpAdapter]:
    return (
        LocalEmbeddingHttpAdapter(
            client,
            "http://local-embedding:8080",
            _EMBED_MODEL,
            _REVISION,
            capability,
        ),
        LocalRerankingHttpAdapter(
            client,
            "http://local-reranker:8080",
            _RERANK_MODEL,
            _REVISION,
            capability,
        ),
        LocalExtractionHttpAdapter(
            client,
            "http://local-extractor:8080",
            _EXTRACT_MODEL,
            _REVISION,
            capability,
        ),
    )


@pytest.mark.asyncio
async def test_local_provider_set_executes_real_protocol_shape_and_behavior(
    tmp_path: Path,
) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)
    async with httpx.AsyncClient(transport=httpx.MockTransport(_provider_response)) as client:
        embeddings, reranker, extractor = _adapters(client, capability)
        proof = await LocalProviderSetCheck(embeddings, reranker, extractor).verify(binding())
        identity_proof = await LocalProviderIdentityCheck(
            embeddings,
            reranker,
            extractor,
        ).verify(binding())
        document = await embeddings.embed_document("doc", "content")
        query = await embeddings.embed_query("query", "question")
        ranking = await reranker.rerank(
            "question",
            (("relevant", "persistent memory"), ("irrelevant", "garden")),
        )
        subject = await extractor.extract_subject("persistent memory")
    assert proof.startswith("local_providers:")
    assert proof.endswith(":validated")
    assert identity_proof.startswith("local_provider_identity:")
    assert len(document.values) == EMBEDDING_DIMENSION
    assert len(query.values) == EMBEDDING_DIMENSION
    assert ranking == (
        RerankItem("relevant", Decimal("0.95")),
        RerankItem("irrelevant", Decimal("0.05")),
    )
    assert subject == "persistent memory"


def test_local_provider_rejects_any_non_exact_internal_identity(tmp_path: Path) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)
    client = httpx.AsyncClient(transport=httpx.MockTransport(_provider_response))
    with pytest.raises(ValueError, match="internal service identity"):
        LocalEmbeddingHttpAdapter(
            client,
            "https://example.com:8080",
            _EMBED_MODEL,
            _REVISION,
            capability,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("status_code", [400, 503])
async def test_provider_maps_http_rejection_to_typed_dependency_failure(
    tmp_path: Path,
    status_code: int,
) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)

    def reject(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(status_code)

    async with httpx.AsyncClient(transport=httpx.MockTransport(reject)) as client:
        embeddings, _, _ = _adapters(client, capability)
        with pytest.raises(OperationError) as raised:
            await embeddings.probe()
    assert raised.value.code is ErrorCode.DEPENDENCY_UNAVAILABLE
    assert raised.value.retryable is (status_code >= 500)


@pytest.mark.asyncio
async def test_provider_rejects_malformed_or_drifted_response(tmp_path: Path) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)

    def malformed(request: httpx.Request) -> httpx.Response:
        del request
        return _streaming_json({"protocol_version": "wrong"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(malformed)) as client:
        embeddings, _, _ = _adapters(client, capability)
        with pytest.raises(OperationError) as raised:
            await embeddings.probe()
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION


@pytest.mark.asyncio
async def test_each_provider_rejects_a_well_formed_but_drifted_contract(tmp_path: Path) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)

    def drifted(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/probe":
            return _streaming_json(
                {
                    "protocol_version": "1.0",
                    "role": "reranking",
                    "model_id": _EMBED_MODEL,
                    "model_revision": _REVISION,
                    "dimension": EMBEDDING_DIMENSION,
                    "supports_cancellation": True,
                    "local_only": True,
                }
            )
        if request.url.path == "/v1/embed":
            return _streaming_json(
                {
                    "model_id": "drifted-model",
                    "model_revision": _REVISION,
                    "dimension": EMBEDDING_DIMENSION,
                    "results": [{"content_id": "doc", "values": [0.25] * EMBEDDING_DIMENSION}],
                }
            )
        if request.url.path == "/v1/rerank":
            return _streaming_json(
                {
                    "model_id": _RERANK_MODEL,
                    "model_revision": _REVISION,
                    "results": [
                        {"content_id": "first", "score": 0.9},
                        {"content_id": "first", "score": 0.8},
                    ],
                }
            )
        return _streaming_json(
            {
                "model_id": "drifted-model",
                "model_revision": _REVISION,
                "subject": "persistent memory",
            }
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(drifted)) as client:
        embeddings, reranker, extractor = _adapters(client, capability)
        with pytest.raises(OperationError):
            await embeddings.probe()
        with pytest.raises(OperationError):
            await embeddings.embed_document("doc", "content")
        with pytest.raises(OperationError):
            await reranker.rerank("query", (("first", "one"), ("second", "two")))
        with pytest.raises(OperationError):
            await extractor.extract_subject("content")


class _ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks: tuple[bytes, ...]) -> None:
        self._chunks = chunks
        self.closed = False

    @override
    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            yield chunk

    @override
    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_provider_stream_enforces_incremental_hard_cap_and_closes_response(
    tmp_path: Path,
) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)
    stream = _ChunkStream((b"x" * MAX_PROVIDER_RESPONSE_BYTES, b"x"))

    def oversized(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"Content-Type": "application/json"}, stream=stream)

    async with httpx.AsyncClient(transport=httpx.MockTransport(oversized)) as client:
        embeddings, _, _ = _adapters(client, capability)
        with pytest.raises(OperationError) as raised:
            await embeddings.probe()
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION
    assert stream.closed


class _BlockingStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.never = asyncio.Event()
        self.closed = False

    @override
    async def __aiter__(self) -> AsyncIterator[bytes]:
        self.started.set()
        await self.never.wait()
        yield b"{}"

    @override
    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_provider_stream_closes_promptly_when_request_is_cancelled(tmp_path: Path) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)
    stream = _BlockingStream()

    def blocking(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(200, headers={"Content-Type": "application/json"}, stream=stream)

    async with httpx.AsyncClient(transport=httpx.MockTransport(blocking)) as client:
        embeddings, _, _ = _adapters(client, capability)
        task = asyncio.create_task(embeddings.probe())
        await stream.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert stream.closed


@pytest.mark.asyncio
async def test_identity_probe_explicitly_disables_model_cancellation_work(tmp_path: Path) -> None:
    capability = tmp_path / "capability"
    write_secret(capability, b"c" * 32)

    def identity(request: httpx.Request) -> httpx.Response:
        assert b'"test_cancellation":false' in request.read()
        return _streaming_json(
            {
                "protocol_version": "1.0",
                "role": "embedding",
                "model_id": _EMBED_MODEL,
                "model_revision": _REVISION,
                "dimension": EMBEDDING_DIMENSION,
                "supports_cancellation": True,
                "local_only": True,
            }
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(identity)) as client:
        embeddings, _, _ = _adapters(client, capability)
        result = await embeddings.probe_identity()
    assert result.role == "embedding"


@dataclass(slots=True)
class _Canonical:
    calls: list[str] = field(default_factory=list[str])
    fail_delete: bool = False

    async def write(self, binding: ReadinessBinding, canary_id: str, content: str) -> str:
        del binding, content
        self.calls.append(f"write:{canary_id}")
        return "a" * 64

    async def delete(self, binding: ReadinessBinding, canary_id: str) -> None:
        del binding
        self.calls.append(f"delete:{canary_id}")
        if self.fail_delete:
            msg = "canonical delete failed"
            raise RuntimeError(msg)


@dataclass(slots=True)
class _Embeddings:
    async def probe(self) -> ProviderAttestation:
        return ProviderAttestation(
            role="embedding",
            model_id=_EMBED_MODEL,
            model_revision=_REVISION,
            dimension=1024,
            supports_cancellation=True,
            local_only=True,
        )

    async def embed_document(self, content_id: str, content: str) -> EmbeddingVector:
        del content
        return EmbeddingVector(content_id, (0.1,) * 1024, _EMBED_MODEL, _REVISION)

    async def embed_query(self, content_id: str, content: str) -> EmbeddingVector:
        del content
        return EmbeddingVector(content_id, (0.2,) * 1024, _EMBED_MODEL, _REVISION)


@dataclass(slots=True)
class _Index:
    recalled: bool = True
    calls: list[str] = field(default_factory=list[str])

    async def index(
        self,
        binding: ReadinessBinding,
        canary_id: str,
        source_digest: str,
        vector: EmbeddingVector,
    ) -> None:
        del binding, source_digest, vector
        self.calls.append(f"index:{canary_id}")

    async def recall(
        self,
        binding: ReadinessBinding,
        query_vector: EmbeddingVector,
        expected_canary_id: str,
    ) -> tuple[str, ...]:
        del binding, query_vector
        self.calls.append(f"recall:{expected_canary_id}")
        return (expected_canary_id,) if self.recalled else ()

    async def delete(self, binding: ReadinessBinding, canary_id: str) -> None:
        del binding
        self.calls.append(f"delete:{canary_id}")


@pytest.mark.asyncio
async def test_semantic_smoke_proves_recall_and_always_cleans_both_stores() -> None:
    canonical = _Canonical()
    index = _Index()
    proof = await SemanticWriteIndexRecallCheck(canonical, _Embeddings(), index).verify(binding())
    assert proof == f"semantic:{'a' * 64}:write:index:recall:cleanup"
    assert canonical.calls[0].startswith("write:")
    assert canonical.calls[-1].startswith("delete:")
    assert index.calls[-1].startswith("delete:")


@pytest.mark.asyncio
async def test_semantic_smoke_cleans_and_fails_closed_when_recall_misses() -> None:
    canonical = _Canonical()
    index = _Index(recalled=False)
    with pytest.raises(OperationError) as raised:
        await SemanticWriteIndexRecallCheck(canonical, _Embeddings(), index).verify(binding())
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION
    assert canonical.calls[-1].startswith("delete:")
    assert index.calls[-1].startswith("delete:")


@pytest.mark.asyncio
async def test_semantic_smoke_reports_cleanup_failure() -> None:
    canonical = _Canonical(fail_delete=True)
    with pytest.raises(OperationError) as raised:
        await SemanticWriteIndexRecallCheck(canonical, _Embeddings(), _Index()).verify(binding())
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION
