from __future__ import annotations

# pyright: reportPrivateUsage=false
import asyncio
import json
import math
from typing import TYPE_CHECKING, cast, override

import httpx
import pytest

from agentmemory.providers.adapters.llama_cpp import (
    MAX_BACKEND_RESPONSE_BYTES,
    LlamaCppBackend,
    _bounded_content,
)
from agentmemory.providers.adapters.strict_json import StrictJsonError

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Callable


def _json_response(
    payload: object,
    *,
    headers: list[tuple[str, str]] | None = None,
) -> httpx.Response:
    content = json.dumps(payload, separators=(",", ":"), allow_nan=True).encode()
    return httpx.Response(
        200,
        content=content,
        headers=headers or [("content-type", "application/json")],
    )


def _client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)


@pytest.mark.asyncio
async def test_llama_health_accepts_only_exact_response() -> None:
    async with _client(lambda _request: _json_response({"status": "ok"})) as client:
        await LlamaCppBackend(client).health()
    async with _client(lambda _request: _json_response({"status": "loading"})) as client:
        with pytest.raises(RuntimeError, match="health response"):
            await LlamaCppBackend(client).health()
    async with _client(lambda _request: httpx.Response(503, json={"error": "loading"})) as client:
        with pytest.raises(RuntimeError, match="not healthy"):
            await LlamaCppBackend(client).health()
    with pytest.raises(ValueError, match="loopback"):
        LlamaCppBackend(httpx.AsyncClient(), "http://localhost:8090")


class _BlockingStream(httpx.AsyncByteStream):
    @override
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"data: started\n\n"
        await asyncio.Event().wait()


@pytest.mark.asyncio
async def test_llama_cancellation_closes_established_stream_and_recovers() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/completion":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=_BlockingStream(),
            )
        return _json_response({"status": "ok"})

    async with _client(handler) as client:
        await LlamaCppBackend(client).verify_cancellation()


@pytest.mark.asyncio
async def test_embedding_translates_exact_backend_shape() -> None:
    payload = {
        "data": [
            {"embedding": [0.5, 0.25], "index": 0, "object": "embedding"},
            {"embedding": [0.1, 0.2], "index": 1, "object": "embedding"},
        ],
        "model": "model",
        "object": "list",
        "usage": {"prompt_tokens": 2, "total_tokens": 2},
    }
    async with _client(lambda _request: _json_response(payload)) as client:
        assert await LlamaCppBackend(client).embed(("a", "b")) == ((0.5, 0.25), (0.1, 0.2))


_INVALID_EMBEDDING_RESPONSES: tuple[object, ...] = (
    {
        "data": [{"embedding": [0.5], "index": 0, "object": "embedding"}],
        "model": "model",
        "object": "list",
        "usage": {"prompt_tokens": 1, "total_tokens": 1},
        "extra": True,
    },
    {
        "data": list[object](),
        "model": "model",
        "object": "bad",
        "usage": dict[str, object](),
    },
    {
        "data": dict[str, object](),
        "model": "model",
        "object": "list",
        "usage": dict[str, object](),
    },
    {
        "data": list[object](),
        "model": "model",
        "object": "list",
        "usage": dict[str, object](),
    },
    {
        "data": [{"embedding": [0.5], "index": 1, "object": "embedding"}],
        "model": "model",
        "object": "list",
        "usage": dict[str, object](),
    },
    {
        "data": [{"embedding": [0.5], "index": 0, "object": "embedding", "extra": True}],
        "model": "model",
        "object": "list",
        "usage": dict[str, object](),
    },
    {
        "data": [
            {
                "embedding": dict[str, object](),
                "index": 0,
                "object": "embedding",
            }
        ],
        "model": "model",
        "object": "list",
        "usage": dict[str, object](),
    },
    {
        "data": [{"embedding": [True], "index": 0, "object": "embedding"}],
        "model": "model",
        "object": "list",
        "usage": dict[str, object](),
    },
    {
        "data": [{"embedding": [math.inf], "index": 0, "object": "embedding"}],
        "model": "model",
        "object": "list",
        "usage": dict[str, object](),
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _INVALID_EMBEDDING_RESPONSES)
async def test_embedding_rejects_every_backend_shape_drift(payload: object) -> None:
    async with _client(lambda _request: _json_response(payload)) as client:
        with pytest.raises((RuntimeError, TypeError)):
            await LlamaCppBackend(client).embed(("a",))


@pytest.mark.asyncio
async def test_reranking_restores_original_document_order() -> None:
    payload = {
        "model": "model",
        "object": "list",
        "results": [
            {"index": 1, "relevance_score": 0.9},
            {"index": 0, "relevance_score": 0.1},
        ],
        "usage": {"prompt_tokens": 2, "total_tokens": 2},
    }
    async with _client(lambda _request: _json_response(payload)) as client:
        assert await LlamaCppBackend(client).rerank("q", ("a", "b")) == (0.1, 0.9)


_INVALID_RERANKING_RESPONSES: tuple[object, ...] = (
    {
        "model": "model",
        "object": "list",
        "results": [{"index": 0, "relevance_score": 0.1}],
        "usage": {},
        "extra": True,
    },
    {"model": "model", "object": "bad", "results": [], "usage": {}},
    {"model": "model", "object": "list", "results": {}, "usage": {}},
    {"model": "model", "object": "list", "results": [], "usage": {}},
    {
        "model": "model",
        "object": "list",
        "results": [{"index": 0, "relevance_score": 0.1, "extra": True}],
        "usage": {},
    },
    {
        "model": "model",
        "object": "list",
        "results": [{"index": True, "relevance_score": 0.1}],
        "usage": {},
    },
    {
        "model": "model",
        "object": "list",
        "results": [{"index": 2, "relevance_score": 0.1}],
        "usage": {},
    },
    {
        "model": "model",
        "object": "list",
        "results": [
            {"index": 0, "relevance_score": 0.1},
            {"index": 0, "relevance_score": 0.2},
        ],
        "usage": {},
    },
    {
        "model": "model",
        "object": "list",
        "results": [{"index": 0, "relevance_score": True}],
        "usage": {},
    },
    {
        "model": "model",
        "object": "list",
        "results": [{"index": 0, "relevance_score": math.inf}],
        "usage": {},
    },
)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _INVALID_RERANKING_RESPONSES)
async def test_reranking_rejects_backend_shape_drift(payload: object) -> None:
    async with _client(lambda _request: _json_response(payload)) as client:
        with pytest.raises((RuntimeError, TypeError)):
            await LlamaCppBackend(client).rerank("q", ("a",))


@pytest.mark.asyncio
async def test_extraction_requires_one_schema_constrained_subject() -> None:
    payload = {"choices": [{"message": {"content": '{"subject":"persistent memory"}'}}]}
    async with _client(lambda _request: _json_response(payload)) as client:
        assert await LlamaCppBackend(client).extract_subject("content") == "persistent memory"


@pytest.mark.asyncio
async def test_memory_extraction_uses_exact_json_schema_and_returns_canonical_bytes() -> None:
    output: dict[str, object] = {
        "schema": "agentmemory.memory-candidates.v1",
        "input_sha256": "a" * 64,
        "candidates": [],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        body = cast("dict[str, object]", json.loads(request.content))
        response_format = cast("dict[str, object]", body["response_format"])
        schema = cast("dict[str, object]", response_format["schema"])
        properties = cast("dict[str, object]", schema["properties"])
        input_property = cast("dict[str, object]", properties["input_sha256"])
        candidates_property = cast("dict[str, object]", properties["candidates"])
        assert input_property["const"] == "a" * 64
        assert candidates_property["maxItems"] == 32
        return _json_response({"choices": [{"message": {"content": json.dumps(output)}}]})

    async with _client(handler) as client:
        raw = await LlamaCppBackend(client).extract_memory_candidates("{}", "a" * 64)
    assert raw == (
        b'{"candidates":[],"input_sha256":"'
        + b"a" * 64
        + b'","schema":"agentmemory.memory-candidates.v1"}'
    )


_INVALID_EXTRACTION_RESPONSES: tuple[object, ...] = (
    {"choices": dict[str, object]()},
    {"choices": list[object]()},
    {"choices": [dict[str, object]()]},
    {"choices": [{"message": {"content": 1}}]},
    {"choices": [{"message": {"content": "not-json"}}]},
    {"choices": [{"message": {"content": '{"subject":"x","extra":1}'}}]},
    {"choices": [{"message": {"content": '{"subject":1}'}}]},
)


@pytest.mark.asyncio
@pytest.mark.parametrize("payload", _INVALID_EXTRACTION_RESPONSES)
async def test_extraction_rejects_backend_shape_drift(payload: object) -> None:
    async with _client(lambda _request: _json_response(payload)) as client:
        with pytest.raises((RuntimeError, TypeError, StrictJsonError, KeyError)):
            await LlamaCppBackend(client).extract_subject("content")


@pytest.mark.asyncio
async def test_backend_json_and_framing_are_strict() -> None:
    duplicate = httpx.Response(
        200,
        content=b'{"a":1,"a":2}',
        headers={"content-type": "application/json"},
    )
    async with _client(lambda _request: duplicate) as client:
        with pytest.raises(RuntimeError, match="malformed JSON"):
            await LlamaCppBackend(client).rerank("q", ("a",))

    bad_responses: list[httpx.Response] = [
        httpx.Response(200, content=b"{}", headers={"content-type": "text/plain"}),
        httpx.Response(
            200,
            stream=httpx.ByteStream(b"{}"),
            headers=[("content-type", "application/json"), ("content-encoding", "gzip")],
        ),
        httpx.Response(
            200,
            content=b"{}",
            headers=[
                ("content-type", "application/json"),
                ("content-length", "2"),
                ("content-length", "2"),
            ],
        ),
        httpx.Response(
            200,
            content=b"{}",
            headers=[("content-type", "application/json"), ("content-length", "bad")],
        ),
        httpx.Response(
            200,
            content=b"{}",
            headers=[
                ("content-type", "application/json"),
                ("content-length", str(MAX_BACKEND_RESPONSE_BYTES + 1)),
            ],
        ),
        httpx.Response(
            200,
            content=b"{}",
            headers=[("content-type", "application/json"), ("content-length", "3")],
        ),
        httpx.Response(
            200,
            content=b"x" * (MAX_BACKEND_RESPONSE_BYTES + 1),
            headers={"content-type": "application/json"},
        ),
    ]
    for response in bad_responses:
        with pytest.raises(RuntimeError):
            await _bounded_content(response)
