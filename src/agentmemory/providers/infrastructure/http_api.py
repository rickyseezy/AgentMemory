"""Authenticated, bounded HTTP adapter for one local-provider role."""

from __future__ import annotations

import asyncio
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.adapters.strict_json import StrictJsonError, loads, require_object
from agentmemory.providers.domain.models import (
    ContentItem,
    EmbeddingPurpose,
    ProviderRole,
)

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from contextlib import AbstractAsyncContextManager
    from pathlib import Path

    from agentmemory.providers.application.service import ProviderService

_MAX_REQUEST_BYTES = 256 * 1024
_REQUEST_TIMEOUT_SECONDS = 8
_CAPABILITY_HEADER = "x-agentmemory-capability"
_CAPABILITY_HEX_CHARACTERS = 64
_ALLOWED_FETCH_SITES = frozenset({None, "none", "same-origin"})


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class ProbeRequest(_StrictModel):
    """Exact identity and cancellation probe."""

    protocol_version: Literal["1.0"]
    role: Literal["embedding", "reranking", "extraction"]
    model_id: str = Field(min_length=1, max_length=256)
    model_revision: str = Field(min_length=40, max_length=64)
    test_cancellation: bool


class ContentRequest(_StrictModel):
    """One bounded protocol content item."""

    content_id: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=32_768)

    def to_domain(self) -> ContentItem:
        """Translate the inbound DTO to a framework-independent value."""
        return ContentItem(self.content_id, self.content)


class EmbedRequest(_StrictModel):
    """Pinned embedding request contract."""

    protocol_version: Literal["1.0"]
    model_id: str
    model_revision: str
    purpose: Literal["retrieval_document", "retrieval_query"]
    classification: Literal["internal"]
    # JSON has arrays rather than tuples. Keep the immutable domain-facing
    # tuple while permitting Pydantic's JSON-array-to-tuple conversion.
    items: tuple[ContentRequest, ...] = Field(min_length=1, max_length=32, strict=False)


class RerankRequest(_StrictModel):
    """Pinned reranking request contract."""

    protocol_version: Literal["1.0"]
    model_id: str
    model_revision: str
    classification: Literal["internal"]
    query: str = Field(min_length=1, max_length=32_768)
    documents: tuple[ContentRequest, ...] = Field(min_length=1, max_length=32, strict=False)


class ExtractRequest(_StrictModel):
    """Pinned readiness-subject extraction request contract."""

    protocol_version: Literal["1.0"]
    model_id: str
    model_revision: str
    classification: Literal["internal"]
    extraction_schema: Literal["readiness-subject-v1"] = Field(alias="schema")
    content: str = Field(min_length=1, max_length=32_768)


@dataclass(frozen=True, slots=True)
class HttpBoundary:
    """Exact network and capability identity of one sidecar."""

    internal_host: str
    capability_file: Path


class _ProviderProtection:
    """Reject requests before inference consumes scarce local resources."""

    def __init__(self, boundary: HttpBoundary, paths: frozenset[str]) -> None:
        self._boundary = boundary
        self._paths = paths
        self._concurrency = asyncio.Semaphore(1)

    async def __call__(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        """Apply framing, authentication, origin, deadline, and concurrency policy."""
        rejected = await self._validate(request)
        if rejected is not None:
            _security_headers(rejected)
            return rejected
        async with self._concurrency:
            response = await call_next(request)
        _security_headers(response)
        return response

    async def _validate(self, request: Request) -> JSONResponse | None:  # noqa: PLR0911
        if request.method != "POST" or request.url.path not in self._paths or request.url.query:
            return _problem(404, "provider route is not available", request)
        allowed_hosts = {
            f"{self._boundary.internal_host}:8080",
            "127.0.0.1:8080",
            "localhost:8080",
        }
        if request.headers.get("host", "") not in allowed_hosts:
            return _problem(403, "provider Host is not allowed", request)
        if (
            request.headers.get("origin") is not None
            or request.headers.get("sec-fetch-site") not in _ALLOWED_FETCH_SITES
        ):
            return _problem(403, "browser origin is not allowed", request)
        if request.headers.get("content-type", "").partition(";")[0].strip().lower() != (
            "application/json"
        ):
            return _problem(415, "provider content type is invalid", request)
        lengths = request.headers.getlist("content-length")
        if (
            request.headers.get("transfer-encoding") is not None
            or len(lengths) != 1
            or not lengths[0].isdigit()
            or not 1 <= int(lengths[0]) <= _MAX_REQUEST_BYTES
        ):
            return _problem(413, "provider request framing is invalid", request)
        supplied = request.headers.getlist(_CAPABILITY_HEADER)
        if (
            len(supplied) != 1
            or len(supplied[0]) != _CAPABILITY_HEX_CHARACTERS
            or supplied[0].lower() != supplied[0]
        ):
            return _problem(401, "provider capability is invalid", request)
        capability = await asyncio.to_thread(read_capability, self._boundary.capability_file)
        try:
            if not hmac.compare_digest(supplied[0], capability.hex()):
                return _problem(401, "provider capability is invalid", request)
        finally:
            zero(capability)
        body = await request.body()
        if len(body) != int(lengths[0]) or len(body) > _MAX_REQUEST_BYTES:
            return _problem(413, "provider request length is invalid", request)
        try:
            require_object(loads(body))
        except StrictJsonError:
            return _problem(422, "provider request JSON is invalid", request)
        return None


def create_app(
    service: ProviderService,
    boundary: HttpBoundary,
    lifespan: Callable[[FastAPI], AbstractAsyncContextManager[None]] | None = None,
) -> FastAPI:
    """Create one role-specific API with no disabled capability routes."""
    application = FastAPI(
        title=f"AgentMemory local {service.identity.role.value} provider",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    paths = {"/v1/probe"}
    paths.add(
        {
            ProviderRole.EMBEDDING: "/v1/embed",
            ProviderRole.RERANKING: "/v1/rerank",
            ProviderRole.EXTRACTION: "/v1/extract",
        }[service.identity.role]
    )
    application.middleware("http")(_ProviderProtection(boundary, frozenset(paths)))
    _register_errors(application)
    _register_probe(application, service)
    if service.identity.role is ProviderRole.EMBEDDING:
        _register_embedding(application, service)
    elif service.identity.role is ProviderRole.RERANKING:
        _register_reranking(application, service)
    else:
        _register_extraction(application, service)
    return application


def _register_probe(application: FastAPI, service: ProviderService) -> None:
    @application.post("/v1/probe")
    async def probe(request: ProbeRequest) -> dict[str, object]:
        _require_identity(request.model_id, request.model_revision, request.role, service)
        identity = await _with_deadline(service.probe(test_cancellation=request.test_cancellation))
        return {
            "protocol_version": "1.0",
            "role": identity.role.value,
            "model_id": identity.model_id,
            "model_revision": identity.model_revision,
            "dimension": identity.dimension,
            "supports_cancellation": True,
            "local_only": True,
        }

    _routes = (probe,)
    del _routes


def _register_embedding(application: FastAPI, service: ProviderService) -> None:
    @application.post("/v1/embed")
    async def embed(request: EmbedRequest) -> dict[str, object]:
        identity = service.identity
        _require_identity(request.model_id, request.model_revision, "embedding", service)
        results = await _with_deadline(
            service.embed(
                tuple(item.to_domain() for item in request.items),
                EmbeddingPurpose(request.purpose),
            )
        )
        return {
            "model_id": identity.model_id,
            "model_revision": identity.model_revision,
            "dimension": identity.dimension,
            "results": [
                {"content_id": result.content_id, "values": list(result.values)}
                for result in results
            ],
        }

    _routes = (embed,)
    del _routes


def _register_reranking(application: FastAPI, service: ProviderService) -> None:
    @application.post("/v1/rerank")
    async def rerank(request: RerankRequest) -> dict[str, object]:
        identity = service.identity
        _require_identity(request.model_id, request.model_revision, "reranking", service)
        results = await _with_deadline(
            service.rerank(
                request.query,
                tuple(document.to_domain() for document in request.documents),
            )
        )
        return {
            "model_id": identity.model_id,
            "model_revision": identity.model_revision,
            "results": [
                {"content_id": result.content_id, "score": result.score} for result in results
            ],
        }

    _routes = (rerank,)
    del _routes


def _register_extraction(application: FastAPI, service: ProviderService) -> None:
    @application.post("/v1/extract")
    async def extract(request: ExtractRequest) -> dict[str, object]:
        identity = service.identity
        _require_identity(request.model_id, request.model_revision, "extraction", service)
        return {
            "model_id": identity.model_id,
            "model_revision": identity.model_revision,
            "subject": await _with_deadline(service.extract_subject(request.content)),
        }

    _routes = (extract,)
    del _routes


def _require_identity(
    model_id: str,
    model_revision: str,
    role: str,
    service: ProviderService,
) -> None:
    identity = service.identity
    if (
        model_id != identity.model_id
        or model_revision != identity.model_revision
        or role != identity.role.value
    ):
        msg = "provider request identity does not match the loaded model"
        raise ValueError(msg)


def _register_errors(application: FastAPI) -> None:
    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, error: RequestValidationError) -> JSONResponse:
        del error
        return _problem(422, "provider request validation failed", request)

    @application.exception_handler(ValueError)
    async def value_error(request: Request, error: ValueError) -> JSONResponse:
        del error
        return _problem(422, "provider request validation failed", request)

    @application.exception_handler(RuntimeError)
    async def runtime_error(request: Request, error: RuntimeError) -> JSONResponse:
        del error
        return _problem(503, "local inference is unavailable", request)

    @application.exception_handler(TimeoutError)
    async def timeout_error(request: Request, error: TimeoutError) -> JSONResponse:
        del error
        return _problem(504, "provider request deadline was exceeded", request)

    _handlers = (validation_error, value_error, runtime_error, timeout_error)
    del _handlers


async def _with_deadline[ResultT](awaitable: Awaitable[ResultT]) -> ResultT:
    """Bound inference without relying on BaseHTTP response-stream cancellation."""
    async with asyncio.timeout(_REQUEST_TIMEOUT_SECONDS):
        return await awaitable


def _problem(status_code: int, detail: str, request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        media_type="application/problem+json",
        content={
            "type": f"urn:agentmemory:provider:error:{status_code}",
            "title": "Provider request rejected",
            "status": status_code,
            "detail": detail,
            "instance": request.url.path,
        },
    )


def _security_headers(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
