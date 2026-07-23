"""Strict internal-HTTP adapters for the three pinned offline provider roles."""

from __future__ import annotations

import asyncio
import math
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentmemory.operations.adapters.outbound.protected_file import read_protected_file, zero_secret
from agentmemory.operations.domain.dependency_ports import (
    EmbeddingVector,
    ProviderAttestation,
    RerankItem,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from pathlib import Path

MAX_PROVIDER_RESPONSE_BYTES = 8 * 1024 * 1024
EMBEDDING_DIMENSION = 1024
_SERVER_ERROR_STATUS = 500
_MAX_TCP_PORT = 65_535
_EMBEDDING_PURPOSES = frozenset(
    {
        "retrieval_query",
        "retrieval_document",
        "code_query",
        "code_document",
        "semantic_similarity",
        "classification",
        "clustering",
    }
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class _ProbeResponse(_StrictModel):
    protocol_version: Literal["1.0"]
    role: Literal["embedding", "reranking", "extraction"]
    model_id: str = Field(min_length=1, max_length=256)
    model_revision: str = Field(min_length=1, max_length=256)
    dimension: int | None = Field(default=None, ge=1, le=65_536)
    supports_cancellation: bool
    local_only: bool


class _EmbeddingResult(_StrictModel):
    content_id: str = Field(min_length=1, max_length=128)
    values: tuple[float, ...]


class _EmbeddingResponse(_StrictModel):
    model_id: str
    model_revision: str
    dimension: int
    results: tuple[_EmbeddingResult, ...]


class _RerankResult(_StrictModel):
    content_id: str = Field(min_length=1, max_length=128)
    score: float


class _RerankResponse(_StrictModel):
    model_id: str
    model_revision: str
    results: tuple[_RerankResult, ...]


class _ExtractionResponse(_StrictModel):
    model_id: str
    model_revision: str
    subject: str = Field(min_length=1, max_length=128)


@dataclass(frozen=True, slots=True)
class _ProviderIdentity:
    """Pinned identity of one internal provider role."""

    base_url: str
    expected_host: str
    model_id: str
    model_revision: str
    role: str


class _LocalHttpAdapter:
    def __init__(
        self,
        client: httpx.AsyncClient,
        identity: _ProviderIdentity,
        capability_file: Path,
    ) -> None:
        _validate_internal_url(identity.base_url, identity.expected_host)
        self._client = client
        self._base_url = identity.base_url.rstrip("/")
        self._model_id = identity.model_id
        self._model_revision = identity.model_revision
        self._role = identity.role
        self._capability_file = capability_file

    async def _post(self, path: str, payload: dict[str, object]) -> bytes:
        capability = await asyncio.to_thread(
            read_protected_file,
            self._capability_file,
            frozenset({32}),
        )
        try:
            capability_header = capability.hex()
            async with self._client.stream(
                "POST",
                f"{self._base_url}{path}",
                json=payload,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "X-AgentMemory-Capability": capability_header,
                },
            ) as response:
                response.raise_for_status()
                content = await _read_bounded_json(response)
        except (httpx.TimeoutException, httpx.NetworkError) as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                f"local {self._role} provider is unavailable",
                retryable=True,
            ) from error
        except httpx.HTTPStatusError as error:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                f"local {self._role} provider rejected its readiness probe",
                retryable=error.response.status_code >= _SERVER_ERROR_STATUS,
            ) from error
        finally:
            zero_secret(capability)
        return content

    async def _probe(
        self,
        expected_role: str,
        expected_dimension: int | None,
        *,
        test_cancellation: bool,
    ) -> ProviderAttestation:
        raw = await self._post(
            "/v1/probe",
            {
                "protocol_version": "1.0",
                "role": expected_role,
                "model_id": self._model_id,
                "model_revision": self._model_revision,
                "test_cancellation": test_cancellation,
            },
        )
        try:
            response = _ProbeResponse.model_validate_json(raw)
        except ValidationError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "local provider probe was malformed"
            ) from error
        if (
            response.role != expected_role
            or response.model_id != self._model_id
            or response.model_revision != self._model_revision
            or response.dimension != expected_dimension
            or not response.supports_cancellation
            or not response.local_only
        ):
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "local provider identity drifted")
        return ProviderAttestation(
            role=response.role,
            model_id=response.model_id,
            model_revision=response.model_revision,
            dimension=response.dimension,
            supports_cancellation=response.supports_cancellation,
            local_only=response.local_only,
        )


class LocalEmbeddingHttpAdapter(_LocalHttpAdapter):
    """Call the pinned Qwen local embedding sidecar without proxy inheritance."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        model_id: str,
        model_revision: str,
        capability_file: Path,
    ) -> None:
        """Bind only the exact internal embedding service identity."""
        super().__init__(
            client,
            _ProviderIdentity(
                base_url=base_url,
                expected_host="local-embedding",
                model_id=model_id,
                model_revision=model_revision,
                role="embedding",
            ),
            capability_file,
        )

    async def probe(self) -> ProviderAttestation:
        """Validate exact local embedding identity, dimension, and cancellation."""
        return await self._probe(
            "embedding",
            EMBEDDING_DIMENSION,
            test_cancellation=True,
        )

    async def probe_identity(self) -> ProviderAttestation:
        """Validate loaded embedding identity without inference or cancellation work."""
        return await self._probe(
            "embedding",
            EMBEDDING_DIMENSION,
            test_cancellation=False,
        )

    async def embed_document(self, content_id: str, content: str) -> EmbeddingVector:
        """Embed one readiness document under the canonical document purpose."""
        return await self._embed(content_id, content, "retrieval_document")

    async def embed_query(self, content_id: str, content: str) -> EmbeddingVector:
        """Embed one readiness query under the canonical query purpose."""
        return await self._embed(content_id, content, "retrieval_query")

    async def _embed(self, content_id: str, content: str, purpose: str) -> EmbeddingVector:
        results = await self.embed_probe(purpose, ((content_id, content),))
        return results[0]

    async def embed_probe(
        self,
        purpose: str,
        items: tuple[tuple[str, str], ...],
    ) -> tuple[EmbeddingVector, ...]:
        """Embed one ordered PRO-003 canary batch with exact content identities."""
        if purpose not in _EMBEDDING_PURPOSES or not items:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "embedding probe purpose or items were invalid",
            )
        raw = await self._post(
            "/v1/embed",
            {
                "protocol_version": "1.0",
                "model_id": self._model_id,
                "model_revision": self._model_revision,
                "purpose": purpose,
                "classification": "internal",
                "items": [
                    {"content_id": content_id, "content": content} for content_id, content in items
                ],
            },
        )
        try:
            response = _EmbeddingResponse.model_validate_json(raw)
        except ValidationError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "embedding response was malformed"
            ) from error
        expected_ids = tuple(content_id for content_id, _ in items)
        result_ids = tuple(result.content_id for result in response.results)
        if (
            response.model_id != self._model_id
            or response.model_revision != self._model_revision
            or response.dimension != EMBEDDING_DIMENSION
            or len(response.results) != len(items)
            or result_ids != expected_ids
            or len(set(result_ids)) != len(result_ids)
            or any(
                len(result.values) != EMBEDDING_DIMENSION
                or not all(math.isfinite(value) for value in result.values)
                for result in response.results
            )
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "embedding response violated its space"
            )
        return tuple(
            EmbeddingVector(
                content_id=result.content_id,
                values=result.values,
                model_id=response.model_id,
                model_revision=response.model_revision,
            )
            for result in response.results
        )


class LocalRerankingHttpAdapter(_LocalHttpAdapter):
    """Call the pinned Qwen local reranking sidecar."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        model_id: str,
        model_revision: str,
        capability_file: Path,
    ) -> None:
        """Bind only the exact internal reranking service identity."""
        super().__init__(
            client,
            _ProviderIdentity(
                base_url=base_url,
                expected_host="local-reranker",
                model_id=model_id,
                model_revision=model_revision,
                role="reranking",
            ),
            capability_file,
        )

    async def probe(self) -> ProviderAttestation:
        """Validate exact local reranking identity and cancellation."""
        return await self._probe("reranking", None, test_cancellation=True)

    async def probe_identity(self) -> ProviderAttestation:
        """Validate loaded reranker identity without inference or cancellation work."""
        return await self._probe("reranking", None, test_cancellation=False)

    async def rerank(
        self,
        query: str,
        documents: tuple[tuple[str, str], ...],
    ) -> tuple[RerankItem, ...]:
        """Validate a complete ordered finite rerank response."""
        raw = await self._post(
            "/v1/rerank",
            {
                "protocol_version": "1.0",
                "model_id": self._model_id,
                "model_revision": self._model_revision,
                "classification": "internal",
                "query": query,
                "documents": [
                    {"content_id": content_id, "content": content}
                    for content_id, content in documents
                ],
            },
        )
        try:
            response = _RerankResponse.model_validate_json(raw)
        except ValidationError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "reranking response was malformed"
            ) from error
        expected_ids = {content_id for content_id, _ in documents}
        result_ids = [result.content_id for result in response.results]
        scores = [result.score for result in response.results]
        if (
            response.model_id != self._model_id
            or response.model_revision != self._model_revision
            or len(response.results) != len(documents)
            or set(result_ids) != expected_ids
            or len(result_ids) != len(set(result_ids))
            or any(not math.isfinite(score) for score in scores)
            or scores != sorted(scores, reverse=True)
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "reranking response was inconsistent"
            )
        return tuple(
            RerankItem(result.content_id, Decimal(str(result.score))) for result in response.results
        )


class LocalExtractionHttpAdapter(_LocalHttpAdapter):
    """Call the pinned local Qwen extraction sidecar."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        model_id: str,
        model_revision: str,
        capability_file: Path,
    ) -> None:
        """Bind only the exact internal extraction service identity."""
        super().__init__(
            client,
            _ProviderIdentity(
                base_url=base_url,
                expected_host="local-extractor",
                model_id=model_id,
                model_revision=model_revision,
                role="extraction",
            ),
            capability_file,
        )

    async def probe(self) -> ProviderAttestation:
        """Validate exact local extraction identity and cancellation."""
        return await self._probe("extraction", None, test_cancellation=True)

    async def probe_identity(self) -> ProviderAttestation:
        """Validate loaded extractor identity without inference or cancellation work."""
        return await self._probe("extraction", None, test_cancellation=False)

    async def extract_subject(self, content: str) -> str:
        """Extract one bounded subject from synthetic readiness content."""
        raw = await self._post(
            "/v1/extract",
            {
                "protocol_version": "1.0",
                "model_id": self._model_id,
                "model_revision": self._model_revision,
                "classification": "internal",
                "schema": "readiness-subject-v1",
                "content": content,
            },
        )
        try:
            response = _ExtractionResponse.model_validate_json(raw)
        except ValidationError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "extraction response was malformed"
            ) from error
        if response.model_id != self._model_id or response.model_revision != self._model_revision:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "extraction model identity drifted")
        return response.subject


def _validate_internal_url(base_url: str, expected_host: str) -> None:
    parsed = urlsplit(base_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.port is None
        or not 1 <= parsed.port <= _MAX_TCP_PORT
    ):
        msg = "local provider URL must use its exact internal service identity"
        raise ValueError(msg)


async def _read_bounded_json(response: httpx.Response) -> bytes:
    media_type = response.headers.get("content-type", "").partition(";")[0].strip().lower()
    declared_lengths = response.headers.get_list("content-length")
    content_encoding = response.headers.get("content-encoding")
    if (
        media_type != "application/json"
        or content_encoding not in {None, "identity"}
        or len(declared_lengths) > 1
        or (
            declared_lengths
            and (
                not declared_lengths[0].isdigit()
                or int(declared_lengths[0]) > MAX_PROVIDER_RESPONSE_BYTES
            )
        )
    ):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "local provider response was malformed")
    content = bytearray()
    try:
        async for chunk in response.aiter_raw():
            if len(content) + len(chunk) > MAX_PROVIDER_RESPONSE_BYTES:
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION, "local provider response was oversized"
                )
            content.extend(chunk)
        if declared_lengths and len(content) != int(declared_lengths[0]):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "local provider response was malformed"
            )
        return bytes(content)
    finally:
        zero_secret(content)
