"""Strict internal HTTP adapter for MEM-001 local candidate extraction."""

from __future__ import annotations

import asyncio
import base64
import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentmemory.memory.domain.consolidation import ExtractorResponse
from agentmemory.memory.domain.errors import MemoryDependencyError, MemoryIntegrityError
from agentmemory.providers.adapters.protected_file import read_capability, zero
from agentmemory.providers.adapters.strict_json import StrictJsonError, loads, require_object

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.memory.domain.consolidation import ExtractorRequest

_MAX_RESPONSE_BYTES = 512 * 1024
_SERVER_ERROR = 500
_SUCCESS = 200
_EXTRACTOR_PORT = 8080


class _StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class _MemoryExtractionResponse(_StrictModel):
    protocol_version: Literal["1.0"]
    operation_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_id: str = Field(min_length=36, max_length=36)
    input_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_id: str = Field(min_length=1, max_length=256)
    model_revision: str = Field(min_length=1, max_length=256)
    extraction_schema: Literal["memory-candidates.v1"] = Field(alias="schema")
    output_json: str = Field(min_length=1, max_length=256 * 1024)
    output_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class LocalMemoryCandidateHttpAdapter:
    """Call only the release-pinned local extraction sidecar."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        capability_file: Path,
    ) -> None:
        """Bind exact internal network identity and protected capability reference."""
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "local-extractor"
            or parsed.port != _EXTRACTOR_PORT
            or parsed.path not in {"", "/"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            msg = "local extractor URL must use its exact internal service identity"
            raise ValueError(msg)
        self._client = client
        self._base_url = base_url.rstrip("/")
        self._capability_file = capability_file

    async def extract(self, request: ExtractorRequest) -> ExtractorResponse:
        """Return an exact hash-bound domain response or fail closed."""
        remaining = (request.deadline - datetime.now(UTC)).total_seconds()
        if remaining <= 0:
            raise MemoryDependencyError
        capability: bytearray | None = None
        try:
            capability = await asyncio.to_thread(read_capability, self._capability_file)
            async with asyncio.timeout(remaining):
                async with self._client.stream(
                    "POST",
                    f"{self._base_url}/v1/extract/memory-candidates",
                    json={
                        "protocol_version": "1.0",
                        "operation_id": request.operation_id,
                        "idempotency_key": request.idempotency_key,
                        "task_id": request.task_id,
                        "model_id": request.extractor.model_id,
                        "model_revision": request.extractor.model_revision,
                        "classification": request.classification,
                        "schema": request.extractor.output_schema,
                        "input_sha256": request.input_sha256,
                        "content_base64": base64.b64encode(request.input_bytes).decode(),
                    },
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                        "X-AgentMemory-Capability": capability.hex(),
                    },
                ) as response:
                    _require_success(response.status_code)
                    raw = await _bounded_json(response)
        except MemoryIntegrityError:
            raise
        except MemoryDependencyError:
            raise
        except (TimeoutError, httpx.TimeoutException, httpx.NetworkError, OSError) as error:
            raise MemoryDependencyError from error
        finally:
            if capability is not None:
                zero(capability)
        return _to_domain(raw, request)


def _require_success(status_code: int) -> None:
    if status_code >= _SERVER_ERROR:
        raise MemoryDependencyError
    if status_code != _SUCCESS:
        raise MemoryIntegrityError


def _to_domain(raw: bytes, request: ExtractorRequest) -> ExtractorResponse:
    try:
        document = require_object(loads(raw))
        response = _MemoryExtractionResponse.model_validate(document)
    except (StrictJsonError, ValidationError, TypeError, ValueError) as error:
        raise MemoryIntegrityError from error
    output = response.output_json.encode()
    if (
        response.operation_id != request.operation_id
        or response.idempotency_key != request.idempotency_key
        or response.task_id != request.task_id
        or response.input_sha256 != request.input_sha256
        or response.model_id != request.extractor.model_id
        or response.model_revision != request.extractor.model_revision
        or response.extraction_schema != request.extractor.output_schema
        or hashlib.sha256(output).hexdigest() != response.output_sha256
    ):
        raise MemoryIntegrityError
    try:
        return ExtractorResponse(
            response.operation_id,
            response.idempotency_key,
            response.task_id,
            response.input_sha256,
            request.extractor,
            output,
            response.output_sha256,
        )
    except (TypeError, ValueError) as error:
        raise MemoryIntegrityError from error


async def _bounded_json(response: httpx.Response) -> bytes:
    media_type = response.headers.get("content-type", "").partition(";")[0].strip().lower()
    lengths = response.headers.get_list("content-length")
    encoding = response.headers.get("content-encoding")
    if (
        media_type != "application/json"
        or encoding not in {None, "identity"}
        or len(lengths) > 1
        or (lengths and (not lengths[0].isdigit() or int(lengths[0]) > _MAX_RESPONSE_BYTES))
    ):
        raise MemoryIntegrityError
    content = bytearray()
    async for chunk in response.aiter_raw():
        if len(content) + len(chunk) > _MAX_RESPONSE_BYTES:
            raise MemoryIntegrityError
        content.extend(chunk)
    if lengths and len(content) != int(lengths[0]):
        raise MemoryIntegrityError
    return bytes(content)
