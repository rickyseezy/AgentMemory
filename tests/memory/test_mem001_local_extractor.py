"""MEM-001 production local-extractor HTTP adapter tests."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import httpx
import pytest

from agentmemory.memory.adapters.outbound.local_extractor import (
    LocalMemoryCandidateHttpAdapter,
)
from agentmemory.memory.domain.consolidation import ExtractorRequest
from agentmemory.memory.domain.errors import MemoryDependencyError, MemoryIntegrityError
from tests.memory.test_mem001_consolidation_domain import TASK_ID, bundle, extractor

if TYPE_CHECKING:
    from pathlib import Path


def _request() -> ExtractorRequest:
    source = bundle()
    return ExtractorRequest(
        "mem001-consolidation",
        "b" * 64,
        TASK_ID,
        source.extractor_input_bytes,
        source.extractor_input_sha256,
        "confidential",
        "memory_consolidation",
        datetime.now(UTC) + timedelta(minutes=1),
        extractor(),
    )


def _capability(tmp_path: Path) -> Path:
    path = tmp_path / "capability"
    path.write_bytes(b"k" * 32)
    path.chmod(0o600)
    return path


def _response(request: ExtractorRequest, **changes: object) -> httpx.Response:
    output = (
        b'{"candidates":[],"input_sha256":"'
        + request.input_sha256.encode()
        + b'","schema":"agentmemory.memory-candidates.v1"}'
    )
    body: dict[str, object] = {
        "protocol_version": "1.0",
        "operation_id": request.operation_id,
        "idempotency_key": request.idempotency_key,
        "task_id": request.task_id,
        "input_sha256": request.input_sha256,
        "model_id": request.extractor.model_id,
        "model_revision": request.extractor.model_revision,
        "schema": request.extractor.output_schema,
        "output_json": output.decode(),
        "output_sha256": hashlib.sha256(output).hexdigest(),
    }
    body.update(changes)
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    return httpx.Response(
        200,
        stream=httpx.ByteStream(raw),
        headers={"content-type": "application/json", "content-length": str(len(raw))},
    )


@pytest.mark.asyncio
async def test_local_extractor_sends_exact_bounded_authenticated_request(tmp_path: Path) -> None:
    request = _request()

    def handler(http_request: httpx.Request) -> httpx.Response:
        assert http_request.url == "http://local-extractor:8080/v1/extract/memory-candidates"
        assert http_request.headers["x-agentmemory-capability"] == (b"k" * 32).hex()
        body = json.loads(http_request.content)
        assert body == {
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
        }
        return _response(request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        result = await LocalMemoryCandidateHttpAdapter(
            client, "http://local-extractor:8080", _capability(tmp_path)
        ).extract(request)
    assert result.matches(request)
    assert hashlib.sha256(result.output_bytes).hexdigest() == result.output_sha256


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes"),
    [
        {"operation_id": "other-operation"},
        {"model_revision": "wrong-revision"},
        {"schema": "wrong-schema"},
        {"output_sha256": "0" * 64},
        {"unknown": True},
    ],
)
async def test_local_extractor_rejects_response_identity_or_digest_drift(
    changes: dict[str, object], tmp_path: Path
) -> None:
    request = _request()
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: _response(request, **changes))
    ) as client:
        adapter = LocalMemoryCandidateHttpAdapter(
            client, "http://local-extractor:8080", _capability(tmp_path)
        )
        with pytest.raises(MemoryIntegrityError):
            await adapter.extract(request)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [500, 503])
async def test_local_extractor_maps_server_outage_to_dependency_failure(
    status: int, tmp_path: Path
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: httpx.Response(status))
    ) as client:
        adapter = LocalMemoryCandidateHttpAdapter(
            client, "http://local-extractor:8080", _capability(tmp_path)
        )
        with pytest.raises(MemoryDependencyError):
            await adapter.extract(_request())


def test_local_extractor_rejects_non_internal_service_identity(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="service identity"):
        LocalMemoryCandidateHttpAdapter(
            httpx.AsyncClient(), "https://example.test", _capability(tmp_path)
        )
