"""ADP-004 loopback transport and installable CLI configuration tests."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import pytest
from pydantic import ValidationError

from agentmemory.ingestion.adapters.generic_http import HttpGenericAgentAdapter
from agentmemory.ingestion.application.generic_adapter import GenericEventFactory
from agentmemory.ingestion.domain.capture import AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.ingestion.domain.generic_adapter import SourceCompletion
from agentmemory.ingestion.infrastructure.generic_cli import (
    GenericAdapterConfig,
    create_generic_cli_parser,
    load_generic_adapter_config,
)
from agentmemory.operations.domain.errors import OperationError
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    DIGEST,
    NOW,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    SESSION_ID,
)
from tests.ingestion.test_adp004_transcript_and_application import context

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


def config_document(credential_file: Path) -> dict[str, object]:
    return {
        "adapter_digest": DIGEST,
        "adapter_version": "1.0.0",
        "brain_id": BRAIN_ID,
        "branch_name": "main",
        "checkout_id": None,
        "classification": "local_only",
        "commit_sha": "a" * 40,
        "correlation_id": None,
        "credential_file": str(credential_file),
        "endpoint": "http://127.0.0.1:8765",
        "ordering_key": None,
        "principal_id": PRINCIPAL_ID,
        "project_id": PROJECT_ID,
        "redaction_patterns": ["customer-[0-9]+"],
        "repository_id": REPOSITORY_ID,
        "retention_policy_id": "default",
        "session_id": SESSION_ID,
        "spool_database": str(credential_file.parent / "spool.sqlite3"),
        "spool_key_file": str(credential_file.parent / "spool-key"),
        "task_id": context().task_id,
    }


def test_cli_loads_only_owner_private_strict_context(tmp_path: Path) -> None:
    credential = tmp_path / "credential"
    credential.write_bytes(b"x" * 32)
    credential.chmod(0o600)
    config_path = tmp_path / "context.json"
    config_path.write_text(json.dumps(config_document(credential)), encoding="utf-8")
    config_path.chmod(0o600)

    loaded = load_generic_adapter_config(config_path)
    first_context = loaded.context()
    repeated_context = loaded.context()

    assert first_context.manifest.adapter_id == "agentmemory.generic"
    assert first_context.session_id == SESSION_ID
    assert first_context.correlation_id == repeated_context.correlation_id == SESSION_ID
    assert first_context.ordering_key == repeated_context.ordering_key == SESSION_ID
    assert loaded.redaction_patterns == ("customer-[0-9]+",)
    config_path.chmod(0o644)
    with pytest.raises(OperationError, match="protected secret source is unsafe"):
        load_generic_adapter_config(config_path)


def test_cli_config_rejects_unknown_fields_and_invalid_release_digest(tmp_path: Path) -> None:
    document = config_document(tmp_path / "credential")
    document["unknown"] = True

    with pytest.raises(ValidationError):
        GenericAdapterConfig.model_validate(document, strict=True)
    document.pop("unknown")
    document["adapter_digest"] = "not-a-digest"
    with pytest.raises(ValidationError):
        GenericAdapterConfig.model_validate(document, strict=True)


def test_cli_parser_requires_an_explicit_operation_and_argv_vector() -> None:
    arguments = create_generic_cli_parser().parse_args(
        ["--config", "/private/context", "wrap", "--", "agent", "--flag"]
    )

    assert arguments.operation == "wrap"
    assert arguments.argv == ["--", "agent", "--flag"]


@pytest.mark.asyncio
async def test_http_adapter_registers_complete_manifest_and_appends_canonical_event() -> None:
    requests: list[httpx.Request] = []
    event = GenericEventFactory(context()).session(
        started=True,
        occurred_at=NOW,
        source_sha256=DIGEST,
        completion=SourceCompletion.COMPLETE,
    )

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/v1/agent-adapters:register":
            return httpx.Response(201, json={"disposition": "registered"})
        return httpx.Response(
            201,
            json={
                "event_id": event.event_id,
                "ingested_at_microseconds": 42,
                "clock_skew_microseconds": -3,
                "status": "accepted",
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as client:
        adapter = HttpGenericAgentAdapter(client, "http://127.0.0.1:8765", b"x" * 32)
        await adapter.ensure_registered(context().manifest)
        result = await adapter.execute(event)

    assert result.disposition is AppendDisposition.ACCEPTED
    assert result.ingested_at_microseconds == 42
    assert result.clock_skew_microseconds == -3
    registration = json.loads(requests[0].content)
    matrix = registration["manifest"]["evidence_availability"]
    assert len(matrix) == len(context().manifest.evidence_availability)
    assert registration["manifest"]["supported_families"]
    expected_authorization = f"Bearer {(b'x' * 32).hex()}"
    assert all(request.headers["Authorization"] == expected_authorization for request in requests)
    assert requests[1].headers["Content-Type"] == "application/json"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1:8765",
        "http://example.com:8765",
        "http://user@127.0.0.1:8765",
        "http://127.0.0.1:8765/path",
        "http://127.0.0.1:8765?query=true",
    ],
)
@pytest.mark.asyncio
async def test_http_adapter_refuses_non_loopback_or_ambiguous_endpoint(endpoint: str) -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(ValueError, match="endpoint"):
            HttpGenericAgentAdapter(client, endpoint, b"x" * 32)


def _redirect(event_id: str) -> httpx.Response:
    del event_id
    return httpx.Response(307, headers={"Location": "http://example.com"})


def _invalid_json(event_id: str) -> httpx.Response:
    del event_id
    return httpx.Response(201, content=b"not-json")


def _deferred(event_id: str) -> httpx.Response:
    return httpx.Response(
        201,
        json={"event_id": event_id, "status": "deferred", "ingested_at_microseconds": 1},
    )


def _conflicting(event_id: str) -> httpx.Response:
    del event_id
    return httpx.Response(
        201,
        json={"event_id": "different", "status": "accepted", "ingested_at_microseconds": 1},
    )


def _invalid_ingestion_time(event_id: str) -> httpx.Response:
    return httpx.Response(
        201,
        json={"event_id": event_id, "status": "accepted", "ingested_at_microseconds": True},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "response_factory",
    [_redirect, _invalid_json, _deferred, _conflicting, _invalid_ingestion_time],
)
async def test_http_adapter_fails_closed_on_redirect_or_malformed_receipt(
    response_factory: Callable[[str], httpx.Response],
) -> None:
    event = GenericEventFactory(context()).session(
        started=True,
        occurred_at=NOW,
        source_sha256=DIGEST,
        completion=SourceCompletion.COMPLETE,
    )

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _request: response_factory(event.event_id)),
        follow_redirects=False,
    ) as client:
        adapter = HttpGenericAgentAdapter(client, "http://127.0.0.1:8765", b"x" * 32)
        with pytest.raises(IngestionDependencyError):
            await adapter.execute(event)
