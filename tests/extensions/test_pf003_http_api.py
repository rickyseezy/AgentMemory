"""PF-003 authenticated strict HTTP and OpenAPI contract tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.extensions.adapters.http_api import (
    create_adapter_extension_router,
    create_contract_adapter_extension_router,
)
from agentmemory.extensions.domain.errors import AdapterAuthorizationError, AdapterProbeError
from agentmemory.extensions.domain.models import (
    AdapterKind,
    AdapterProbeEvidence,
    AdapterRegistration,
    AdapterRegistrationState,
    ProtocolVersion,
)

if TYPE_CHECKING:
    from agentmemory.extensions.application.register_adapter import RegisterAdapterCommand

NOW = datetime(2026, 7, 22, 14, 0, tzinfo=UTC)


def _document() -> dict[str, object]:
    return {
        "operation_id": "pf003-api-1",
        "brain_id": "018f0000-0000-7000-8000-000000000341",
        "actor_id": "018f0000-0000-7000-8000-000000000342",
        "grant_id": "018f0000-0000-7000-8000-000000000343",
        "requested_at": "2026-07-22T14:00:00Z",
        "manifest": {
            "schema_version": 1,
            "adapter_id": "go-reference-agent",
            "adapter_version": "1.0.0",
            "kind": "agent",
            "package_digest": "a" * 64,
            "signature_digest": "b" * 64,
            "signer_identity": "approved-publisher",
            "protocol_min": "1.0",
            "protocol_max": "1.2",
            "capabilities": ["agent.event.capture"],
            "requested_permissions": ["canonical_event.write"],
        },
    }


def _registration(command: RegisterAdapterCommand) -> AdapterRegistration:
    evidence = AdapterProbeEvidence.create(
        manifest=command.manifest,
        negotiated_protocol=ProtocolVersion(1, 2),
        observed_capabilities=command.manifest.capabilities,
        runtime_digest="c" * 64,
        probed_at=NOW,
    )
    return AdapterRegistration.create(
        registration_id="018f0000-0000-7000-8000-000000000344",
        brain_id=command.brain_id,
        actor_id=command.actor_id,
        grant_id=command.grant_id,
        manifest=command.manifest,
        evidence=evidence,
        state=AdapterRegistrationState.ACTIVE,
        registered_at=NOW,
    )


@pytest.mark.asyncio
async def test_pf003_http_registers_strict_manifest_and_returns_content_free_evidence() -> None:
    handler = _Handler()
    response = await _post(
        _Authenticator(),
        handler,
        headers={"Authorization": "Bearer local", "Idempotency-Key": "pf003-api-1"},
        document=_document(),
    )

    assert response.status_code == 201
    assert response.json()["adapter_id"] == "go-reference-agent"
    assert response.json()["negotiated_protocol"] == "1.2"
    assert "signature_digest" not in response.text
    assert handler.command is not None
    assert handler.command.manifest.kind is AdapterKind.AGENT


@pytest.mark.parametrize(
    ("headers", "mutation", "status_code"),
    [
        ({"Authorization": "Bearer local", "Idempotency-Key": "wrong"}, None, 422),
        ({"Authorization": "Bearer local", "Idempotency-Key": "pf003-api-1"}, "unknown", 422),
        ({"Authorization": "Bearer local", "Idempotency-Key": "pf003-api-1"}, "kind", 422),
    ],
)
@pytest.mark.asyncio
async def test_pf003_http_rejects_header_unknown_field_and_cross_kind_manifest(
    headers: dict[str, str],
    mutation: str | None,
    status_code: int,
) -> None:
    document = _document()
    if mutation == "unknown":
        document["unknown"] = True
    elif mutation == "kind":
        manifest = document["manifest"]
        assert isinstance(manifest, dict)
        manifest["kind"] = "provider"
    response = await _post(
        _Authenticator(),
        _Handler(),
        headers=headers,
        document=document,
    )
    assert response.status_code == status_code


@pytest.mark.asyncio
async def test_pf003_http_maps_auth_and_probe_errors_without_exception_disclosure() -> None:
    forbidden = await _post(
        _Authenticator(denied=True),
        _Handler(),
        headers={"Authorization": "Bearer wrong", "Idempotency-Key": "pf003-api-1"},
        document=_document(),
    )
    assert forbidden.status_code == 403
    failed = await _post(
        _Authenticator(),
        _Handler(probe_failure=True),
        headers={"Authorization": "Bearer local", "Idempotency-Key": "pf003-api-1"},
        document=_document(),
    )
    assert failed.status_code == 424
    assert "raw adapter exception" not in failed.text


def test_pf003_contract_router_publishes_versioned_operation() -> None:
    application = FastAPI()
    application.include_router(create_contract_adapter_extension_router())
    operation = application.openapi()["paths"]["/v1/adapter-extensions:register"]["post"]
    assert operation["responses"]["201"]
    assert operation["security"] == [{"AgentMemoryBearer": []}]


@dataclass
class _Authenticator:
    denied: bool = False

    async def authenticate(self, authorization: str | None) -> None:
        if self.denied or authorization != "Bearer local":
            message = "credential details must not escape"
            raise AdapterAuthorizationError(message)


@dataclass
class _Handler:
    probe_failure: bool = False
    command: RegisterAdapterCommand | None = None

    async def execute(self, command: RegisterAdapterCommand) -> AdapterRegistration:
        self.command = command
        if self.probe_failure:
            message = "raw adapter exception"
            raise AdapterProbeError(message)
        return _registration(command)


async def _post(
    authenticator: _Authenticator,
    handler: _Handler,
    *,
    headers: dict[str, str],
    document: dict[str, object],
) -> httpx.Response:
    application = FastAPI()
    application.include_router(create_adapter_extension_router(authenticator, handler))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application, raise_app_exceptions=False),
        base_url="http://agentmemory.test",
    ) as client:
        return await client.post(
            "/v1/adapter-extensions:register",
            headers=headers,
            json=document,
        )
