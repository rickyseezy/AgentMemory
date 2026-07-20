"""ADP-003 authenticated capability command, query, and display tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.ingestion.adapters.inbound.capability_http_api import (
    create_adapter_capability_router,
    create_contract_adapter_capability_router,
)
from agentmemory.ingestion.application.adapter_capabilities import (
    CapabilityMatrixView,
    GetAdapterCapabilitiesQuery,
    ListAdapterCapabilitiesQuery,
)
from agentmemory.ingestion.domain.adapter_capability import (
    CapabilityChangeDisposition,
    CapabilityChangeResult,
    CapabilityCompatibilityImpact,
    CapabilityCompatibilityWarning,
)
from agentmemory.ingestion.domain.agent_event import CaptureCapability, CaptureMethod
from agentmemory.operations.bootstrap import export_core_openapi_schema
from tests.ingestion.adp002_support import NOW, descriptor
from tests.ingestion.capability_support import registered

if TYPE_CHECKING:
    from agentmemory.ingestion.application.adapter_capabilities import (
        ObserveAdapterCapabilitiesCommand,
        RegisterAgentAdapterCommand,
    )


@dataclass
class _Auth:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        assert authorization == "Bearer local"
        self.calls += 1


class _Register:
    def __init__(self) -> None:
        self.commands: list[RegisterAgentAdapterCommand] = []

    async def execute(
        self,
        command: RegisterAgentAdapterCommand,
    ) -> CapabilityChangeResult:
        self.commands.append(command)
        return CapabilityChangeResult(
            registered(command.manifest, observed_at=NOW),
            CapabilityChangeDisposition.REGISTERED,
            (),
        )


class _Observe:
    def __init__(self) -> None:
        self.commands: list[ObserveAdapterCapabilitiesCommand] = []

    async def execute(
        self,
        command: ObserveAdapterCapabilitiesCommand,
    ) -> CapabilityChangeResult:
        self.commands.append(command)
        configured = descriptor()
        result = registered(
            configured,
            observed_at=NOW,
            revision=2,
            session_lifecycle=CaptureMethod.PERMISSION_DENIED,
        )
        warning = CapabilityCompatibilityWarning(
            CaptureCapability.SESSION_LIFECYCLE,
            CaptureMethod.NATIVE,
            CaptureMethod.PERMISSION_DENIED,
            CapabilityCompatibilityImpact.BREAKING,
            "permission_lost",
        )
        return CapabilityChangeResult(
            result,
            CapabilityChangeDisposition.OBSERVED,
            (warning,),
        )


@dataclass
class _List:
    view: CapabilityMatrixView
    calls: int = 0

    async def execute(
        self,
        query: ListAdapterCapabilitiesQuery,
    ) -> tuple[CapabilityMatrixView, ...]:
        assert query.warning_limit == 20
        self.calls += 1
        return (self.view,)


@dataclass
class _Get:
    view: CapabilityMatrixView | None
    calls: int = 0

    async def execute(
        self,
        query: GetAdapterCapabilitiesQuery,
    ) -> CapabilityMatrixView | None:
        assert query.adapter_id == descriptor().adapter_id
        self.calls += 1
        return self.view


def _manifest_document() -> dict[str, object]:
    configured = descriptor()
    return {
        "adapter_id": configured.adapter_id,
        "adapter_version": configured.adapter_version,
        "adapter_digest": configured.adapter_digest,
        "schema_major": 1,
        "supported_families": [item.value for item in configured.supported_families],
        "evidence_availability": [
            {"capability": item.capability.value, "status": item.status.value}
            for item in configured.evidence_availability
        ],
    }


def _view() -> CapabilityMatrixView:
    configured = descriptor()
    return CapabilityMatrixView(registered(configured, observed_at=NOW), ())


async def _client(
    register: _Register | None = None,
    observe: _Observe | None = None,
    list_handler: _List | None = None,
    get_handler: _Get | None = None,
) -> tuple[httpx.AsyncClient, _Auth, _Register, _Observe, _List, _Get]:
    auth = _Auth()
    resolved_register = register or _Register()
    resolved_observe = observe or _Observe()
    resolved_list = list_handler or _List(_view())
    resolved_get = get_handler or _Get(_view())
    app = FastAPI()
    app.include_router(
        create_adapter_capability_router(
            auth,
            resolved_register,
            resolved_observe,
            resolved_list,
            resolved_get,
        )
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://127.0.0.1:9411",
        headers={"Authorization": "Bearer local"},
    )
    return (
        client,
        auth,
        resolved_register,
        resolved_observe,
        resolved_list,
        resolved_get,
    )


@pytest.mark.asyncio
async def test_register_displays_complete_explicit_matrix_and_binds_idempotency() -> None:
    client, auth, register, _observe, _list, _get = await _client()
    try:
        response = await client.post(
            "/v1/agent-adapters:register",
            headers={"Idempotency-Key": "register-1"},
            json={
                "operation_id": "register-1",
                "manifest": _manifest_document(),
                "permission_denied": [],
            },
        )
    finally:
        await client.aclose()
    assert response.status_code == 201
    assert response.json()["disposition"] == "registered"
    matrix = response.json()["capability_matrix"]
    assert len(matrix["evidence_availability"]) == len(CaptureCapability)
    assert {item["status"] for item in matrix["evidence_availability"]} == {
        "native",
        "unsupported",
    }
    assert len(register.commands) == 1
    assert auth.calls == 1


@pytest.mark.asyncio
async def test_observe_displays_permission_loss_and_compatibility_warning() -> None:
    client, _auth, _register, observe, _list, _get = await _client()
    configured = descriptor()
    denied = [
        {
            "capability": item.capability.value,
            "status": (
                "permission_denied"
                if item.capability is CaptureCapability.SESSION_LIFECYCLE
                else item.status.value
            ),
        }
        for item in configured.evidence_availability
    ]
    try:
        response = await client.post(
            "/v1/agent-adapters/agentmemory.codex/versions/1.0.0:observe",
            headers={"Idempotency-Key": "observe-2"},
            json={
                "operation_id": "observe-2",
                "adapter_digest": configured.adapter_digest,
                "capability_manifest_digest": configured.manifest_sha256,
                "evidence_availability": denied,
            },
        )
    finally:
        await client.aclose()
    assert response.status_code == 200
    warning = response.json()["capability_matrix"]["warnings"][0]
    assert warning == {
        "capability": "session_lifecycle",
        "previous_status": "native",
        "current_status": "permission_denied",
        "impact": "breaking",
        "code": "permission_lost",
    }
    assert observe.commands[0].adapter_id == "agentmemory.codex"


@pytest.mark.asyncio
async def test_list_get_not_found_and_invalid_idempotency_are_safe() -> None:
    client, _auth, register, _observe, list_handler, _get = await _client(
        get_handler=_Get(None)
    )
    try:
        listed = await client.get("/v1/agent-adapters/capabilities")
        missing = await client.get(
            "/v1/agent-adapters/agentmemory.codex/versions/1.0.0/capabilities"
        )
        invalid = await client.post(
            "/v1/agent-adapters:register",
            headers={"Idempotency-Key": "wrong"},
            json={
                "operation_id": "register-1",
                "manifest": _manifest_document(),
            },
        )
    finally:
        await client.aclose()
    assert listed.status_code == 200
    assert listed.json()[0]["adapter_id"] == "agentmemory.codex"
    assert list_handler.calls == 1
    assert missing.status_code == 404
    assert missing.json()["code"] == "AM_NOT_FOUND"
    assert invalid.status_code == 422
    assert register.commands == []


@pytest.mark.asyncio
async def test_unknown_capability_is_field_rejected_before_command_handler() -> None:
    client, _auth, register, _observe, _list, _get = await _client()
    document = _manifest_document()
    availability = list(
        cast("list[dict[str, str]]", document["evidence_availability"])
    )
    availability[0] = {"capability": "hidden_reasoning", "status": "native"}
    document["evidence_availability"] = availability
    try:
        response = await client.post(
            "/v1/agent-adapters:register",
            headers={"Idempotency-Key": "register-1"},
            json={
                "operation_id": "register-1",
                "manifest": document,
            },
        )
    finally:
        await client.aclose()
    assert response.status_code == 422
    assert response.json()["fields"] == [
        {"field": "capability", "code": "unsupported"}
    ]
    assert register.commands == []


def test_contract_openapi_exposes_all_command_and_display_routes() -> None:
    app = FastAPI()
    app.include_router(create_contract_adapter_capability_router())
    paths = app.openapi()["paths"]
    assert "/v1/agent-adapters:register" in paths
    assert "/v1/agent-adapters/{adapter_id}/versions/{adapter_version}:observe" in paths
    assert "/v1/agent-adapters/capabilities" in paths
    assert (
        "/v1/agent-adapters/{adapter_id}/versions/{adapter_version}/capabilities"
        in paths
    )
    core_paths = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    assert set(paths).issubset(core_paths)
