# pyright: reportPrivateUsage=false
"""MEM-005 lifecycle HTTP translation, error, and OpenAPI contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.memory.adapters.inbound.lifecycle_http_api import (
    create_contract_memory_lifecycle_router,
    create_memory_lifecycle_router,
)
from agentmemory.memory.domain.consolidation import MemoryScope
from agentmemory.memory.domain.errors import MemoryConflictError
from agentmemory.memory.domain.lifecycle import (
    MemoryLifecycleAction,
    MemoryLifecyclePlan,
    MemoryLifecycleResult,
    MemoryLifecycleSnapshot,
    MemoryRecallState,
    lifecycle_idempotency_key,
)
from agentmemory.operations.adapters.inbound.http_api import export_openapi_schema
from tests.memory.test_mem005_lifecycle_application import (
    ACTOR_ID,
    CAUSATION_ID,
    CORRELATION_ID,
    GRANT_ID,
    OPERATION_ID,
)
from tests.memory.test_mem005_lifecycle_domain import (
    BRAIN_ID,
    CHECKOUT_ID,
    MEMORY_ID,
    NOW,
    PROJECT_ID,
    REPOSITORY_ID,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.memory.application.memory_lifecycle import (
        ArchiveMemoryCommand,
        ForgetMemoryCommand,
        PinMemoryCommand,
        SetMemoryExpiryCommand,
    )


def _calls() -> list[str | None]:
    return []


@dataclass
class _Auth:
    calls: list[str | None] = field(default_factory=_calls)

    async def authenticate(self, authorization: str | None) -> None:
        self.calls.append(authorization)


@dataclass
class _Pin:
    result: MemoryLifecycleResult
    command: PinMemoryCommand | None = None
    error: Exception | None = None

    async def execute(self, command: PinMemoryCommand) -> MemoryLifecycleResult:
        self.command = command
        if self.error is not None:
            raise self.error
        return self.result


@dataclass
class _Archive:
    result: MemoryLifecycleResult
    command: ArchiveMemoryCommand | None = None

    async def execute(self, command: ArchiveMemoryCommand) -> MemoryLifecycleResult:
        self.command = command
        return self.result


@dataclass
class _Expiry:
    result: MemoryLifecycleResult
    command: SetMemoryExpiryCommand | None = None

    async def execute(self, command: SetMemoryExpiryCommand) -> MemoryLifecycleResult:
        self.command = command
        return self.result


@dataclass
class _Forget:
    result: MemoryLifecycleResult
    command: ForgetMemoryCommand | None = None

    async def execute(self, command: ForgetMemoryCommand) -> MemoryLifecycleResult:
        self.command = command
        return self.result


def _app(
    *,
    pin_error: Exception | None = None,
) -> tuple[FastAPI, _Auth, _Pin, _Archive, _Expiry, _Forget]:
    result = _result()
    auth = _Auth()
    pin = _Pin(result, error=pin_error)
    archive = _Archive(result)
    expiry = _Expiry(result)
    forget = _Forget(result)
    application = FastAPI()
    application.include_router(create_memory_lifecycle_router(auth, pin, archive, expiry, forget))
    return application, auth, pin, archive, expiry, forget


@pytest.mark.asyncio
async def test_lifecycle_routes_authenticate_then_translate_separate_commands() -> None:
    application, auth, pin, archive, expiry, forget = _app()
    transport = httpx.ASGITransport(app=application)
    request = _request()
    cases: tuple[tuple[str, str, Callable[[], object]], ...] = (
        ("POST", f"/memories/{MEMORY_ID}:pin", lambda: pin.command),
        ("POST", f"/memories/{MEMORY_ID}:archive", lambda: archive.command),
        ("POST", f"/memories/{MEMORY_ID}:expiry", lambda: expiry.command),
        ("DELETE", f"/memories/{MEMORY_ID}", lambda: forget.command),
    )
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        for method, path, captured in cases:
            payload = dict(request)
            if path.endswith(":expiry"):
                payload["expires_at"] = _time(NOW + timedelta(minutes=10))
            if method == "DELETE":
                payload["confirmation"] = "forget-memory"
            response = await client.request(
                method,
                path,
                json=payload,
                headers={"Authorization": "Bearer local"},
            )
            assert response.status_code == 200, response.text
            assert captured() is not None
            assert response.json()["memory_id"] == MEMORY_ID
            assert "statement" not in response.json()

    assert auth.calls == ["Bearer local"] * 4
    assert expiry.command is not None
    assert expiry.command.expires_at == NOW + timedelta(minutes=10)
    assert forget.command is not None
    assert forget.command.confirmation == "forget-memory"


@pytest.mark.asyncio
async def test_lifecycle_transport_is_strict_and_maps_domain_conflict() -> None:
    application, auth, _, _, _, _ = _app(pin_error=MemoryConflictError())
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        conflict = await client.post(
            f"/memories/{MEMORY_ID}:pin",
            json=_request(),
            headers={"Authorization": "Bearer local"},
        )
        invalid = await client.post(
            f"/memories/{MEMORY_ID}:pin",
            json={**_request(), "unexpected": True},
            headers={"Authorization": "Bearer local"},
        )

    assert conflict.status_code == 409
    assert conflict.json()["code"] == "AM_CONFLICT"
    assert invalid.status_code == 422
    assert auth.calls == ["Bearer local"]


def test_contract_router_exports_all_lifecycle_operations() -> None:
    schema = export_openapi_schema((create_contract_memory_lifecycle_router(),))
    encoded = json.dumps(schema, separators=(",", ":"), sort_keys=True)
    for operation in (
        "PinMemoryCommand",
        "ArchiveMemoryCommand",
        "SetMemoryExpiryCommand",
        "ForgetMemoryCommand",
    ):
        assert f'"operationId":"{operation}"' in encoded
    assert '"$ref":"#/components/schemas/MemoryLifecycleReceiptResponse"' in encoded


def _result() -> MemoryLifecycleResult:
    source = MemoryLifecycleSnapshot(
        MEMORY_ID,
        MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID),
        MemoryRecallState.ACTIVE,
        pinned=False,
        expires_at=None,
        version=1,
        updated_at=NOW,
    )
    plan = MemoryLifecyclePlan.create(
        source,
        MemoryLifecycleAction.PIN,
        expected_version=1,
        occurred_at=NOW + timedelta(minutes=1),
    )
    key = lifecycle_idempotency_key(OPERATION_ID, MEMORY_ID, "pin")
    return MemoryLifecycleResult.create(key, "e" * 64, OPERATION_ID, plan)


def _request() -> dict[str, object]:
    return {
        "operation_id": OPERATION_ID,
        "actor_id": ACTOR_ID,
        "grant_id": GRANT_ID,
        "brain_id": BRAIN_ID,
        "correlation_id": CORRELATION_ID,
        "causation_id": CAUSATION_ID,
        "expected_version": 1,
        "requested_at": _time(NOW),
        "deadline": _time(NOW + timedelta(minutes=5)),
    }


def _time(value: datetime) -> str:
    return value.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
