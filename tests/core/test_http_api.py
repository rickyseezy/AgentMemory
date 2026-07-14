"""Authenticated loopback API and deterministic OpenAPI contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import httpx
import pytest

from agentmemory.operations.adapters.inbound.http_api import (
    ApiDependencies,
    create_app,
    export_openapi_schema,
)
from agentmemory.operations.application.commands.active_release import ActiveReleaseStageResult
from agentmemory.operations.application.commands.bootstrap_local_brain import BootstrapResult
from agentmemory.operations.application.commands.verify_readiness import (
    ReadinessFailure,
    ReadinessVerification,
)
from agentmemory.operations.domain.active_release import (
    ActiveReleasePointer,
    active_release_stage_digest,
)
from agentmemory.operations.domain.bootstrap import BootstrapDisposition, BootstrapRequest
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.readiness import (
    ReadinessBinding,
    ReadinessProbe,
    ReadinessReceipt,
)
from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest
from tests.core.support import active_pointer, binding, bootstrap_request, receipt

if TYPE_CHECKING:
    from collections.abc import AsyncIterator


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            raise OperationError(ErrorCode.UNAUTHENTICATED, "authentication is required")


@dataclass(slots=True)
class _BootstrapHandler:
    async def execute(self, request: BootstrapRequest) -> BootstrapResult:
        return BootstrapResult(
            installation_id=request.installation_id.value,
            brain_id=request.brain_id.value,
            disposition=BootstrapDisposition.CREATED,
        )


@dataclass(slots=True)
class _ReadinessHandler:
    execute_ready: bool = True

    async def execute(self, binding: ReadinessBinding) -> ReadinessVerification:
        if not self.execute_ready:
            return ReadinessVerification(
                ready=False,
                receipt=None,
                failures=(ReadinessFailure(ReadinessProbe.KEY_ACCESS, "probe_failed"),),
            )
        return ReadinessVerification(
            ready=True,
            receipt=receipt(binding),
            failures=(),
        )


@dataclass(slots=True)
class _ActiveReleaseHandler:
    stages: int = 0
    commits: int = 0
    comparisons: int = 0

    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> ActiveReleaseStageResult:
        self.stages += 1
        return ActiveReleaseStageResult(
            active_release_stage_digest(operation_id, pointer),
            self.stages > 1,
        )

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        assert stage_digest == active_release_stage_digest(operation_id, pointer)
        self.commits += 1
        return pointer.pointer_digest

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        self.comparisons += 1
        return not pointer.pointer_digest.value.startswith("0")


@dataclass(slots=True)
class _Status:
    value: ReadinessReceipt | None

    async def latest(self) -> ReadinessReceipt | None:
        return self.value


@dataclass(slots=True)
class _RuntimeReadiness:
    ready: bool = True
    calls: int = 0

    async def verify(self, anchor: ReadinessReceipt) -> ReadinessReceipt | None:
        self.calls += 1
        return anchor if self.ready else None


def _dependencies(
    *,
    stored_receipt: ReadinessReceipt | None = None,
    live_ready: bool = True,
    execute_ready: bool = True,
) -> tuple[ApiDependencies, _Authenticator, _RuntimeReadiness]:
    authenticator = _Authenticator()
    readiness = _ReadinessHandler(execute_ready=execute_ready)
    runtime_readiness = _RuntimeReadiness(ready=live_ready)
    return (
        ApiDependencies(
            authenticator=authenticator,
            bootstrap=_BootstrapHandler(),
            readiness=readiness,
            active_release=_ActiveReleaseHandler(),
            runtime_readiness=runtime_readiness,
            status_query=_Status(stored_receipt),
            allowed_hosts=frozenset({"127.0.0.1:9411"}),
        ),
        authenticator,
        runtime_readiness,
    )


def _bootstrap_json() -> dict[str, str]:
    request = bootstrap_request()
    return {
        "command_id": request.command_id.value,
        "installation_id": request.installation_id.value,
        "owner_principal_id": request.owner_principal_id.value,
        "owner_grant_id": request.owner_grant_id.value,
        "owner_subject_digest": request.owner_subject_digest.value,
        "brain_id": request.brain_id.value,
        "brain_name": request.brain_name,
        "release_digest": request.release_digest.value,
        "generation_id": request.generation_id.value,
    }


def _readiness_json() -> dict[str, str]:
    value = binding()
    return {
        "operation_id": value.operation_id.value,
        "plan_digest": value.plan_digest.value,
        "release_id": value.release_id.value,
        "generation_id": value.generation_id.value,
        "manifest_digest": value.manifest_digest.value,
        "compose_digest": value.compose_digest.value,
    }


@pytest.mark.asyncio
async def test_liveness_is_minimal_but_boundary_policy_still_applies() -> None:
    dependencies, authenticator, _ = _dependencies()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
    ) as client:
        response = await client.get("/health/live")
        wrong_host = await client.get("/health/live", headers={"Host": "attacker.example"})
        browser = await client.get("/health/live", headers={"Origin": "http://localhost"})
    assert response.json() == {"alive": True}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert wrong_host.status_code == 403
    assert browser.status_code == 403
    assert authenticator.calls == 0


@pytest.mark.asyncio
async def test_ready_never_returns_true_from_historical_receipt_without_live_dependencies() -> None:
    dependencies, _, runtime_readiness = _dependencies(
        stored_receipt=receipt(),
        live_ready=False,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
        headers={"Authorization": "Bearer valid"},
    ) as client:
        response = await client.get("/ready")
        status_response = await client.get("/v1/status")
    assert response.status_code == 503
    assert response.json() == {"ready": False}
    assert status_response.json() == {"ready": False, "receipt": None}
    assert runtime_readiness.calls == 2


@pytest.mark.asyncio
async def test_ready_requires_authentication_and_a_fresh_complete_receipt() -> None:
    dependencies, _, runtime_readiness = _dependencies(stored_receipt=receipt())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
    ) as client:
        denied = await client.get("/ready")
        ready = await client.get("/ready", headers={"Authorization": "Bearer valid"})
    assert denied.status_code == 401
    assert denied.headers["content-type"].startswith("application/problem+json")
    assert ready.status_code == 200
    assert ready.json() == {"ready": True}
    assert runtime_readiness.calls == 1


@pytest.mark.asyncio
async def test_bootstrap_requires_matching_idempotency_key_and_strict_body() -> None:
    dependencies, _, _ = _dependencies()
    body = _bootstrap_json()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
        headers={"Authorization": "Bearer valid"},
    ) as client:
        denied = await client.post("/v1/bootstrap", json=body)
        body["unknown"] = "rejected"
        invalid = await client.post(
            "/v1/bootstrap",
            json=body,
            headers={"Idempotency-Key": "bootstrap-0001"},
        )
        body.pop("unknown")
        created = await client.post(
            "/v1/bootstrap",
            json=body,
            headers={"Idempotency-Key": "bootstrap-0001"},
        )
    assert denied.status_code == 422
    assert invalid.status_code == 422
    assert created.status_code == 201
    assert created.json()["disposition"] == "created"


@pytest.mark.asyncio
async def test_mutations_reject_chunked_duplicate_or_oversized_framing() -> None:
    dependencies, _, _ = _dependencies()

    async def chunks() -> AsyncIterator[bytes]:
        yield b"{}"

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
        headers={"Authorization": "Bearer valid"},
    ) as client:
        chunked = await client.post("/v1/bootstrap", content=chunks())
        duplicated = await client.post(
            "/v1/bootstrap",
            content=b"{}",
            headers=[("Content-Length", "2"), ("Content-Length", "2")],
        )
        oversized = await client.post(
            "/v1/bootstrap",
            content=b"{}",
            headers={"Content-Length": str(65 * 1024)},
        )
    assert chunked.status_code == 400
    assert duplicated.status_code == 400
    assert oversized.status_code == 413


@pytest.mark.asyncio
async def test_readiness_endpoint_returns_exact_complete_or_negative_contract() -> None:
    positive_dependencies, _, _ = _dependencies()
    negative_dependencies, _, _ = _dependencies(execute_ready=False)
    headers = {
        "Authorization": "Bearer valid",
        "Idempotency-Key": "install-0001",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(positive_dependencies)),
        base_url="http://127.0.0.1:9411",
        headers=headers,
    ) as client:
        positive = await client.post("/v1/readiness:verify", json=_readiness_json())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(negative_dependencies)),
        base_url="http://127.0.0.1:9411",
        headers=headers,
    ) as client:
        negative = await client.post("/v1/readiness:verify", json=_readiness_json())
    assert positive.status_code == 200
    assert positive.json()["ready"] is True
    assert len(positive.json()["receipt"]["results"]) == 11
    assert negative.json() == {
        "ready": False,
        "receipt": None,
        "failures": [{"probe": "key_access", "code": "probe_failed"}],
    }


@pytest.mark.asyncio
async def test_active_release_endpoints_require_exact_idempotency_and_pointer_digest() -> None:
    dependencies, _, _ = _dependencies()
    pointer = active_pointer()
    operation_id = "install-0001"
    stage_body = {"operation_id": operation_id, "pointer": pointer.record()}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
        headers={"Authorization": "Bearer valid"},
    ) as client:
        denied = await client.post("/v1/active-release:stage", json=stage_body)
        staged = await client.post(
            "/v1/active-release:stage",
            json=stage_body,
            headers={"Idempotency-Key": operation_id},
        )
        stage_digest = staged.json()["stage_digest"]
        committed = await client.post(
            "/v1/active-release:commit",
            json={**stage_body, "stage_digest": stage_digest},
            headers={"Idempotency-Key": operation_id},
        )
        matched = await client.post(
            "/v1/active-release:matches",
            json={"pointer": pointer.record()},
            headers={"Idempotency-Key": pointer.pointer_digest.value},
        )
    assert denied.status_code == 422
    assert staged.status_code == 201
    assert stage_digest == active_release_stage_digest(OperationId(operation_id), pointer).value
    assert committed.json() == {"pointer_digest": pointer.pointer_digest.value}
    assert matched.json() == {"matches": True}


def test_openapi_export_is_deterministic_closed_and_serializable() -> None:
    first = export_openapi_schema()
    second = export_openapi_schema()
    assert json.dumps(first, sort_keys=True, separators=(",", ":")) == json.dumps(
        second,
        sort_keys=True,
        separators=(",", ":"),
    )
    paths: object = first["paths"]
    assert isinstance(paths, dict)
    assert set(cast("dict[str, object]", paths)) == {
        "/v1/status",
        "/v1/bootstrap",
        "/v1/readiness:verify",
        "/v1/active-release:stage",
        "/v1/active-release:commit",
        "/v1/active-release:matches",
    }
    components = first["components"]
    assert isinstance(components, dict)
    security_schemes = cast("dict[str, object]", components)["securitySchemes"]
    assert isinstance(security_schemes, dict)
    assert "AgentMemoryBearer" in security_schemes
