"""Authenticated loopback API and deterministic OpenAPI contract tests."""

from __future__ import annotations

import hashlib

# pyright: reportPrivateUsage=false
import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from starlette.requests import Request

from agentmemory.operations.adapters.inbound.http_api import (
    ApiDependencies,
    _bootstrap_status,
    _problem,
    _request_size_rejection,
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
from agentmemory.operations.domain.mcp_session import (
    McpSession,
    McpSessionRegistration,
    McpSessionState,
)
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRebuild,
    RebuildState,
    StartProjectionRebuildCommand,
    derive_generation_id,
    derive_rebuild_key,
)
from agentmemory.operations.domain.readiness import (
    ReadinessBinding,
    ReadinessProbe,
    ReadinessReceipt,
)
from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceIndexCoverage,
)
from tests.core.support import (
    BRAIN_ID,
    GRANT_ID,
    INSTALLATION_ID,
    NOW,
    OWNER_ID,
    FixedClock,
    active_pointer,
    binding,
    bootstrap_request,
    digest,
    receipt,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from datetime import datetime, timedelta


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


@dataclass(slots=True)
class _ProjectionRebuilds:
    value: ProjectionRebuild | None = None

    async def execute(self, command: StartProjectionRebuildCommand) -> ProjectionRebuild:
        key = derive_rebuild_key(
            command.projection_type,
            command.brain_id,
            0,
            command.manifest.implementation_fingerprint,
        )
        self.value = ProjectionRebuild(
            command.operation_id,
            command.brain_id,
            command.actor_id,
            command.grant_id,
            command.projection_type,
            0,
            0,
            key,
            derive_generation_id(key, command.manifest.digest),
            command.manifest,
            RebuildState.QUEUED,
            None,
            0,
            0,
            None,
            None,
            NOW,
            NOW,
        )
        return self.value

    async def get(self, operation_id: str) -> ProjectionRebuild | None:
        if self.value is None or self.value.operation_id != operation_id:
            return None
        return self.value


@dataclass(slots=True)
class _McpSessions:
    values: dict[Uuid7Id, McpSession] = field(default_factory=dict[Uuid7Id, McpSession])

    async def execute(self, registration: McpSessionRegistration) -> tuple[McpSession, bool]:
        existing = self.values.get(registration.session_id)
        if existing is not None:
            return existing, False
        session = McpSession.register(registration)
        self.values[registration.session_id] = session
        return session, True

    async def begin(self, session_id: Uuid7Id, now: datetime, lease: timedelta) -> McpSession:
        current = self.values[session_id].begin(now, lease)
        self.values[session_id] = current
        return current

    async def heartbeat(self, session_id: Uuid7Id, now: datetime) -> McpSession:
        current = self.values[session_id].heartbeat(now)
        self.values[session_id] = current
        return current

    async def finish(
        self, session_id: Uuid7Id, state: McpSessionState, now: datetime
    ) -> McpSession:
        current = self.values[session_id].finish(state, now)
        self.values[session_id] = current
        return current

    async def revoke(self, digest: Sha256Digest, now: datetime) -> tuple[McpSession | None, bool]:
        previous = next(
            (
                value
                for value in self.values.values()
                if value.registration.credential_digest == digest
            ),
            None,
        )
        if previous is None or previous.revoked_at is not None:
            return previous, False
        current = previous.revoke(now)
        self.values[previous.registration.session_id] = current
        return current, True


@dataclass(slots=True)
class _SessionAuthenticator:
    sessions: _McpSessions

    async def authenticate(self, authorization: str | None, session_id: str) -> McpSession:
        identifier = Uuid7Id(session_id)
        session = self.sessions.values.get(identifier)
        if authorization != "Bearer session" or session is None:
            raise OperationError(ErrorCode.UNAUTHENTICATED, "session authentication is required")
        return session


@dataclass(slots=True)
class _WorkspaceCheckpoints:
    digests: set[Sha256Digest] = field(default_factory=set[Sha256Digest])

    async def execute(self, batch: WorkspaceCheckpointBatch) -> bool:
        created = batch.batch_digest not in self.digests
        self.digests.add(batch.batch_digest)
        return created

    async def coverage(self, session_id: Uuid7Id) -> WorkspaceIndexCoverage:
        del session_id
        return WorkspaceIndexCoverage.COMPLETE


def _dependencies(
    *,
    stored_receipt: ReadinessReceipt | None = None,
    live_ready: bool = True,
    execute_ready: bool = True,
) -> tuple[ApiDependencies, _Authenticator, _RuntimeReadiness]:
    authenticator = _Authenticator()
    readiness = _ReadinessHandler(execute_ready=execute_ready)
    runtime_readiness = _RuntimeReadiness(ready=live_ready)
    rebuilds = _ProjectionRebuilds()
    mcp_sessions = _McpSessions()
    workspace_checkpoints = _WorkspaceCheckpoints()
    return (
        ApiDependencies(
            authenticator=authenticator,
            bootstrap=_BootstrapHandler(),
            readiness=readiness,
            active_release=_ActiveReleaseHandler(),
            runtime_readiness=runtime_readiness,
            status_query=_Status(stored_receipt),
            projection_rebuild=rebuilds,
            projection_rebuild_query=rebuilds,
            register_mcp_session=mcp_sessions,
            mcp_session_lifecycle=mcp_sessions,
            session_authenticator=_SessionAuthenticator(mcp_sessions),
            workspace_checkpoint=workspace_checkpoints,
            workspace_coverage=workspace_checkpoints,
            clock=FixedClock(),
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


def _rebuild_json() -> dict[str, object]:
    request = bootstrap_request()
    return {
        "operation_id": "projection-rebuild-1",
        "brain_id": request.brain_id.value,
        "actor_id": request.owner_principal_id.value,
        "grant_id": request.owner_grant_id.value,
        "projection_type": "graph",
        "manifest": {
            "application_build": "1.0.0+abc",
            "relational_schema": "0002_pf002_projection_rebuild",
            "graph_schema": "0002_pf002_projection_schema",
            "parser_version": "parser@1",
            "extractor_version": "extractor@1",
            "provider_versions": ["provider@1"],
            "embedding_space": "embedding@1",
            "implementation_fingerprint": Sha256Digest.from_bytes(b"implementation").value,
        },
    }


def _mcp_registration_json() -> dict[str, object]:
    return {
        "session_id": "019f4d50-4154-7902-b2a0-7c164ae2549f",
        "installation_id": INSTALLATION_ID,
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "agent_id": "codex",
        "workspace_fingerprint": digest("workspace").value,
        "device_identity": "dev:1",
        "git_repository_id": "",
        "git_worktree_id": "",
        "git_coverage": "none",
        "security_epoch": 1,
        "credential_digest": digest("credential").value,
        "issued_at": "2026-07-14T08:09:10.123456Z",
        "expires_at": "2026-07-14T09:09:10.123456Z",
    }


def _workspace_checkpoint_json(session_id: str) -> dict[str, object]:
    content = b"package brain\n"
    document: dict[str, object] = {
        "session_id": session_id,
        "workspace_fingerprint": digest("workspace").value,
        "batch_digest": "",
        "partial": False,
        "changes": [
            {
                "relative_path": "internal/brain.go",
                "sha256": hashlib.sha256(content).hexdigest(),
                "content_base64": "cGFja2FnZSBicmFpbgo=",
                "deleted": False,
            }
        ],
    }
    canonical = json.dumps(document, ensure_ascii=False, separators=(",", ":")).encode()
    document["batch_digest"] = hashlib.sha256(canonical).hexdigest()
    return document


@pytest.mark.asyncio
async def test_pf005_session_http_contract_is_strict_idempotent_and_content_free() -> None:
    dependencies, _, _ = _dependencies()
    registration = _mcp_registration_json()
    session_id = cast("str", registration["session_id"])
    credential_digest = cast("str", registration["credential_digest"])
    headers = {"Authorization": "Bearer valid", "Idempotency-Key": session_id}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
    ) as client:
        created = await client.post(
            "/v1/launcher/sessions/credentials", headers=headers, json=registration
        )
        replay = await client.post(
            "/v1/launcher/sessions/credentials", headers=headers, json=registration
        )
        session_status = await client.get(
            "/v1/session/status",
            headers={
                "Authorization": "Bearer session",
                "X-AgentMemory-Session-ID": session_id,
            },
        )
        denied_session_status = await client.get(
            "/v1/session/status",
            headers={
                "Authorization": "Bearer valid",
                "X-AgentMemory-Session-ID": session_id,
            },
        )
        began = await client.post(
            "/v1/launcher/sessions:begin",
            headers=headers,
            json={
                "session_id": session_id,
                "started_at": "2026-07-14T08:09:10.123456Z",
                "lease_seconds": 120,
            },
        )
        checkpoint_document = _workspace_checkpoint_json(session_id)
        checkpoint_headers = {
            "Authorization": "Bearer valid",
            "Idempotency-Key": cast("str", checkpoint_document["batch_digest"]),
        }
        checkpointed = await client.post(
            "/v1/launcher/sessions:checkpoint",
            headers=checkpoint_headers,
            json=checkpoint_document,
        )
        checkpoint_replay = await client.post(
            "/v1/launcher/sessions:checkpoint",
            headers=checkpoint_headers,
            json=checkpoint_document,
        )
        heartbeat = await client.post(
            "/v1/launcher/sessions:heartbeat",
            headers=headers,
            json={
                "session_id": session_id,
                "heartbeat_at": "2026-07-14T08:09:40.123456Z",
            },
        )
        revoke_headers = {
            "Authorization": "Bearer valid",
            "Idempotency-Key": credential_digest,
        }
        revoked = await client.post(
            "/v1/launcher/sessions/credentials:revoke",
            headers=revoke_headers,
            json={"credential_digest": credential_digest},
        )
        revoke_replay = await client.post(
            "/v1/launcher/sessions/credentials:revoke",
            headers=revoke_headers,
            json={"credential_digest": credential_digest},
        )
        finished = await client.post(
            "/v1/launcher/sessions:finish",
            headers=headers,
            json={
                "session_id": session_id,
                "status": "completed",
                "finished_at": "2026-07-14T08:09:42.123456Z",
            },
        )
    assert created.status_code == 201
    assert created.json()["status"] == "registered"
    assert "credential" not in created.text.replace("credential_digest", "")
    assert replay.status_code == 200
    assert replay.json()["status"] == "already_registered"
    assert session_status.status_code == 200
    assert session_status.json()["workspace_fingerprint"] == registration["workspace_fingerprint"]
    assert session_status.json()["git_coverage"] == "none"
    assert session_status.json()["index_coverage"] == "complete"
    assert denied_session_status.status_code == 401
    assert began.json() == {"session_id": session_id, "state": "active", "revision": 1}
    assert heartbeat.json()["revision"] == 2
    assert checkpointed.status_code == 201, checkpointed.text
    assert checkpointed.json()["status"] == "checkpointed"
    assert checkpoint_replay.status_code == 200
    assert checkpoint_replay.json()["status"] == "already_checkpointed"
    assert revoked.json()["status"] == "revoked"
    assert revoke_replay.json()["status"] == "already_revoked"
    assert finished.json() == {"session_id": session_id, "state": "completed", "revision": 4}


@pytest.mark.asyncio
async def test_projection_rebuild_contract_queues_and_returns_content_free_status() -> None:
    dependencies, _, _ = _dependencies()
    headers = {
        "Authorization": "Bearer valid",
        "Idempotency-Key": "projection-rebuild-1",
    }
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
    ) as client:
        started = await client.post("/operations/rebuilds", headers=headers, json=_rebuild_json())
        queried = await client.get(
            "/operations/rebuilds/projection-rebuild-1",
            headers={"Authorization": "Bearer valid"},
        )
    assert started.status_code == 202
    assert started.json()["state"] == "queued"
    assert queried.status_code == 200
    assert queried.json() == started.json()
    assert "payload" not in started.text


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
        status_response = await client.get("/v1/status", headers={"Authorization": "Bearer valid"})
    assert denied.status_code == 401
    assert denied.headers["content-type"].startswith("application/problem+json")
    assert ready.status_code == 200
    assert ready.json() == {"ready": True}
    assert status_response.json()["ready"] is True
    assert runtime_readiness.calls == 2


@pytest.mark.asyncio
async def test_ready_and_status_are_negative_before_first_receipt() -> None:
    dependencies, _, runtime_readiness = _dependencies(stored_receipt=None)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(dependencies)),
        base_url="http://127.0.0.1:9411",
        headers={"Authorization": "Bearer valid"},
    ) as client:
        ready = await client.get("/ready")
        status_response = await client.get("/v1/status")
    assert ready.status_code == 503
    assert ready.json() == {"ready": False}
    assert status_response.json() == {"ready": False, "receipt": None}
    assert runtime_readiness.calls == 0


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [([], 411), ([(b"content-length", b"not-a-number")], 400)],
)
def test_request_framing_rejects_missing_or_invalid_content_length(
    headers: list[tuple[bytes, bytes]], expected_status: int
) -> None:
    request = Request(
        {
            "type": "http",
            "method": "POST",
            "scheme": "http",
            "path": "/v1/bootstrap",
            "raw_path": b"/v1/bootstrap",
            "query_string": b"",
            "headers": headers,
            "client": ("127.0.0.1", 1234),
            "server": ("127.0.0.1", 9411),
        }
    )
    rejection = _request_size_rejection(request)
    assert rejection is not None
    assert rejection.status_code == expected_status


def test_http_helpers_cover_replay_status_and_generated_correlation() -> None:
    assert _bootstrap_status(BootstrapDisposition.ALREADY_INITIALIZED) == 200
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "scheme": "http",
            "path": "/failure",
            "raw_path": b"/failure",
            "query_string": b"",
            "headers": [],
            "client": ("127.0.0.1", 1234),
            "server": ("127.0.0.1", 9411),
        }
    )
    response = _problem(ErrorCode.VALIDATION, 400, "invalid", request)
    payload = json.loads(bytes(response.body))
    assert payload["correlation_id"]


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
        "/operations/rebuilds",
        "/operations/rebuilds/{operation_id}",
        "/v1/status",
        "/v1/bootstrap",
        "/v1/readiness:verify",
        "/v1/active-release:stage",
        "/v1/active-release:commit",
        "/v1/active-release:matches",
        "/v1/launcher/sessions/credentials",
        "/v1/launcher/sessions/credentials:revoke",
        "/v1/launcher/sessions:begin",
        "/v1/launcher/sessions:heartbeat",
        "/v1/launcher/sessions:finish",
        "/v1/launcher/sessions:checkpoint",
        "/v1/session/status",
    }
    components = first["components"]
    assert isinstance(components, dict)
    security_schemes = cast("dict[str, object]", components)["securitySchemes"]
    assert isinstance(security_schemes, dict)
    assert "AgentMemoryBearer" in security_schemes
