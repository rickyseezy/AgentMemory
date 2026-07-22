"""PRO-001 authenticated provider-profile HTTP and OpenAPI contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import timedelta
from typing import TYPE_CHECKING

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.providers.adapters.profile_http_api import (
    create_contract_provider_profile_router,
    create_provider_profile_router,
)
from agentmemory.providers.application.profiles import (
    CreateProviderProfileCommand,
    GetProviderProfileQuery,
    ProbeProviderCommand,
)
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderProfileAuthorizationError,
)
from agentmemory.providers.domain.profiles import ProviderProbeEvidence, ProviderProfile
from tests.core.support import BRAIN_ID, GRANT_ID, NOW, OWNER_ID, FixedClock
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    manifest,
    probe_result,
    profile,
    scope,
)

_ERR_AUTHORIZATION = "provider profile action is not authorized"

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            raise ProviderProfileAuthorizationError(_ERR_AUTHORIZATION)


@dataclass(slots=True)
class _Resolver:
    calls: int = 0

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        del query
        self.calls += 1
        resolved = scope("provider.profile.read")
        return RetrievalScopeResolution(
            resolved,
            ScopeExplanation(resolved.mode, ("brain_owner",)),
        )


@dataclass(slots=True)
class _Create:
    result: ProviderProfile = field(default_factory=profile)
    commands: list[CreateProviderProfileCommand] = field(
        default_factory=list[CreateProviderProfileCommand]
    )

    async def execute(self, command: CreateProviderProfileCommand) -> ProviderProfile:
        self.commands.append(command)
        return self.result


@dataclass(slots=True)
class _Probe:
    result: ProviderProfile
    error: Exception | None = None
    commands: list[ProbeProviderCommand] = field(default_factory=list[ProbeProviderCommand])

    async def execute(self, command: ProbeProviderCommand) -> ProviderProfile:
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return self.result


@dataclass(slots=True)
class _Get:
    result: ProviderProfile
    queries: list[GetProviderProfileQuery] = field(default_factory=list[GetProviderProfileQuery])

    async def execute(self, query: GetProviderProfileQuery) -> ProviderProfile:
        self.queries.append(query)
        return self.result


def _active_profile() -> ProviderProfile:
    draft = profile()
    evidence = ProviderProbeEvidence.create(
        PROFILE_ID,
        manifest().digest,
        probe_result(),
        NOW + timedelta(seconds=1),
    )
    return draft.activate(evidence)


def _body(operation_id: str = "pro001-create-http") -> dict[str, object]:
    return {
        "operation_id": operation_id,
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
        "adapter_id": "openai",
        "operation": "embedding",
        "model_id": "text-embedding-3-large",
        "purposes": ["retrieval_document", "retrieval_query"],
        "execution_class": "remote",
        "limits": {
            "max_items": 16,
            "max_input_bytes": 64_000,
            "max_item_tokens": 4096,
            "max_request_tokens": 65_536,
            "timeout_milliseconds": 30_000,
        },
        "remote_policy": {
            "endpoint_policy_ref": "policy://providers/openai-production",
            "secret_ref": "secret://providers/openai-production",
            "egress_approval_ref": "approval://providers/openai-production",
            "data_policy": {
                "declaration_version": "2026-07-01",
                "retention_days": 30,
                "training_allowed": False,
                "residency": "US",
            },
            "quota": {
                "requests_per_minute": 60,
                "tokens_per_minute": 250_000,
                "monthly_tokens": 25_000_000,
            },
            "budget": {"currency": "USD", "monthly_micros": 50_000_000},
        },
    }


def _etag(value: ProviderProfile | None = None) -> str:
    current = profile() if value is None else value
    return f'"provider-profile:{current.profile_id}:{current.version}:{current.snapshot_digest}"'


def _client(
    *,
    probe_error: Exception | None = None,
) -> tuple[httpx.AsyncClient, _Authenticator, _Resolver, _Create, _Probe, _Get]:
    authenticator = _Authenticator()
    resolver = _Resolver()
    create = _Create()
    active = _active_profile()
    probe = _Probe(active, probe_error)
    get = _Get(active)
    app = FastAPI()
    app.include_router(
        create_provider_profile_router(
            authenticator,
            resolver,
            create,
            probe,
            get,
            FixedClock(NOW),
        )
    )
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://agentmemory.test",
    )
    return client, authenticator, resolver, create, probe, get


@pytest.mark.asyncio
async def test_create_probe_and_get_are_authenticated_strict_and_credential_free() -> None:
    client, authenticator, resolver, create, probe, get = _client()
    async with client:
        created = await client.post(
            "/v1/providers/profiles",
            json=_body(),
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "pro001-create-http",
            },
        )
        assert created.status_code == 201
        assert created.headers["etag"] == _etag()
        created_json = created.json()
        assert created_json["status"] == "draft"
        assert created_json["credential_configured"] is True
        assert created_json["remote_policy_configured"] is True
        serialized = json.dumps(created_json, sort_keys=True)
        assert "secret://" not in serialized
        assert "policy://" not in serialized
        assert "approval://" not in serialized
        assert len(create.commands) == 1
        assert create.commands[0].configuration.secret_ref is not None
        assert create.commands[0].configuration.secret_ref.startswith("secret://")

        probed = await client.post(
            f"/v1/providers/profiles/{PROFILE_ID}/probe",
            json={
                "operation_id": "pro001-probe-http",
                "brain_id": BRAIN_ID,
                "actor_id": OWNER_ID,
                "grant_id": GRANT_ID,
                "project_id": PROJECT_ID,
                "repository_id": REPOSITORY_ID,
            },
            headers={
                "Authorization": "Bearer valid",
                "If-Match": created.headers["etag"],
                "Idempotency-Key": "pro001-probe-http",
            },
        )
        assert probed.status_code == 200
        assert probed.headers["etag"] == _etag(_active_profile())
        assert probed.json()["active_probe"]["revision_fingerprint"] == (
            probe_result().revision_fingerprint
        )
        assert len(probe.commands) == 1

        read = await client.get(
            f"/v1/providers/profiles/{PROFILE_ID}",
            params={
                "brain_id": BRAIN_ID,
                "actor_id": OWNER_ID,
                "grant_id": GRANT_ID,
                "project_id": PROJECT_ID,
                "repository_id": REPOSITORY_ID,
            },
            headers={"Authorization": "Bearer valid"},
        )
        assert read.status_code == 200
        assert read.headers["etag"] == _etag(_active_profile())
        assert read.json()["profile_id"] == PROFILE_ID
        assert len(get.queries) == 1
    assert authenticator.calls == 3
    assert resolver.calls == 3


@pytest.mark.asyncio
async def test_authentication_and_idempotency_fail_before_scope_or_provider_work() -> None:
    client, authenticator, resolver, create, probe, get = _client()
    del probe, get
    async with client:
        denied = await client.post(
            "/v1/providers/profiles",
            json=_body(),
            headers={"Idempotency-Key": "pro001-create-http"},
        )
        assert denied.status_code == 403
        assert resolver.calls == 0
        assert create.commands == []

        wrong_key = await client.post(
            "/v1/providers/profiles",
            json=_body(),
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "different"},
        )
        assert wrong_key.status_code == 422
        assert resolver.calls == 0
        assert create.commands == []
    assert authenticator.calls == 2


@pytest.mark.asyncio
async def test_invalid_provider_secret_error_is_safe_and_never_echoes_upstream_data() -> None:
    marker = "sk-pro001-invalid-secret-upstream-body"
    error = ProviderAdapterError(ProviderErrorCode.AUTHENTICATION)
    client, _, _, _, _, _ = _client(probe_error=error)
    async with client:
        response = await client.post(
            f"/v1/providers/profiles/{PROFILE_ID}/probe",
            json={
                "operation_id": "pro001-probe-invalid-secret",
                "brain_id": BRAIN_ID,
                "actor_id": OWNER_ID,
                "grant_id": GRANT_ID,
                "project_id": PROJECT_ID,
                "repository_id": REPOSITORY_ID,
            },
            headers={
                "Authorization": "Bearer valid",
                "If-Match": _etag(),
                "Idempotency-Key": "pro001-probe-invalid-secret",
            },
        )
    assert response.status_code == 422
    assert response.json()["type"] == "urn:agentmemory:provider:provider_rejected"
    assert marker not in response.text
    assert "secret://" not in response.text
    assert "authentication" not in response.text


@pytest.mark.asyncio
async def test_probe_requires_a_strong_matching_profile_etag_before_scope_resolution() -> None:
    client, _, resolver, _, probe, _ = _client()
    body = {
        "operation_id": "pro001-probe-precondition",
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }
    headers = {
        "Authorization": "Bearer valid",
        "Idempotency-Key": "pro001-probe-precondition",
    }
    async with client:
        missing = await client.post(
            f"/v1/providers/profiles/{PROFILE_ID}/probe", json=body, headers=headers
        )
        assert missing.status_code == 422
        mismatched = await client.post(
            f"/v1/providers/profiles/{PROFILE_ID}/probe",
            json=body,
            headers={**headers, "If-Match": _etag().replace(PROFILE_ID, PROJECT_ID)},
        )
    assert mismatched.status_code == 422
    assert resolver.calls == 0
    assert probe.commands == []


@pytest.mark.asyncio
async def test_request_models_reject_extra_fields_and_incomplete_remote_policy() -> None:
    client, _, resolver, create, _, _ = _client()
    invalid = _body()
    invalid["credential_value"] = "must-not-be-accepted"
    async with client:
        response = await client.post(
            "/v1/providers/profiles",
            json=invalid,
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "pro001-create-http",
            },
        )
        assert response.status_code == 422
        incomplete = _body()
        remote = incomplete["remote_policy"]
        assert isinstance(remote, dict)
        del remote["budget"]
        response = await client.post(
            "/v1/providers/profiles",
            json=incomplete,
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "pro001-create-http",
            },
        )
        assert response.status_code == 422
    assert resolver.calls == 0
    assert create.commands == []


def test_provider_openapi_is_deterministic_and_exposes_complete_lifecycle() -> None:
    app = FastAPI()
    app.include_router(create_contract_provider_profile_router())
    first = json.dumps(app.openapi(), sort_keys=True, separators=(",", ":"))
    app.openapi_schema = None
    second = json.dumps(app.openapi(), sort_keys=True, separators=(",", ":"))
    assert first == second
    schema = json.loads(first)
    assert set(schema["paths"]) == {
        "/v1/providers/profiles",
        "/v1/providers/profiles/{profile_id}",
        "/v1/providers/profiles/{profile_id}/probe",
    }
    assert "credential_value" not in first
