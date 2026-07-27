"""PRO-010 authenticated provider observability HTTP contract tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.operations.bootstrap import export_core_openapi_schema
from agentmemory.providers.adapters.observability_http_api import (
    create_contract_provider_observability_router,
    create_provider_observability_router,
)
from agentmemory.providers.application.observability import (
    GetProviderStatusQuery,
    PublishBudgetPolicyCommand,
    PublishPricingSnapshotCommand,
    RegisterDriftCanaryCommand,
    RunDriftProbeCommand,
)
from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderObservabilityAuthorizationError,
)
from agentmemory.providers.domain.observability import (
    BudgetExhaustionBehavior,
    DriftEvaluation,
    DriftVerdict,
    GenerationPinState,
    ProviderBudgetStatus,
    ProviderGenerationStatus,
    ProviderHealth,
    ProviderHealthStatus,
    ProviderQueueStatus,
    ProviderStatusSnapshot,
)
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID, FixedClock
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    scope,
)
from tests.providers.test_pro010_observability_domain import (
    GENERATION_ID,
    SPACE_ID,
    budget,
    canary,
    pricing,
)

_ERR_AUTH = "private credential detail"

if TYPE_CHECKING:
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )
    from agentmemory.providers.domain.observability import (
        DriftCanary,
        PricingSnapshot,
        ProviderBudgetPolicy,
    )


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            raise ProviderObservabilityAuthorizationError(_ERR_AUTH)


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
class _Pricing:
    commands: list[PublishPricingSnapshotCommand] = field(
        default_factory=list[PublishPricingSnapshotCommand]
    )

    async def execute(self, command: PublishPricingSnapshotCommand) -> PricingSnapshot:
        self.commands.append(command)
        return command.snapshot


@dataclass(slots=True)
class _Budget:
    commands: list[PublishBudgetPolicyCommand] = field(
        default_factory=list[PublishBudgetPolicyCommand]
    )

    async def execute(self, command: PublishBudgetPolicyCommand) -> ProviderBudgetPolicy:
        self.commands.append(command)
        return command.policy


@dataclass(slots=True)
class _Canary:
    commands: list[RegisterDriftCanaryCommand] = field(
        default_factory=list[RegisterDriftCanaryCommand]
    )

    async def execute(self, command: RegisterDriftCanaryCommand) -> DriftCanary:
        self.commands.append(command)
        return command.canary


@dataclass(slots=True)
class _Probe:
    commands: list[RunDriftProbeCommand] = field(default_factory=list[RunDriftProbeCommand])

    async def execute(self, command: RunDriftProbeCommand) -> DriftEvaluation:
        self.commands.append(command)
        return DriftEvaluation(
            verdict=DriftVerdict.STABLE,
            reason_code=None,
            suspend_writes=False,
            requires_new_space=False,
        )


@dataclass(slots=True)
class _Status:
    result: ProviderStatusSnapshot
    queries: list[GetProviderStatusQuery] = field(default_factory=list[GetProviderStatusQuery])

    async def execute(self, query: GetProviderStatusQuery) -> ProviderStatusSnapshot:
        self.queries.append(query)
        return self.result


def _scope_fields() -> dict[str, object]:
    return {
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
    }


def _status() -> ProviderStatusSnapshot:
    return ProviderStatusSnapshot(
        brain_id=BRAIN_ID,
        observed_at_microseconds=round(FixedClock().now().timestamp() * 1_000_000),
        health=(
            ProviderHealth(
                profile_id=PROFILE_ID,
                profile_version=2,
                status=ProviderHealthStatus.DEGRADED,
                circuit_counts=(1, 1, 0),
                requests=10,
                items=20,
                input_units=100,
                output_units=0,
                cost_micros=400,
                latency_p50_microseconds=10,
                latency_p95_microseconds=20,
                latency_p99_microseconds=30,
                safe_errors=((ProviderErrorCode.RATE_LIMIT, 1),),
            ),
        ),
        queues=ProviderQueueStatus(2, 1, 1, 0, 0, 1_000_000),
        budgets=(
            ProviderBudgetStatus(
                profile_id=PROFILE_ID,
                policy_id=budget().policy_id,
                currency="USD",
                limit_micros=1_000,
                spent_micros=400,
                reserved_micros=100,
                remaining_micros=500,
                behavior=BudgetExhaustionBehavior.QUEUE,
            ),
        ),
        generations=(
            ProviderGenerationStatus(
                space_id=SPACE_ID,
                active_generation_id=GENERATION_ID,
                rollback_generation_id=None,
                pin_state=GenerationPinState.PINNED,
                write_suspended=False,
                suspension_reason=None,
            ),
        ),
        retry_count=1,
        dead_letter_count=0,
        active_alert_count=1,
    )


def _app(  # noqa: PLR0913 -- Mirror the explicit production boundary.
    authenticator: _Authenticator,
    resolver: _Resolver,
    publish_pricing: _Pricing,
    publish_budget: _Budget,
    register_canary: _Canary,
    run_probe: _Probe,
    get_status: _Status,
) -> FastAPI:
    application = FastAPI()
    application.include_router(
        create_provider_observability_router(
            authenticator,
            resolver,
            publish_pricing,
            publish_budget,
            register_canary,
            run_probe,
            get_status,
            FixedClock(),
        )
    )
    return application


@pytest.mark.asyncio
async def test_administration_routes_authenticate_resolve_and_return_safe_versions() -> None:
    auth = _Authenticator()
    resolver = _Resolver()
    pricing_handler, budget_handler, canary_handler = _Pricing(), _Budget(), _Canary()
    application = _app(
        auth,
        resolver,
        pricing_handler,
        budget_handler,
        canary_handler,
        _Probe(),
        _Status(_status()),
    )
    pricing_body = {**_scope_fields(), **pricing().creation_document, "operation_id": "price-1"}
    budget_body = {**_scope_fields(), **budget().creation_document, "operation_id": "budget-1"}
    canary_body = {**_scope_fields(), **canary().document, "operation_id": "canary-1"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        price_response = await client.put(
            "/v1/providers/pricing-snapshots",
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "price-1"},
            json=pricing_body,
        )
        budget_response = await client.put(
            "/v1/providers/budget-policies",
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "budget-1"},
            json=budget_body,
        )
        canary_response = await client.put(
            "/v1/providers/drift-canaries",
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "canary-1"},
            json=canary_body,
        )

    assert price_response.status_code == budget_response.status_code == 200
    assert canary_response.status_code == 200
    assert price_response.json()["snapshot_id"] == pricing().snapshot_id
    assert budget_response.json()["policy_id"] == budget().policy_id
    assert canary_response.json()["canary_id"] == canary().canary_id
    assert pricing_handler.commands[0].scope.action == ("provider.observability.pricing.publish")
    assert budget_handler.commands[0].scope.action == "provider.observability.budget.publish"
    assert canary_handler.commands[0].scope.action == "provider.observability.drift.register"
    assert auth.calls == resolver.calls == 3
    serialized = json.dumps(
        [price_response.json(), budget_response.json(), canary_response.json()]
    ).lower()
    assert "raw_vector" not in serialized
    assert "credential" not in serialized
    assert "payload" not in serialized


@pytest.mark.asyncio
async def test_status_and_immediate_probe_expose_complete_safe_operator_state() -> None:
    run_probe, get_status = _Probe(), _Status(_status())
    application = _app(
        _Authenticator(),
        _Resolver(),
        _Pricing(),
        _Budget(),
        _Canary(),
        run_probe,
        get_status,
    )
    query = "&".join(f"{key}={value}" for key, value in _scope_fields().items())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        status_response = await client.get(
            f"/v1/providers/status?{query}",
            headers={"Authorization": "Bearer valid"},
        )
        probe_response = await client.post(
            f"/v1/providers/drift-canaries/{canary().canary_id}:probe",
            headers={"Authorization": "Bearer valid"},
            json=_scope_fields(),
        )

    assert status_response.status_code == probe_response.status_code == 200
    payload = status_response.json()
    assert set(payload) == {
        "active_alert_count",
        "brain_id",
        "budgets",
        "dead_letter_count",
        "generations",
        "health",
        "observed_at_microseconds",
        "queues",
        "retry_count",
    }
    assert payload["health"][0]["safe_errors"] == [["rate_limit", 1]]
    assert payload["generations"][0]["pin_state"] == "pinned"
    assert probe_response.json() == {
        "verdict": "stable",
        "reason_code": None,
        "suspend_writes": False,
        "requires_new_space": False,
    }
    assert get_status.queries[0].scope.action == "provider.observability.status.read"
    assert run_probe.commands[0].scope.action == "provider.observability.drift.run"


@pytest.mark.asyncio
async def test_authentication_idempotency_and_strict_input_fail_closed() -> None:
    resolver, pricing_handler = _Resolver(), _Pricing()
    application = _app(
        _Authenticator(),
        resolver,
        pricing_handler,
        _Budget(),
        _Canary(),
        _Probe(),
        _Status(_status()),
    )
    body = {**_scope_fields(), **pricing().creation_document, "operation_id": "price-1"}
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://test",
    ) as client:
        unauthenticated = await client.put(
            "/v1/providers/pricing-snapshots",
            headers={"Idempotency-Key": "price-1"},
            json=body,
        )
        wrong_key = await client.put(
            "/v1/providers/pricing-snapshots",
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "wrong"},
            json=body,
        )
        extra = await client.put(
            "/v1/providers/pricing-snapshots",
            headers={"Authorization": "Bearer valid", "Idempotency-Key": "price-1"},
            json={**body, "raw_vector": [1.0]},
        )

    assert unauthenticated.status_code == 403
    assert "private credential detail" not in unauthenticated.text
    assert wrong_key.status_code == 422
    assert extra.status_code == 422
    assert resolver.calls == 0
    assert pricing_handler.commands == []


def test_contract_is_strict_authenticated_deterministic_and_in_complete_openapi() -> None:
    first, second = FastAPI(), FastAPI()
    first.include_router(create_contract_provider_observability_router())
    second.include_router(create_contract_provider_observability_router())

    schema = first.openapi()
    assert schema == second.openapi()
    operation = schema["paths"]["/v1/providers/pricing-snapshots"]["put"]
    assert operation["operationId"] == "PublishPricingSnapshotCommand"
    assert operation["security"] == [{"AgentMemoryBearer": []}]
    request_schema = schema["components"]["schemas"]["PricingSnapshotRequestModel"]
    assert request_schema["additionalProperties"] is False
    complete_paths = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    for path in (
        "/v1/providers/pricing-snapshots",
        "/v1/providers/budget-policies",
        "/v1/providers/drift-canaries",
        "/v1/providers/drift-canaries/{canary_id}:probe",
        "/v1/providers/status",
    ):
        assert path in complete_paths
