"""GRA-006 authenticated graph integrity HTTP contract tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.graph.adapters.inbound.graph_integrity_http_api import (
    create_graph_integrity_router,
)
from agentmemory.graph.domain.errors import GraphUnavailableError
from agentmemory.graph.domain.graph_integrity import (
    GraphIntegrityPolicy,
    GraphMigrationRun,
    GraphRepairPolicy,
)
from agentmemory.identity.domain.retrieval_scope import (
    RetrievalScopeMode,
    RetrievalScopeResolution,
    ScopeExplanation,
)
from agentmemory.operations.bootstrap import export_core_openapi_schema
from tests.core.support import BRAIN_ID, GRANT_ID, OWNER_ID
from tests.graph.test_gra002_sqlite_assertions import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra006_graph_integrity_domain import (
    CHECKSUM,
    CURRENT_GENERATION,
    NOW,
    _observation,  # pyright: ignore[reportPrivateUsage]
)
from tests.identity.test_checkout_observation_sqlite import PROJECT_ID, REPOSITORY_ID

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.application.graph_integrity import (
        RepairGraphFindingCommand,
        RunGraphMigrationCommand,
        StartGraphMigrationCommand,
        ValidateGraphIntegrityQuery,
    )
    from agentmemory.graph.domain.graph_integrity import (
        GraphIntegrityFinding,
        GraphRepairPlan,
    )
    from agentmemory.identity.application.queries.resolve_retrieval_scope import (
        ResolveRetrievalScopeQuery,
    )


@pytest.mark.asyncio
async def test_operator_routes_start_resume_validate_and_repair_without_content() -> None:
    migration = _migration()
    finding = _finding()
    start = _Start(migration)
    run = _Run(migration)
    validate = _Validate((finding,))
    repair = _Repair(GraphRepairPolicy.plan(finding))
    async with _client(_Auth(), _Resolver(), start, run, validate, repair) as client:
        started = await client.post(
            "/graph/integrity/migrations/start",
            headers={"Authorization": "Bearer local"},
            json={
                **_scope_body("migration-1"),
                "migration_id": "gra006-integrity-v1",
                "migration_checksum": CHECKSUM,
                "batch_size": 128,
            },
        )
        resumed = await client.post(
            "/graph/integrity/migrations/run", json=_scope_body("migration-1")
        )
        findings = await client.post(
            "/graph/integrity/validate",
            json={
                **_scope_body("validate-1"),
                "current_generation_id": CURRENT_GENERATION,
            },
        )
        repaired = await client.post(
            "/graph/integrity/repair",
            json={**_scope_body("repair-1"), "finding_id": finding.id},
        )
    assert started.status_code == 201
    assert resumed.status_code == 200
    assert findings.status_code == 200
    assert repaired.status_code == 200
    assert started.json()["migration_checksum"] == CHECKSUM
    assert findings.json()[0]["kind"] == "orphan_edge"
    assert "payload" not in findings.text
    assert repaired.json() == {
        "finding_id": finding.id,
        "action": "quarantine",
        "approval_id": None,
    }
    assert start.commands[0].scope.action == "graph.integrity.migrate"
    assert validate.queries[0].scope.action == "graph.integrity.validate"
    assert repair.commands[0].scope.action == "graph.integrity.repair"


@pytest.mark.asyncio
async def test_authentication_precedes_scope_resolution_and_failures_are_sanitized() -> None:
    auth = _Auth(error=GraphUnavailableError("secret graph database path"))
    resolver = _Resolver()
    dependencies = (_Start(_migration()), _Run(_migration()), _Validate(()), _Repair(None))
    async with _client(auth, resolver, *dependencies) as client:
        response = await client.post(
            "/graph/integrity/migrations/run",
            headers={"Authorization": "Bearer invalid"},
            json=_scope_body("migration-auth"),
        )
    assert response.status_code == 503
    assert response.json()["code"] == "AM_DEPENDENCY_UNAVAILABLE"
    assert "secret graph database path" not in response.text
    assert auth.calls == ["Bearer invalid"]
    assert resolver.queries == []


@pytest.mark.asyncio
async def test_boundary_rejects_caller_asserted_rebuild_verification() -> None:
    finding = _finding()
    async with _client(
        _Auth(),
        _Resolver(),
        _Start(_migration()),
        _Run(_migration()),
        _Validate((finding,)),
        _Repair(GraphRepairPolicy.plan(finding)),
    ) as client:
        response = await client.post(
            "/graph/integrity/repair",
            json={
                **_scope_body("repair-forged"),
                "finding_id": finding.id,
                "destructive": True,
                "approval_id": GRANT_ID,
                "canonical_rebuild_verified": True,
            },
        )
    assert response.status_code == 422


def test_openapi_exposes_all_closed_graph_integrity_operations() -> None:
    app = _app(
        _Auth(),
        _Resolver(),
        _Start(_migration()),
        _Run(_migration()),
        _Validate(()),
        _Repair(None),
    )
    paths = app.openapi()["paths"]
    assert paths["/graph/integrity/migrations/start"]["post"]["operationId"] == (
        "StartGraphMigration"
    )
    assert paths["/graph/integrity/migrations/run"]["post"]["operationId"] == ("RunGraphMigration")
    assert paths["/graph/integrity/validate"]["post"]["operationId"] == ("ValidateGraphIntegrity")
    assert paths["/graph/integrity/repair"]["post"]["operationId"] == "RepairGraphFinding"


def test_complete_core_openapi_includes_graph_integrity_contract() -> None:
    paths = cast("dict[str, object]", export_core_openapi_schema()["paths"])
    assert "/graph/integrity/migrations/start" in paths
    assert "/graph/integrity/migrations/run" in paths
    assert "/graph/integrity/validate" in paths
    assert "/graph/integrity/repair" in paths


def _app(  # noqa: PLR0913 -- Test composition mirrors explicit production capabilities.
    auth: _Auth,
    resolver: _Resolver,
    start: _Start,
    run: _Run,
    validate: _Validate,
    repair: _Repair,
) -> FastAPI:
    app = FastAPI()
    app.include_router(
        create_graph_integrity_router(
            auth,
            resolver,
            start,
            run,
            validate,
            repair,
            _Clock(),
        )
    )
    return app


def _client(  # noqa: PLR0913 -- Test client accepts the same explicit capabilities.
    auth: _Auth,
    resolver: _Resolver,
    start: _Start,
    run: _Run,
    validate: _Validate,
    repair: _Repair,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(auth, resolver, start, run, validate, repair)),
        base_url="http://testserver",
    )


def _scope_body(operation_id: str) -> dict[str, object]:
    return {
        "operation_id": operation_id,
        "brain_id": BRAIN_ID,
        "actor_id": OWNER_ID,
        "grant_id": GRANT_ID,
        "project_id": PROJECT_ID.value,
        "repository_id": REPOSITORY_ID.value,
    }


def _migration() -> GraphMigrationRun:
    return GraphMigrationRun.start(
        operation_id="migration-1",
        brain_id=BRAIN_ID,
        migration_id="gra006-integrity-v1",
        migration_checksum=CHECKSUM,
        source_watermark=10,
        batch_size=128,
        started_at=NOW,
    )


def _finding() -> GraphIntegrityFinding:
    return GraphIntegrityPolicy.evaluate(
        (
            replace(
                _observation(),
                brain_id=BRAIN_ID,
                project_id=PROJECT_ID.value,
                repository_id=REPOSITORY_ID.value,
                canonical_id=None,
            ),
        ),
        CURRENT_GENERATION,
        NOW,
    )[0]


@dataclass(slots=True)
class _Auth:
    error: Exception | None = None
    calls: list[str | None] = field(default_factory=list[str | None])

    async def authenticate(self, authorization: str | None) -> None:
        self.calls.append(authorization)
        if self.error is not None:
            raise self.error


@dataclass(slots=True)
class _Resolver:
    queries: list[ResolveRetrievalScopeQuery] = field(
        default_factory=list["ResolveRetrievalScopeQuery"]
    )

    async def execute(self, query: ResolveRetrievalScopeQuery) -> RetrievalScopeResolution:
        self.queries.append(query)
        return RetrievalScopeResolution(
            _scope("memory.recall"),
            ScopeExplanation(RetrievalScopeMode.CURRENT, (f"current:{PROJECT_ID.value}",)),
        )


@dataclass(slots=True)
class _Clock:
    def now(self) -> datetime:
        return NOW


@dataclass(slots=True)
class _Start:
    result: GraphMigrationRun
    commands: list[StartGraphMigrationCommand] = field(
        default_factory=list["StartGraphMigrationCommand"]
    )

    async def execute(self, command: StartGraphMigrationCommand) -> GraphMigrationRun:
        self.commands.append(command)
        return self.result


@dataclass(slots=True)
class _Run:
    result: GraphMigrationRun
    commands: list[RunGraphMigrationCommand] = field(
        default_factory=list["RunGraphMigrationCommand"]
    )

    async def execute(self, command: RunGraphMigrationCommand) -> GraphMigrationRun:
        self.commands.append(command)
        return self.result


@dataclass(slots=True)
class _Validate:
    result: tuple[GraphIntegrityFinding, ...]
    queries: list[ValidateGraphIntegrityQuery] = field(
        default_factory=list["ValidateGraphIntegrityQuery"]
    )

    async def execute(
        self, query: ValidateGraphIntegrityQuery
    ) -> tuple[GraphIntegrityFinding, ...]:
        self.queries.append(query)
        return self.result


@dataclass(slots=True)
class _Repair:
    result: GraphRepairPlan | None
    commands: list[RepairGraphFindingCommand] = field(
        default_factory=list["RepairGraphFindingCommand"]
    )

    async def execute(self, command: RepairGraphFindingCommand) -> GraphRepairPlan:
        self.commands.append(command)
        if self.result is None:
            message = "secret repair dependency"
            raise GraphUnavailableError(message)
        return self.result
