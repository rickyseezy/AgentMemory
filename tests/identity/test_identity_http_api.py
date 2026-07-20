"""ID-001 path-free authenticated HTTP contract tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import httpx
import pytest
from fastapi import FastAPI

from agentmemory.identity.adapters.inbound.http_api import create_identity_router
from agentmemory.identity.application.queries.discover_repository_topology import (
    DiscoverRepositoryTopologyQuery,
    RepositoryTopologyDiscovery,
)
from agentmemory.identity.domain.checkout import CheckoutAggregate
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityDependencyError,
)
from agentmemory.identity.domain.topology import (
    LinkConfirmation,
    ProjectRepositoryLink,
    RepositoryRelationType,
    RepositoryTopologyCandidate,
    TopologyEndpointType,
    TopologyEvidence,
    TopologyEvidenceKind,
    TopologyEvidenceStrength,
)
from agentmemory.identity.domain.value_objects import (
    DeviceIdentity,
    Fingerprint,
    IdentityCandidate,
    IdentitySource,
    ObservedWorkspaceQuery,
    ProjectManifest,
    ResolutionStatus,
    StableId,
    VcsIdentity,
    WorkspaceResolution,
)
from agentmemory.operations.bootstrap import export_core_openapi_schema

if TYPE_CHECKING:
    from agentmemory.identity.application.commands.confirm_repository_link import (
        ConfirmRepositoryLinkCommand,
    )
    from agentmemory.identity.application.commands.observe_checkout import ObserveCheckoutCommand

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
ACTOR_ID = StableId("018f0000-0000-7000-8000-000000000002")
GRANT_ID = StableId("018f0000-0000-7000-8000-000000000003")
DEVICE_ID = StableId("018f0000-0000-7000-8000-000000000006")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHECKOUT_ID = StableId("018f0000-0000-7000-8000-000000000030")
DIGEST = "a" * 64


@dataclass(slots=True)
class _Authenticator:
    calls: int = 0

    async def authenticate(self, authorization: str | None) -> None:
        self.calls += 1
        if authorization != "Bearer valid":
            raise IdentityAuthorizationError


@dataclass(slots=True)
class _Resolver:
    error: Exception | None = None
    calls: int = 0

    async def execute_observed(
        self,
        query: ObservedWorkspaceQuery,
        device: DeviceIdentity,
        vcs: VcsIdentity | None,
        manifest: ProjectManifest | None,
    ) -> WorkspaceResolution:
        self.calls += 1
        assert query.brain_id == BRAIN_ID
        assert device.device_id == DEVICE_ID
        assert vcs is not None
        assert manifest is None
        if self.error is not None:
            raise self.error
        candidate = IdentityCandidate(PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID)
        return WorkspaceResolution(
            BRAIN_ID,
            ResolutionStatus.RESOLVED,
            IdentitySource.CHECKOUT_REGISTRY,
            candidate,
            (candidate,),
            ("selected:checkout_registry",),
        )


@dataclass(slots=True)
class _Observer:
    calls: int = 0

    async def execute(self, command: ObserveCheckoutCommand) -> CheckoutAggregate:
        self.calls += 1
        aggregate, _ = CheckoutAggregate.create(
            CHECKOUT_ID,
            command.brain_id,
            command.observation(),
        )
        return aggregate


def _topology_candidate() -> RepositoryTopologyCandidate:
    return RepositoryTopologyCandidate(
        BRAIN_ID,
        TopologyEndpointType.REPOSITORY,
        REPOSITORY_ID,
        RepositoryRelationType.CONTAINS_REPOSITORY,
        TopologyEndpointType.REPOSITORY,
        StableId("018f0000-0000-7000-8000-000000000021"),
        None,
        (
            TopologyEvidence(
                Fingerprint("6" * 64),
                TopologyEvidenceKind.NESTED_GIT_MARKER,
                TopologyEvidenceStrength.DETERMINISTIC_VCS,
            ),
        ),
    )


@dataclass(slots=True)
class _TopologyDiscovery:
    calls: int = 0

    async def execute(
        self,
        query: DiscoverRepositoryTopologyQuery,
    ) -> RepositoryTopologyDiscovery:
        self.calls += 1
        assert query.brain_id == BRAIN_ID
        return RepositoryTopologyDiscovery(
            query.brain_id,
            query.observations,
            ("candidate:contains_repository",),
        )


@dataclass(slots=True)
class _LinkConfirmer:
    calls: int = 0

    async def execute(self, command: ConfirmRepositoryLinkCommand) -> ProjectRepositoryLink:
        self.calls += 1
        aggregate, _ = ProjectRepositoryLink.confirm(
            StableId("018f0000-0000-7000-8000-000000000040"),
            command.candidate,
            LinkConfirmation(
                command.operation_id,
                command.actor_id,
                command.grant_id,
                command.confirmation_source,
                123,
            ),
        )
        return aggregate


def _body() -> dict[str, object]:
    return {
        "operation_id": "resolve-1",
        "brain_id": BRAIN_ID.value,
        "actor_id": ACTOR_ID.value,
        "grant_id": GRANT_ID.value,
        "device": {
            "device_id": DEVICE_ID.value,
            "device_fingerprint": DIGEST,
            "volume_fingerprint": "b" * 64,
            "path_fingerprint": "c" * 64,
            "verified": True,
        },
        "vcs": {
            "vcs_type": "git",
            "repository_fingerprint": "d" * 64,
            "checkout_fingerprint": "e" * 64,
            "worktree_fingerprint": "f" * 64,
            "repository_lookup_approved": True,
        },
    }


def _observe_body() -> dict[str, object]:
    body = _body()
    body["operation_id"] = "observe-1"
    body["repository_id"] = REPOSITORY_ID.value
    device = cast("dict[str, object]", body["device"])
    device["logical_path_fingerprint"] = "1" * 64
    device["file_fingerprint"] = "2" * 64
    vcs = cast("dict[str, object]", body["vcs"])
    vcs["common_directory_fingerprint"] = "3" * 64
    vcs["branch"] = "main"
    vcs["head_commit"] = "a" * 40
    vcs["remote_fingerprints"] = ["4" * 64]
    vcs["dirty_digest"] = "5" * 64
    return body


def _topology_body(operation_id: str = "discover-topology-1") -> dict[str, object]:
    candidate = _topology_candidate()
    return {
        "operation_id": operation_id,
        "brain_id": BRAIN_ID.value,
        "actor_id": ACTOR_ID.value,
        "grant_id": GRANT_ID.value,
        "observations": [
            {
                "subject_type": candidate.subject_type.value,
                "subject_id": candidate.subject_id.value,
                "relation_type": candidate.relation_type.value,
                "target_type": candidate.target_type.value,
                "target_id": candidate.target_id.value,
                "component_root_fingerprint": None,
                "evidence": [
                    {
                        "digest": candidate.evidence[0].digest.value,
                        "kind": candidate.evidence[0].kind.value,
                        "strength": candidate.evidence[0].strength.value,
                    }
                ],
            }
        ],
    }


def _app(authenticator: _Authenticator, resolver: _Resolver) -> FastAPI:
    application = FastAPI()
    application.include_router(create_identity_router(authenticator, resolver))
    return application


@pytest.mark.asyncio
async def test_resolve_contract_returns_only_authorized_identity_and_explanation() -> None:
    authenticator = _Authenticator()
    resolver = _Resolver()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(authenticator, resolver)),
        base_url="http://127.0.0.1",
    ) as client:
        response = await client.post(
            "/v1/projects:resolve",
            headers={"Authorization": "Bearer valid"},
            json=_body(),
        )
    assert response.status_code == 200
    assert response.json() == {
        "brain_id": BRAIN_ID.value,
        "status": "resolved",
        "source": "checkout_registry",
        "selected": {
            "project_id": PROJECT_ID.value,
            "repository_id": REPOSITORY_ID.value,
            "checkout_id": CHECKOUT_ID.value,
        },
        "candidates": [
            {
                "project_id": PROJECT_ID.value,
                "repository_id": REPOSITORY_ID.value,
                "checkout_id": CHECKOUT_ID.value,
            }
        ],
        "explanation": ["selected:checkout_registry"],
    }
    assert "fingerprint" not in response.text
    assert "path" not in response.text
    assert authenticator.calls == 1
    assert resolver.calls == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "status_code", "code", "retryable"),
    [
        (IdentityAuthorizationError(), 403, "AM_FORBIDDEN", False),
        (IdentityConflictError(), 409, "AM_CONFLICT", False),
        (IdentityDependencyError(), 503, "AM_DEPENDENCY_UNAVAILABLE", True),
    ],
)
async def test_identity_failures_map_to_content_free_canonical_problems(
    error: Exception,
    status_code: int,
    code: str,
    retryable: bool,  # noqa: FBT001 -- Pytest supplies the closed boolean expectation.
) -> None:
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Authenticator(), _Resolver(error))),
        base_url="http://127.0.0.1",
    ) as client:
        response = await client.post(
            "/v1/projects:resolve",
            headers={"Authorization": "Bearer valid"},
            json=_body(),
        )
    assert response.status_code == status_code
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.json()["code"] == code
    assert response.json()["retryable"] is retryable
    assert response.json()["correlation_id"] == "resolve-1"
    assert repr(error) not in response.text


@pytest.mark.asyncio
async def test_malformed_fingerprint_fails_before_repository_access() -> None:
    resolver = _Resolver()
    body = _body()
    device = body["device"]
    assert isinstance(device, dict)
    device["path_fingerprint"] = "raw/path"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=_app(_Authenticator(), resolver)),
        base_url="http://127.0.0.1",
    ) as client:
        response = await client.post(
            "/v1/projects:resolve",
            headers={"Authorization": "Bearer valid"},
            json=body,
        )
    assert response.status_code == 422
    assert response.json()["code"] == "AM_VALIDATION"
    assert resolver.calls == 0


@pytest.mark.asyncio
async def test_observe_checkout_contract_is_authenticated_path_free_and_content_free() -> None:
    observer = _Observer()
    application = FastAPI()
    application.include_router(create_identity_router(_Authenticator(), _Resolver(), observer))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://127.0.0.1",
    ) as client:
        response = await client.post(
            "/v1/checkouts:observe",
            headers={"Authorization": "Bearer valid"},
            json=_observe_body(),
        )
    assert response.status_code == 200
    assert response.json() == {
        "brain_id": BRAIN_ID.value,
        "repository_id": REPOSITORY_ID.value,
        "checkout_id": CHECKOUT_ID.value,
        "version": 1,
    }
    assert "fingerprint" not in response.text
    assert "branch" not in response.text
    assert observer.calls == 1


@pytest.mark.asyncio
async def test_topology_discovery_and_confirmation_are_path_free_and_idempotent() -> None:
    discovery = _TopologyDiscovery()
    confirmer = _LinkConfirmer()
    application = FastAPI()
    application.include_router(
        create_identity_router(
            _Authenticator(),
            _Resolver(),
            _Observer(),
            discovery,
            confirmer,
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=application),
        base_url="http://127.0.0.1",
    ) as client:
        discovery_response = await client.post(
            "/v1/repositories:discover-topology",
            headers={"Authorization": "Bearer valid"},
            json=_topology_body(),
        )
        confirmation_body = _topology_body("confirm-topology-1")
        observations = confirmation_body.pop("observations")
        assert isinstance(observations, list)
        confirmation_body["candidate"] = observations[0]
        confirmation_body["confirmation_source"] = "deterministic_vcs"
        confirmation_response = await client.post(
            "/v1/repository-links:confirm",
            headers={
                "Authorization": "Bearer valid",
                "Idempotency-Key": "confirm-topology-1",
            },
            json=confirmation_body,
        )
        missing_key_response = await client.post(
            "/v1/repository-links:confirm",
            headers={"Authorization": "Bearer valid"},
            json=confirmation_body,
        )
    assert discovery_response.status_code == 200
    assert discovery_response.json()["explanation"] == ["candidate:contains_repository"]
    assert "path" not in discovery_response.text
    assert "remote" not in discovery_response.text
    assert confirmation_response.status_code == 200
    assert confirmation_response.json()["version"] == 1
    assert confirmation_response.json()["subject_id"] == REPOSITORY_ID.value
    assert missing_key_response.status_code == 422
    assert discovery.calls == 1
    assert confirmer.calls == 1


def test_complete_openapi_publishes_normative_identity_operation() -> None:
    schema = export_core_openapi_schema()
    paths = cast("dict[str, object]", schema["paths"])
    route = cast("dict[str, object]", paths["/v1/projects:resolve"])
    operation = cast("dict[str, object]", route["post"])
    assert operation["operationId"] == "ResolveWorkspaceQuery"
    assert operation["security"] == [{"AgentMemoryBearer": []}]
    observe_route = cast("dict[str, object]", paths["/v1/checkouts:observe"])
    observe = cast("dict[str, object]", observe_route["post"])
    assert observe["operationId"] == "ObserveCheckoutCommand"
    assert observe["security"] == [{"AgentMemoryBearer": []}]
    topology_route = cast(
        "dict[str, object]",
        paths["/v1/repositories:discover-topology"],
    )
    topology = cast("dict[str, object]", topology_route["post"])
    assert topology["operationId"] == "DiscoverRepositoryTopologyQuery"
    assert topology["security"] == [{"AgentMemoryBearer": []}]
    confirmation_route = cast("dict[str, object]", paths["/v1/repository-links:confirm"])
    confirmation = cast("dict[str, object]", confirmation_route["post"])
    assert confirmation["operationId"] == "ConfirmRepositoryLinkCommand"
    assert confirmation["security"] == [{"AgentMemoryBearer": []}]
