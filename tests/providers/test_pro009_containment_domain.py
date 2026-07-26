"""PRO-009 provider-egress and adapter-sandbox domain invariants."""

from __future__ import annotations

from dataclasses import replace

import pytest

from agentmemory.identity.domain.retrieval_scope import Classification
from agentmemory.providers.domain.containment import (
    AdapterOperationSandbox,
    ContentTaint,
    EgressDestination,
    ProviderEgressBatch,
    ProviderEgressPolicy,
    ProviderEgressRequest,
    ProviderEgressRoute,
    _invalid,  # pyright: ignore[reportPrivateUsage]
    provider_egress_request_digest,
)
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentValidationError,
)
from tests.core.support import digest

BRAIN_ID = "018f0000-0000-7000-8000-000000000001"
PROJECT_ID = "018f0000-0000-7000-8000-000000000002"
PROFILE_ID = "018f0000-0000-7000-8000-000000000901"
POLICY_ID = "018f0000-0000-7000-8000-000000000902"
ATTESTATION_ID = "018f0000-0000-7000-8000-000000000903"
PROFILE_ATTESTATION_ID = digest("profile-attestation").value


def test_containment_invalid_helper_raises_only_the_closed_validation_error() -> None:
    with pytest.raises(
        ProviderContainmentValidationError,
        match=r"^provider containment input is invalid$",
    ):
        _invalid()


def destination(**changes: object) -> EgressDestination:
    values: dict[str, object] = {
        "scheme": "https",
        "hostname": "api.openai.com",
        "port": 443,
        "region": "US",
        "path_prefix": "/v1/embeddings",
    }
    values.update(changes)
    return EgressDestination(**values)  # type: ignore[arg-type]


def policy(**changes: object) -> ProviderEgressPolicy:
    values: dict[str, object] = {
        "policy_id": POLICY_ID,
        "brain_id": BRAIN_ID,
        "version": 1,
        "security_epoch": 7,
        "classification_ceiling": Classification.CONFIDENTIAL,
        "allowed_destinations": (destination(),),
        "allowed_profile_ids": (PROFILE_ID,),
        "allowed_purposes": ("retrieval_document",),
        "allowed_operation_types": ("embedding",),
        "allowed_routes": (
            ProviderEgressRoute(
                profile_id=PROFILE_ID,
                profile_version=3,
                profile_attestation_id=PROFILE_ATTESTATION_ID,
                model_revision="text-embedding-3-small-2026-07-01",
                operation_type="embedding",
                purpose="retrieval_document",
                destination=destination(),
            ),
        ),
        "maximum_retention_days": 30,
        "training_allowed": False,
        "maximum_request_bytes": 1_000_000,
        "maximum_response_bytes": 2_000_000,
        "maximum_timeout_milliseconds": 30_000,
        "maximum_requests_per_minute": 120,
        "maximum_tokens_per_minute": 100_000,
        "maximum_monthly_cost_micros": 50_000_000,
        "attestation_id": ATTESTATION_ID,
        "attestation_digest": digest("attestation").value,
        "valid_from_microseconds": 1_000,
        "valid_until_microseconds": 10_000,
    }
    values.update(changes)
    return ProviderEgressPolicy(**values)  # type: ignore[arg-type]


def request(**changes: object) -> ProviderEgressRequest:
    values: dict[str, object] = {
        "operation_id": "provider-operation-pro009",
        "brain_id": BRAIN_ID,
        "project_id": PROJECT_ID,
        "profile_id": PROFILE_ID,
        "profile_version": 3,
        "profile_attestation_id": PROFILE_ATTESTATION_ID,
        "model_revision": "text-embedding-3-small-2026-07-01",
        "purpose": "retrieval_document",
        "operation_type": "embedding",
        "destination": destination(),
        "taint": ContentTaint(
            classification=Classification.CONFIDENTIAL,
            private_block=False,
            secret_bearing=False,
        ),
        "retention_days": 0,
        "training_allowed": False,
        "policy_version": 1,
        "security_epoch": 7,
        "quota_requests_per_minute": 100,
        "quota_tokens_per_minute": 50_000,
        "budget_monthly_micros": 20_000_000,
        "request_bytes": 1024,
        "maximum_response_bytes": 4096,
        "timeout_milliseconds": 5_000,
        "content_digests": (digest("one").value, digest("two").value),
        "wire_request_digest": digest("wire-request").value,
        "token_count": 200,
        "estimated_cost_micros": 250,
    }
    values.update(changes)
    return ProviderEgressRequest(**values)  # type: ignore[arg-type]


def test_policy_authorizes_only_the_exact_attested_operation() -> None:
    permit = policy().authorize(request(), now_microseconds=2_000)

    assert permit.request_digest == provider_egress_request_digest(request())
    assert permit.policy_id == POLICY_ID
    assert permit.policy_version == 1
    assert permit.destination == destination()
    assert permit.content_digests == (digest("one").value, digest("two").value)
    assert permit.expires_at_microseconds == 10_000
    assert permit.document == {
        "attestation_digest": digest("attestation").value,
        "attestation_id": ATTESTATION_ID,
        "brain_id": BRAIN_ID,
        "budget_monthly_micros": 20_000_000,
        "content_digests": [digest("one").value, digest("two").value],
        "destination": destination().document,
        "estimated_cost_micros": 250,
        "expires_at_microseconds": 10000,
        "issued_at_microseconds": 2000,
        "maximum_request_bytes": 1000000,
        "maximum_response_bytes": 4096,
        "model_revision": "text-embedding-3-small-2026-07-01",
        "operation_id": "provider-operation-pro009",
        "operation_type": "embedding",
        "policy_id": POLICY_ID,
        "policy_version": 1,
        "profile_id": PROFILE_ID,
        "profile_version": 3,
        "profile_attestation_id": PROFILE_ATTESTATION_ID,
        "purpose": "retrieval_document",
        "quota_requests_per_minute": 100,
        "quota_tokens_per_minute": 50000,
        "request_digest": provider_egress_request_digest(request()),
        "security_epoch": 7,
        "timeout_milliseconds": 5000,
        "token_count": 200,
        "wire_request_digest": digest("wire-request").value,
    }


@pytest.mark.parametrize(
    "taint",
    [
        ContentTaint(
            classification=Classification.RESTRICTED,
            private_block=False,
            secret_bearing=False,
        ),
        ContentTaint(
            classification=Classification.LOCAL_ONLY,
            private_block=False,
            secret_bearing=False,
        ),
        ContentTaint(
            classification=Classification.PUBLIC,
            private_block=True,
            secret_bearing=False,
        ),
        ContentTaint(
            classification=Classification.PUBLIC,
            private_block=False,
            secret_bearing=True,
        ),
    ],
)
def test_intrinsically_unsafe_content_is_unconditionally_denied(
    taint: ContentTaint,
) -> None:
    with pytest.raises(ProviderContainmentDeniedError, match="denied"):
        policy(classification_ceiling=Classification.LOCAL_ONLY).authorize(
            request(taint=taint),
            now_microseconds=2_000,
        )


@pytest.mark.parametrize(
    "changed",
    [
        {"brain_id": PROJECT_ID},
        {"profile_id": PROJECT_ID},
        {"purpose": "code_document"},
        {"operation_type": "reranking"},
        {"destination": destination(hostname="evil.example")},
        {"destination": destination(region="EU")},
        {"retention_days": 31},
        {"training_allowed": True},
        {"policy_version": 2},
        {"security_epoch": 8},
        {"quota_requests_per_minute": 121},
        {"quota_tokens_per_minute": 100_001},
        {"budget_monthly_micros": 50_000_001},
        {"estimated_cost_micros": 20_000_001},
        {"request_bytes": 1_000_001},
        {"maximum_response_bytes": 2_000_001},
        {"timeout_milliseconds": 30_001},
    ],
)
def test_every_policy_coordinate_fails_closed_independently(
    changed: dict[str, object],
) -> None:
    with pytest.raises(ProviderContainmentDeniedError, match="denied"):
        policy().authorize(request(**changed), now_microseconds=2_000)


def test_policy_time_window_is_closed_and_non_bypassable() -> None:
    for now in (999, 10_000):
        with pytest.raises(ProviderContainmentDeniedError, match="denied"):
            policy().authorize(request(), now_microseconds=now)
    policy().authorize(request(), now_microseconds=1_000)
    policy().authorize(request(), now_microseconds=9_999)


def test_policy_denies_profile_destination_cross_product_not_bound_as_exact_route() -> None:
    second_profile = "018f0000-0000-7000-8000-000000000904"
    second_destination = destination(hostname="api.cohere.com")
    first_route = policy().allowed_routes[0]
    second_route = ProviderEgressRoute(
        profile_id=second_profile,
        profile_version=3,
        profile_attestation_id=digest("second-profile-attestation").value,
        model_revision="text-embedding-3-small-2026-07-01",
        operation_type="embedding",
        purpose="retrieval_document",
        destination=second_destination,
    )
    route_policy = policy(
        allowed_destinations=tuple(
            sorted(
                (destination(), second_destination),
                key=lambda value: value.fingerprint,
            )
        ),
        allowed_profile_ids=(PROFILE_ID, second_profile),
        allowed_routes=tuple(sorted((first_route, second_route), key=lambda value: value.digest)),
    )

    with pytest.raises(ProviderContainmentDeniedError, match="denied"):
        route_policy.authorize(
            request(destination=second_destination),
            now_microseconds=2_000,
        )


def test_batch_rejects_mixed_privacy_or_provider_coordinates() -> None:
    allowed = request(content_digests=(digest("one").value,))
    ProviderEgressBatch((allowed, replace(allowed, content_digests=(digest("two").value,))))

    for mixed in (
        replace(allowed, brain_id=PROJECT_ID),
        replace(allowed, profile_version=4),
        replace(allowed, purpose="code_document"),
        replace(allowed, destination=destination(hostname="evil.example")),
        replace(
            allowed,
            taint=ContentTaint(
                classification=Classification.RESTRICTED,
                private_block=False,
                secret_bearing=False,
            ),
        ),
    ):
        with pytest.raises(ValueError, match="homogeneous"):
            ProviderEgressBatch((allowed, mixed))


def test_request_digest_is_canonical_complete_and_content_free() -> None:
    first = request()
    assert provider_egress_request_digest(first) == (
        "1b6dc9cf3deeed32244941953bde5644706386e84dc70e72ef1f08ad4d2694a4"
    )
    assert provider_egress_request_digest(first) != provider_egress_request_digest(
        replace(first, token_count=201)
    )


def test_operation_sandbox_is_closed_and_has_no_credential_or_host_authority() -> None:
    sandbox = AdapterOperationSandbox.production(
        operation_id="provider-operation-pro009",
        image="registry.example/adapter@sha256:" + digest("image").value,
        internal_network="agentmemory_0123456789abcdef0123456789abcdef_internal",
        input_source="/run/agentmemory/operations/pro009/input",
        output_source="/run/agentmemory/operations/pro009/output",
        timeout_seconds=30,
    )

    assert sandbox.read_only_rootfs is True
    assert sandbox.user == "10001:10001"
    assert sandbox.cap_drop == ("ALL",)
    assert sandbox.security_options == ("no-new-privileges:true",)
    assert sandbox.networks == ("agentmemory_0123456789abcdef0123456789abcdef_internal",)
    assert sandbox.tmpfs == (("/tmp", 64 * 1024 * 1024, 0o1777),)  # noqa: S108
    assert sandbox.environment == ()
    assert sandbox.secret_mounts == ()
    assert sandbox.publish_ports == ()
    assert sandbox.docker_socket is False
    assert sandbox.privileged is False
    assert sandbox.auto_remove is True
    assert sandbox.pids_limit == 128
    assert sandbox.memory_bytes == 1024 * 1024 * 1024
    assert sandbox.nano_cpus == 1_000_000_000


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("image", "adapter:latest"),
        ("internal_network", "bridge"),
        ("input_source", "/home/user/project"),
        ("output_source", "/var/lib/agentmemory/state"),
        ("timeout_seconds", 0),
    ],
)
def test_operation_sandbox_rejects_unpinned_or_ambient_resources(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "operation_id": "provider-operation-pro009",
        "image": "registry.example/adapter@sha256:" + digest("image").value,
        "internal_network": "agentmemory_0123456789abcdef0123456789abcdef_internal",
        "input_source": "/run/agentmemory/operations/pro009/input",
        "output_source": "/run/agentmemory/operations/pro009/output",
        "timeout_seconds": 30,
    }
    values[field] = value
    with pytest.raises(ValueError, match="sandbox"):
        AdapterOperationSandbox.production(**values)  # type: ignore[arg-type]
