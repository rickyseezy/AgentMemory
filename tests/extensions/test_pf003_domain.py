"""PF-003 public adapter manifest and negotiation acceptance tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest

from agentmemory.extensions.domain.errors import AdapterValidationError
from agentmemory.extensions.domain.models import (
    AdapterCapability,
    AdapterKind,
    AdapterManifest,
    AdapterPermission,
    AdapterProbeEvidence,
    AdapterRegistration,
    AdapterRegistrationState,
    ProtocolVersion,
    negotiate_protocol,
)

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


def manifest(kind: AdapterKind = AdapterKind.AGENT) -> AdapterManifest:
    """Return one canonical manifest for a public external adapter."""
    capabilities = (
        (AdapterCapability.AGENT_EVENT_CAPTURE, AdapterCapability.AGENT_SESSION_RESUME)
        if kind is AdapterKind.AGENT
        else (AdapterCapability.PROVIDER_EMBED, AdapterCapability.PROVIDER_RERANK)
    )
    permissions = (
        (AdapterPermission.CANONICAL_EVENT_WRITE,)
        if kind is AdapterKind.AGENT
        else (AdapterPermission.PROVIDER_EXECUTE,)
    )
    return AdapterManifest.create(
        schema_version=1,
        adapter_id=f"external-{kind.value}",
        adapter_version="1.2.3",
        kind=kind,
        package_digest=DIGEST_A,
        signature_digest=DIGEST_B,
        signer_identity="agentmemory-community",
        protocol_min=ProtocolVersion(1, 0),
        protocol_max=ProtocolVersion(1, 4),
        capabilities=capabilities,
        requested_permissions=permissions,
    )


def test_pf003_manifest_is_canonical_immutable_and_content_addressed() -> None:
    candidate = manifest()

    assert candidate.capabilities == tuple(sorted(candidate.capabilities, key=str))
    assert candidate.requested_permissions == tuple(
        sorted(candidate.requested_permissions, key=str)
    )
    assert candidate.manifest_digest == (
        "014764e4982b0cd9f1ab33f599d9137c854d06457579a55d87e2ad033a49cbd1"
    )
    assert candidate.manifest_digest == manifest().manifest_digest
    assert replace(candidate, adapter_version="1.2.4").manifest_digest != candidate.manifest_digest


@pytest.mark.parametrize(
    ("change", "field"),
    [
        ({"schema_version": 2}, "schema_version"),
        ({"adapter_id": "Bad Adapter"}, "adapter_id"),
        ({"adapter_version": "latest"}, "adapter_version"),
        ({"package_digest": "A" * 64}, "package_digest"),
        ({"signature_digest": ""}, "signature_digest"),
        ({"signer_identity": "../signer"}, "signer_identity"),
        ({"protocol_min": ProtocolVersion(2, 0)}, "protocol_range"),
        ({"capabilities": ()}, "capabilities"),
        (
            {"capabilities": (AdapterCapability.PROVIDER_EMBED,)},
            "capabilities",
        ),
        (
            {"requested_permissions": (AdapterPermission.PROVIDER_EXECUTE,)},
            "requested_permissions",
        ),
    ],
)
def test_pf003_manifest_rejects_ambiguous_or_cross_kind_authority(
    change: dict[str, object], field: str
) -> None:
    with pytest.raises(AdapterValidationError, match=field):
        replace(manifest(), **cast("Any", change))


def test_pf003_manifest_rejects_duplicate_and_noncanonical_collections() -> None:
    with pytest.raises(AdapterValidationError, match="capabilities"):
        replace(
            manifest(),
            capabilities=(
                AdapterCapability.AGENT_SESSION_RESUME,
                AdapterCapability.AGENT_EVENT_CAPTURE,
            ),
        )
    with pytest.raises(AdapterValidationError, match="requested_permissions"):
        replace(
            manifest(),
            requested_permissions=(
                AdapterPermission.CANONICAL_EVENT_WRITE,
                AdapterPermission.CANONICAL_EVENT_WRITE,
            ),
        )


@pytest.mark.parametrize(
    ("supported", "expected"),
    [
        ((ProtocolVersion(1, 0), ProtocolVersion(1, 3)), ProtocolVersion(1, 3)),
        ((ProtocolVersion(1, 0), ProtocolVersion(1, 4)), ProtocolVersion(1, 4)),
        ((ProtocolVersion(1, 4), ProtocolVersion(2, 0)), ProtocolVersion(1, 4)),
    ],
)
def test_pf003_negotiates_highest_mutually_supported_protocol(
    supported: tuple[ProtocolVersion, ProtocolVersion], expected: ProtocolVersion
) -> None:
    assert negotiate_protocol(manifest(), *supported) == expected


def test_pf003_rejects_unsupported_protocol_before_execution() -> None:
    with pytest.raises(AdapterValidationError, match="unsupported_protocol"):
        negotiate_protocol(manifest(), ProtocolVersion(2, 0), ProtocolVersion(2, 3))


def test_pf003_probe_and_registration_bind_exact_manifest_and_package() -> None:
    candidate = manifest(AdapterKind.PROVIDER)
    evidence = AdapterProbeEvidence.create(
        manifest=candidate,
        negotiated_protocol=ProtocolVersion(1, 4),
        observed_capabilities=candidate.capabilities,
        runtime_digest=DIGEST_C,
        probed_at=NOW,
    )
    registration = AdapterRegistration.create(
        registration_id="018f0000-0000-7000-8000-000000000301",
        brain_id="018f0000-0000-7000-8000-000000000302",
        actor_id="018f0000-0000-7000-8000-000000000303",
        grant_id="018f0000-0000-7000-8000-000000000304",
        manifest=candidate,
        evidence=evidence,
        state=AdapterRegistrationState.ACTIVE,
        registered_at=NOW,
    )

    assert registration.manifest_digest == candidate.manifest_digest
    assert registration.package_digest == candidate.package_digest
    assert registration.evidence.manifest_digest == candidate.manifest_digest
    assert evidence.evidence_digest == (
        "608bdc23e5179ba67043ce521702d0bce344e31d20cf3ffb994f1579f7a664a6"
    )
    assert registration.registration_digest == (
        "d329811bff0d27cc8043f70b1ee7e08658dfa9354f87786921e85ed84f90bbb9"
    )

    with pytest.raises(AdapterValidationError, match=r"evidence_digest|manifest_digest"):
        replace(evidence, manifest_digest=DIGEST_C)
    with pytest.raises(AdapterValidationError, match="observed_capabilities"):
        replace(evidence, observed_capabilities=(AdapterCapability.PROVIDER_EMBED,))
