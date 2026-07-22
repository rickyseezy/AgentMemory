"""PF-003 signed-package admission and live capability-probe tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

import pytest

from agentmemory.extensions.adapters.policies import (
    ClosedAdapterPermissionPolicy,
    DigestBoundAdapterPackageTrust,
)
from agentmemory.extensions.adapters.probe import StrictAdapterCapabilityProbe
from agentmemory.extensions.domain.errors import (
    AdapterAuthorizationError,
    AdapterProbeError,
    AdapterTrustError,
)
from agentmemory.extensions.domain.models import (
    AdapterCapability,
    AdapterKind,
    AdapterManifest,
    AdapterPermission,
    ProtocolVersion,
)
from agentmemory.extensions.domain.ports import AdapterProbeTransportResponse

NOW = datetime(2026, 7, 22, 14, 0, tzinfo=UTC)


def _manifest(kind: AdapterKind = AdapterKind.AGENT) -> AdapterManifest:
    return AdapterManifest.create(
        schema_version=1,
        adapter_id=f"external-{kind.value}",
        adapter_version="1.0.0",
        kind=kind,
        package_digest="a" * 64,
        signature_digest="b" * 64,
        signer_identity="approved-publisher",
        protocol_min=ProtocolVersion(1, 0),
        protocol_max=ProtocolVersion(1, 2),
        capabilities=(
            (AdapterCapability.AGENT_EVENT_CAPTURE,)
            if kind is AdapterKind.AGENT
            else (AdapterCapability.PROVIDER_EMBED,)
        ),
        requested_permissions=(
            (AdapterPermission.CANONICAL_EVENT_WRITE,)
            if kind is AdapterKind.AGENT
            else (AdapterPermission.PROVIDER_EXECUTE,)
        ),
    )


@pytest.mark.asyncio
async def test_pf003_trust_binds_exact_digest_signature_and_publisher() -> None:
    verifier = _SignatureVerifier()
    trust = DigestBoundAdapterPackageTrust(verifier, frozenset({"approved-publisher"}))
    candidate = _manifest()

    await trust.verify(candidate)

    assert verifier.calls == [
        (candidate.package_digest, candidate.signature_digest, candidate.signer_identity)
    ]


@pytest.mark.asyncio
async def test_pf003_trust_rejects_publisher_and_signature_failure() -> None:
    verifier = _SignatureVerifier()
    trust = DigestBoundAdapterPackageTrust(verifier, frozenset({"different-publisher"}))
    with pytest.raises(AdapterTrustError, match="publisher"):
        await trust.verify(_manifest())
    assert verifier.calls == []

    verifier.failure = True
    trust = DigestBoundAdapterPackageTrust(verifier, frozenset({"approved-publisher"}))
    with pytest.raises(AdapterTrustError, match="signature"):
        await trust.verify(_manifest())


@pytest.mark.asyncio
async def test_pf003_permission_policy_is_kind_specific_and_default_minimal() -> None:
    policy = ClosedAdapterPermissionPolicy.default()
    await policy.approve(_manifest(AdapterKind.AGENT))
    await policy.approve(_manifest(AdapterKind.PROVIDER))

    expanded = replace(
        _manifest(),
        requested_permissions=tuple(
            sorted(
                (
                    AdapterPermission.CANONICAL_EVENT_WRITE,
                    AdapterPermission.TRANSCRIPT_READ,
                ),
                key=str,
            )
        ),
    )
    with pytest.raises(AdapterAuthorizationError, match="permission"):
        await policy.approve(expanded)

    approved = ClosedAdapterPermissionPolicy(
        agent=frozenset(
            {
                AdapterPermission.CANONICAL_EVENT_WRITE,
                AdapterPermission.TRANSCRIPT_READ,
            }
        ),
        provider=frozenset({AdapterPermission.PROVIDER_EXECUTE}),
    )
    await approved.approve(expanded)


@pytest.mark.asyncio
async def test_pf003_live_probe_binds_challenge_protocol_package_and_capabilities() -> None:
    candidate = _manifest()
    transport = _ProbeTransport(candidate)
    probe = StrictAdapterCapabilityProbe(
        transport=transport,
        challenges=_Challenge(),
        clock=_Clock(),
        timeout_milliseconds=2_000,
        max_response_bytes=64 * 1024,
    )

    evidence = await probe.probe(candidate, ProtocolVersion(1, 2))

    assert evidence.binds(candidate)
    assert evidence.negotiated_protocol == ProtocolVersion(1, 2)
    assert evidence.runtime_digest == candidate.package_digest
    assert transport.requests == [
        (
            '{"capabilities":["agent.event.capture"],"challenge":"challenge-1",'
            f'"kind":"agent","manifest_digest":"{candidate.manifest_digest}",'
            f'"package_digest":"{candidate.package_digest}","protocol":"1.2",'
            '"schema_version":1}'
        ).encode()
    ]
    request = json.loads(transport.requests[0])
    assert request["challenge"] == "challenge-1"
    assert request["manifest_digest"] == candidate.manifest_digest
    assert transport.timeout == 2_000
    assert transport.maximum == 64 * 1024


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "challenge",
        "manifest_digest",
        "package_digest",
        "protocol",
        "capabilities",
        "status",
        "unknown",
        "duplicate",
        "oversized",
        "runtime_digest",
    ],
)
async def test_pf003_live_probe_rejects_substitution_and_malformed_responses(
    mutation: str,
) -> None:
    candidate = _manifest()
    transport = _ProbeTransport(candidate, mutation=mutation)
    probe = StrictAdapterCapabilityProbe(
        transport=transport,
        challenges=_Challenge(),
        clock=_Clock(),
        timeout_milliseconds=2_000,
        max_response_bytes=256,
    )

    with pytest.raises(AdapterProbeError):
        await probe.probe(candidate, ProtocolVersion(1, 2))


@dataclass
class _SignatureVerifier:
    calls: list[tuple[str, str, str]] = field(default_factory=list[tuple[str, str, str]])
    failure: bool = False

    async def verify(
        self,
        package_digest: str,
        signature_digest: str,
        signer_identity: str,
    ) -> None:
        self.calls.append((package_digest, signature_digest, signer_identity))
        if self.failure:
            message = "bad signature"
            raise ValueError(message)


@dataclass
class _Challenge:
    def new(self) -> str:
        return "challenge-1"


@dataclass
class _Clock:
    def now(self) -> datetime:
        return NOW


@dataclass
class _ProbeTransport:
    manifest: AdapterManifest
    mutation: str | None = None
    requests: list[bytes] = field(default_factory=list[bytes])
    timeout: int = 0
    maximum: int = 0

    async def exchange(
        self,
        manifest: AdapterManifest,
        request: bytes,
        timeout_milliseconds: int,
        max_response_bytes: int,
    ) -> AdapterProbeTransportResponse:
        self.requests.append(request)
        self.timeout = timeout_milliseconds
        self.maximum = max_response_bytes
        request_document = json.loads(request)
        document: dict[str, object] = {
            "capabilities": [item.value for item in manifest.capabilities],
            "challenge": request_document["challenge"],
            "manifest_digest": manifest.manifest_digest,
            "package_digest": manifest.package_digest,
            "protocol": request_document["protocol"],
            "schema_version": 1,
            "status": "passed",
        }
        runtime_digest = manifest.package_digest
        if self.mutation == "duplicate":
            body = b'{"status":"passed","status":"passed"}'
        elif self.mutation == "oversized":
            body = b"{" + b" " * (max_response_bytes + 1) + b"}"
        else:
            if self.mutation == "capabilities":
                document["capabilities"] = []
            elif self.mutation == "unknown":
                document["unknown"] = True
            elif self.mutation == "runtime_digest":
                runtime_digest = "d" * 64
            elif self.mutation is not None:
                document[self.mutation] = "substituted"
            body = json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
        return AdapterProbeTransportResponse(body=body, runtime_digest=runtime_digest)
