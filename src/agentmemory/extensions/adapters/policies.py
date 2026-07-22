"""PF-003 digest-bound package trust and closed least-authority policy adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.extensions.domain.errors import (
    AdapterAuthorizationError,
    AdapterTrustError,
    AdapterValidationError,
)
from agentmemory.extensions.domain.models import AdapterKind, AdapterPermission

if TYPE_CHECKING:
    from agentmemory.extensions.domain.models import AdapterManifest
    from agentmemory.extensions.domain.ports import AdapterPackageSignatureVerifier

_ERR_PUBLISHERS = "approved adapter publisher policy is empty"
_ERR_PUBLISHER = "adapter publisher is not approved"
_ERR_SIGNATURE = "adapter package signature is invalid"
_ERR_PERMISSION = "adapter permission request is not approved"


@dataclass(frozen=True, slots=True)
class DigestBoundAdapterPackageTrust:
    """Verify exact package signature evidence against an explicit publisher allowlist."""

    verifier: AdapterPackageSignatureVerifier
    approved_publishers: frozenset[str]

    def __post_init__(self) -> None:
        """Refuse an accidentally trust-all empty authority set."""
        if not self.approved_publishers:
            raise AdapterValidationError(_ERR_PUBLISHERS)

    async def verify(self, manifest: AdapterManifest) -> None:
        """Reject publisher substitution before invoking cryptographic verification."""
        if manifest.signer_identity not in self.approved_publishers:
            raise AdapterTrustError(_ERR_PUBLISHER)
        try:
            await self.verifier.verify(
                manifest.package_digest,
                manifest.signature_digest,
                manifest.signer_identity,
            )
        except Exception as error:
            raise AdapterTrustError(_ERR_SIGNATURE) from error


@dataclass(frozen=True, slots=True)
class ClosedAdapterPermissionPolicy:
    """Approve only explicit kind-specific authority ceilings."""

    agent: frozenset[AdapterPermission]
    provider: frozenset[AdapterPermission]

    @classmethod
    def default(cls) -> ClosedAdapterPermissionPolicy:
        """Return the minimal useful offline authority for each adapter kind."""
        return cls(
            agent=frozenset({AdapterPermission.CANONICAL_EVENT_WRITE}),
            provider=frozenset({AdapterPermission.PROVIDER_EXECUTE}),
        )

    def __post_init__(self) -> None:
        """Require explicit non-empty policy for both extension kinds."""
        if not self.agent or not self.provider:
            raise AdapterValidationError(_ERR_PERMISSION)

    async def approve(self, manifest: AdapterManifest) -> None:
        """Reject any requested authority outside the configured kind ceiling."""
        allowed = self.agent if manifest.kind is AdapterKind.AGENT else self.provider
        if not set(manifest.requested_permissions) <= allowed:
            raise AdapterAuthorizationError(_ERR_PERMISSION)
