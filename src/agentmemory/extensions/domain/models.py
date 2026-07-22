"""PF-003 immutable public adapter contracts and protocol negotiation."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import override
from uuid import UUID

from agentmemory.extensions.domain.errors import AdapterValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_SEMVER = re.compile(
    r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
_UUID7 = 7
_MAX_PROTOCOL_COMPONENT = 65535


class AdapterKind(StrEnum):
    """Closed runtime boundary selected without vendor identity."""

    AGENT = "agent"
    PROVIDER = "provider"


class AdapterCapability(StrEnum):
    """Version-one capabilities admitted by the public extension contract."""

    AGENT_EVENT_CAPTURE = "agent.event.capture"
    AGENT_SESSION_RESUME = "agent.session.resume"
    AGENT_EXPLICIT_CHECKPOINT = "agent.checkpoint.explicit"
    PROVIDER_EMBED = "provider.embed"
    PROVIDER_RERANK = "provider.rerank"
    PROVIDER_EXTRACT = "provider.extract"


class AdapterPermission(StrEnum):
    """Least-authority permissions a package may request."""

    CANONICAL_EVENT_WRITE = "canonical_event.write"
    WORKSPACE_METADATA_READ = "workspace.metadata.read"
    TRANSCRIPT_READ = "transcript.read"
    PROVIDER_EXECUTE = "provider.execute"
    PROVIDER_GATEWAY = "provider.gateway"


class AdapterRegistrationState(StrEnum):
    """Closed governed registry state."""

    ACTIVE = "active"
    DISABLED = "disabled"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class AdapterAuthorizationRequest:
    """Exact actor/grant/Brain authority evaluated before registry candidate access."""

    brain_id: str
    actor_id: str
    grant_id: str
    requested_at: datetime

    def __post_init__(self) -> None:
        """Require canonical scope identities and UTC policy time."""
        for value, field in (
            (self.brain_id, "brain_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
        ):
            _require_uuid7(value, field)
        _require_utc(self.requested_at, "requested_at")


_CAPABILITIES_BY_KIND = {
    AdapterKind.AGENT: frozenset(
        {
            AdapterCapability.AGENT_EVENT_CAPTURE,
            AdapterCapability.AGENT_SESSION_RESUME,
            AdapterCapability.AGENT_EXPLICIT_CHECKPOINT,
        }
    ),
    AdapterKind.PROVIDER: frozenset(
        {
            AdapterCapability.PROVIDER_EMBED,
            AdapterCapability.PROVIDER_RERANK,
            AdapterCapability.PROVIDER_EXTRACT,
        }
    ),
}
_PERMISSIONS_BY_KIND = {
    AdapterKind.AGENT: frozenset(
        {
            AdapterPermission.CANONICAL_EVENT_WRITE,
            AdapterPermission.WORKSPACE_METADATA_READ,
            AdapterPermission.TRANSCRIPT_READ,
        }
    ),
    AdapterKind.PROVIDER: frozenset(
        {
            AdapterPermission.PROVIDER_EXECUTE,
            AdapterPermission.PROVIDER_GATEWAY,
        }
    ),
}
_REQUIRED_CAPABILITY = {
    AdapterKind.AGENT: AdapterCapability.AGENT_EVENT_CAPTURE,
    AdapterKind.PROVIDER: AdapterCapability.PROVIDER_EMBED,
}


@dataclass(frozen=True, slots=True, order=True)
class ProtocolVersion:
    """One bounded public adapter protocol version."""

    major: int
    minor: int

    def __post_init__(self) -> None:
        """Reject booleans, negatives, and allocation-amplifying components."""
        if (
            isinstance(self.major, bool)
            or isinstance(self.minor, bool)
            or not 1 <= self.major <= _MAX_PROTOCOL_COMPONENT
            or not 0 <= self.minor <= _MAX_PROTOCOL_COMPONENT
        ):
            message = "protocol_version is invalid"
            raise AdapterValidationError(message)

    @override
    def __str__(self) -> str:
        """Return the canonical major.minor representation."""
        return f"{self.major}.{self.minor}"


@dataclass(frozen=True, slots=True)
class AdapterManifest:
    """Canonical signed-package declaration shared by agent and provider SDKs."""

    schema_version: int
    adapter_id: str
    adapter_version: str
    kind: AdapterKind
    package_digest: str
    signature_digest: str
    signer_identity: str
    protocol_min: ProtocolVersion
    protocol_max: ProtocolVersion
    capabilities: tuple[AdapterCapability, ...]
    requested_permissions: tuple[AdapterPermission, ...]

    @classmethod
    def create(  # noqa: PLR0913 -- public signed identity is intentionally explicit.
        cls,
        *,
        schema_version: int,
        adapter_id: str,
        adapter_version: str,
        kind: AdapterKind,
        package_digest: str,
        signature_digest: str,
        signer_identity: str,
        protocol_min: ProtocolVersion,
        protocol_max: ProtocolVersion,
        capabilities: tuple[AdapterCapability, ...],
        requested_permissions: tuple[AdapterPermission, ...],
    ) -> AdapterManifest:
        """Canonicalize unordered authority sets while retaining strict construction."""
        return cls(
            schema_version=schema_version,
            adapter_id=adapter_id,
            adapter_version=adapter_version,
            kind=kind,
            package_digest=package_digest,
            signature_digest=signature_digest,
            signer_identity=signer_identity,
            protocol_min=protocol_min,
            protocol_max=protocol_max,
            capabilities=tuple(sorted(capabilities, key=str)),
            requested_permissions=tuple(sorted(requested_permissions, key=str)),
        )

    def __post_init__(self) -> None:
        """Fail closed on ambiguous identity, protocol, capability, or authority."""
        _validate_manifest_identity(self)
        _validate_manifest_authority(self)

    @property
    def manifest_digest(self) -> str:
        """Return the SHA-256 identity of canonical public JSON."""
        return _digest(self.to_document())

    def to_document(self) -> dict[str, object]:
        """Return a canonical JSON-compatible public representation."""
        return {
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "capabilities": [item.value for item in self.capabilities],
            "kind": self.kind.value,
            "package_digest": self.package_digest,
            "protocol_max": str(self.protocol_max),
            "protocol_min": str(self.protocol_min),
            "requested_permissions": [item.value for item in self.requested_permissions],
            "schema_version": self.schema_version,
            "signature_digest": self.signature_digest,
            "signer_identity": self.signer_identity,
        }


def _validate_manifest_identity(manifest: AdapterManifest) -> None:
    """Validate versioned public identity and signed package coordinates."""
    if manifest.schema_version != 1:
        message = "schema_version is unsupported"
        raise AdapterValidationError(message)
    if _TOKEN.fullmatch(manifest.adapter_id) is None:
        message = "adapter_id is invalid"
        raise AdapterValidationError(message)
    if _SEMVER.fullmatch(manifest.adapter_version) is None:
        message = "adapter_version is invalid"
        raise AdapterValidationError(message)
    _require_digest(manifest.package_digest, "package_digest")
    _require_digest(manifest.signature_digest, "signature_digest")
    if _TOKEN.fullmatch(manifest.signer_identity) is None:
        message = "signer_identity is invalid"
        raise AdapterValidationError(message)
    if manifest.protocol_min > manifest.protocol_max:
        message = "protocol_range is invalid"
        raise AdapterValidationError(message)


def _validate_manifest_authority(manifest: AdapterManifest) -> None:
    """Validate kind-specific capabilities and least-authority permissions."""
    _require_canonical_unique(manifest.capabilities, "capabilities")
    allowed_capabilities = _CAPABILITIES_BY_KIND[manifest.kind]
    if (
        not manifest.capabilities
        or _REQUIRED_CAPABILITY[manifest.kind] not in manifest.capabilities
        or any(item not in allowed_capabilities for item in manifest.capabilities)
    ):
        message = "capabilities do not match adapter kind"
        raise AdapterValidationError(message)
    _require_canonical_unique(manifest.requested_permissions, "requested_permissions")
    allowed_permissions = _PERMISSIONS_BY_KIND[manifest.kind]
    if not manifest.requested_permissions or any(
        item not in allowed_permissions for item in manifest.requested_permissions
    ):
        message = "requested_permissions do not match adapter kind"
        raise AdapterValidationError(message)


@dataclass(frozen=True, slots=True)
class AdapterProbeEvidence:
    """Live conformance evidence bound to one exact package and manifest."""

    manifest_digest: str
    package_digest: str
    negotiated_protocol: ProtocolVersion
    declared_capabilities: tuple[AdapterCapability, ...]
    observed_capabilities: tuple[AdapterCapability, ...]
    runtime_digest: str
    probed_at: datetime
    evidence_digest: str

    @classmethod
    def create(
        cls,
        *,
        manifest: AdapterManifest,
        negotiated_protocol: ProtocolVersion,
        observed_capabilities: tuple[AdapterCapability, ...],
        runtime_digest: str,
        probed_at: datetime,
    ) -> AdapterProbeEvidence:
        """Create and self-authenticate exact live evidence."""
        document = _probe_document(
            manifest.manifest_digest,
            manifest.package_digest,
            negotiated_protocol,
            manifest.capabilities,
            observed_capabilities,
            runtime_digest,
            probed_at,
        )
        return cls(
            manifest_digest=manifest.manifest_digest,
            package_digest=manifest.package_digest,
            negotiated_protocol=negotiated_protocol,
            declared_capabilities=manifest.capabilities,
            observed_capabilities=observed_capabilities,
            runtime_digest=runtime_digest,
            probed_at=probed_at,
            evidence_digest=_digest(document),
        )

    def __post_init__(self) -> None:
        """Reject claim-only, partial, reordered, stale-shaped, or altered evidence."""
        _require_digest(self.manifest_digest, "manifest_digest")
        _require_digest(self.package_digest, "package_digest")
        _require_digest(self.runtime_digest, "runtime_digest")
        _require_digest(self.evidence_digest, "evidence_digest")
        _require_canonical_unique(self.declared_capabilities, "declared_capabilities")
        _require_canonical_unique(self.observed_capabilities, "observed_capabilities")
        if self.observed_capabilities != self.declared_capabilities:
            message = "observed_capabilities do not exactly match declaration"
            raise AdapterValidationError(message)
        _require_utc(self.probed_at, "probed_at")
        expected = _digest(
            _probe_document(
                self.manifest_digest,
                self.package_digest,
                self.negotiated_protocol,
                self.declared_capabilities,
                self.observed_capabilities,
                self.runtime_digest,
                self.probed_at,
            )
        )
        if self.evidence_digest != expected:
            message = "evidence_digest does not authenticate probe"
            raise AdapterValidationError(message)

    def binds(self, manifest: AdapterManifest) -> bool:
        """Return whether this evidence proves the exact manifest and package."""
        return (
            self.manifest_digest == manifest.manifest_digest
            and self.package_digest == manifest.package_digest
            and self.declared_capabilities == manifest.capabilities
        )


@dataclass(frozen=True, slots=True)
class AdapterRegistration:
    """One governed active adapter registration with exact live evidence."""

    registration_id: str
    brain_id: str
    actor_id: str
    grant_id: str
    manifest: AdapterManifest
    evidence: AdapterProbeEvidence
    state: AdapterRegistrationState
    registered_at: datetime

    @classmethod
    def create(  # noqa: PLR0913 -- complete authorization lineage is required.
        cls,
        *,
        registration_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        manifest: AdapterManifest,
        evidence: AdapterProbeEvidence,
        state: AdapterRegistrationState,
        registered_at: datetime,
    ) -> AdapterRegistration:
        """Create one immutable governed registration."""
        return cls(
            registration_id,
            brain_id,
            actor_id,
            grant_id,
            manifest,
            evidence,
            state,
            registered_at,
        )

    def __post_init__(self) -> None:
        """Bind scope, manifest, evidence, state, and canonical time."""
        for value, field in (
            (self.registration_id, "registration_id"),
            (self.brain_id, "brain_id"),
            (self.actor_id, "actor_id"),
            (self.grant_id, "grant_id"),
        ):
            _require_uuid7(value, field)
        if not self.evidence.binds(self.manifest):
            message = "probe evidence does not bind manifest_digest"
            raise AdapterValidationError(message)
        if self.state is not AdapterRegistrationState.ACTIVE:
            message = "new registration state must be active"
            raise AdapterValidationError(message)
        _require_utc(self.registered_at, "registered_at")

    @property
    def manifest_digest(self) -> str:
        """Expose the immutable manifest coordinate without duplication."""
        return self.manifest.manifest_digest

    @property
    def package_digest(self) -> str:
        """Expose the verified executable package coordinate."""
        return self.manifest.package_digest

    @property
    def registration_digest(self) -> str:
        """Authenticate complete registration and authorization lineage."""
        return _digest(
            {
                "actor_id": self.actor_id,
                "brain_id": self.brain_id,
                "evidence_digest": self.evidence.evidence_digest,
                "grant_id": self.grant_id,
                "manifest_digest": self.manifest_digest,
                "registered_at": self.registered_at.isoformat().replace("+00:00", "Z"),
                "registration_id": self.registration_id,
                "state": self.state.value,
            }
        )


def negotiate_protocol(
    manifest: AdapterManifest,
    supported_min: ProtocolVersion,
    supported_max: ProtocolVersion,
) -> ProtocolVersion:
    """Select the highest mutually supported version or reject before execution."""
    lower = max(manifest.protocol_min, supported_min)
    upper = min(manifest.protocol_max, supported_max)
    if lower > upper:
        message = "unsupported_protocol"
        raise AdapterValidationError(message)
    return upper


def _probe_document(  # noqa: PLR0913 -- exact evidence identity has seven independent fields.
    manifest_digest: str,
    package_digest: str,
    negotiated_protocol: ProtocolVersion,
    declared_capabilities: tuple[AdapterCapability, ...],
    observed_capabilities: tuple[AdapterCapability, ...],
    runtime_digest: str,
    probed_at: datetime,
) -> dict[str, object]:
    return {
        "declared_capabilities": [item.value for item in declared_capabilities],
        "manifest_digest": manifest_digest,
        "negotiated_protocol": str(negotiated_protocol),
        "observed_capabilities": [item.value for item in observed_capabilities],
        "package_digest": package_digest,
        "probed_at": probed_at.isoformat().replace("+00:00", "Z"),
        "runtime_digest": runtime_digest,
    }


def _require_canonical_unique(values: tuple[object, ...], field: str) -> None:
    canonical = tuple(sorted(set(values), key=str))
    if not values or values != canonical:
        message = f"{field} must be a non-empty canonical unique tuple"
        raise AdapterValidationError(message)


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        message = f"{field} is invalid"
        raise AdapterValidationError(message)


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except (ValueError, AttributeError) as error:
        message = f"{field} is invalid"
        raise AdapterValidationError(message) from error
    if parsed.version != _UUID7 or str(parsed) != value:
        message = f"{field} is invalid"
        raise AdapterValidationError(message)


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        message = f"{field} must be UTC"
        raise AdapterValidationError(message)


def _digest(document: object) -> str:
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()
