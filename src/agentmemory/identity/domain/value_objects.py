"""Immutable identity values and resolution outcomes for ID-001."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import StrEnum
from uuid import UUID

from agentmemory.identity.domain.errors import IdentityValidationError

_DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_OPERATION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_MAX_PATH_LENGTH = 32_768
_UUID_VERSION = 7
_MIN_AMBIGUOUS_CANDIDATES = 2


@dataclass(frozen=True, slots=True)
class StableId:
    """A canonical RFC 9562 UUIDv7 used for durable identity entities."""

    value: str

    def __post_init__(self) -> None:
        """Require canonical lowercase UUIDv7 values."""
        try:
            parsed = UUID(self.value)
        except ValueError as error:
            msg = "stable identity must be a canonical UUIDv7"
            raise IdentityValidationError(msg) from error
        if str(parsed) != self.value or parsed.version != _UUID_VERSION:
            msg = "stable identity must be a canonical UUIDv7"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class Fingerprint:
    """A non-zero lowercase SHA-256 or HMAC-SHA-256 lookup value."""

    value: str

    def __post_init__(self) -> None:
        """Reject malformed, uppercase, and sentinel fingerprints."""
        if _DIGEST_PATTERN.fullmatch(self.value) is None or set(self.value) == {"0"}:
            msg = "identity fingerprint must be a non-zero lowercase SHA-256 value"
            raise IdentityValidationError(msg)

    @classmethod
    def from_bytes(cls, value: bytes) -> Fingerprint:
        """Create deterministic non-secret test or content evidence."""
        return cls(hashlib.sha256(value).hexdigest())


class VcsType(StrEnum):
    """Closed version-control families supported by identity resolution."""

    GIT = "git"
    NONE = "none"


class IdentitySource(StrEnum):
    """Normative ID-001 resolution precedence."""

    MANIFEST = "manifest"
    CHECKOUT_REGISTRY = "checkout_registry"
    REPOSITORY_FINGERPRINT = "repository_fingerprint"
    APPROVED_HEURISTIC = "approved_heuristic"


class ResolutionStatus(StrEnum):
    """Closed workspace-resolution outcomes."""

    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    NOT_FOUND = "not_found"


@dataclass(frozen=True, slots=True)
class WorkspaceObservation:
    """Authenticated ephemeral path observation; the path is never an entity ID."""

    operation_id: str
    brain_id: StableId
    actor_id: StableId
    grant_id: StableId
    path: str = field(repr=False)

    def __post_init__(self) -> None:
        """Bound operation and host path data before any adapter call."""
        if _OPERATION_PATTERN.fullmatch(self.operation_id) is None:
            msg = "workspace resolution operation ID is invalid"
            raise IdentityValidationError(msg)
        if not self.path or "\x00" in self.path or len(self.path) > _MAX_PATH_LENGTH:
            msg = "workspace observation path is invalid"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class ObservedWorkspaceQuery:
    """Authenticated privacy-safe observation supplied by a local session bridge."""

    operation_id: str
    brain_id: StableId
    actor_id: StableId
    grant_id: StableId

    def __post_init__(self) -> None:
        """Apply the same operation bound without accepting a raw host path."""
        if _OPERATION_PATTERN.fullmatch(self.operation_id) is None:
            msg = "workspace resolution operation ID is invalid"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class ProjectManifest:
    """Strict non-authoritative identity declaration from a workspace."""

    schema_version: int
    project_id: StableId
    repository_id: StableId | None

    def __post_init__(self) -> None:
        """Accept only the current closed manifest schema."""
        if self.schema_version != 1:
            msg = "project manifest schema version is unsupported"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class DeviceIdentity:
    """Privacy-safe device, volume, and canonical-path evidence."""

    device_id: StableId
    device_fingerprint: Fingerprint
    volume_fingerprint: Fingerprint
    path_fingerprint: Fingerprint
    verified: bool


@dataclass(frozen=True, slots=True)
class VcsIdentity:
    """Privacy-safe repository and checkout evidence returned by a VCS adapter."""

    vcs_type: VcsType
    repository_fingerprint: Fingerprint | None
    checkout_fingerprint: Fingerprint | None
    worktree_fingerprint: Fingerprint | None
    repository_lookup_approved: bool = False

    def __post_init__(self) -> None:
        """Git evidence must identify a repository; non-Git evidence must not pretend to."""
        if self.vcs_type is VcsType.GIT and self.repository_fingerprint is None:
            msg = "Git identity requires a repository fingerprint"
            raise IdentityValidationError(msg)
        if self.vcs_type is VcsType.NONE and self.repository_fingerprint is not None:
            msg = "non-Git identity cannot create durable repository identity"
            raise IdentityValidationError(msg)
        if self.repository_lookup_approved and self.repository_fingerprint is None:
            msg = "repository lookup authority requires a repository fingerprint"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class IdentityCandidate:
    """One authorized existing Project/Repository/Checkout mapping."""

    project_id: StableId
    repository_id: StableId
    checkout_id: StableId | None


@dataclass(frozen=True, slots=True)
class IdentityEvidence:
    """Candidate sets in normative precedence order."""

    manifest: tuple[IdentityCandidate, ...]
    checkout: tuple[IdentityCandidate, ...]
    repository: tuple[IdentityCandidate, ...]
    heuristic: tuple[IdentityCandidate, ...]


@dataclass(frozen=True, slots=True)
class WorkspaceResolution:
    """Content-free typed identity result with deterministic explanation codes."""

    brain_id: StableId
    status: ResolutionStatus
    source: IdentitySource | None
    selected: IdentityCandidate | None
    candidates: tuple[IdentityCandidate, ...]
    explanation: tuple[str, ...]

    def __post_init__(self) -> None:
        """Prevent callers from misreading ambiguous or absent identity as resolved."""
        if self.status is ResolutionStatus.RESOLVED and (
            self.selected is None or self.source is None or self.candidates != (self.selected,)
        ):
            msg = "resolved identity requires exactly one selected candidate"
            raise IdentityValidationError(msg)
        if self.status is ResolutionStatus.AMBIGUOUS and (
            self.selected is not None
            or self.source is None
            or len(self.candidates) < _MIN_AMBIGUOUS_CANDIDATES
        ):
            msg = "ambiguous identity requires at least two unselected candidates"
            raise IdentityValidationError(msg)
        if self.status is ResolutionStatus.NOT_FOUND and (
            self.source is not None or self.selected is not None or self.candidates
        ):
            msg = "not-found identity cannot carry candidates"
            raise IdentityValidationError(msg)

    @classmethod
    def not_found(cls, brain_id: StableId) -> WorkspaceResolution:
        """Return an explicit absence without deriving identity from a path."""
        return cls(
            brain_id,
            ResolutionStatus.NOT_FOUND,
            None,
            None,
            (),
            ("not_found:no_authoritative_evidence",),
        )
