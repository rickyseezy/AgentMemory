"""ID-004 immutable authorization and retrieval-scope values."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityValidationError

if TYPE_CHECKING:
    from agentmemory.identity.domain.value_objects import StableId

_TOKEN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MAX_SCOPE_MEMBERS = 500
_MAX_RANK_BOOST_MICROS = 1_000_000


def _scope_digest(content: object) -> str:
    """Hash one canonical scope document for downstream authorization checks."""
    canonical = json.dumps(content, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class RetrievalScopeMode(StrEnum):
    """Closed user-selectable retrieval modes."""

    CURRENT = "current"
    RELATED = "related"
    SELECTED = "selected"
    GLOBAL = "global"


class RetrievalRole(StrEnum):
    """Normative local authorization roles."""

    OWNER = "owner"
    ADMIN = "admin"
    EDITOR = "editor"
    READER = "reader"
    AUDITOR = "auditor"
    ADAPTER = "adapter"
    WORKER = "worker"


class Classification(StrEnum):
    """Ordered local information classifications."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    LOCAL_ONLY = "local_only"


@dataclass(frozen=True, slots=True)
class TemporalScope:
    """Optional inclusive-from, exclusive-to retrieval interval in microseconds."""

    valid_from: int | None
    valid_to: int | None

    def __post_init__(self) -> None:
        """Require a non-empty, ordered temporal interval when bounded."""
        if self.valid_from is not None and self.valid_from < 0:
            msg = "temporal scope start is invalid"
            raise IdentityValidationError(msg)
        if self.valid_to is not None and self.valid_to < 1:
            msg = "temporal scope end is invalid"
            raise IdentityValidationError(msg)
        if (
            self.valid_from is not None
            and self.valid_to is not None
            and self.valid_to <= self.valid_from
        ):
            msg = "temporal scope interval is empty"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class ScopeMember:
    """One explicit authorized Project and its repository/checkout restriction."""

    project_id: StableId
    repository_ids: tuple[StableId, ...]
    checkout_ids: tuple[StableId, ...]
    rank_boost_micros: int = 0

    def __post_init__(self) -> None:
        """Require canonical IDs and bounded deterministic ranking."""
        if not self.repository_ids:
            msg = "scope member requires a Repository"
            raise IdentityValidationError(msg)
        if self.checkout_ids and not self.repository_ids:
            msg = "Checkout scope requires Repository scope"
            raise IdentityValidationError(msg)
        if self.rank_boost_micros < 0 or self.rank_boost_micros > _MAX_RANK_BOOST_MICROS:
            msg = "scope rank boost is invalid"
            raise IdentityValidationError(msg)
        if (
            tuple(sorted(set(self.repository_ids), key=lambda item: item.value))
            != self.repository_ids
        ):
            msg = "scope Repository IDs must be unique and sorted"
            raise IdentityValidationError(msg)
        if tuple(sorted(set(self.checkout_ids), key=lambda item: item.value)) != self.checkout_ids:
            msg = "scope Checkout IDs must be unique and sorted"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class RetrievalGrant:
    """One active grant narrowed within exactly one Brain."""

    grant_id: StableId
    role: RetrievalRole
    project_id: StableId | None
    repository_id: StableId | None
    version: int

    def __post_init__(self) -> None:
        """Require valid nested scope shape and a positive revision."""
        if self.repository_id is not None and self.project_id is None:
            msg = "Repository grant requires a Project grant"
            raise IdentityValidationError(msg)
        if self.version < 1:
            msg = "grant version is invalid"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class ProjectBinding:
    """Canonical active Project topology visible to authorization resolution."""

    brain_id: StableId
    project_id: StableId
    repository_ids: tuple[StableId, ...]
    checkout_ids: tuple[StableId, ...]

    def __post_init__(self) -> None:
        """Reject a Project with no active Repository binding."""
        if not self.repository_ids:
            msg = "Project binding requires a Repository"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class AuthorizationSnapshot:
    """Transactionally consistent grants, bindings, and policy epochs."""

    brain_id: StableId
    principal_id: StableId
    grants: tuple[RetrievalGrant, ...]
    bindings: tuple[ProjectBinding, ...]
    classification_ceiling: Classification
    policy_version: int
    security_epoch: int

    def __post_init__(self) -> None:
        """Require current policy epochs and one-Brain bindings."""
        if not self.grants or self.policy_version < 1 or self.security_epoch < 1:
            msg = "authorization snapshot is incomplete"
            raise IdentityValidationError(msg)
        if any(binding.brain_id != self.brain_id for binding in self.bindings):
            msg = "authorization snapshot crosses a Brain"
            raise IdentityValidationError(msg)

    @property
    def grant_version(self) -> int:
        """Produce a revocation-sensitive stable version over every active grant."""
        payload = ":".join(
            f"{grant.grant_id.value}:{grant.version}"
            for grant in sorted(self.grants, key=lambda item: item.grant_id.value)
        )
        return int.from_bytes(hashlib.sha256(payload.encode()).digest()[:8], "big") or 1


@dataclass(frozen=True, slots=True)
class RelatedProject:
    """One evidence-backed bounded graph result."""

    project_id: StableId
    depth: int
    cost: int
    evidence: str

    def __post_init__(self) -> None:
        """Require positive path metrics and a closed evidence token."""
        if self.depth < 1 or self.cost < 1 or _TOKEN.fullmatch(self.evidence) is None:
            msg = "related Project evidence is invalid"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class AuthorizedScope:
    """Immutable, explicit scope required by every downstream retrieval port."""

    brain_id: StableId
    principal_id: StableId
    role: RetrievalRole
    mode: RetrievalScopeMode
    members: tuple[ScopeMember, ...]
    classification_ceiling: Classification
    temporal_scope: TemporalScope
    grant_version: int
    policy_version: int
    security_epoch: int
    action: str
    purpose: str
    scope_fingerprint: str
    cache_key: str

    @classmethod
    def create(  # noqa: PLR0913 -- Factory binds every mandatory authorization dimension.
        cls,
        *,
        brain_id: StableId,
        principal_id: StableId,
        role: RetrievalRole,
        mode: RetrievalScopeMode,
        members: tuple[ScopeMember, ...],
        classification_ceiling: Classification,
        temporal_scope: TemporalScope,
        grant_version: int,
        policy_version: int,
        security_epoch: int,
        action: str,
        purpose: str,
    ) -> AuthorizedScope:
        """Canonicalize members and bind cache identity to all security epochs."""
        if not members or len(members) > _MAX_SCOPE_MEMBERS:
            msg = "authorized scope member count is invalid"
            raise IdentityValidationError(msg)
        if min(grant_version, policy_version, security_epoch) < 1:
            msg = "authorized scope version is invalid"
            raise IdentityValidationError(msg)
        if _TOKEN.fullmatch(action) is None or _TOKEN.fullmatch(purpose) is None:
            msg = "authorized scope action or purpose is invalid"
            raise IdentityValidationError(msg)
        canonical = tuple(
            sorted(members, key=lambda item: (-item.rank_boost_micros, item.project_id.value))
        )
        if len({member.project_id for member in canonical}) != len(canonical):
            msg = "authorized scope contains duplicate Projects"
            raise IdentityValidationError(msg)
        content = {
            "action": action,
            "brain_id": brain_id.value,
            "classification_ceiling": classification_ceiling.value,
            "grant_version": grant_version,
            "members": [
                {
                    "checkout_ids": [value.value for value in member.checkout_ids],
                    "project_id": member.project_id.value,
                    "rank_boost_micros": member.rank_boost_micros,
                    "repository_ids": [value.value for value in member.repository_ids],
                }
                for member in canonical
            ],
            "principal_id": principal_id.value,
            "purpose": purpose,
            "temporal": [temporal_scope.valid_from, temporal_scope.valid_to],
        }
        fingerprint = _scope_digest(content)
        cache_key = (
            f"scope:v1:{mode.value}:{principal_id.value}:{grant_version}:"
            f"{policy_version}:{security_epoch}:{fingerprint}"
        )
        return cls(
            brain_id,
            principal_id,
            role,
            mode,
            canonical,
            classification_ceiling,
            temporal_scope,
            grant_version,
            policy_version,
            security_epoch,
            action,
            purpose,
            fingerprint,
            cache_key,
        )

    @property
    def project_ids(self) -> tuple[StableId, ...]:
        """Return explicit Project restrictions in ranking order."""
        return tuple(member.project_id for member in self.members)

    @property
    def repository_ids(self) -> tuple[StableId, ...]:
        """Return the canonical union of explicit Repository restrictions."""
        return tuple(
            sorted(
                {value for member in self.members for value in member.repository_ids},
                key=lambda item: item.value,
            )
        )

    @property
    def checkout_ids(self) -> tuple[StableId, ...]:
        """Return the canonical union of explicit Checkout restrictions."""
        return tuple(
            sorted(
                {value for member in self.members for value in member.checkout_ids},
                key=lambda item: item.value,
            )
        )


@dataclass(frozen=True, slots=True)
class ScopeExplanation:
    """Content-free explanation of included authorized scope members."""

    mode: RetrievalScopeMode
    entries: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RetrievalScopeResolution:
    """The enforceable scope and its public explanation."""

    scope: AuthorizedScope
    explanation: ScopeExplanation
