"""ID-003 explicit repository-topology candidates and governed link aggregate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityConflictError, IdentityValidationError

if TYPE_CHECKING:
    from agentmemory.identity.domain.value_objects import Fingerprint, StableId

_OPERATION_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_REASON_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
_MAX_EVIDENCE = 32


class TopologyEndpointType(StrEnum):
    """Closed identity entity types that can participate in topology."""

    PROJECT = "project"
    REPOSITORY = "repository"


class RepositoryRelationType(StrEnum):
    """Closed evidence-backed repository topology predicates."""

    CONTAINS_REPOSITORY = "contains_repository"
    SUBMODULE_OF = "submodule_of"
    FORK_OF = "fork_of"
    PROJECT_USES_REPOSITORY = "project_uses_repository"


class TopologyEvidenceKind(StrEnum):
    """Closed evidence origins; no arbitrary host values enter canonical state."""

    NESTED_GIT_MARKER = "nested_git_marker"
    GITLINK = "gitlink"
    GITMODULE_DECLARATION = "gitmodule_declaration"
    SHARED_GIT_ROOTS = "shared_git_roots"
    UPSTREAM_REMOTE = "upstream_remote"
    SIMILAR_REMOTE = "similar_remote"
    SHARED_CONTENT = "shared_content"
    PROJECT_MANIFEST = "project_manifest"
    NON_GIT_MANIFEST = "non_git_manifest"
    USER_CONFIRMATION = "user_confirmation"


class TopologyEvidenceStrength(StrEnum):
    """Whether evidence independently proves a relationship or only proposes it."""

    CANDIDATE = "candidate"
    DETERMINISTIC_VCS = "deterministic_vcs"
    DETERMINISTIC_MANIFEST = "deterministic_manifest"
    USER_CONFIRMED = "user_confirmed"


class TopologyConfirmationSource(StrEnum):
    """Authority used to turn an inferred assertion into canonical state."""

    DETERMINISTIC_VCS = "deterministic_vcs"
    DETERMINISTIC_MANIFEST = "deterministic_manifest"
    USER = "user"


class TopologyLinkEventType(StrEnum):
    """Append-only ProjectRepositoryLink lifecycle event types."""

    CONFIRMED = "RepositoryLinkConfirmed"
    CORRECTED = "RepositoryLinkCorrected"


@dataclass(frozen=True, slots=True)
class TopologyEvidence:
    """One privacy-safe immutable evidence fact for a candidate assertion."""

    digest: Fingerprint
    kind: TopologyEvidenceKind
    strength: TopologyEvidenceStrength

    @property
    def deterministic(self) -> bool:
        """Return whether this fact may support non-user confirmation."""
        return self.strength in {
            TopologyEvidenceStrength.DETERMINISTIC_VCS,
            TopologyEvidenceStrength.DETERMINISTIC_MANIFEST,
            TopologyEvidenceStrength.USER_CONFIRMED,
        }


@dataclass(frozen=True, slots=True)
class RepositoryTopologyCandidate:
    """An authorized inferred link that never mutates identity by itself."""

    brain_id: StableId
    subject_type: TopologyEndpointType
    subject_id: StableId
    relation_type: RepositoryRelationType
    target_type: TopologyEndpointType
    target_id: StableId
    component_root_fingerprint: Fingerprint | None
    evidence: tuple[TopologyEvidence, ...]

    def __post_init__(self) -> None:
        """Enforce endpoint, separation, scope, and evidence invariants."""
        _validate_endpoint_shape(self)
        if not self.evidence or len(self.evidence) > _MAX_EVIDENCE:
            msg = "repository topology evidence is empty or exceeds its bound"
            raise IdentityValidationError(msg)
        canonical = tuple(sorted(set(self.evidence), key=lambda item: item.digest.value))
        if self.evidence != canonical:
            msg = "repository topology evidence must be unique and canonical"
            raise IdentityValidationError(msg)

    def can_confirm(self, source: TopologyConfirmationSource) -> bool:
        """Apply the closed confirmation policy without persisting the candidate."""
        if source is TopologyConfirmationSource.USER:
            return True
        expected_strength = (
            TopologyEvidenceStrength.DETERMINISTIC_VCS
            if source is TopologyConfirmationSource.DETERMINISTIC_VCS
            else TopologyEvidenceStrength.DETERMINISTIC_MANIFEST
        )
        return any(evidence.strength is expected_strength for evidence in self.evidence)


@dataclass(frozen=True, slots=True)
class RepositoryLinkHistoryEntry:
    """One immutable aggregate version and its complete confirmation provenance."""

    version: int
    previous_version: int | None
    operation_id: str
    actor_id: StableId
    grant_id: StableId
    confirmation_source: TopologyConfirmationSource
    relation_type: RepositoryRelationType
    component_root_fingerprint: Fingerprint | None
    evidence: tuple[TopologyEvidence, ...]
    correction_reason: str | None
    effective_at: int

    def __post_init__(self) -> None:
        """Reject noncanonical history before it reaches the event ledger."""
        if self.version < 1 or self.effective_at < 1:
            msg = "repository link history version and effective time must be positive"
            raise IdentityValidationError(msg)
        if _OPERATION_PATTERN.fullmatch(self.operation_id) is None:
            msg = "repository link operation ID is invalid"
            raise IdentityValidationError(msg)
        if (
            self.correction_reason is not None
            and _REASON_PATTERN.fullmatch(self.correction_reason) is None
        ):
            msg = "repository link correction reason is invalid"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class RepositoryLinkEvent:
    """One canonical event emitted with a ProjectRepositoryLink version."""

    link_id: StableId
    brain_id: StableId
    event_type: TopologyLinkEventType
    history_entry: RepositoryLinkHistoryEntry


@dataclass(frozen=True, slots=True)
class LinkConfirmation:
    """Bound confirmation/correction actor, authority, time, and reason."""

    operation_id: str
    actor_id: StableId
    grant_id: StableId
    source: TopologyConfirmationSource
    effective_at: int
    correction_reason: str | None = None

    def __post_init__(self) -> None:
        """Validate metadata independently of an aggregate transition."""
        if _OPERATION_PATTERN.fullmatch(self.operation_id) is None:
            msg = "repository link operation ID is invalid"
            raise IdentityValidationError(msg)
        if self.effective_at < 1:
            msg = "repository link effective time must be positive"
            raise IdentityValidationError(msg)
        if (
            self.correction_reason is not None
            and _REASON_PATTERN.fullmatch(self.correction_reason) is None
        ):
            msg = "repository link correction reason is invalid"
            raise IdentityValidationError(msg)


@dataclass(frozen=True, slots=True)
class ProjectRepositoryLink:
    """Governed aggregate for Project-Repository and Repository topology links."""

    link_id: StableId
    brain_id: StableId
    subject_type: TopologyEndpointType
    subject_id: StableId
    relation_type: RepositoryRelationType
    target_type: TopologyEndpointType
    target_id: StableId
    component_root_fingerprint: Fingerprint | None
    evidence: tuple[TopologyEvidence, ...]
    valid_from: int
    valid_to: int | None
    version: int
    history: tuple[RepositoryLinkHistoryEntry, ...]

    def __post_init__(self) -> None:
        """Ensure the snapshot and append-only history describe the same aggregate."""
        _validate_endpoint_shape(self)
        if (
            self.version < 1
            or self.valid_from < 1
            or (self.valid_to is not None and self.valid_to <= self.valid_from)
            or len(self.history) != self.version
            or not self.history
            or self.history[-1].version != self.version
            or self.history[-1].relation_type is not self.relation_type
            or self.history[-1].component_root_fingerprint != self.component_root_fingerprint
            or self.history[-1].evidence != self.evidence
            or tuple(entry.version for entry in self.history) != tuple(range(1, self.version + 1))
        ):
            msg = "repository link snapshot and history are inconsistent"
            raise IdentityValidationError(msg)

    @classmethod
    def confirm(
        cls,
        link_id: StableId,
        candidate: RepositoryTopologyCandidate,
        confirmation: LinkConfirmation,
    ) -> tuple[ProjectRepositoryLink, RepositoryLinkEvent]:
        """Confirm one candidate as version one without merging its endpoints."""
        if confirmation.correction_reason is not None:
            msg = "initial repository link confirmation cannot carry a correction reason"
            raise IdentityValidationError(msg)
        _require_confirmation(candidate, confirmation.source)
        history_entry = RepositoryLinkHistoryEntry(
            version=1,
            previous_version=None,
            operation_id=confirmation.operation_id,
            actor_id=confirmation.actor_id,
            grant_id=confirmation.grant_id,
            confirmation_source=confirmation.source,
            relation_type=candidate.relation_type,
            component_root_fingerprint=candidate.component_root_fingerprint,
            evidence=candidate.evidence,
            correction_reason=None,
            effective_at=confirmation.effective_at,
        )
        aggregate = cls(
            link_id=link_id,
            brain_id=candidate.brain_id,
            subject_type=candidate.subject_type,
            subject_id=candidate.subject_id,
            relation_type=candidate.relation_type,
            target_type=candidate.target_type,
            target_id=candidate.target_id,
            component_root_fingerprint=candidate.component_root_fingerprint,
            evidence=candidate.evidence,
            valid_from=confirmation.effective_at,
            valid_to=None,
            version=1,
            history=(history_entry,),
        )
        return aggregate, RepositoryLinkEvent(
            link_id,
            candidate.brain_id,
            TopologyLinkEventType.CONFIRMED,
            history_entry,
        )

    def correct(
        self,
        candidate: RepositoryTopologyCandidate,
        confirmation: LinkConfirmation,
        *,
        expected_version: int,
    ) -> tuple[ProjectRepositoryLink, RepositoryLinkEvent]:
        """Append a correction while preserving endpoint identity and every prior version."""
        if expected_version != self.version:
            raise IdentityConflictError
        if (
            candidate.brain_id != self.brain_id
            or candidate.subject_type is not self.subject_type
            or candidate.subject_id != self.subject_id
            or candidate.target_type is not self.target_type
            or candidate.target_id != self.target_id
        ):
            raise IdentityConflictError
        if confirmation.correction_reason is None:
            msg = "repository link correction requires a reason"
            raise IdentityValidationError(msg)
        if confirmation.effective_at <= self.history[-1].effective_at:
            msg = "repository link correction must occur after the current version"
            raise IdentityValidationError(msg)
        _require_confirmation(candidate, confirmation.source)
        next_version = self.version + 1
        history_entry = RepositoryLinkHistoryEntry(
            version=next_version,
            previous_version=self.version,
            operation_id=confirmation.operation_id,
            actor_id=confirmation.actor_id,
            grant_id=confirmation.grant_id,
            confirmation_source=confirmation.source,
            relation_type=candidate.relation_type,
            component_root_fingerprint=candidate.component_root_fingerprint,
            evidence=candidate.evidence,
            correction_reason=confirmation.correction_reason,
            effective_at=confirmation.effective_at,
        )
        aggregate = ProjectRepositoryLink(
            link_id=self.link_id,
            brain_id=self.brain_id,
            subject_type=self.subject_type,
            subject_id=self.subject_id,
            relation_type=candidate.relation_type,
            target_type=self.target_type,
            target_id=self.target_id,
            component_root_fingerprint=candidate.component_root_fingerprint,
            evidence=candidate.evidence,
            valid_from=self.valid_from,
            valid_to=None,
            version=next_version,
            history=(*self.history, history_entry),
        )
        return aggregate, RepositoryLinkEvent(
            self.link_id,
            self.brain_id,
            TopologyLinkEventType.CORRECTED,
            history_entry,
        )


def _validate_endpoint_shape(
    value: RepositoryTopologyCandidate | ProjectRepositoryLink,
) -> None:
    repository_relation = value.relation_type in {
        RepositoryRelationType.CONTAINS_REPOSITORY,
        RepositoryRelationType.SUBMODULE_OF,
        RepositoryRelationType.FORK_OF,
    }
    if repository_relation:
        valid = (
            value.subject_type is TopologyEndpointType.REPOSITORY
            and value.target_type is TopologyEndpointType.REPOSITORY
            and value.subject_id != value.target_id
            and value.component_root_fingerprint is None
        )
        if not valid:
            msg = "repository topology requires distinct Repository endpoint shape"
            raise IdentityValidationError(msg)
        return
    if not (
        value.subject_type is TopologyEndpointType.PROJECT
        and value.target_type is TopologyEndpointType.REPOSITORY
    ):
        msg = "project repository relation has an invalid endpoint shape"
        raise IdentityValidationError(msg)


def _require_confirmation(
    candidate: RepositoryTopologyCandidate,
    confirmation_source: TopologyConfirmationSource,
) -> None:
    if not candidate.can_confirm(confirmation_source):
        msg = "repository link confirmation lacks deterministic evidence"
        raise IdentityValidationError(msg)
