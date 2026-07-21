"""GRA-004 bitemporal truth, VCS reachability, and explanation values."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from agentmemory.graph.domain.assertions import AssertionPredicate
from agentmemory.graph.domain.errors import GraphValidationError
from agentmemory.graph.domain.models import stable_graph_id

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.graph.domain.assertions import Assertion

_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_MAX_BRANCH = 1_024
_MAX_PARENTS = 64
_MAX_NODES = 20_000
_MAX_REFS = 1_000
_MAX_IMPACTS = 20_000
_MAX_QUERY_RESULTS = 1_000
_ERR_BATCH = "VCS revision batch is invalid"
_ERR_EXPLANATION = "temporal truth explanation is invalid"
_ERR_PROOF = "VCS revision proof is invalid"
_ERR_REVISION = "VCS revision selector is invalid"
_ERR_SCOPE = "temporal truth scope is invalid"


class TemporalTruthMode(StrEnum):
    """Whether a query asks for current authority or an explicit historical view."""

    CURRENT = "current"
    HISTORICAL = "historical"


class TruthCurrency(StrEnum):
    """Closed label preventing historical knowledge from being presented as current."""

    CURRENT = "current"
    HISTORICAL = "historical"


class RevisionApplicability(StrEnum):
    """How one evidence item relates to the concrete requested revision."""

    UNVERSIONED = "unversioned"
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class VcsRevisionSelector:
    """One repository-bound branch or immutable commit selector."""

    repository_id: str
    branch_name: str | None = None
    commit_sha: str | None = None

    def __post_init__(self) -> None:
        """Require exactly one safe selector and a stable Repository identity."""
        stable_graph_id(self.repository_id)
        if (self.branch_name is None) == (self.commit_sha is None):
            raise GraphValidationError(_ERR_REVISION)
        if self.branch_name is not None:
            _require_branch(self.branch_name)
        if self.commit_sha is not None:
            _require_commit(self.commit_sha)


@dataclass(frozen=True, slots=True)
class TruthTemporalScope:
    """Explicit Current or historical valid/recorded/revision coordinates."""

    mode: TemporalTruthMode
    as_of_valid: datetime | None = None
    as_of_recorded: datetime | None = None
    revision: VcsRevisionSelector | None = None

    @classmethod
    def current(cls) -> TruthTemporalScope:
        """Construct the only valid unqualified current scope."""
        return cls(TemporalTruthMode.CURRENT)

    @classmethod
    def historical(
        cls,
        *,
        as_of_valid: datetime | None = None,
        as_of_recorded: datetime | None = None,
        revision: VcsRevisionSelector | None = None,
    ) -> TruthTemporalScope:
        """Construct an explicitly historical scope with at least one coordinate."""
        return cls(TemporalTruthMode.HISTORICAL, as_of_valid, as_of_recorded, revision)

    def __post_init__(self) -> None:
        """Forbid ambiguous implicit history and qualified Current requests."""
        _require_truth_mode(self.mode)
        for value in (self.as_of_valid, self.as_of_recorded):
            if value is not None:
                _require_utc(value)
        coordinates = (self.as_of_valid, self.as_of_recorded, self.revision)
        if self.mode is TemporalTruthMode.CURRENT and any(item is not None for item in coordinates):
            raise GraphValidationError(_ERR_SCOPE)
        if self.mode is TemporalTruthMode.HISTORICAL and all(item is None for item in coordinates):
            raise GraphValidationError(_ERR_SCOPE)

    def evaluation_times(self, evaluated_at: datetime) -> tuple[datetime, datetime]:
        """Resolve omitted historical axes to the authorized query evaluation instant."""
        _require_utc(evaluated_at)
        return self.as_of_valid or evaluated_at, self.as_of_recorded or evaluated_at


@dataclass(frozen=True, slots=True)
class VcsRevisionNode:
    """One immutable commit and its complete direct-parent set."""

    commit_sha: str
    parent_shas: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require a canonical bounded acyclic local edge set."""
        _require_commit(self.commit_sha)
        if (
            len(self.parent_shas) > _MAX_PARENTS
            or self.parent_shas != tuple(sorted(set(self.parent_shas)))
            or self.commit_sha in self.parent_shas
        ):
            raise GraphValidationError(_ERR_BATCH)
        for value in self.parent_shas:
            _require_commit(value)


@dataclass(frozen=True, slots=True)
class VcsRefObservation:
    """One append-only observation of a branch ref resolving to a commit."""

    branch_name: str
    commit_sha: str
    observed_at: datetime

    def __post_init__(self) -> None:
        """Require safe branch text, an immutable commit, and UTC observation time."""
        _require_branch(self.branch_name)
        _require_commit(self.commit_sha)
        _require_utc(self.observed_at)

    @property
    def id(self) -> str:
        """Derive deterministic observation identity without storing path content."""
        payload = f"vcs-ref.v1\0{self.branch_name}\0{self.commit_sha}\0{_time(self.observed_at)}"
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceRevisionImpact:
    """A code change that invalidates one evidence lineage on descendants of a commit."""

    evidence_id: str
    invalidating_commit_sha: str
    changed_at: datetime

    def __post_init__(self) -> None:
        """Require stable evidence, immutable revision, and UTC change time."""
        stable_graph_id(self.evidence_id)
        _require_commit(self.invalidating_commit_sha)
        _require_utc(self.changed_at)

    @property
    def id(self) -> str:
        """Derive replay-stable impact identity."""
        payload = (
            f"vcs-impact.v1\0{self.evidence_id}\0{self.invalidating_commit_sha}\0"
            f"{_time(self.changed_at)}"
        )
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class VcsRevisionBatch:
    """One authorized immutable commit-DAG/ref/impact observation transaction."""

    operation_id: str
    brain_id: str
    repository_id: str
    nodes: tuple[VcsRevisionNode, ...]
    refs: tuple[VcsRefObservation, ...]
    impacts: tuple[EvidenceRevisionImpact, ...]
    observed_at: datetime
    source_digest: str

    def __post_init__(self) -> None:
        """Require closed canonical content and internally resolvable references."""
        if _OPERATION.fullmatch(self.operation_id) is None:
            raise GraphValidationError(_ERR_BATCH)
        stable_graph_id(self.brain_id)
        stable_graph_id(self.repository_id)
        _require_utc(self.observed_at)
        _require_digest(self.source_digest)
        if (
            not (self.nodes or self.refs or self.impacts)
            or len(self.nodes) > _MAX_NODES
            or len(self.refs) > _MAX_REFS
            or len(self.impacts) > _MAX_IMPACTS
            or self.nodes != tuple(sorted(self.nodes, key=lambda item: item.commit_sha))
            or self.refs
            != tuple(sorted(self.refs, key=lambda item: (item.branch_name, item.observed_at)))
            or self.impacts
            != tuple(
                sorted(
                    self.impacts,
                    key=lambda item: (item.evidence_id, item.invalidating_commit_sha),
                )
            )
        ):
            raise GraphValidationError(_ERR_BATCH)
        commits = {item.commit_sha for item in self.nodes}
        if len(commits) != len(self.nodes):
            raise GraphValidationError(_ERR_BATCH)
        if len({item.id for item in self.refs}) != len(self.refs) or len(
            {item.id for item in self.impacts}
        ) != len(self.impacts):
            raise GraphValidationError(_ERR_BATCH)
        if any(item.observed_at > self.observed_at for item in self.refs) or any(
            item.changed_at > self.observed_at for item in self.impacts
        ):
            raise GraphValidationError(_ERR_BATCH)

    @property
    def digest(self) -> str:
        """Bind the complete replay contract to one canonical digest."""
        document = {
            "brain_id": self.brain_id,
            "impacts": [
                [item.evidence_id, item.invalidating_commit_sha, _time(item.changed_at)]
                for item in self.impacts
            ],
            "nodes": [[item.commit_sha, list(item.parent_shas)] for item in self.nodes],
            "observed_at": _time(self.observed_at),
            "operation_id": self.operation_id,
            "refs": [
                [item.branch_name, item.commit_sha, _time(item.observed_at)] for item in self.refs
            ],
            "repository_id": self.repository_id,
            "source_digest": self.source_digest,
        }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class EvidenceRevisionAnchor:
    """The immutable repository revision observed for one assertion evidence item."""

    evidence_id: str
    repository_id: str
    checkout_id: str
    commit_sha: str
    branch_at_capture: str | None
    observed_at: datetime

    def __post_init__(self) -> None:
        """Validate stable scope and capture-time VCS evidence."""
        for value in (self.evidence_id, self.repository_id, self.checkout_id):
            stable_graph_id(value)
        _require_commit(self.commit_sha)
        if self.branch_at_capture is not None:
            _require_branch(self.branch_at_capture)
        _require_utc(self.observed_at)


@dataclass(frozen=True, slots=True)
class ResolvedVcsRevision:
    """A branch/commit selector resolved to an immutable commit and graph watermark."""

    selector: VcsRevisionSelector
    commit_sha: str
    graph_digest: str
    observed_at: datetime
    ref_observation_id: str | None
    force_pushed: bool

    def __post_init__(self) -> None:
        """Require proof coordinates consistent with selector kind."""
        _require_commit(self.commit_sha)
        _require_digest(self.graph_digest)
        _require_utc(self.observed_at)
        _require_bool(self.force_pushed, _ERR_PROOF)
        if (self.selector.branch_name is None) != (self.ref_observation_id is None):
            raise GraphValidationError(_ERR_PROOF)
        if self.ref_observation_id is not None:
            _require_digest(self.ref_observation_id)


@dataclass(frozen=True, slots=True)
class RevisionEvidenceProof:
    """Content-free explanation of one evidence item's revision applicability."""

    evidence_id: str
    applicability: RevisionApplicability
    evidence_commit_sha: str | None
    target_commit_sha: str
    invalidating_commit_shas: tuple[str, ...]
    graph_digest: str

    def __post_init__(self) -> None:
        """Reject contradictory or unbounded reachability evidence."""
        stable_graph_id(self.evidence_id)
        _require_revision_applicability(self.applicability)
        _require_commit(self.target_commit_sha)
        _require_digest(self.graph_digest)
        if self.evidence_commit_sha is not None:
            _require_commit(self.evidence_commit_sha)
        if self.invalidating_commit_shas != tuple(sorted(set(self.invalidating_commit_shas))):
            raise GraphValidationError(_ERR_PROOF)
        for value in self.invalidating_commit_shas:
            _require_commit(value)
        if (
            self.applicability is RevisionApplicability.UNVERSIONED
            and (self.evidence_commit_sha is not None or self.invalidating_commit_shas)
        ) or (
            self.applicability is RevisionApplicability.STALE and not self.invalidating_commit_shas
        ):
            raise GraphValidationError(_ERR_PROOF)

    @property
    def supports_revision(self) -> bool:
        """Return whether this evidence still supports truth at the target revision."""
        return self.applicability in {
            RevisionApplicability.UNVERSIONED,
            RevisionApplicability.REACHABLE,
        }


@dataclass(frozen=True, slots=True)
class TemporalAssertionCriteria:
    """Canonical bounded filters passed to the assertion repository as one value."""

    assertion_id: str | None
    subject_id: str | None
    predicates: tuple[AssertionPredicate, ...]
    valid_at: datetime
    recorded_at: datetime
    limit: int

    def __post_init__(self) -> None:
        """Validate exact identifiers, temporal coordinates, and bounded result count."""
        for value in (self.assertion_id, self.subject_id):
            if value is not None:
                stable_graph_id(value)
        validate_predicates(self.predicates)
        _require_utc(self.valid_at)
        _require_utc(self.recorded_at)
        if not 1 <= self.limit <= _MAX_QUERY_RESULTS:
            raise GraphValidationError(_ERR_SCOPE)


@dataclass(frozen=True, slots=True)
class TemporalAssertionCandidate:
    """Canonical assertion state selected at one recorded-time snapshot."""

    assertion: Assertion
    lifecycle_event_id: str
    currently_authoritative: bool
    evidence_anchors: tuple[EvidenceRevisionAnchor | None, ...]

    def __post_init__(self) -> None:
        """Bind one optional VCS anchor to every canonical evidence item."""
        stable_graph_id(self.lifecycle_event_id)
        _require_bool(self.currently_authoritative, _ERR_EXPLANATION)
        if len(self.evidence_anchors) != len(self.assertion.evidence):
            raise GraphValidationError(_ERR_EXPLANATION)
        for evidence, anchor in zip(self.assertion.evidence, self.evidence_anchors, strict=True):
            if anchor is not None and anchor.evidence_id != evidence.evidence_id:
                raise GraphValidationError(_ERR_EXPLANATION)


@dataclass(frozen=True, slots=True)
class TemporalAssertionExplanation:
    """Authority, time, and revision proof returned with one truth result."""

    assertion_id: str
    assertion_revision_id: str
    lifecycle_event_id: str
    currency: TruthCurrency
    valid_at: datetime
    recorded_at: datetime
    currently_authoritative: bool
    resolved_revision: ResolvedVcsRevision | None
    evidence_proofs: tuple[RevisionEvidenceProof, ...]

    def __post_init__(self) -> None:
        """Ensure historical/current labels and proof coordinates cannot disagree."""
        stable_graph_id(self.assertion_id)
        stable_graph_id(self.lifecycle_event_id)
        _require_digest(self.assertion_revision_id)
        _require_utc(self.valid_at)
        _require_utc(self.recorded_at)
        _require_truth_currency(self.currency)
        _require_bool(self.currently_authoritative, _ERR_EXPLANATION)
        if self.currency is TruthCurrency.CURRENT and not self.currently_authoritative:
            raise GraphValidationError(_ERR_EXPLANATION)
        if self.resolved_revision is None and self.evidence_proofs:
            raise GraphValidationError(_ERR_EXPLANATION)
        if self.resolved_revision is not None and any(
            item.target_commit_sha != self.resolved_revision.commit_sha
            or item.graph_digest != self.resolved_revision.graph_digest
            for item in self.evidence_proofs
        ):
            raise GraphValidationError(_ERR_EXPLANATION)


@dataclass(frozen=True, slots=True)
class TemporalAssertionResult:
    """One canonical assertion paired with its complete temporal authority explanation."""

    assertion: Assertion
    explanation: TemporalAssertionExplanation

    def __post_init__(self) -> None:
        """Prevent an explanation from being attached to another assertion revision."""
        if (
            self.assertion.id != self.explanation.assertion_id
            or self.assertion.revision_id != self.explanation.assertion_revision_id
        ):
            raise GraphValidationError(_ERR_EXPLANATION)


class RevisionEvidencePolicy:
    """Apply reachability and lineage invalidation without trusting branch labels."""

    @staticmethod
    def proof(
        evidence_id: str,
        anchor: EvidenceRevisionAnchor | None,
        resolved: ResolvedVcsRevision,
        *,
        anchor_reachable: bool,
        reachable_invalidations: tuple[str, ...],
    ) -> RevisionEvidenceProof:
        """Classify an evidence item against one concrete target commit."""
        invalidations = tuple(sorted(set(reachable_invalidations)))
        if anchor is None:
            applicability = RevisionApplicability.UNVERSIONED
            commit_sha = None
            invalidations = ()
        elif anchor.repository_id != resolved.selector.repository_id or not anchor_reachable:
            applicability = RevisionApplicability.UNREACHABLE
            commit_sha = anchor.commit_sha
            invalidations = ()
        elif invalidations:
            applicability = RevisionApplicability.STALE
            commit_sha = anchor.commit_sha
        else:
            applicability = RevisionApplicability.REACHABLE
            commit_sha = anchor.commit_sha
        return RevisionEvidenceProof(
            evidence_id,
            applicability,
            commit_sha,
            resolved.commit_sha,
            invalidations,
            resolved.graph_digest,
        )

    @staticmethod
    def assertion_supported(proofs: tuple[RevisionEvidenceProof, ...]) -> bool:
        """Preserve an assertion while at least one authorized evidence item still supports it."""
        return bool(proofs) and any(item.supports_revision for item in proofs)


def validate_predicates(predicates: tuple[AssertionPredicate, ...]) -> None:
    """Require a canonical closed predicate filter when supplied."""
    if predicates != tuple(dict.fromkeys(predicates)):
        raise GraphValidationError(_ERR_SCOPE)
    for item in predicates:
        if not isinstance(cast("object", item), AssertionPredicate):
            raise GraphValidationError(_ERR_SCOPE)


def _require_commit(value: object) -> None:
    if not isinstance(value, str) or _COMMIT.fullmatch(value) is None:
        raise GraphValidationError(_ERR_REVISION)


def _require_digest(value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise GraphValidationError(_ERR_BATCH)


def _require_branch(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_BRANCH
        or any(character in value for character in "\x00\r\n")
    ):
        raise GraphValidationError(_ERR_REVISION)


def _require_utc(value: object) -> None:
    if not hasattr(value, "tzinfo") or not hasattr(value, "utcoffset"):
        raise GraphValidationError(_ERR_SCOPE)
    timestamp = cast("datetime", value)
    offset = timestamp.utcoffset()
    if timestamp.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise GraphValidationError(_ERR_SCOPE)


def _require_truth_currency(value: object) -> None:
    if not isinstance(value, TruthCurrency):
        raise GraphValidationError(_ERR_EXPLANATION)


def _require_truth_mode(value: object) -> None:
    if not isinstance(value, TemporalTruthMode):
        raise GraphValidationError(_ERR_SCOPE)


def _require_revision_applicability(value: object) -> None:
    if not isinstance(value, RevisionApplicability):
        raise GraphValidationError(_ERR_PROOF)


def _require_bool(value: object, message: str) -> None:
    if not isinstance(value, bool):
        raise GraphValidationError(message)


def _time(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")
