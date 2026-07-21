"""GRA-005 explicit contradiction aggregates and retrieval abstention policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
from typing import cast

from agentmemory.graph.domain.assertions import AssertionPolarity, AssertionPredicate
from agentmemory.graph.domain.models import stable_graph_id

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_MAX_EVIDENCE = 128
_MAX_CANDIDATES = 2_000
_MAX_BASIS_POINTS = 10_000
_POLICY_VERSION = "graph-contradiction.v1"
_EXCLUSIVE_OBJECT_PREDICATES = frozenset({AssertionPredicate.DEPLOYED_AS})
_ERR_CANDIDATE = "contradiction candidate is invalid"
_ERR_DETECTION = "contradiction detection is invalid"
_ERR_RESOLUTION = "contradiction resolution is invalid"
_ERR_POLICY = "contradiction retrieval policy input is invalid"


class ContradictionValidationError(ValueError):
    """Contradiction data violates the closed deterministic contract."""


class AssertionAuthority(StrEnum):
    """Closed authority class; model-only candidates never establish a dispute."""

    EVIDENCE_BACKED = "evidence_backed"
    USER_STATEMENT = "user_statement"
    MODEL_ONLY = "model_only"

    @property
    def decisive(self) -> bool:
        """Return whether the assertion may participate in domain truth."""
        return self is not AssertionAuthority.MODEL_ONLY


class ConflictDimension(StrEnum):
    """Closed dimensions emitted by incompatibility rules."""

    POLARITY = "polarity"
    EXCLUSIVE_OBJECT = "exclusive_object"


class ContradictionState(StrEnum):
    """Append-only contradiction lifecycle state."""

    UNRESOLVED = "unresolved"
    RESOLVED = "resolved"


class ContradictionResolutionOutcome(StrEnum):
    """Closed user-authoritative resolution outcomes."""

    LEFT_ASSERTION = "left_assertion"
    RIGHT_ASSERTION = "right_assertion"
    BOTH_VALID = "both_valid"
    NEITHER_VALID = "neither_valid"


class ContradictionDecision(StrEnum):
    """Truth qualification returned after rank fusion."""

    CERTAIN = "certain"
    QUALIFIED = "qualified"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ContradictionCandidate:
    """Content-free assertion metadata eligible for deterministic conflict detection."""

    assertion_id: str
    subject_id: str
    predicate: AssertionPredicate
    object_id: str
    polarity: AssertionPolarity
    authority: AssertionAuthority
    valid_from: datetime
    valid_to: datetime | None
    evidence_ids: tuple[str, ...]
    confidence_basis_points: int

    def __post_init__(self) -> None:
        """Reject forged identities, open registries, and noncanonical evidence."""
        for value in (self.assertion_id, self.subject_id, self.object_id):
            _stable_id(value, _ERR_CANDIDATE)
        if self.subject_id == self.object_id:
            raise ContradictionValidationError(_ERR_CANDIDATE)
        _enum(self.predicate, AssertionPredicate, _ERR_CANDIDATE)
        _enum(self.polarity, AssertionPolarity, _ERR_CANDIDATE)
        _enum(self.authority, AssertionAuthority, _ERR_CANDIDATE)
        _interval(self.valid_from, self.valid_to, _ERR_CANDIDATE)
        if (
            not self.evidence_ids
            or len(self.evidence_ids) > _MAX_EVIDENCE
            or self.evidence_ids != tuple(sorted(set(self.evidence_ids)))
        ):
            raise ContradictionValidationError(_ERR_CANDIDATE)
        for evidence_id in self.evidence_ids:
            _stable_id(evidence_id, _ERR_CANDIDATE)
        _basis_points(self.confidence_basis_points, _ERR_CANDIDATE)


@dataclass(frozen=True, slots=True)
class ContradictionResolution:
    """Immutable explicit resolution authority and supporting evidence."""

    contradiction_id: str
    outcome: ContradictionResolutionOutcome
    actor_id: str
    grant_id: str
    reason_code: str
    evidence_ids: tuple[str, ...]
    resolved_at: datetime
    resolution_digest: str
    policy_version: str = _POLICY_VERSION

    @classmethod
    def create(  # noqa: PLR0913 -- Digest binds all resolution authority coordinates.
        cls,
        *,
        contradiction_id: str,
        outcome: ContradictionResolutionOutcome,
        actor_id: str,
        grant_id: str,
        reason_code: str,
        evidence_ids: tuple[str, ...],
        resolved_at: datetime,
    ) -> ContradictionResolution:
        """Create a digest-bound user-authoritative resolution."""
        normalized = tuple(sorted(evidence_ids))
        digest = _digest(
            {
                "actor_id": actor_id,
                "contradiction_id": contradiction_id,
                "evidence_ids": normalized,
                "grant_id": grant_id,
                "outcome": _enum_value(outcome),
                "policy_version": _POLICY_VERSION,
                "reason_code": reason_code,
                "resolved_at": _time(resolved_at),
            }
        )
        return cls(
            contradiction_id,
            outcome,
            actor_id,
            grant_id,
            reason_code,
            normalized,
            resolved_at,
            digest,
        )

    def __post_init__(self) -> None:
        """Authenticate resolution coordinates and canonical digest."""
        _digest_value(self.contradiction_id, _ERR_RESOLUTION)
        _enum(self.outcome, ContradictionResolutionOutcome, _ERR_RESOLUTION)
        for value in (self.actor_id, self.grant_id):
            _stable_id(value, _ERR_RESOLUTION)
        if _REASON.fullmatch(self.reason_code) is None:
            raise ContradictionValidationError(_ERR_RESOLUTION)
        if (
            not self.evidence_ids
            or len(self.evidence_ids) > _MAX_EVIDENCE
            or self.evidence_ids != tuple(sorted(set(self.evidence_ids)))
        ):
            raise ContradictionValidationError(_ERR_RESOLUTION)
        for evidence_id in self.evidence_ids:
            _stable_id(evidence_id, _ERR_RESOLUTION)
        _utc(self.resolved_at, _ERR_RESOLUTION)
        if self.policy_version != _POLICY_VERSION:
            raise ContradictionValidationError(_ERR_RESOLUTION)
        expected = _digest(
            {
                "actor_id": self.actor_id,
                "contradiction_id": self.contradiction_id,
                "evidence_ids": self.evidence_ids,
                "grant_id": self.grant_id,
                "outcome": _enum_value(self.outcome),
                "policy_version": self.policy_version,
                "reason_code": self.reason_code,
                "resolved_at": _time(self.resolved_at),
            }
        )
        if self.resolution_digest != expected:
            raise ContradictionValidationError(_ERR_RESOLUTION)


@dataclass(frozen=True, slots=True)
class Contradiction:
    """One immutable assertion conflict with optional append-only resolution."""

    id: str
    left_assertion_id: str
    right_assertion_id: str
    predicate: AssertionPredicate
    dimension: ConflictDimension
    valid_from: datetime
    valid_to: datetime | None
    evidence_ids: tuple[str, ...]
    detected_at: datetime
    state: ContradictionState
    detection_digest: str
    resolution: ContradictionResolution | None = None
    policy_version: str = _POLICY_VERSION

    def __post_init__(self) -> None:
        """Verify canonical pair order, overlap, state, evidence, and digests."""
        _digest_value(self.id, _ERR_DETECTION)
        for value in (self.left_assertion_id, self.right_assertion_id):
            _stable_id(value, _ERR_DETECTION)
        if self.left_assertion_id >= self.right_assertion_id:
            raise ContradictionValidationError(_ERR_DETECTION)
        _enum(self.predicate, AssertionPredicate, _ERR_DETECTION)
        _enum(self.dimension, ConflictDimension, _ERR_DETECTION)
        _interval(self.valid_from, self.valid_to, _ERR_DETECTION)
        _utc(self.detected_at, _ERR_DETECTION)
        if (
            not self.evidence_ids
            or len(self.evidence_ids) > _MAX_EVIDENCE
            or self.evidence_ids != tuple(sorted(set(self.evidence_ids)))
        ):
            raise ContradictionValidationError(_ERR_DETECTION)
        for evidence_id in self.evidence_ids:
            _stable_id(evidence_id, _ERR_DETECTION)
        _enum(self.state, ContradictionState, _ERR_DETECTION)
        if self.policy_version != _POLICY_VERSION:
            raise ContradictionValidationError(_ERR_DETECTION)
        expected_id = _conflict_id(
            self.left_assertion_id,
            self.right_assertion_id,
            self.predicate,
            self.dimension,
            self.valid_from,
            self.valid_to,
            self.evidence_ids,
        )
        expected_detection = _detection_digest(
            expected_id,
            self.detected_at,
        )
        if self.id != expected_id or self.detection_digest != expected_detection:
            raise ContradictionValidationError(_ERR_DETECTION)
        if (self.state is ContradictionState.UNRESOLVED) != (self.resolution is None):
            raise ContradictionValidationError(_ERR_RESOLUTION)
        if self.resolution is not None and (
            self.resolution.contradiction_id != self.id
            or self.resolution.resolved_at < self.detected_at
        ):
            raise ContradictionValidationError(_ERR_RESOLUTION)

    def resolve(self, resolution: ContradictionResolution) -> Contradiction:
        """Return a resolved revision while retaining the complete dispute identity."""
        if (
            self.state is not ContradictionState.UNRESOLVED
            or resolution.contradiction_id != self.id
        ):
            raise ContradictionValidationError(_ERR_RESOLUTION)
        if resolution.resolved_at < self.detected_at:
            raise ContradictionValidationError(_ERR_RESOLUTION)
        return replace(self, state=ContradictionState.RESOLVED, resolution=resolution)


class ContradictionDetector:
    """Deterministic predicate-specific incompatibility rules."""

    @staticmethod
    def detect(
        candidates: tuple[ContradictionCandidate, ...], detected_at: datetime
    ) -> tuple[Contradiction, ...]:
        """Return canonical decisive conflicts without elevating model-only output."""
        _utc(detected_at, _ERR_DETECTION)
        if len(candidates) > _MAX_CANDIDATES:
            raise ContradictionValidationError(_ERR_DETECTION)
        ordered = tuple(sorted(candidates, key=lambda item: item.assertion_id))
        if len({item.assertion_id for item in ordered}) != len(ordered):
            raise ContradictionValidationError(_ERR_DETECTION)
        conflicts: list[Contradiction] = []
        for index, left in enumerate(ordered):
            for right in ordered[index + 1 :]:
                dimension = _dimension(left, right)
                overlap = _overlap(left, right)
                if dimension is None or overlap is None:
                    continue
                evidence = tuple(sorted(set(left.evidence_ids) | set(right.evidence_ids)))
                contradiction_id = _conflict_id(
                    left.assertion_id,
                    right.assertion_id,
                    left.predicate,
                    dimension,
                    overlap[0],
                    overlap[1],
                    evidence,
                )
                detection_digest = _detection_digest(
                    contradiction_id,
                    detected_at,
                )
                conflicts.append(
                    Contradiction(
                        contradiction_id,
                        left.assertion_id,
                        right.assertion_id,
                        left.predicate,
                        dimension,
                        overlap[0],
                        overlap[1],
                        evidence,
                        detected_at,
                        ContradictionState.UNRESOLVED,
                        detection_digest,
                    )
                )
        return tuple(conflicts)


@dataclass(frozen=True, slots=True)
class RetrievalAssertionCandidate:
    """One already-fused retrieval candidate presented to contradiction policy."""

    assertion_id: str
    rank_basis_points: int
    authoritative: bool

    def __post_init__(self) -> None:
        """Validate content-free rank input without treating rank as authority."""
        _stable_id(self.assertion_id, _ERR_POLICY)
        _basis_points(self.rank_basis_points, _ERR_POLICY)
        if not isinstance(cast("object", self.authoritative), bool):
            raise ContradictionValidationError(_ERR_POLICY)


@dataclass(frozen=True, slots=True)
class ContradictionPolicyResult:
    """Deterministic truth decision after candidate fusion."""

    decision: ContradictionDecision
    selected_assertion_ids: tuple[str, ...]
    disputed_assertion_ids: tuple[str, ...]
    contradiction_ids: tuple[str, ...]


class ContradictionPolicy:
    """Qualify or abstain after rank fusion and before response synthesis."""

    @staticmethod
    def apply(
        candidates: tuple[RetrievalAssertionCandidate, ...],
        contradictions: tuple[Contradiction, ...],
    ) -> ContradictionPolicyResult:
        """Never permit relevance rank to erase an unresolved decisive conflict."""
        if len({item.assertion_id for item in candidates}) != len(candidates):
            raise ContradictionValidationError(_ERR_POLICY)
        candidate_ids = {item.assertion_id for item in candidates}
        selected = {item.assertion_id for item in candidates if item.authoritative}
        disputed: set[str] = set()
        relevant: list[Contradiction] = []
        unresolved_complete = False
        qualified = False
        for contradiction in contradictions:
            pair = {contradiction.left_assertion_id, contradiction.right_assertion_id}
            if not pair & candidate_ids:
                continue
            relevant.append(contradiction)
            if contradiction.state is ContradictionState.UNRESOLVED:
                disputed.update(pair & candidate_ids)
                if pair <= candidate_ids:
                    unresolved_complete = True
                    selected.difference_update(pair)
                else:
                    qualified = True
                continue
            resolution = cast("ContradictionResolution", contradiction.resolution)
            _apply_resolution(selected, pair, contradiction, resolution)
        if unresolved_complete or not selected:
            decision = ContradictionDecision.UNKNOWN
        elif qualified or disputed or any(not item.authoritative for item in candidates):
            decision = ContradictionDecision.QUALIFIED
        else:
            decision = ContradictionDecision.CERTAIN
        return ContradictionPolicyResult(
            decision,
            tuple(
                item.assertion_id
                for item in sorted(
                    candidates,
                    key=lambda value: (-value.rank_basis_points, value.assertion_id),
                )
                if item.assertion_id in selected
            ),
            tuple(sorted(disputed)),
            tuple(sorted(item.id for item in relevant)),
        )


def _dimension(
    left: ContradictionCandidate, right: ContradictionCandidate
) -> ConflictDimension | None:
    if (
        not left.authority.decisive
        or not right.authority.decisive
        or left.subject_id != right.subject_id
        or left.predicate is not right.predicate
    ):
        return None
    if left.object_id == right.object_id and left.polarity is not right.polarity:
        return ConflictDimension.POLARITY
    if (
        left.predicate in _EXCLUSIVE_OBJECT_PREDICATES
        and left.polarity is AssertionPolarity.POSITIVE
        and right.polarity is AssertionPolarity.POSITIVE
        and left.object_id != right.object_id
    ):
        return ConflictDimension.EXCLUSIVE_OBJECT
    return None


def _overlap(
    left: ContradictionCandidate, right: ContradictionCandidate
) -> tuple[datetime, datetime | None] | None:
    start = max(left.valid_from, right.valid_from)
    ends = tuple(value for value in (left.valid_to, right.valid_to) if value is not None)
    end = min(ends) if ends else None
    if end is not None and start >= end:
        return None
    return start, end


def _apply_resolution(
    selected: set[str],
    pair: set[str],
    contradiction: Contradiction,
    resolution: ContradictionResolution,
) -> None:
    if resolution.outcome is ContradictionResolutionOutcome.LEFT_ASSERTION:
        selected.discard(contradiction.right_assertion_id)
    elif resolution.outcome is ContradictionResolutionOutcome.RIGHT_ASSERTION:
        selected.discard(contradiction.left_assertion_id)
    elif resolution.outcome is ContradictionResolutionOutcome.NEITHER_VALID:
        selected.difference_update(pair)


def _conflict_id(  # noqa: PLR0913 -- Identity binds the complete conflict fact.
    left_assertion_id: str,
    right_assertion_id: str,
    predicate: AssertionPredicate,
    dimension: ConflictDimension,
    valid_from: datetime,
    valid_to: datetime | None,
    evidence_ids: tuple[str, ...],
) -> str:
    return _digest(
        {
            "dimension": dimension.value,
            "evidence_ids": evidence_ids,
            "left_assertion_id": left_assertion_id,
            "policy_version": _POLICY_VERSION,
            "predicate": predicate.value,
            "right_assertion_id": right_assertion_id,
            "valid_from": _time(valid_from),
            "valid_to": None if valid_to is None else _time(valid_to),
        }
    )


def _detection_digest(contradiction_id: str, detected_at: datetime) -> str:
    return _digest(
        {
            "contradiction_id": contradiction_id,
            "detected_at": _time(detected_at),
            "policy_version": _POLICY_VERSION,
        }
    )


def _digest(document: dict[str, object]) -> str:
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )
    return hashlib.sha256(encoded).hexdigest()


def _time(value: datetime) -> str:
    _utc(value, _ERR_DETECTION)
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _interval(start: datetime, end: datetime | None, message: str) -> None:
    _utc(start, message)
    if end is not None:
        _utc(end, message)
        if end <= start:
            raise ContradictionValidationError(message)


def _utc(value: object, message: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ContradictionValidationError(message)


def _stable_id(value: object, message: str) -> None:
    if not isinstance(value, str):
        raise ContradictionValidationError(message)
    try:
        stable_graph_id(value)
    except ValueError as error:
        raise ContradictionValidationError(message) from error


def _digest_value(value: object, message: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise ContradictionValidationError(message)


def _basis_points(value: object, message: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= _MAX_BASIS_POINTS:
        raise ContradictionValidationError(message)


def _enum(value: object, enum_type: type[StrEnum], message: str) -> None:
    if not isinstance(value, enum_type):
        raise ContradictionValidationError(message)


def _enum_value(value: object) -> str:
    if not isinstance(value, StrEnum):
        raise ContradictionValidationError(_ERR_RESOLUTION)
    return value.value
