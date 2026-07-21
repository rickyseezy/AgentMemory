"""GRA-002 evidence-backed assertion aggregate and closed policies."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from typing import TYPE_CHECKING

from agentmemory.graph.domain.models import stable_graph_id

if TYPE_CHECKING:
    from datetime import datetime

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_MAX_CONFIDENCE = 10_000
_AUTOMATED_ACTIVATION_MINIMUM = 7_000
_MIN_INDEPENDENT_SOURCES = 2
_MAX_EVIDENCE = 64
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_ERR_CLASSIFICATION = "assertion classification is invalid"
_ERR_INTERVAL = "assertion temporal interval is invalid"
_ERR_CONFIDENCE = "assertion confidence is invalid"
_ERR_EXTRACTOR = "assertion extractor identity is invalid"
_ERR_EVIDENCE_KIND = "assertion evidence kind is invalid"
_ERR_EVIDENCE_STATE = "assertion evidence state is invalid"
_ERR_ENDPOINTS = "assertion endpoints are invalid"
_ERR_PREDICATE = "assertion predicate is invalid"
_ERR_CANDIDATE_STATUS = "assertion candidate status is invalid"
_ERR_EVIDENCE_IDS = "assertion evidence identities are invalid"
_ERR_FINGERPRINT = "assertion candidate fingerprint is invalid"
_ERR_STATUS = "assertion status is invalid"
_ERR_EVIDENCE_REQUIRED = "authoritative assertion evidence is required"
_ERR_TRANSITION = "only active assertions can reconcile evidence"
_ERR_UNRESOLVED = "assertion evidence is unresolved"
_ERR_UNAVAILABLE = "assertion evidence is unavailable"
_ERR_EVIDENCE_POLICY = "assertion evidence policy did not authorize activation"
_ERR_DIGEST = "assertion digest is invalid"
_ERR_TIME = "assertion time is not UTC"
_ERR_EVENT = "assertion lifecycle event is invalid"
_ERR_EVIDENCE_REFERENCE = "assertion evidence reference is invalid"
_ERR_REVOCATION = "assertion evidence revocation is invalid"
_ERR_TEMPORAL_POLICY = "assertion temporal policy did not authorize activation"


class AssertionValidationError(ValueError):
    """An assertion value violates the closed schema."""


class AssertionTransitionError(RuntimeError):
    """An assertion state transition is not reachable."""


class AssertionEvidenceError(PermissionError):
    """Evidence does not authorize assertion activation."""


class TemporalPolicy:
    """Closed temporal authorization rules for assertion activation."""

    @staticmethod
    def authorize_activation(
        candidate: AssertionCandidate,
        evidence: tuple[ResolvedAssertionEvidence, ...],
        activated_at: datetime,
    ) -> None:
        """Reject time travel and evidence that had not occurred at activation."""
        _require_utc(activated_at)
        if activated_at < candidate.temporal.recorded_from or any(
            item.occurred_at > activated_at for item in evidence
        ):
            raise AssertionEvidenceError(_ERR_TEMPORAL_POLICY)


class EvidencePolicy:
    """Closed evidence threshold and explicit-user-authority policy."""

    @staticmethod
    def authorize_activation(
        candidate: AssertionCandidate,
        evidence: tuple[ResolvedAssertionEvidence, ...],
    ) -> None:
        """Require exact usable lineage and governed authority strength."""
        _require_activation_evidence(candidate, evidence)


class AssertionPredicate(StrEnum):
    """Closed factual predicates eligible for later edge materialization."""

    CALLS = "calls"
    IMPORTS = "imports"
    CONSUMES = "consumes"
    IMPLEMENTS = "implements"
    DEPENDS_ON = "depends_on"
    PRODUCES = "produces"
    DEPLOYED_AS = "deployed_as"


class AssertionPolarity(StrEnum):
    """Closed polarity carried by every canonical assertion revision."""

    POSITIVE = "positive"
    NEGATIVE = "negative"


class AssertionStatus(StrEnum):
    """Closed authoritative assertion lifecycle."""

    CANDIDATE = "candidate"
    ACTIVE = "active"
    DISPUTED = "disputed"
    INVALIDATED = "invalidated"


class EvidenceKind(StrEnum):
    """Closed immutable evidence origins resolved by an EvidenceRepository."""

    EVENT = "event"
    ARTIFACT = "artifact"
    SOURCE_SPAN = "source_span"
    USER_STATEMENT = "user_statement"


class EvidenceRevocationReason(StrEnum):
    """Closed reasons that remove evidence from current assertion authority."""

    DELETED = "deleted"
    ACCESS_REVOKED = "access_revoked"
    SOURCE_INVALIDATED = "source_invalidated"
    USER_RETRACTED = "user_retracted"


class AssertionEventType(StrEnum):
    """Closed canonical lifecycle event types."""

    ACTIVATED = "AssertionActivated"
    DISPUTED = "AssertionDisputed"


@dataclass(frozen=True, slots=True)
class AssertionScope:
    """Exact Brain/workspace/classification coordinates for a factual claim."""

    brain_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    classification: str

    def __post_init__(self) -> None:
        """Require exact UUIDv7 coordinates and a closed classification."""
        for value in (self.brain_id, self.project_id, self.repository_id):
            stable_graph_id(value)
        if self.checkout_id is not None:
            stable_graph_id(self.checkout_id)
        if self.classification not in _CLASSIFICATIONS:
            raise AssertionValidationError(_ERR_CLASSIFICATION)


@dataclass(frozen=True, slots=True)
class AssertionTemporal:
    """Half-open valid and recorded intervals for a claim revision."""

    valid_from: datetime
    valid_to: datetime | None
    recorded_from: datetime
    recorded_to: datetime | None

    def __post_init__(self) -> None:
        """Require valid UTC half-open intervals."""
        for value in (self.valid_from, self.recorded_from):
            _require_utc(value)
        for start, end in (
            (self.valid_from, self.valid_to),
            (self.recorded_from, self.recorded_to),
        ):
            if end is not None:
                _require_utc(end)
                if end <= start:
                    raise AssertionValidationError(_ERR_INTERVAL)


@dataclass(frozen=True, slots=True)
class AssertionConfidence:
    """Deterministic basis-point confidence components."""

    evidence_support: int
    source_reliability: int
    extraction_quality: int

    def __post_init__(self) -> None:
        """Require integer basis points within the closed range."""
        values: tuple[object, ...] = (
            self.evidence_support,
            self.source_reliability,
            self.extraction_quality,
        )
        for value in values:
            _require_confidence(value)

    @property
    def automated_activation_eligible(self) -> bool:
        """Require every independent component to meet the governed threshold."""
        return (
            min(
                self.evidence_support,
                self.source_reliability,
                self.extraction_quality,
            )
            >= _AUTOMATED_ACTIVATION_MINIMUM
        )


@dataclass(frozen=True, slots=True)
class AssertionExtractor:
    """Immutable extractor/model identity; manual statements use the closed user extractor."""

    extractor_id: str
    extractor_version: str
    model_id: str
    model_revision: str

    def __post_init__(self) -> None:
        """Reject empty, mutable, or syntactically ambiguous identity parts."""
        values: tuple[object, ...] = (
            self.extractor_id,
            self.extractor_version,
            self.model_id,
            self.model_revision,
        )
        for value in values:
            _require_token(value)


@dataclass(frozen=True, slots=True)
class ResolvedAssertionEvidence:
    """Content-free immutable evidence metadata resolved under current authority."""

    evidence_id: str
    source_id: str
    kind: EvidenceKind
    scope: AssertionScope
    source_digest: str
    occurred_at: datetime
    accessible: bool
    deleted: bool
    immutable: bool

    def __post_init__(self) -> None:
        """Validate stable source identity, digest, time, kind, and state flags."""
        stable_graph_id(self.evidence_id)
        stable_graph_id(self.source_id)
        _require_evidence_kind(self.kind)
        _require_digest(self.source_digest)
        _require_utc(self.occurred_at)
        for value in (self.accessible, self.deleted, self.immutable):
            _require_bool(value)

    @property
    def usable(self) -> bool:
        """Return whether this exact evidence may currently support authority."""
        return self.accessible and not self.deleted and self.immutable


@dataclass(frozen=True, slots=True)
class AssertionEvidenceReference:
    """A typed reference to one canonical event, artifact, or artifact span."""

    evidence_id: str
    event_id: str
    kind: EvidenceKind
    artifact_id: str | None = None
    span_start: int | None = None
    span_end: int | None = None

    def __post_init__(self) -> None:
        """Reject URLs, free text, and invalid source-coordinate combinations."""
        stable_graph_id(self.evidence_id)
        stable_graph_id(self.event_id)
        _require_evidence_kind(self.kind)
        if self.artifact_id is not None:
            stable_graph_id(self.artifact_id)
        event_only = (
            self.kind in {EvidenceKind.EVENT, EvidenceKind.USER_STATEMENT}
            and self.artifact_id is None
            and self.span_start is None
            and self.span_end is None
        )
        artifact = (
            self.kind is EvidenceKind.ARTIFACT
            and self.artifact_id is not None
            and self.span_start is None
            and self.span_end is None
        )
        span = (
            self.kind is EvidenceKind.SOURCE_SPAN
            and self.artifact_id is not None
            and isinstance(self.span_start, int)
            and not isinstance(self.span_start, bool)
            and isinstance(self.span_end, int)
            and not isinstance(self.span_end, bool)
            and self.span_start >= 0
            and self.span_end > self.span_start
        )
        if not (event_only or artifact or span):
            raise AssertionValidationError(_ERR_EVIDENCE_REFERENCE)


@dataclass(frozen=True, slots=True)
class AssertionEvidenceRevocation:
    """An immutable request to withdraw one registered evidence handle."""

    operation_id: str
    evidence_id: str
    reason: EvidenceRevocationReason
    revoked_at: datetime

    def __post_init__(self) -> None:
        """Require a stable evidence ID, closed reason, and UTC boundary."""
        _require_operation_id(self.operation_id)
        stable_graph_id(self.evidence_id)
        _require_revocation_reason(self.reason)
        _require_utc(self.revoked_at)


@dataclass(frozen=True, slots=True)
class AssertionCandidate:
    """A proposed claim that has no authority until evidence policy activates it."""

    id: str
    subject_id: str
    predicate: AssertionPredicate
    object_id: str
    scope: AssertionScope
    temporal: AssertionTemporal
    confidence: AssertionConfidence
    extractor: AssertionExtractor
    evidence_ids: tuple[str, ...]
    content_fingerprint: str
    revision_id: str
    status: AssertionStatus = AssertionStatus.CANDIDATE
    polarity: AssertionPolarity = AssertionPolarity.POSITIVE

    @classmethod
    def create(  # noqa: PLR0913 -- Complete claim schema is mandatory.
        cls,
        *,
        candidate_id: str,
        subject_id: str,
        predicate: AssertionPredicate,
        object_id: str,
        scope: AssertionScope,
        temporal: AssertionTemporal,
        confidence: AssertionConfidence,
        extractor: AssertionExtractor,
        evidence_ids: tuple[str, ...],
        polarity: AssertionPolarity = AssertionPolarity.POSITIVE,
    ) -> AssertionCandidate:
        """Create a deterministic candidate without granting it authority."""
        normalized_evidence = tuple(sorted(evidence_ids))
        fingerprint = _fingerprint(
            subject_id,
            predicate,
            object_id,
            scope,
            temporal,
            confidence,
            extractor,
            normalized_evidence,
            polarity,
        )
        return cls(
            candidate_id,
            subject_id,
            predicate,
            object_id,
            scope,
            temporal,
            confidence,
            extractor,
            normalized_evidence,
            fingerprint,
            _revision(candidate_id, fingerprint),
            AssertionStatus.CANDIDATE,
            polarity,
        )

    def __post_init__(self) -> None:
        """Verify endpoints, registry values, evidence set, and deterministic identity."""
        for value in (self.id, self.subject_id, self.object_id):
            stable_graph_id(value)
        if self.subject_id == self.object_id:
            raise AssertionValidationError(_ERR_ENDPOINTS)
        _require_predicate(self.predicate)
        _require_polarity(self.polarity)
        if self.status is not AssertionStatus.CANDIDATE:
            raise AssertionValidationError(_ERR_CANDIDATE_STATUS)
        if len(self.evidence_ids) > _MAX_EVIDENCE or self.evidence_ids != tuple(
            sorted(set(self.evidence_ids))
        ):
            raise AssertionValidationError(_ERR_EVIDENCE_IDS)
        for evidence_id in self.evidence_ids:
            stable_graph_id(evidence_id)
        if self.temporal.recorded_to is not None:
            raise AssertionValidationError(_ERR_INTERVAL)
        expected = _fingerprint(
            self.subject_id,
            self.predicate,
            self.object_id,
            self.scope,
            self.temporal,
            self.confidence,
            self.extractor,
            self.evidence_ids,
            self.polarity,
        )
        if self.content_fingerprint != expected or self.revision_id != _revision(self.id, expected):
            raise AssertionValidationError(_ERR_FINGERPRINT)

    def activate(
        self,
        evidence: tuple[ResolvedAssertionEvidence, ...],
        activated_at: datetime,
    ) -> Assertion:
        """Activate only with exact usable, scoped evidence and governed authority."""
        TemporalPolicy.authorize_activation(self, evidence, activated_at)
        EvidencePolicy.authorize_activation(self, evidence)
        return Assertion(
            self.id,
            self.subject_id,
            self.predicate,
            self.object_id,
            self.scope,
            AssertionTemporal(
                self.temporal.valid_from,
                self.temporal.valid_to,
                activated_at,
                None,
            ),
            self.confidence,
            self.extractor,
            tuple(sorted(evidence, key=lambda item: item.evidence_id)),
            self.content_fingerprint,
            self.revision_id,
            AssertionStatus.ACTIVE,
            self.polarity,
        )


@dataclass(frozen=True, slots=True)
class Assertion:
    """An authoritative evidence-backed claim revision."""

    id: str
    subject_id: str
    predicate: AssertionPredicate
    object_id: str
    scope: AssertionScope
    temporal: AssertionTemporal
    confidence: AssertionConfidence
    extractor: AssertionExtractor
    evidence: tuple[ResolvedAssertionEvidence, ...]
    content_fingerprint: str
    revision_id: str
    status: AssertionStatus
    polarity: AssertionPolarity = AssertionPolarity.POSITIVE

    def __post_init__(self) -> None:
        """Require authoritative status, stable identity, digests, and evidence."""
        for value in (self.id, self.subject_id, self.object_id):
            stable_graph_id(value)
        _require_digest(self.content_fingerprint)
        _require_digest(self.revision_id)
        _require_polarity(self.polarity)
        if self.status not in {
            AssertionStatus.ACTIVE,
            AssertionStatus.DISPUTED,
            AssertionStatus.INVALIDATED,
        }:
            raise AssertionValidationError(_ERR_STATUS)
        if not self.evidence:
            raise AssertionValidationError(_ERR_EVIDENCE_REQUIRED)

    def reconcile_evidence(
        self,
        evidence: tuple[ResolvedAssertionEvidence, ...],
        recorded_at: datetime,
    ) -> Assertion:
        """Dispute an active assertion when all supporting evidence loses authority."""
        _require_utc(recorded_at)
        if self.status is not AssertionStatus.ACTIVE:
            raise AssertionTransitionError(_ERR_TRANSITION)
        usable = tuple(item for item in evidence if item.usable and item.scope == self.scope)
        if usable:
            return self
        return Assertion(
            self.id,
            self.subject_id,
            self.predicate,
            self.object_id,
            self.scope,
            AssertionTemporal(
                self.temporal.valid_from,
                self.temporal.valid_to,
                self.temporal.recorded_from,
                recorded_at,
            ),
            self.confidence,
            self.extractor,
            self.evidence,
            self.content_fingerprint,
            self.revision_id,
            AssertionStatus.DISPUTED,
            self.polarity,
        )


@dataclass(frozen=True, slots=True)
class AssertionLifecycleEvent:
    """Content-free, digest-authenticated assertion transition evidence."""

    event_id: str
    operation_id: str
    assertion_id: str
    revision_id: str
    event_type: AssertionEventType
    status: AssertionStatus
    evidence_ids: tuple[str, ...]
    occurred_at: datetime
    digest: str

    @classmethod
    def create(
        cls,
        *,
        event_id: str,
        operation_id: str,
        assertion: Assertion,
        event_type: AssertionEventType,
        occurred_at: datetime,
    ) -> AssertionLifecycleEvent:
        """Bind one content-free transition to its assertion revision and evidence IDs."""
        evidence_ids = tuple(sorted(item.evidence_id for item in assertion.evidence))
        digest = _event_digest(
            event_id,
            operation_id,
            assertion.id,
            assertion.revision_id,
            event_type,
            assertion.status,
            evidence_ids,
            occurred_at,
        )
        return cls(
            event_id,
            operation_id,
            assertion.id,
            assertion.revision_id,
            event_type,
            assertion.status,
            evidence_ids,
            occurred_at,
            digest,
        )

    def __post_init__(self) -> None:
        """Reject forged, content-bearing, or mismatched lifecycle evidence."""
        stable_graph_id(self.event_id)
        stable_graph_id(self.assertion_id)
        _require_operation_id(self.operation_id)
        _require_digest(self.revision_id)
        _require_utc(self.occurred_at)
        for value in self.evidence_ids:
            stable_graph_id(value)
        if self.evidence_ids != tuple(sorted(set(self.evidence_ids))):
            raise AssertionValidationError(_ERR_EVENT)
        if (
            self.event_type is AssertionEventType.ACTIVATED
            and self.status is not AssertionStatus.ACTIVE
        ) or (
            self.event_type is AssertionEventType.DISPUTED
            and self.status is not AssertionStatus.DISPUTED
        ):
            raise AssertionValidationError(_ERR_EVENT)
        expected = _event_digest(
            self.event_id,
            self.operation_id,
            self.assertion_id,
            self.revision_id,
            self.event_type,
            self.status,
            self.evidence_ids,
            self.occurred_at,
        )
        if self.digest != expected:
            raise AssertionValidationError(_ERR_EVENT)


def _require_activation_evidence(
    candidate: AssertionCandidate,
    evidence: tuple[ResolvedAssertionEvidence, ...],
) -> None:
    if tuple(sorted(item.evidence_id for item in evidence)) != candidate.evidence_ids:
        raise AssertionEvidenceError(_ERR_UNRESOLVED)
    if not evidence or any(not item.usable for item in evidence):
        raise AssertionEvidenceError(_ERR_UNAVAILABLE)
    if candidate.predicate is AssertionPredicate.CONSUMES:
        same_brain_and_classification = all(
            item.scope.brain_id == candidate.scope.brain_id
            and item.scope.classification == candidate.scope.classification
            for item in evidence
        )
        client_scope_is_evidenced = any(item.scope == candidate.scope for item in evidence)
        if not same_brain_and_classification or not client_scope_is_evidenced:
            raise AssertionEvidenceError(_ERR_UNAVAILABLE)
    elif any(item.scope != candidate.scope for item in evidence):
        raise AssertionEvidenceError(_ERR_UNAVAILABLE)
    explicit = any(item.kind is EvidenceKind.USER_STATEMENT for item in evidence)
    independent_sources = {item.source_id for item in evidence}
    exact_deterministic_artifact = (
        candidate.extractor.extractor_id == "artifact-topology-parser"
        and candidate.extractor.model_id == "deterministic"
        and candidate.predicate
        in {
            AssertionPredicate.DEPENDS_ON,
            AssertionPredicate.DEPLOYED_AS,
            AssertionPredicate.PRODUCES,
            AssertionPredicate.CONSUMES,
        }
        and len(evidence) == 1
        and evidence[0].kind in {EvidenceKind.ARTIFACT, EvidenceKind.SOURCE_SPAN}
        and evidence[0].immutable
    )
    if (
        not explicit
        and not exact_deterministic_artifact
        and (
            not candidate.confidence.automated_activation_eligible
            or len(independent_sources) < _MIN_INDEPENDENT_SOURCES
        )
    ):
        raise AssertionEvidenceError(_ERR_EVIDENCE_POLICY)


def _fingerprint(  # noqa: PLR0913 -- Fingerprint binds every claim coordinate.
    subject_id: str,
    predicate: AssertionPredicate,
    object_id: str,
    scope: AssertionScope,
    temporal: AssertionTemporal,
    confidence: AssertionConfidence,
    extractor: AssertionExtractor,
    evidence_ids: tuple[str, ...],
    polarity: AssertionPolarity,
) -> str:
    document = {
        "confidence": {
            "evidence_support": confidence.evidence_support,
            "extraction_quality": confidence.extraction_quality,
            "source_reliability": confidence.source_reliability,
        },
        "evidence_ids": list(evidence_ids),
        "extractor": {
            "extractor_id": extractor.extractor_id,
            "extractor_version": extractor.extractor_version,
            "model_id": extractor.model_id,
            "model_revision": extractor.model_revision,
        },
        "object_id": object_id,
        "predicate": predicate.value,
        "scope": {
            "brain_id": scope.brain_id,
            "checkout_id": scope.checkout_id,
            "classification": scope.classification,
            "project_id": scope.project_id,
            "repository_id": scope.repository_id,
        },
        "subject_id": subject_id,
        "temporal": {
            "recorded_from": _time(temporal.recorded_from),
            "recorded_to": _optional_time(temporal.recorded_to),
            "valid_from": _time(temporal.valid_from),
            "valid_to": _optional_time(temporal.valid_to),
        },
    }
    if polarity is AssertionPolarity.NEGATIVE:
        document["polarity"] = polarity.value
    encoded = json.dumps(
        document, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _revision(assertion_id: str, fingerprint: str) -> str:
    stable_graph_id(assertion_id)
    _require_digest(fingerprint)
    return hashlib.sha256(
        b"assertion-revision.v1\x00" + assertion_id.encode() + b"\x00" + fingerprint.encode()
    ).hexdigest()


def _event_digest(  # noqa: PLR0913 -- Digest binds the complete event envelope.
    event_id: str,
    operation_id: str,
    assertion_id: str,
    revision_id: str,
    event_type: AssertionEventType,
    status: AssertionStatus,
    evidence_ids: tuple[str, ...],
    occurred_at: datetime,
) -> str:
    document = {
        "assertion_id": assertion_id,
        "event_id": event_id,
        "event_type": event_type.value,
        "evidence_ids": list(evidence_ids),
        "occurred_at": _time(occurred_at),
        "operation_id": operation_id,
        "revision_id": revision_id,
        "status": status.value,
    }
    return hashlib.sha256(
        json.dumps(document, separators=(",", ":"), sort_keys=True).encode()
    ).hexdigest()


def _require_digest(value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise AssertionValidationError(_ERR_DIGEST)


def _require_confidence(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _MAX_CONFIDENCE:
        raise AssertionValidationError(_ERR_CONFIDENCE)


def _require_token(value: object) -> None:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise AssertionValidationError(_ERR_EXTRACTOR)


def _require_evidence_kind(value: object) -> None:
    if not isinstance(value, EvidenceKind):
        raise AssertionValidationError(_ERR_EVIDENCE_KIND)


def _require_revocation_reason(value: object) -> None:
    if not isinstance(value, EvidenceRevocationReason):
        raise AssertionValidationError(_ERR_REVOCATION)


def _require_predicate(value: object) -> None:
    if not isinstance(value, AssertionPredicate):
        raise AssertionValidationError(_ERR_PREDICATE)


def _require_polarity(value: object) -> None:
    if not isinstance(value, AssertionPolarity):
        raise AssertionValidationError(_ERR_PREDICATE)


def _require_bool(value: object) -> None:
    if not isinstance(value, bool):
        raise AssertionValidationError(_ERR_EVIDENCE_STATE)


def _require_operation_id(value: object) -> None:
    if not isinstance(value, str) or _TOKEN.fullmatch(value) is None:
        raise AssertionValidationError(_ERR_EVENT)


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise AssertionValidationError(_ERR_TIME)


def _time(value: datetime) -> str:
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _optional_time(value: datetime | None) -> str | None:
    return None if value is None else _time(value)
