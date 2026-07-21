"""GRA-003 deterministic materialized assertion edges and integrity policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import UTC
from enum import StrEnum
from typing import TYPE_CHECKING, ClassVar, cast
from uuid import UUID

from agentmemory.graph.domain.assertions import AssertionPredicate, AssertionStatus
from agentmemory.graph.domain.errors import GraphValidationError
from agentmemory.graph.domain.models import (
    GraphClassification,
    GraphRelationshipType,
    stable_graph_id,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from agentmemory.graph.domain.assertions import Assertion

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SCHEMA_VERSION = 1
_ACTIVE_VERSION = 1
_RETIRED_VERSION = 2
_MAX_JOB_ATTEMPTS = 1_000
_ERR_ASSERTION_STATUS = "assertion status cannot be materialized"
_ERR_DOCUMENT = "materialized assertion edge document is invalid"
_ERR_GENERATION = "materialized assertion edge generation is invalid"
_ERR_INTEGRITY = "materialized assertion edge integrity is invalid"
_ERR_QUARANTINE = "materialized assertion edge quarantine is invalid"
_ERR_PREDICATE = "materialized assertion predicate is invalid"
_ERR_SCOPE = "materialized assertion edge scope is invalid"
_ERR_TIME = "materialized assertion edge time is invalid"
_ERR_VERSION = "materialized assertion edge version is invalid"
_ERR_WORK = "materialized assertion edge work item is invalid"


class ProjectionEdgeStatus(StrEnum):
    """Retrieval-visible lifecycle of one denormalized assertion edge."""

    ACTIVE = "active"
    RETIRED = "retired"


class EdgeIntegrityFindingKind(StrEnum):
    """Closed bidirectional projection mismatch taxonomy."""

    ORPHAN = "orphan"
    MISSING = "missing"
    MISMATCH = "mismatch"


class ProjectionJobFailureCode(StrEnum):
    """Closed safe failure reasons persisted by the durable projection worker."""

    AUTHORIZATION_REVOKED = "authorization_revoked"
    CONCURRENT_CONFLICT = "concurrent_conflict"
    DEPENDENCY_UNAVAILABLE = "dependency_unavailable"
    GENERATION_UNAVAILABLE = "generation_unavailable"
    INTEGRITY_VIOLATION = "integrity_violation"
    INTERNAL_ERROR = "internal_error"


class PredicateRegistry:
    """Map factual predicates to reviewed relationship types only."""

    _MAPPING: ClassVar[dict[AssertionPredicate, GraphRelationshipType]] = {
        AssertionPredicate.CALLS: GraphRelationshipType.CALLS,
        AssertionPredicate.IMPORTS: GraphRelationshipType.IMPORTS,
        AssertionPredicate.CONSUMES: GraphRelationshipType.CONSUMES,
        AssertionPredicate.IMPLEMENTS: GraphRelationshipType.IMPLEMENTS,
        AssertionPredicate.DEPENDS_ON: GraphRelationshipType.DEPENDS_ON,
        AssertionPredicate.PRODUCES: GraphRelationshipType.PRODUCES,
        AssertionPredicate.DEPLOYED_AS: GraphRelationshipType.DEPLOYED_AS,
    }

    @classmethod
    def relationship_type(cls, predicate: object) -> GraphRelationshipType:
        """Return the exact closed relationship type for a validated predicate."""
        if not _is_instance(predicate, AssertionPredicate):
            raise GraphValidationError(_ERR_PREDICATE)
        return cls._MAPPING[cast("AssertionPredicate", predicate)]


@dataclass(frozen=True, slots=True)
class MaterializedAssertionEdge:
    """One rebuildable direct edge whose authority remains a canonical Assertion."""

    id: str
    assertion_id: str
    assertion_revision_id: str
    source_event_id: str
    brain_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    relationship_type: GraphRelationshipType
    subject_id: str
    object_id: str
    classification: GraphClassification
    valid_from: datetime
    valid_to: datetime | None
    recorded_from: datetime
    recorded_to: datetime | None
    aggregate_version: int
    projection_status: ProjectionEdgeStatus
    generation_id: str
    schema_version: int
    projected_at: datetime
    content_fingerprint: str
    projection_digest: str
    quarantined: bool = False
    quarantine_reason: str | None = None

    @classmethod
    def from_assertion(
        cls,
        assertion: Assertion,
        *,
        source_event_id: str,
        generation_id: str,
        projected_at: datetime,
    ) -> MaterializedAssertionEdge:
        """Create the deterministic expected edge for the latest assertion lifecycle."""
        if assertion.status is AssertionStatus.ACTIVE:
            aggregate_version = _ACTIVE_VERSION
            status = ProjectionEdgeStatus.ACTIVE
        elif assertion.status in {AssertionStatus.DISPUTED, AssertionStatus.INVALIDATED}:
            aggregate_version = _RETIRED_VERSION
            status = ProjectionEdgeStatus.RETIRED
        else:
            raise GraphValidationError(_ERR_ASSERTION_STATUS)
        values: dict[str, object] = {
            "id": _projection_edge_id(assertion.id, generation_id),
            "assertion_id": assertion.id,
            "assertion_revision_id": assertion.revision_id,
            "source_event_id": source_event_id,
            "brain_id": assertion.scope.brain_id,
            "project_id": assertion.scope.project_id,
            "repository_id": assertion.scope.repository_id,
            "checkout_id": assertion.scope.checkout_id,
            "relationship_type": PredicateRegistry.relationship_type(assertion.predicate),
            "subject_id": assertion.subject_id,
            "object_id": assertion.object_id,
            "classification": GraphClassification(assertion.scope.classification),
            "valid_from": assertion.temporal.valid_from,
            "valid_to": assertion.temporal.valid_to,
            "recorded_from": assertion.temporal.recorded_from,
            "recorded_to": assertion.temporal.recorded_to,
            "aggregate_version": aggregate_version,
            "projection_status": status,
            "generation_id": generation_id,
            "schema_version": _SCHEMA_VERSION,
            "projected_at": projected_at,
            "content_fingerprint": assertion.content_fingerprint,
        }
        return cls(
            id=_projection_edge_id(assertion.id, generation_id),
            assertion_id=assertion.id,
            assertion_revision_id=assertion.revision_id,
            source_event_id=source_event_id,
            brain_id=assertion.scope.brain_id,
            project_id=assertion.scope.project_id,
            repository_id=assertion.scope.repository_id,
            checkout_id=assertion.scope.checkout_id,
            relationship_type=PredicateRegistry.relationship_type(assertion.predicate),
            subject_id=assertion.subject_id,
            object_id=assertion.object_id,
            classification=GraphClassification(assertion.scope.classification),
            valid_from=assertion.temporal.valid_from,
            valid_to=assertion.temporal.valid_to,
            recorded_from=assertion.temporal.recorded_from,
            recorded_to=assertion.temporal.recorded_to,
            aggregate_version=aggregate_version,
            projection_status=status,
            generation_id=generation_id,
            schema_version=_SCHEMA_VERSION,
            projected_at=projected_at,
            content_fingerprint=assertion.content_fingerprint,
            projection_digest=_projection_digest(values),
        )

    def __post_init__(self) -> None:
        """Reject malformed lineage, scope, time, generation, and projection digests."""
        _validate_edge_identity(self)
        _validate_edge_time(self)
        _validate_edge_lifecycle(self)
        _validate_edge_quarantine(self)
        if self.projection_digest != _projection_digest(self._digest_values()):
            raise GraphValidationError(_ERR_INTEGRITY)

    @property
    def retrieval_visible(self) -> bool:
        """Return whether ordinary current traversal may expose this edge."""
        return self.projection_status is ProjectionEdgeStatus.ACTIVE and not self.quarantined

    def quarantine(self, reason: str) -> MaterializedAssertionEdge:
        """Exclude a corrupt projection without altering its authoritative metadata."""
        return replace(self, quarantined=True, quarantine_reason=reason)

    def document(self) -> dict[str, object]:
        """Return the exact closed Neo4j persistence document."""
        return {
            **self._digest_values(),
            "created_at": self.recorded_from,
            "revision_id": self.assertion_revision_id,
            "relationship_type": self.relationship_type.value,
            "classification": self.classification.value,
            "projection_status": self.projection_status.value,
            "quarantined": self.quarantined,
            "quarantine_reason": self.quarantine_reason,
            "projection_digest": self.projection_digest,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> MaterializedAssertionEdge:
        """Defensively decode an untrusted Neo4j relationship document."""
        try:
            return cls(
                id=_string(document, "id"),
                assertion_id=_string(document, "assertion_id"),
                assertion_revision_id=_string(document, "assertion_revision_id"),
                source_event_id=_string(document, "source_event_id"),
                brain_id=_string(document, "brain_id"),
                project_id=_string(document, "project_id"),
                repository_id=_string(document, "repository_id"),
                checkout_id=_optional_string(document, "checkout_id"),
                relationship_type=GraphRelationshipType(_string(document, "relationship_type")),
                subject_id=_string(document, "subject_id"),
                object_id=_string(document, "object_id"),
                classification=GraphClassification(_string(document, "classification")),
                valid_from=_datetime(document, "valid_from"),
                valid_to=_optional_datetime(document, "valid_to"),
                recorded_from=_datetime(document, "recorded_from"),
                recorded_to=_optional_datetime(document, "recorded_to"),
                aggregate_version=_integer(document, "aggregate_version"),
                projection_status=ProjectionEdgeStatus(_string(document, "projection_status")),
                generation_id=_string(document, "generation_id"),
                schema_version=_integer(document, "schema_version"),
                projected_at=_datetime(document, "projected_at"),
                content_fingerprint=_string(document, "content_fingerprint"),
                projection_digest=_string(document, "projection_digest"),
                quarantined=_boolean(document, "quarantined"),
                quarantine_reason=_optional_string(document, "quarantine_reason"),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise GraphValidationError(_ERR_DOCUMENT) from error

    def _digest_values(self) -> dict[str, object]:
        return {
            "aggregate_version": self.aggregate_version,
            "assertion_id": self.assertion_id,
            "assertion_revision_id": self.assertion_revision_id,
            "brain_id": self.brain_id,
            "checkout_id": self.checkout_id,
            "classification": self.classification,
            "content_fingerprint": self.content_fingerprint,
            "generation_id": self.generation_id,
            "id": self.id,
            "object_id": self.object_id,
            "project_id": self.project_id,
            "projected_at": self.projected_at,
            "projection_status": self.projection_status,
            "recorded_from": self.recorded_from,
            "recorded_to": self.recorded_to,
            "relationship_type": self.relationship_type,
            "repository_id": self.repository_id,
            "schema_version": self.schema_version,
            "source_event_id": self.source_event_id,
            "subject_id": self.subject_id,
            "valid_from": self.valid_from,
            "valid_to": self.valid_to,
        }


@dataclass(frozen=True, slots=True)
class MaterializedEdgeWriteResult:
    """Content-free idempotent edge projection outcome."""

    assertion_id: str
    projection_digest: str
    applied: bool
    created: bool

    def __post_init__(self) -> None:
        """Require stable assertion lineage and exact digest evidence."""
        stable_graph_id(self.assertion_id)
        _require_digest(self.projection_digest)
        flags: tuple[object, ...] = (self.applied, self.created)
        if any(not _is_instance(value, bool) for value in flags) or (
            self.created and not self.applied
        ):
            raise GraphValidationError(_ERR_INTEGRITY)


@dataclass(frozen=True, slots=True)
class MaterializedEdgeProjectionJob:
    """One leased canonical assertion event awaiting graph materialization."""

    source_event_id: str
    assertion_id: str
    brain_id: str
    principal_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    classification: GraphClassification
    aggregate_version: int
    event_digest: str
    occurred_at: datetime
    attempts: int
    lease_owner: str
    lease_until: datetime

    def __post_init__(self) -> None:
        """Require exact immutable lineage plus a current bounded lease."""
        for value in (
            self.source_event_id,
            self.assertion_id,
            self.brain_id,
            self.principal_id,
            self.project_id,
            self.repository_id,
        ):
            stable_graph_id(value)
        if self.checkout_id is not None:
            stable_graph_id(self.checkout_id)
        classification: object = self.classification
        if (
            not _is_instance(classification, GraphClassification)
            or self.aggregate_version not in {_ACTIVE_VERSION, _RETIRED_VERSION}
            or not 1 <= self.attempts <= _MAX_JOB_ATTEMPTS
            or _TOKEN.fullmatch(self.lease_owner) is None
        ):
            raise GraphValidationError(_ERR_WORK)
        _require_digest(self.event_digest)
        _require_utc(self.occurred_at)
        _require_utc(self.lease_until)
        if self.lease_until <= self.occurred_at:
            raise GraphValidationError(_ERR_WORK)


@dataclass(frozen=True, slots=True)
class TraversalEdgeExplanation:
    """Minimal authority pointer returned beside one traversed direct edge."""

    assertion_id: str
    assertion_revision_id: str
    source_event_id: str
    relationship_type: GraphRelationshipType
    subject_id: str
    object_id: str
    valid_from: datetime
    valid_to: datetime | None
    recorded_from: datetime
    recorded_to: datetime | None
    generation_id: str

    @classmethod
    def from_edge(cls, edge: MaterializedAssertionEdge) -> TraversalEdgeExplanation:
        """Expose authority coordinates only for a retrieval-visible edge."""
        if not edge.retrieval_visible:
            raise GraphValidationError(_ERR_INTEGRITY)
        return cls(
            edge.assertion_id,
            edge.assertion_revision_id,
            edge.source_event_id,
            edge.relationship_type,
            edge.subject_id,
            edge.object_id,
            edge.valid_from,
            edge.valid_to,
            edge.recorded_from,
            edge.recorded_to,
            edge.generation_id,
        )


def _validate_edge_identity(edge: MaterializedAssertionEdge) -> None:
    for value in (
        edge.id,
        edge.assertion_id,
        edge.source_event_id,
        edge.brain_id,
        edge.project_id,
        edge.repository_id,
        edge.subject_id,
        edge.object_id,
    ):
        stable_graph_id(value)
    if (
        edge.id != _projection_edge_id(edge.assertion_id, edge.generation_id)
        or edge.subject_id == edge.object_id
    ):
        raise GraphValidationError(_ERR_SCOPE)
    if edge.checkout_id is not None:
        stable_graph_id(edge.checkout_id)
    relationship_type: object = edge.relationship_type
    classification: object = edge.classification
    if not _is_instance(relationship_type, GraphRelationshipType) or not _is_instance(
        classification, GraphClassification
    ):
        raise GraphValidationError(_ERR_SCOPE)
    for digest in (
        edge.assertion_revision_id,
        edge.generation_id,
        edge.content_fingerprint,
        edge.projection_digest,
    ):
        _require_digest(digest)


def _validate_edge_time(edge: MaterializedAssertionEdge) -> None:
    if edge.schema_version != _SCHEMA_VERSION or edge.aggregate_version not in {
        _ACTIVE_VERSION,
        _RETIRED_VERSION,
    }:
        raise GraphValidationError(_ERR_VERSION)
    for value in (edge.valid_from, edge.recorded_from, edge.projected_at):
        _require_utc(value)
    for start, end in (
        (edge.valid_from, edge.valid_to),
        (edge.recorded_from, edge.recorded_to),
    ):
        if end is not None:
            _require_utc(end)
            if end <= start:
                raise GraphValidationError(_ERR_TIME)


def _validate_edge_lifecycle(edge: MaterializedAssertionEdge) -> None:
    active_invalid = edge.aggregate_version == _ACTIVE_VERSION and (
        edge.projection_status is not ProjectionEdgeStatus.ACTIVE or edge.recorded_to is not None
    )
    retired_invalid = edge.aggregate_version == _RETIRED_VERSION and (
        edge.projection_status is not ProjectionEdgeStatus.RETIRED or edge.recorded_to is None
    )
    if active_invalid or retired_invalid:
        raise GraphValidationError(_ERR_VERSION)


def _validate_edge_quarantine(edge: MaterializedAssertionEdge) -> None:
    quarantined: object = edge.quarantined
    invalid_reason = quarantined is True and (
        not isinstance(edge.quarantine_reason, str)
        or _TOKEN.fullmatch(edge.quarantine_reason) is None
    )
    if (
        not _is_instance(quarantined, bool)
        or invalid_reason
        or (quarantined is False and edge.quarantine_reason is not None)
    ):
        raise GraphValidationError(_ERR_QUARANTINE)


@dataclass(frozen=True, slots=True)
class EdgeIntegrityFinding:
    """One deterministic content-free reverse-check result."""

    id: str
    generation_id: str
    kind: EdgeIntegrityFindingKind
    assertion_id: str
    expected_digest: str | None
    actual_digest: str | None
    detected_at: datetime

    @classmethod
    def create(  # noqa: PLR0913 -- Identity binds the complete mismatch evidence.
        cls,
        kind: EdgeIntegrityFindingKind,
        generation_id: str,
        assertion_id: str,
        expected_digest: str | None,
        actual_digest: str | None,
        detected_at: datetime,
    ) -> EdgeIntegrityFinding:
        """Derive stable finding identity from mismatch coordinates."""
        stable_graph_id(assertion_id)
        _require_digest(generation_id)
        _require_utc(detected_at)
        for digest in (expected_digest, actual_digest):
            if digest is not None:
                _require_digest(digest)
        payload = "\x00".join(
            (
                generation_id,
                kind.value,
                assertion_id,
                expected_digest or "missing",
                actual_digest or "missing",
            )
        )
        finding_id = hashlib.sha256(f"edge-finding.v1\x00{payload}".encode()).hexdigest()
        return cls(
            finding_id,
            generation_id,
            kind,
            assertion_id,
            expected_digest,
            actual_digest,
            detected_at,
        )

    def __post_init__(self) -> None:
        """Require a closed finding kind and deterministic digest identity."""
        _require_digest(self.id)
        _require_digest(self.generation_id)
        if not _is_instance(self.kind, EdgeIntegrityFindingKind):
            raise GraphValidationError(_ERR_INTEGRITY)


class EdgeIntegrityPolicy:
    """Perform assertion-to-edge and edge-to-assertion checks deterministically."""

    @staticmethod
    def evaluate(
        expected: tuple[MaterializedAssertionEdge, ...],
        actual: tuple[MaterializedAssertionEdge, ...],
        detected_at: datetime,
    ) -> tuple[EdgeIntegrityFinding, ...]:
        """Return every missing, orphaned, divergent, or quarantined edge."""
        _require_utc(detected_at)
        expected_by_id = _unique_edges(expected)
        actual_by_id = _group_edges(actual)
        findings: list[EdgeIntegrityFinding] = []
        for assertion_id in sorted(set(expected_by_id) | set(actual_by_id)):
            wanted = expected_by_id.get(assertion_id)
            found_values = tuple(
                edge for edge in actual_by_id.get(assertion_id, ()) if not edge.quarantined
            )
            found = found_values[0] if len(found_values) == 1 else None
            if wanted is None:
                if found_values:
                    findings.append(
                        EdgeIntegrityFinding.create(
                            EdgeIntegrityFindingKind.ORPHAN,
                            found_values[0].generation_id,
                            assertion_id,
                            None,
                            _actual_digest(found_values),
                            detected_at,
                        )
                    )
                continue
            if len(found_values) > 1:
                findings.append(
                    EdgeIntegrityFinding.create(
                        EdgeIntegrityFindingKind.MISMATCH,
                        wanted.generation_id,
                        assertion_id,
                        wanted.projection_digest,
                        _actual_digest(found_values),
                        detected_at,
                    )
                )
                continue
            if found is None:
                if wanted.projection_status is ProjectionEdgeStatus.ACTIVE:
                    findings.append(
                        EdgeIntegrityFinding.create(
                            EdgeIntegrityFindingKind.MISSING,
                            wanted.generation_id,
                            assertion_id,
                            wanted.projection_digest,
                            None,
                            detected_at,
                        )
                    )
                continue
            if found.projection_digest != wanted.projection_digest or found.quarantined:
                findings.append(
                    EdgeIntegrityFinding.create(
                        EdgeIntegrityFindingKind.MISMATCH,
                        wanted.generation_id,
                        assertion_id,
                        wanted.projection_digest,
                        found.projection_digest,
                        detected_at,
                    )
                )
        return tuple(findings)


def _unique_edges(
    edges: tuple[MaterializedAssertionEdge, ...],
) -> dict[str, MaterializedAssertionEdge]:
    values: dict[str, MaterializedAssertionEdge] = {}
    for edge in edges:
        if edge.assertion_id in values:
            raise GraphValidationError(_ERR_INTEGRITY)
        values[edge.assertion_id] = edge
    return values


def _group_edges(
    edges: tuple[MaterializedAssertionEdge, ...],
) -> dict[str, tuple[MaterializedAssertionEdge, ...]]:
    grouped: dict[str, list[MaterializedAssertionEdge]] = {}
    for edge in edges:
        grouped.setdefault(edge.assertion_id, []).append(edge)
    return {
        assertion_id: tuple(
            sorted(values, key=lambda item: (item.relationship_type.value, item.id))
        )
        for assertion_id, values in grouped.items()
    }


def _actual_digest(edges: tuple[MaterializedAssertionEdge, ...]) -> str:
    if len(edges) == 1:
        return edges[0].projection_digest
    payload = "\x00".join(
        f"{edge.id}:{edge.relationship_type.value}:{edge.projection_digest}" for edge in edges
    )
    return hashlib.sha256(f"materialized-edge-set.v1\x00{payload}".encode()).hexdigest()


def _projection_digest(values: Mapping[str, object]) -> str:
    document = {
        key: _canonical_value(value)
        for key, value in sorted(values.items())
        if key not in {"quarantined", "quarantine_reason", "projection_digest"}
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _projection_edge_id(assertion_id: str, generation_id: str) -> str:
    stable_graph_id(assertion_id)
    _require_digest(generation_id)
    payload = hashlib.sha256(
        b"materialized-assertion-edge.v1\x00"
        + assertion_id.encode()
        + b"\x00"
        + generation_id.encode()
    ).digest()
    value = bytearray(payload[:16])
    value[6] = (value[6] & 0x0F) | 0x70
    value[8] = (value[8] & 0x3F) | 0x80
    return str(UUID(bytes=bytes(value)))


def _canonical_value(value: object) -> object:
    if isinstance(value, StrEnum):
        return value.value
    if hasattr(value, "isoformat"):
        timestamp = cast("datetime", value)
        return timestamp.isoformat(timespec="microseconds").replace("+00:00", "Z")
    return value


def _require_digest(value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise GraphValidationError(_ERR_GENERATION)


def _require_utc(value: object) -> None:
    if not hasattr(value, "tzinfo") or not hasattr(value, "utcoffset"):
        raise GraphValidationError(_ERR_TIME)
    timestamp = cast("datetime", value)
    if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(None):
        raise GraphValidationError(_ERR_TIME)


def _is_instance(value: object, expected: type[object]) -> bool:
    return isinstance(value, expected)


def _string(document: Mapping[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError(key)
    return value


def _optional_string(document: Mapping[str, object], key: str) -> str | None:
    value = document.get(key)
    if value is not None and not isinstance(value, str):
        raise TypeError(key)
    return value


def _integer(document: Mapping[str, object], key: str) -> int:
    value = document[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(key)
    return value


def _boolean(document: Mapping[str, object], key: str) -> bool:
    value = document[key]
    if not isinstance(value, bool):
        raise TypeError(key)
    return value


def _datetime(document: Mapping[str, object], key: str) -> datetime:
    value = document[key]
    if not hasattr(value, "tzinfo") or not hasattr(value, "utcoffset"):
        raise TypeError(key)
    convert = getattr(value, "to_native", None)
    return cast("datetime", convert() if callable(convert) else value)


def _optional_datetime(document: Mapping[str, object], key: str) -> datetime | None:
    value = document.get(key)
    if value is None:
        return None
    if not hasattr(value, "tzinfo") or not hasattr(value, "utcoffset"):
        raise TypeError(key)
    convert = getattr(value, "to_native", None)
    return cast("datetime", convert() if callable(convert) else value)
