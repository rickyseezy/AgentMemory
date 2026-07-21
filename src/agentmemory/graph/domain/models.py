"""GRA-001 closed Brain-scoped graph schema and deterministic identities."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC
from enum import StrEnum
from typing import TYPE_CHECKING, cast
from uuid import UUID

from agentmemory.graph.domain.errors import GraphValidationError

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_SCHEMA_VERSION = 2_147_483_647
_ERR_ENTITY_TYPE = "graph entity type is invalid"
_ERR_REVISION = "graph revision identity is invalid"
_ERR_DOCUMENT = "graph entity document is invalid"
_ERR_ENDPOINTS = "graph relationship endpoints are invalid"
_ERR_RELATIONSHIP_TYPE = "graph relationship type is invalid"
_ERR_GLOBAL_SCOPE = "global graph entity scope is invalid"
_ERR_PROJECT_REQUIRED = "graph entity project scope is required"
_ERR_PROJECT_SCOPE = "Project graph entity scope is invalid"
_ERR_REPOSITORY_REQUIRED = "graph entity repository scope is required"
_ERR_REPOSITORY_SCOPE = "Repository graph entity scope is invalid"
_ERR_CHECKOUT_SCOPE = "Checkout graph entity scope is invalid"
_ERR_SCHEMA_VERSION = "graph schema version is invalid"
_ERR_CLASSIFICATION = "graph classification is invalid"
_ERR_RECORDED_TIME = "graph recorded time is invalid"
_ERR_RECORDED_INTERVAL = "graph recorded interval is invalid"
_ERR_STABLE_ID = "graph stable identity is invalid"
_ERR_FINGERPRINT = "graph content fingerprint is invalid"
_ERR_TIME = "graph time is invalid"


class GraphEntityType(StrEnum):
    """Closed stable labels from the production graph schema."""

    BRAIN = "Brain"
    PROJECT = "Project"
    REPOSITORY = "Repository"
    CHECKOUT = "Checkout"
    BRANCH = "Branch"
    COMMIT = "Commit"
    AGENT = "Agent"
    SESSION = "Session"
    TASK = "Task"
    TURN = "Turn"
    EVENT = "Event"
    ARTIFACT = "Artifact"
    FILE = "File"
    FILE_REVISION = "FileRevision"
    SYMBOL = "Symbol"
    SYMBOL_REVISION = "SymbolRevision"
    PACKAGE = "Package"
    SERVICE = "Service"
    ENDPOINT = "Endpoint"
    CONTRACT = "Contract"
    DEPENDENCY = "Dependency"
    ENVIRONMENT = "Environment"
    MEMORY = "Memory"
    DECISION = "Decision"
    CONSTRAINT = "Constraint"
    PREFERENCE = "Preference"
    PROCEDURE = "Procedure"
    LESSON = "Lesson"
    FAILURE = "Failure"
    OUTCOME = "Outcome"
    ASSERTION = "Assertion"
    EVIDENCE = "Evidence"
    CONTRADICTION = "Contradiction"
    CAUSAL_HYPOTHESIS = "CausalHypothesis"
    EVALUATION = "Evaluation"
    PROCEDURE_REVISION = "ProcedureRevision"
    DEPLOYMENT = "Deployment"
    EMBEDDING_SPACE = "EmbeddingSpace"
    INDEX_GENERATION = "IndexGeneration"
    VECTOR_RECORD = "VectorRecord"


_GLOBAL_ENTITY_TYPES = frozenset(
    {
        GraphEntityType.BRAIN,
        GraphEntityType.EMBEDDING_SPACE,
        GraphEntityType.INDEX_GENERATION,
    }
)


class GraphRelationshipType(StrEnum):
    """Closed structural and materialized relationship types."""

    SUBJECT_OF = "SUBJECT_OF"
    OBJECT_OF = "OBJECT_OF"
    SUPPORTED_BY = "SUPPORTED_BY"
    CONTRADICTED_BY = "CONTRADICTED_BY"
    INVALIDATED_BY = "INVALIDATED_BY"
    CALLS = "CALLS"
    IMPORTS = "IMPORTS"
    CONSUMES = "CONSUMES"
    IMPLEMENTS = "IMPLEMENTS"
    DEPENDS_ON = "DEPENDS_ON"
    PRODUCES = "PRODUCES"
    DEPLOYED_AS = "DEPLOYED_AS"


class GraphClassification(StrEnum):
    """Closed graph classification copied from an authorized canonical fact."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    LOCAL_ONLY = "local_only"


@dataclass(frozen=True, slots=True)
class GraphEntity:
    """One immutable effective version at a constrained stable graph identity."""

    id: str
    brain_id: str
    entity_type: GraphEntityType
    project_id: str | None
    repository_id: str | None
    checkout_id: str | None
    schema_version: int
    created_at: datetime
    recorded_from: datetime
    recorded_to: datetime | None
    classification: GraphClassification
    content_fingerprint: str
    revision_id: str

    @classmethod
    def create(  # noqa: PLR0913 -- Factory binds the complete required graph schema.
        cls,
        *,
        entity_id: str,
        brain_id: str,
        entity_type: GraphEntityType,
        project_id: str | None,
        repository_id: str | None,
        checkout_id: str | None,
        schema_version: int,
        created_at: datetime,
        recorded_from: datetime,
        recorded_to: datetime | None,
        classification: GraphClassification,
        content_fingerprint: str,
    ) -> GraphEntity:
        """Derive the immutable revision identity from entity and content fingerprint."""
        return cls(
            entity_id,
            brain_id,
            entity_type,
            project_id,
            repository_id,
            checkout_id,
            schema_version,
            created_at,
            recorded_from,
            recorded_to,
            classification,
            content_fingerprint,
            derive_revision_id(entity_id, content_fingerprint),
        )

    def __post_init__(self) -> None:
        """Reject missing, malformed, or internally divergent graph fields."""
        _require_uuid7(self.id)
        _require_uuid7(self.brain_id)
        _require_entity_type(self.entity_type)
        _validate_coordinates(self)
        _validate_common(self)
        if self.revision_id != derive_revision_id(self.id, self.content_fingerprint):
            raise GraphValidationError(_ERR_REVISION)

    def document(self) -> dict[str, object]:
        """Return the exact closed persistence document."""
        return {
            "id": self.id,
            "brain_id": self.brain_id,
            "entity_type": self.entity_type.value,
            "project_id": self.project_id,
            "repository_id": self.repository_id,
            "checkout_id": self.checkout_id,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "recorded_from": self.recorded_from,
            "recorded_to": self.recorded_to,
            "classification": self.classification.value,
            "content_fingerprint": self.content_fingerprint,
            "revision_id": self.revision_id,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> GraphEntity:
        """Fail closed while decoding an untrusted graph projection row."""
        try:
            return cls(
                _string(document, "id"),
                _string(document, "brain_id"),
                GraphEntityType(_string(document, "entity_type")),
                _optional_string(document, "project_id"),
                _optional_string(document, "repository_id"),
                _optional_string(document, "checkout_id"),
                _integer(document, "schema_version"),
                _datetime(document, "created_at"),
                _datetime(document, "recorded_from"),
                _optional_datetime(document, "recorded_to"),
                GraphClassification(_string(document, "classification")),
                _string(document, "content_fingerprint"),
                _string(document, "revision_id"),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise GraphValidationError(_ERR_DOCUMENT) from error


@dataclass(frozen=True, slots=True)
class GraphRelationship:
    """One immutable typed graph relationship between stable entity identities."""

    id: str
    brain_id: str
    relationship_type: GraphRelationshipType
    subject_id: str
    object_id: str
    project_id: str
    repository_id: str
    schema_version: int
    created_at: datetime
    recorded_from: datetime
    recorded_to: datetime | None
    classification: GraphClassification
    content_fingerprint: str
    revision_id: str

    @classmethod
    def create(  # noqa: PLR0913 -- Factory binds every required relationship field.
        cls,
        *,
        relationship_id: str,
        brain_id: str,
        relationship_type: GraphRelationshipType,
        subject_id: str,
        object_id: str,
        project_id: str,
        repository_id: str,
        schema_version: int,
        created_at: datetime,
        recorded_from: datetime,
        recorded_to: datetime | None,
        classification: GraphClassification,
        content_fingerprint: str,
    ) -> GraphRelationship:
        """Create a complete relationship with a deterministic revision identity."""
        return cls(
            relationship_id,
            brain_id,
            relationship_type,
            subject_id,
            object_id,
            project_id,
            repository_id,
            schema_version,
            created_at,
            recorded_from,
            recorded_to,
            classification,
            content_fingerprint,
            derive_revision_id(relationship_id, content_fingerprint),
        )

    def __post_init__(self) -> None:
        """Validate stable endpoints, scope, schema, time, and deterministic revision."""
        for value in (
            self.id,
            self.brain_id,
            self.subject_id,
            self.object_id,
            self.project_id,
            self.repository_id,
        ):
            _require_uuid7(value)
        if self.subject_id == self.object_id:
            raise GraphValidationError(_ERR_ENDPOINTS)
        _require_relationship_type(self.relationship_type)
        _validate_common(self)
        if self.revision_id != derive_revision_id(self.id, self.content_fingerprint):
            raise GraphValidationError(_ERR_REVISION)

    def document(self) -> dict[str, object]:
        """Return the closed relationship persistence document."""
        return {
            "id": self.id,
            "brain_id": self.brain_id,
            "relationship_type": self.relationship_type.value,
            "subject_id": self.subject_id,
            "object_id": self.object_id,
            "project_id": self.project_id,
            "repository_id": self.repository_id,
            "schema_version": self.schema_version,
            "created_at": self.created_at,
            "recorded_from": self.recorded_from,
            "recorded_to": self.recorded_to,
            "classification": self.classification.value,
            "content_fingerprint": self.content_fingerprint,
            "revision_id": self.revision_id,
        }


@dataclass(frozen=True, slots=True)
class GraphEntityQuery:
    """Bounded exact query with no caller-provided Cypher, label, or path."""

    entity_type: GraphEntityType
    entity_id: str

    def __post_init__(self) -> None:
        """Accept only a closed label and canonical stable identity."""
        _require_entity_type(self.entity_type)
        _require_uuid7(self.entity_id)


@dataclass(frozen=True, slots=True)
class GraphWriteResult:
    """Content-free idempotent projection outcome."""

    stable_id: str
    revision_id: str
    created: bool


def stable_graph_id(canonical_entity_id: str) -> str:
    """Use the canonical entity UUID directly as its stable graph identity."""
    _require_uuid7(canonical_entity_id)
    return canonical_entity_id


def derive_revision_id(entity_id: str, content_fingerprint: str) -> str:
    """Derive a collision-resistant revision ID from a framed stable entity and digest."""
    _require_uuid7(entity_id)
    _require_digest(content_fingerprint)
    payload = b"graph-revision.v1\x00" + entity_id.encode() + b"\x00" + content_fingerprint.encode()
    return hashlib.sha256(payload).hexdigest()


def _validate_coordinates(entity: GraphEntity) -> None:
    for value in (entity.project_id, entity.repository_id, entity.checkout_id):
        if value is not None:
            _require_uuid7(value)
    if entity.entity_type in _GLOBAL_ENTITY_TYPES:
        if any((entity.project_id, entity.repository_id, entity.checkout_id)):
            raise GraphValidationError(_ERR_GLOBAL_SCOPE)
        return
    _validate_scoped_coordinates(entity)


def _validate_scoped_coordinates(entity: GraphEntity) -> None:
    if entity.project_id is None:
        raise GraphValidationError(_ERR_PROJECT_REQUIRED)
    if entity.entity_type is GraphEntityType.PROJECT:
        if entity.project_id != entity.id or entity.repository_id is not None:
            raise GraphValidationError(_ERR_PROJECT_SCOPE)
        return
    if entity.repository_id is None:
        raise GraphValidationError(_ERR_REPOSITORY_REQUIRED)
    if entity.entity_type is GraphEntityType.REPOSITORY and entity.repository_id != entity.id:
        raise GraphValidationError(_ERR_REPOSITORY_SCOPE)
    if entity.entity_type is GraphEntityType.CHECKOUT and entity.checkout_id != entity.id:
        raise GraphValidationError(_ERR_CHECKOUT_SCOPE)


def _validate_common(record: GraphEntity | GraphRelationship) -> None:
    _require_schema_version(record.schema_version)
    _require_classification(record.classification)
    _require_utc(record.created_at)
    _require_utc(record.recorded_from)
    if record.created_at > record.recorded_from:
        raise GraphValidationError(_ERR_RECORDED_TIME)
    if record.recorded_to is not None:
        _require_utc(record.recorded_to)
        if record.recorded_to <= record.recorded_from:
            raise GraphValidationError(_ERR_RECORDED_INTERVAL)
    _require_digest(record.content_fingerprint)


def _require_uuid7(value: object) -> None:
    if not isinstance(value, str):
        raise GraphValidationError(_ERR_STABLE_ID)
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise GraphValidationError(_ERR_STABLE_ID) from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise GraphValidationError(_ERR_STABLE_ID)


def _require_entity_type(value: object) -> None:
    if not isinstance(value, GraphEntityType):
        raise GraphValidationError(_ERR_ENTITY_TYPE)


def _require_relationship_type(value: object) -> None:
    if not isinstance(value, GraphRelationshipType):
        raise GraphValidationError(_ERR_RELATIONSHIP_TYPE)


def _require_schema_version(value: object) -> None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= _MAX_SCHEMA_VERSION
    ):
        raise GraphValidationError(_ERR_SCHEMA_VERSION)


def _require_classification(value: object) -> None:
    if not isinstance(value, GraphClassification):
        raise GraphValidationError(_ERR_CLASSIFICATION)


def _require_digest(value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise GraphValidationError(_ERR_FINGERPRINT)


def _require_utc(value: object) -> None:
    if not hasattr(value, "tzinfo") or not hasattr(value, "utcoffset"):
        raise GraphValidationError(_ERR_TIME)
    timestamp = cast("datetime", value)
    if timestamp.tzinfo is None or timestamp.utcoffset() != UTC.utcoffset(None):
        raise GraphValidationError(_ERR_TIME)


def _string(document: Mapping[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError(key)
    return value


def _optional_string(document: Mapping[str, object], key: str) -> str | None:
    value = document[key]
    if value is not None and not isinstance(value, str):
        raise TypeError(key)
    return value


def _integer(document: Mapping[str, object], key: str) -> int:
    value = document[key]
    if not isinstance(value, int):
        raise TypeError(key)
    return value


def _datetime(document: Mapping[str, object], key: str) -> datetime:
    value = document[key]
    if not hasattr(value, "tzinfo") or not hasattr(value, "utcoffset"):
        raise TypeError(key)
    return cast("datetime", value)


def _optional_datetime(document: Mapping[str, object], key: str) -> datetime | None:
    value = document[key]
    if value is None:
        return None
    if not hasattr(value, "tzinfo") or not hasattr(value, "utcoffset"):
        raise TypeError(key)
    return cast("datetime", value)
