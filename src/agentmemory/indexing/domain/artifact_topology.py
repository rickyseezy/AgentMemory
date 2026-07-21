"""IDX-005 evidence-backed build, messaging, and infrastructure topology."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from uuid import UUID

from agentmemory.indexing.domain.errors import IndexingValidationError

if TYPE_CHECKING:
    from datetime import datetime

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_REFERENCE = re.compile(r"^[A-Za-z0-9@*^~<>=][A-Za-z0-9@._+:/<>=,|^~*-]{0,511}$")
_ENVIRONMENT_REFERENCE = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_PLUGIN_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_PATH_BYTES = 4_096
_MAX_CANDIDATES = 100_000
_MAX_UNKNOWN = 10_000
_MAX_LINE_NUMBER = 10_000_000
_UUID7 = 7
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_ERR_EVIDENCE = "artifact topology evidence is invalid"
_ERR_CANDIDATE = "artifact topology candidate is invalid"
_ERR_RELATION = "artifact topology relation is invalid"
_ERR_BATCH = "artifact topology batch is invalid"


class ArtifactTopologyPluginKind(StrEnum):
    """Closed deterministic artifact parser families."""

    DEPENDENCY_MANIFEST = "dependency_manifest"
    DEPENDENCY_LOCK = "dependency_lock"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    TERRAFORM = "terraform"
    CI = "ci"
    ENVIRONMENT = "environment"
    MESSAGING_SCHEMA = "messaging_schema"


class TopologyEntityKind(StrEnum):
    """Closed graph entity classes emitted by every artifact parser."""

    PACKAGE = "package"
    CONTAINER_IMAGE = "container_image"
    WORKLOAD = "workload"
    INFRASTRUCTURE_RESOURCE = "infrastructure_resource"
    PIPELINE = "pipeline"
    ENVIRONMENT_REFERENCE = "environment_reference"
    MESSAGE_CHANNEL = "message_channel"
    EVENT_SCHEMA = "event_schema"
    SERVICE = "service"


class TopologyRelationKind(StrEnum):
    """Closed factual relationships supported by canonical graph assertions."""

    DEPENDS_ON = "depends_on"
    DEPLOYED_AS = "deployed_as"
    PRODUCES = "produces"
    CONSUMES = "consumes"


class ReferenceSensitivity(StrEnum):
    """Whether a normalized configuration name points to secret material."""

    PUBLIC_CONFIGURATION = "public_configuration"
    SENSITIVE_CONFIGURATION = "sensitive_configuration"
    SECRET_REFERENCE = "secret_reference"  # noqa: S105  # nosec B105 -- Classification label.


class UnknownConstructReason(StrEnum):
    """Why deterministic parsing retained only an authorized evidence coordinate."""

    UNSUPPORTED_CONSTRUCT = "unsupported_construct"
    UNRESOLVED_TEMPLATE = "unresolved_template"
    UNRESOLVED_OVERLAY = "unresolved_overlay"


@dataclass(frozen=True, slots=True)
class ArtifactTopologyEvidence:
    """Exact immutable source coordinates shared by all topology observations."""

    brain_id: str
    project_id: str
    repository_id: str
    source_file_id: str
    source_revision_context_id: str
    source_semantic_id: str
    evidence_id: str
    relative_path: str
    classification: str
    observed_at: datetime

    def __post_init__(self) -> None:
        """Reject unstable identities, path escape, invalid classification, and non-UTC time."""
        for value in (self.brain_id, self.project_id, self.repository_id, self.evidence_id):
            _stable_id(value, _ERR_EVIDENCE)
        for value in (
            self.source_file_id,
            self.source_revision_context_id,
            self.source_semantic_id,
        ):
            _digest(value, _ERR_EVIDENCE)
        _path(self.relative_path)
        if self.classification not in _CLASSIFICATIONS:
            raise IndexingValidationError(_ERR_EVIDENCE)
        _utc(self.observed_at, _ERR_EVIDENCE)

    @property
    def scope_key(self) -> tuple[str, str, str]:
        """Return exact authorization coordinates."""
        return self.brain_id, self.project_id, self.repository_id


@dataclass(frozen=True, slots=True)
class TopologyCandidate:
    """One common evidence-backed topology entity emitted by any artifact parser."""

    evidence: ArtifactTopologyEvidence
    entity_id: str
    kind: TopologyEntityKind
    name: str
    version: str | None = None
    environment_reference: str | None = None
    sensitivity: ReferenceSensitivity | None = None
    qualifiers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Accept only closed metadata fields that cannot retain environment values."""
        _stable_id(self.entity_id, _ERR_CANDIDATE)
        _enum(self.kind, TopologyEntityKind, _ERR_CANDIDATE)
        _reference(self.name)
        if self.version is not None:
            _reference(self.version)
        if self.environment_reference is not None:
            _environment_reference(self.environment_reference)
        if self.sensitivity is not None:
            _enum(self.sensitivity, ReferenceSensitivity, _ERR_CANDIDATE)
        if (self.environment_reference is None) != (self.sensitivity is None):
            raise IndexingValidationError(_ERR_CANDIDATE)
        if self.kind is TopologyEntityKind.ENVIRONMENT_REFERENCE and (
            self.environment_reference is None or self.name != self.environment_reference
        ):
            raise IndexingValidationError(_ERR_CANDIDATE)
        _sorted_references(self.qualifiers)

    @property
    def id(self) -> str:
        """Return immutable candidate identity independent of parser ordering."""
        return _identity(
            "artifact-topology-candidate.v1",
            {
                "entity_id": self.entity_id,
                "environment_reference": self.environment_reference,
                "evidence_id": self.evidence.evidence_id,
                "kind": self.kind.value,
                "name": self.name,
                "qualifiers": list(self.qualifiers),
                "sensitivity": None if self.sensitivity is None else self.sensitivity.value,
                "version": self.version,
            },
        )


@dataclass(frozen=True, slots=True)
class TopologyRelationCandidate:
    """One temporal dependency, deployment, publication, or subscription observation."""

    evidence: ArtifactTopologyEvidence
    subject_entity_id: str
    relation: TopologyRelationKind
    object_entity_id: str
    environment_reference: str | None
    valid_from: datetime
    valid_to: datetime | None = None

    def __post_init__(self) -> None:
        """Require stable endpoints, normalized environment identity, and a UTC interval."""
        for value in (self.subject_entity_id, self.object_entity_id):
            _stable_id(value, _ERR_RELATION)
        if self.subject_entity_id == self.object_entity_id:
            raise IndexingValidationError(_ERR_RELATION)
        _enum(self.relation, TopologyRelationKind, _ERR_RELATION)
        if self.environment_reference is not None:
            _environment_reference(self.environment_reference)
        _utc(self.valid_from, _ERR_RELATION)
        if self.valid_to is not None:
            _utc(self.valid_to, _ERR_RELATION)
            if self.valid_to <= self.valid_from:
                raise IndexingValidationError(_ERR_RELATION)

    @property
    def id(self) -> str:
        """Return an identity that preserves conflicting temporal observations."""
        return _identity(
            "artifact-topology-relation.v1",
            {
                "environment_reference": self.environment_reference,
                "evidence_id": self.evidence.evidence_id,
                "object_entity_id": self.object_entity_id,
                "relation": self.relation.value,
                "subject_entity_id": self.subject_entity_id,
                "valid_from": self.valid_from.isoformat(),
                "valid_to": None if self.valid_to is None else self.valid_to.isoformat(),
            },
        )


@dataclass(frozen=True, slots=True)
class UnknownTopologyEvidence:
    """Digest-only coordinate for a construct deterministic parsers cannot interpret."""

    evidence: ArtifactTopologyEvidence
    reason: UnknownConstructReason
    fragment_digest: str
    start_line: int
    end_line: int

    def __post_init__(self) -> None:
        """Retain bounded location and digest without storing the source fragment."""
        _enum(self.reason, UnknownConstructReason, _ERR_CANDIDATE)
        _digest(self.fragment_digest, _ERR_CANDIDATE)
        if not 1 <= self.start_line <= self.end_line <= _MAX_LINE_NUMBER:
            raise IndexingValidationError(_ERR_CANDIDATE)

    @property
    def id(self) -> str:
        """Return immutable unknown-evidence identity."""
        return _identity(
            "artifact-topology-unknown.v1",
            {
                "end_line": self.end_line,
                "evidence_id": self.evidence.evidence_id,
                "fragment_digest": self.fragment_digest,
                "reason": self.reason.value,
                "start_line": self.start_line,
            },
        )


@dataclass(frozen=True, slots=True)
class ArtifactTopologySourceArtifact:
    """Ephemeral bounded artifact passed to exactly one deterministic parser."""

    evidence: ArtifactTopologyEvidence
    commit_sha: str
    content: bytes

    def __post_init__(self) -> None:
        """Require immutable revision identity and bounded non-empty bytes."""
        if _COMMIT.fullmatch(self.commit_sha) is None:
            raise IndexingValidationError(_ERR_BATCH)
        if not 0 < len(self.content) <= _MAX_ARTIFACT_BYTES:
            raise IndexingValidationError(_ERR_BATCH)


@dataclass(frozen=True, slots=True)
class ArtifactTopologyBatch:
    """Complete deterministic output for one artifact revision."""

    plugin_kind: ArtifactTopologyPluginKind
    plugin_version: str
    source_revision_context_id: str
    source_file_id: str
    commit_sha: str
    candidates: tuple[TopologyCandidate, ...] = ()
    relations: tuple[TopologyRelationCandidate, ...] = ()
    unknown_evidence: tuple[UnknownTopologyEvidence, ...] = ()

    def __post_init__(self) -> None:  # noqa: C901 -- Complete batch invariants remain centralized.
        """Require canonical complete output, including explicit empty removal batches."""
        _enum(self.plugin_kind, ArtifactTopologyPluginKind, _ERR_BATCH)
        if _PLUGIN_VERSION.fullmatch(self.plugin_version) is None:
            raise IndexingValidationError(_ERR_BATCH)
        _digest(self.source_revision_context_id, _ERR_BATCH)
        _digest(self.source_file_id, _ERR_BATCH)
        if _COMMIT.fullmatch(self.commit_sha) is None:
            raise IndexingValidationError(_ERR_BATCH)
        if len(self.candidates) + len(self.relations) > _MAX_CANDIDATES:
            raise IndexingValidationError(_ERR_BATCH)
        if len(self.unknown_evidence) > _MAX_UNKNOWN:
            raise IndexingValidationError(_ERR_BATCH)
        for values in (self.candidates, self.relations, self.unknown_evidence):
            if tuple(item.id for item in values) != tuple(sorted({item.id for item in values})):
                raise IndexingValidationError(_ERR_BATCH)
            for item in values:
                if (
                    item.evidence.source_revision_context_id != self.source_revision_context_id
                    or item.evidence.source_file_id != self.source_file_id
                ):
                    raise IndexingValidationError(_ERR_BATCH)
        observations: tuple[
            TopologyCandidate | TopologyRelationCandidate | UnknownTopologyEvidence, ...
        ] = (*self.candidates, *self.relations, *self.unknown_evidence)
        if len({item.evidence.scope_key for item in observations}) > 1:
            raise IndexingValidationError(_ERR_BATCH)
        known_entities = {
            *(item.entity_id for item in self.candidates),
            *(item.evidence.project_id for item in observations),
            *(item.evidence.repository_id for item in observations),
        }
        if any(
            item.subject_entity_id not in known_entities
            or item.object_entity_id not in known_entities
            for item in self.relations
        ):
            raise IndexingValidationError(_ERR_BATCH)

    @property
    def digest(self) -> str:
        """Bind every observation and explicit removal state."""
        return _identity(
            "artifact-topology-batch.v1",
            {
                "candidates": [item.id for item in self.candidates],
                "commit_sha": self.commit_sha,
                "plugin_kind": self.plugin_kind.value,
                "plugin_version": self.plugin_version,
                "relations": [item.id for item in self.relations],
                "source_file_id": self.source_file_id,
                "source_revision_context_id": self.source_revision_context_id,
                "unknown_evidence": [item.id for item in self.unknown_evidence],
            },
        )


@dataclass(frozen=True, slots=True)
class ArtifactTopologySnapshot:
    """Authorized immutable topology observations at a requested temporal cutoff."""

    candidates: tuple[TopologyCandidate, ...]
    relations: tuple[TopologyRelationCandidate, ...]
    unknown_evidence: tuple[UnknownTopologyEvidence, ...]
    cutoff: datetime

    def __post_init__(self) -> None:
        """Require canonical result ordering and UTC cutoff."""
        _utc(self.cutoff, _ERR_BATCH)
        for values in (self.candidates, self.relations, self.unknown_evidence):
            if tuple(item.id for item in values) != tuple(sorted({item.id for item in values})):
                raise IndexingValidationError(_ERR_BATCH)


def stable_topology_entity_id(kind: TopologyEntityKind, canonical_name: str) -> str:
    """Derive a deterministic UUIDv7 graph identity from kind and canonical name."""
    _enum(kind, TopologyEntityKind, _ERR_CANDIDATE)
    _reference(canonical_name)
    raw = bytearray(
        hashlib.sha256(
            f"artifact-topology-entity.v1\0{kind.value}\0{canonical_name}".encode()
        ).digest()[:16]
    )
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(UUID(bytes=bytes(raw)))


def normalize_environment_reference(value: str) -> str:
    """Normalize configuration identity without accepting or returning its value."""
    normalized = re.sub(r"[^A-Za-z0-9]+", "_", value.strip()).strip("_").upper()
    _environment_reference(normalized)
    return normalized


def safe_external_reference(value: str) -> str:
    """Reject credentials, query data, fragments, whitespace, and environment interpolation."""
    candidate = value.strip()
    if not candidate or any(marker in candidate for marker in ("${", "{{", "}}")):
        raise IndexingValidationError(_ERR_CANDIDATE)
    parsed = urlsplit(candidate if "://" in candidate else f"scheme://host/{candidate}")
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise IndexingValidationError(_ERR_CANDIDATE)
    _reference(candidate)
    return candidate


def _identity(namespace: str, document: dict[str, object]) -> str:
    encoded = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(f"{namespace}\0{encoded}".encode()).hexdigest()


def _stable_id(value: str, message: str) -> None:
    try:
        parsed = UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise IndexingValidationError(message) from error
    if parsed.version != _UUID7 or str(parsed) != value:
        raise IndexingValidationError(message)


def _digest(value: str, message: str) -> None:
    if _DIGEST.fullmatch(value) is None:
        raise IndexingValidationError(message)


def _path(value: str) -> None:
    if not value or len(value.encode()) > _MAX_PATH_BYTES or "\\" in value or "\x00" in value:
        raise IndexingValidationError(_ERR_EVIDENCE)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(_ERR_EVIDENCE)


def _reference(value: str) -> None:
    if _REFERENCE.fullmatch(value) is None:
        raise IndexingValidationError(_ERR_CANDIDATE)


def _environment_reference(value: str) -> None:
    if _ENVIRONMENT_REFERENCE.fullmatch(value) is None:
        raise IndexingValidationError(_ERR_CANDIDATE)


def _sorted_references(values: tuple[str, ...]) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(_ERR_CANDIDATE)
    for value in values:
        _reference(value)


def _enum(value: object, expected: type[StrEnum], message: str) -> None:
    if type(value) is not expected:
        raise IndexingValidationError(message)


def _utc(value: datetime, message: str) -> None:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise IndexingValidationError(message)
