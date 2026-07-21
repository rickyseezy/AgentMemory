"""IDX-007 immutable source-evidence links and safe checkout mappings."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import cast
from urllib.parse import quote

from agentmemory.indexing.domain.code_entities import (
    OccurrenceRole,
    SemanticSource,
    SourceSpan,
    SymbolKind,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_ERR_EVIDENCE = "source navigation evidence is invalid"
_ERR_LINK = "source navigation link is invalid"
_MAX_PATH_BYTES = 4_096
_MAX_IDENTITY = 2_048
_LF = 10


class SourceEvidenceKind(StrEnum):
    """Closed persisted semantic-evidence kinds accepted by navigation."""

    DEFINITION = "definition"
    OCCURRENCE = "occurrence"


class CheckoutResolution(StrEnum):
    """Explicit relationship between immutable evidence and the active checkout."""

    EXACT = "exact"
    DIFFERENT_MAPPED = "different_mapped"
    DIFFERENT_UNMAPPED = "different_unmapped"
    UNAVAILABLE = "unavailable"


class WorktreeMappingKind(StrEnum):
    """How an exact historical span maps into current worktree bytes."""

    EXACT = "exact"
    RENAMED = "renamed"
    SHIFTED = "shifted"
    RENAMED_AND_SHIFTED = "renamed_and_shifted"


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    """Complete immutable coordinates behind one code-derived result."""

    evidence_id: str
    kind: SourceEvidenceKind
    brain_id: str
    project_id: str
    repository_id: str
    snapshot_id: str
    commit_id: str | None
    source_file_id: str
    file_revision_id: str
    relative_path: str
    symbol_id: str
    symbol_stable_key: str
    symbol_display_name: str
    symbol_kind: SymbolKind
    occurrence_role: OccurrenceRole | None
    span: SourceSpan
    content_digest: str
    byte_length: int
    parser_version: str
    grammar_revision: str
    query_pack_digest: str
    semantic_source: SemanticSource

    def __post_init__(self) -> None:
        """Reject incomplete scope, revision, symbol, parser, or span coordinates."""
        for value in (
            self.evidence_id,
            self.snapshot_id,
            self.source_file_id,
            self.file_revision_id,
            self.symbol_id,
            self.content_digest,
            self.query_pack_digest,
        ):
            _digest(value, _ERR_EVIDENCE)
        for value in (self.brain_id, self.project_id, self.repository_id):
            _identity(value, _ERR_EVIDENCE)
        _path(self.relative_path, _ERR_EVIDENCE)
        _enum(self.kind, SourceEvidenceKind, _ERR_EVIDENCE)
        _enum(self.symbol_kind, SymbolKind, _ERR_EVIDENCE)
        _enum(self.semantic_source, SemanticSource, _ERR_EVIDENCE)
        if self.commit_id is not None and _COMMIT.fullmatch(self.commit_id) is None:
            raise IndexingValidationError(_ERR_EVIDENCE)
        if (
            isinstance(cast("object", self.byte_length), bool)
            or not isinstance(cast("object", self.byte_length), int)
            or self.byte_length < 1
            or self.span.end_byte <= self.span.start_byte
            or self.span.end_byte > self.byte_length
        ):
            raise IndexingValidationError(_ERR_EVIDENCE)
        for value in (
            self.symbol_stable_key,
            self.symbol_display_name,
            self.parser_version,
            self.grammar_revision,
        ):
            _identity(value, _ERR_EVIDENCE)
        expected_role = self.kind is SourceEvidenceKind.OCCURRENCE
        if expected_role != (self.occurrence_role is not None):
            raise IndexingValidationError(_ERR_EVIDENCE)
        if self.occurrence_role is not None:
            _enum(self.occurrence_role, OccurrenceRole, _ERR_EVIDENCE)

    @property
    def immutable_revision_uri(self) -> str:
        """Return a path-safe immutable URI bound to revision, digest, and byte span."""
        revision = self.commit_id or f"snapshot-{self.snapshot_id}"
        path = quote(self.relative_path, safe="/")
        return (
            f"agentmemory://source/{quote(self.repository_id, safe='')}/{revision}/{path}"
            f"?sha256={self.content_digest}&file_revision={self.file_revision_id}"
            f"#bytes={self.span.start_byte},{self.span.end_byte}"
        )


@dataclass(frozen=True, slots=True)
class CheckoutCandidate:
    """Ephemeral bounded current-checkout bytes supplied by a trusted adapter."""

    commit_id: str
    relative_path: str
    content: bytes
    checkout_dirty: bool = False

    def __post_init__(self) -> None:
        """Require a canonical commit, safe relative path, and immutable byte value."""
        if _COMMIT.fullmatch(self.commit_id) is None:
            raise IndexingValidationError(_ERR_LINK)
        _path(self.relative_path, _ERR_LINK)
        if not isinstance(cast("object", self.content), bytes):
            raise IndexingValidationError(_ERR_LINK)
        if not isinstance(cast("object", self.checkout_dirty), bool):
            raise IndexingValidationError(_ERR_LINK)

    @property
    def content_digest(self) -> str:
        """Return the candidate's exact SHA-256 digest."""
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, slots=True)
class CurrentWorktreeMapping:
    """Verified optional mapping from immutable evidence into current bytes."""

    relative_path: str
    span: SourceSpan
    content_digest: str
    kind: WorktreeMappingKind

    def __post_init__(self) -> None:
        """Require only repository-relative, content-addressed mapping coordinates."""
        _path(self.relative_path, _ERR_LINK)
        _digest(self.content_digest, _ERR_LINK)
        _enum(self.kind, WorktreeMappingKind, _ERR_LINK)


@dataclass(frozen=True, slots=True)
class SourceLink:
    """Revision-bound navigation result with an explicit checkout mismatch state."""

    evidence: SourceEvidence
    immutable_revision_uri: str
    checkout_resolution: CheckoutResolution
    checkout_commit_id: str | None
    checkout_dirty: bool | None
    checkout_mismatch: bool
    historical_blob_available: bool
    current_mapping: CurrentWorktreeMapping | None

    def __post_init__(self) -> None:
        """Prevent a mutable mapping from masquerading as immutable evidence."""
        if self.immutable_revision_uri != self.evidence.immutable_revision_uri:
            raise IndexingValidationError(_ERR_LINK)
        _enum(self.checkout_resolution, CheckoutResolution, _ERR_LINK)
        if (
            self.checkout_commit_id is not None
            and _COMMIT.fullmatch(self.checkout_commit_id) is None
        ):
            raise IndexingValidationError(_ERR_LINK)
        if self.checkout_dirty is not None and not isinstance(
            cast("object", self.checkout_dirty), bool
        ):
            raise IndexingValidationError(_ERR_LINK)
        if not isinstance(cast("object", self.checkout_mismatch), bool) or not isinstance(
            cast("object", self.historical_blob_available), bool
        ):
            raise IndexingValidationError(_ERR_LINK)
        if self.checkout_resolution is CheckoutResolution.EXACT:
            if (
                self.checkout_mismatch
                or self.checkout_dirty is not False
                or self.current_mapping is None
            ):
                raise IndexingValidationError(_ERR_LINK)
        elif not self.checkout_mismatch:
            raise IndexingValidationError(_ERR_LINK)
        if (self.checkout_resolution is CheckoutResolution.DIFFERENT_MAPPED) != (
            self.current_mapping is not None
            and self.checkout_resolution is not CheckoutResolution.EXACT
        ):
            raise IndexingValidationError(_ERR_LINK)


@dataclass(frozen=True, slots=True)
class LocalSourceTarget:
    """Transient host-only open target; absolute paths are never persisted."""

    absolute_path: str
    relative_path: str
    span: SourceSpan
    content_digest: str

    def __post_init__(self) -> None:
        """Require a validated adapter-produced absolute target and exact mapping digest."""
        if not self.absolute_path or not self.absolute_path.startswith("/"):
            raise IndexingValidationError(_ERR_LINK)
        _path(self.relative_path, _ERR_LINK)
        _digest(self.content_digest, _ERR_LINK)


def span_for_offsets(content: bytes, start: int, end: int) -> SourceSpan:
    """Construct exact byte-column coordinates for a half-open range."""
    if (
        isinstance(cast("object", start), bool)
        or isinstance(cast("object", end), bool)
        or not isinstance(cast("object", start), int)
        or not isinstance(cast("object", end), int)
        or start < 0
        or end <= start
        or end > len(content)
    ):
        raise IndexingValidationError(_ERR_LINK)
    starts = [0]
    starts.extend(index + 1 for index, value in enumerate(content) if value == _LF)
    start_line = _line_index(starts, start)
    end_line = _line_index(starts, end)
    span = SourceSpan(
        start,
        end,
        start_line,
        start - starts[start_line],
        end_line,
        end - starts[end_line],
    )
    span.validate_source(content)
    return span


def _line_index(starts: list[int], offset: int) -> int:
    for index in range(len(starts) - 1, -1, -1):
        if starts[index] <= offset:
            return index
    raise IndexingValidationError(_ERR_LINK)


def _path(value: str, message: str) -> None:
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError as error:
        raise IndexingValidationError(message) from error
    path = PurePosixPath(value)
    if (
        not value
        or len(encoded) > _MAX_PATH_BYTES
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(message)


def _digest(value: str, message: str) -> None:
    if _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise IndexingValidationError(message)


def _identity(value: str, message: str) -> None:
    if (
        not value
        or len(value) > _MAX_IDENTITY
        or any(character in "\x00\r\n" for character in value)
    ):
        raise IndexingValidationError(message)


def _enum(value: object, enum_type: type[StrEnum], message: str) -> None:
    if not isinstance(value, enum_type):
        raise IndexingValidationError(message)
