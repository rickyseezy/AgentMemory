"""IDX-001 immutable source, symbol, occurrence, and parser evidence model."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import IntEnum, StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, cast

from agentmemory.indexing.domain.errors import IndexingValidationError

if TYPE_CHECKING:
    from collections.abc import Mapping

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[a-z][a-z0-9_+.-]{0,63}$")
_ERR_ENTITY = "code entity is invalid"
_ERR_SPAN = "source span is invalid"
_ERR_PATH = "repository-relative source path is invalid"
_ERR_PARSE = "parse evidence is invalid"
_MAX_IDENTITY = 128
_MAX_STABLE_KEY = 2_048
_MAX_DISPLAY_NAME = 512
_MAX_PATH_BYTES = 4_096
_LF = 10


class LanguageTier(StrEnum):
    """Supported code-intelligence precision tier."""

    PRECISE = "precise"
    STRUCTURAL = "structural"
    LEXICAL = "lexical"


class SemanticSource(StrEnum):
    """Closed provenance classes; source data is always retained."""

    LEXICAL = "lexical"
    TREE_SITTER = "tree_sitter"
    SCIP = "scip"
    COMPILER = "compiler"


class SemanticPriority(IntEnum):
    """Higher precision supersedes compatible lower-priority candidates."""

    LEXICAL = 10
    TREE_SITTER = 100
    SCIP = 300
    COMPILER = 400


class SymbolKind(StrEnum):
    """Language-neutral symbol taxonomy."""

    MODULE = "module"
    PACKAGE = "package"
    NAMESPACE = "namespace"
    CLASS = "class"
    INTERFACE = "interface"
    TRAIT = "trait"
    ENUM = "enum"
    TYPE = "type"
    FUNCTION = "function"
    METHOD = "method"
    CONSTRUCTOR = "constructor"
    VARIABLE = "variable"
    CONSTANT = "constant"
    FIELD = "field"
    PROPERTY = "property"
    PARAMETER = "parameter"
    UNKNOWN = "unknown"


class OccurrenceRole(StrEnum):
    """Definition and navigation relationships emitted by language evidence."""

    DEFINITION = "definition"
    REFERENCE = "reference"
    CALL = "call"
    INHERITANCE = "inheritance"
    IMPLEMENTATION = "implementation"
    IMPORT = "import"


class ParseStatus(StrEnum):
    """Per-file parse outcome; partial recovery remains visible."""

    SUCCEEDED = "succeeded"
    RECOVERED = "recovered"
    FAILED = "failed"
    LEXICAL_ONLY = "lexical_only"


@dataclass(frozen=True, slots=True)
class SourceSpan:
    """Half-open UTF-8 byte and zero-based line/byte-column range."""

    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def __post_init__(self) -> None:
        """Reject negative, reversed, or coordinate-incoherent ranges."""
        values = (
            self.start_byte,
            self.end_byte,
            self.start_line,
            self.start_column,
            self.end_line,
            self.end_column,
        )
        if any(
            isinstance(cast("object", value), bool)
            or not isinstance(cast("object", value), int)
            or value < 0
            for value in values
        ):
            raise IndexingValidationError(_ERR_SPAN)
        if self.end_byte < self.start_byte or (self.end_line, self.end_column) < (
            self.start_line,
            self.start_column,
        ):
            raise IndexingValidationError(_ERR_SPAN)
        if (self.end_byte == self.start_byte) != (
            (self.end_line, self.end_column) == (self.start_line, self.start_column)
        ):
            raise IndexingValidationError(_ERR_SPAN)

    def validate_source(self, source: bytes) -> None:
        """Prove byte bounds and byte-column coordinates against exact source bytes."""
        if self.end_byte > len(source):
            raise IndexingValidationError(_ERR_SPAN)
        starts = _line_starts(source)
        if self.start_line >= len(starts) or self.end_line >= len(starts):
            raise IndexingValidationError(_ERR_SPAN)
        if starts[self.start_line] + self.start_column != self.start_byte:
            raise IndexingValidationError(_ERR_SPAN)
        if starts[self.end_line] + self.end_column != self.end_byte:
            raise IndexingValidationError(_ERR_SPAN)


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    """Immutable repository state selected for one indexing operation."""

    id: str
    brain_id: str
    project_id: str
    repository_id: str
    commit_id: str | None
    working_digest: str
    created_at: datetime

    @classmethod
    def create(  # noqa: PLR0913 -- Snapshot identity requires every repository coordinate.
        cls,
        *,
        brain_id: str,
        project_id: str,
        repository_id: str,
        commit_id: str | None,
        working_digest: str,
        created_at: datetime,
    ) -> SourceSnapshot:
        """Derive stable snapshot identity from scope and exact repository coordinates."""
        document = {
            "brain_id": brain_id,
            "commit_id": commit_id,
            "project_id": project_id,
            "repository_id": repository_id,
            "working_digest": working_digest,
        }
        return cls(
            _identity("source_snapshot", document),
            brain_id,
            project_id,
            repository_id,
            commit_id,
            working_digest,
            created_at,
        )

    def __post_init__(self) -> None:
        """Validate immutable scope, VCS, digest, and time coordinates."""
        for value in (self.id, self.working_digest):
            _digest(value)
        for value in (self.brain_id, self.project_id, self.repository_id):
            _opaque(value)
        if self.commit_id is not None and (
            not self.commit_id
            or len(self.commit_id) > _MAX_IDENTITY
            or any(ch.isspace() for ch in self.commit_id)
        ):
            raise IndexingValidationError(_ERR_ENTITY)
        _utc(self.created_at)


@dataclass(frozen=True, slots=True)
class SourceFile:
    """Stable repository-relative file identity."""

    id: str
    repository_id: str
    relative_path: str

    @classmethod
    def create(cls, repository_id: str, relative_path: str) -> SourceFile:
        """Create path identity without persisting an absolute host path."""
        _relative_path(relative_path)
        return cls(
            _identity("source_file", {"repository_id": repository_id, "path": relative_path}),
            repository_id,
            relative_path,
        )

    def __post_init__(self) -> None:
        """Validate stable file identity and repository-relative path."""
        _digest(self.id)
        _opaque(self.repository_id)
        _relative_path(self.relative_path)


@dataclass(frozen=True, slots=True)
class FileRevision:
    """One exact byte revision and its parser evidence."""

    id: str
    file_id: str
    snapshot_id: str
    content_digest: str
    byte_length: int
    language: str
    language_tier: LanguageTier
    parser_version: str
    grammar_revision: str
    query_pack_digest: str
    status: ParseStatus
    error_count: int

    @classmethod
    def create(  # noqa: PLR0913 -- Revision identity requires every parser coordinate.
        cls,
        *,
        file_id: str,
        snapshot_id: str,
        content_digest: str,
        byte_length: int,
        language: str,
        language_tier: LanguageTier,
        parser_version: str,
        grammar_revision: str,
        query_pack_digest: str,
        status: ParseStatus,
        error_count: int,
    ) -> FileRevision:
        """Derive immutable revision identity without source content or absolute path."""
        document = {
            "content_digest": content_digest,
            "file_id": file_id,
            "grammar_revision": grammar_revision,
            "language": language,
            "parser_version": parser_version,
            "query_pack_digest": query_pack_digest,
            "snapshot_id": snapshot_id,
        }
        return cls(
            _identity("file_revision", document),
            **document,
            byte_length=byte_length,
            language_tier=language_tier,
            status=status,
            error_count=error_count,
        )

    def __post_init__(self) -> None:
        """Validate parser coordinates and coherent parse status."""
        for value in (
            self.id,
            self.file_id,
            self.snapshot_id,
            self.content_digest,
            self.query_pack_digest,
        ):
            _digest(value)
        if _TOKEN.fullmatch(self.language) is None or not self.parser_version:
            raise IndexingValidationError(_ERR_ENTITY)
        if not self.grammar_revision or len(self.grammar_revision) > _MAX_IDENTITY:
            raise IndexingValidationError(_ERR_ENTITY)
        _enum(self.language_tier, LanguageTier)
        _enum(self.status, ParseStatus)
        if min(self.byte_length, self.error_count) < 0:
            raise IndexingValidationError(_ERR_ENTITY)
        if self.status is ParseStatus.SUCCEEDED and self.error_count != 0:
            raise IndexingValidationError(_ERR_PARSE)
        if self.status in {ParseStatus.RECOVERED, ParseStatus.FAILED} and self.error_count < 1:
            raise IndexingValidationError(_ERR_PARSE)


@dataclass(frozen=True, slots=True)
class CodeSymbol:
    """Stable semantic identity independent of a source revision."""

    id: str
    repository_id: str
    stable_key: str
    display_name: str
    kind: SymbolKind

    @classmethod
    def create(
        cls, repository_id: str, stable_key: str, display_name: str, kind: SymbolKind
    ) -> CodeSymbol:
        """Derive identity from the repository and source-specific stable key."""
        document = {"repository_id": repository_id, "stable_key": stable_key}
        return cls(
            _identity("code_symbol", document), repository_id, stable_key, display_name, kind
        )

    def __post_init__(self) -> None:
        """Validate stable symbol identity and bounded display metadata."""
        _digest(self.id)
        _opaque(self.repository_id)
        if not self.stable_key or len(self.stable_key) > _MAX_STABLE_KEY:
            raise IndexingValidationError(_ERR_ENTITY)
        if not self.display_name or len(self.display_name) > _MAX_DISPLAY_NAME:
            raise IndexingValidationError(_ERR_ENTITY)
        _enum(self.kind, SymbolKind)


@dataclass(frozen=True, slots=True)
class SymbolRevision:
    """One symbol definition tied to exact file bytes and provenance."""

    id: str
    symbol_id: str
    file_revision_id: str
    span: SourceSpan
    source: SemanticSource
    priority: SemanticPriority
    source_identity: str

    @classmethod
    def create(  # noqa: PLR0913 -- Provenance and exact coordinates are inseparable.
        cls,
        *,
        symbol_id: str,
        file_revision_id: str,
        span: SourceSpan,
        source: SemanticSource,
        priority: SemanticPriority,
        source_identity: str,
    ) -> SymbolRevision:
        """Derive stable evidence identity; lower-priority evidence remains distinct."""
        document = {
            "file_revision_id": file_revision_id,
            "priority": int(priority),
            "source": source.value,
            "source_identity": source_identity,
            "span": _span_document(span),
            "symbol_id": symbol_id,
        }
        return cls(
            _identity("symbol_revision", document),
            symbol_id,
            file_revision_id,
            span,
            source,
            priority,
            source_identity,
        )

    def __post_init__(self) -> None:
        """Validate symbol-revision provenance and identity."""
        _semantic_evidence(
            self.id,
            self.symbol_id,
            self.file_revision_id,
            self.source,
            self.priority,
            self.source_identity,
        )


@dataclass(frozen=True, slots=True)
class SymbolOccurrence:
    """Definition/reference/call/implementation fact with exact evidence."""

    id: str
    file_revision_id: str
    target_symbol_id: str
    role: OccurrenceRole
    span: SourceSpan
    source: SemanticSource
    priority: SemanticPriority
    source_identity: str

    @classmethod
    def create(  # noqa: PLR0913 -- Occurrence identity binds all evidence coordinates.
        cls,
        *,
        file_revision_id: str,
        target_symbol_id: str,
        role: OccurrenceRole,
        span: SourceSpan,
        source: SemanticSource,
        priority: SemanticPriority,
        source_identity: str,
    ) -> SymbolOccurrence:
        """Create a provenance-preserving navigation fact."""
        document = {
            "file_revision_id": file_revision_id,
            "priority": int(priority),
            "role": role.value,
            "source": source.value,
            "source_identity": source_identity,
            "span": _span_document(span),
            "target_symbol_id": target_symbol_id,
        }
        return cls(
            _identity("symbol_occurrence", document),
            file_revision_id,
            target_symbol_id,
            role,
            span,
            source,
            priority,
            source_identity,
        )

    def __post_init__(self) -> None:
        """Validate occurrence role, provenance, and identity."""
        _enum(self.role, OccurrenceRole)
        _semantic_evidence(
            self.id,
            self.target_symbol_id,
            self.file_revision_id,
            self.source,
            self.priority,
            self.source_identity,
        )


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """Visible content-free parser failure scoped to one file revision."""

    id: str
    file_revision_id: str
    language: str
    parser_version: str
    error_code: str
    recoverable: bool

    @classmethod
    def create(
        cls,
        *,
        file_revision_id: str,
        language: str,
        parser_version: str,
        error_code: str,
        recoverable: bool,
    ) -> ParseFailure:
        """Create deterministic failure evidence without raw parser output."""
        document = {
            "error_code": error_code,
            "file_revision_id": file_revision_id,
            "language": language,
            "parser_version": parser_version,
            "recoverable": recoverable,
        }
        return cls(
            _identity("parse_failure", document),
            file_revision_id,
            language,
            parser_version,
            error_code,
            recoverable,
        )

    def __post_init__(self) -> None:
        """Validate content-free parser failure evidence."""
        _digest(self.id)
        _digest(self.file_revision_id)
        if _TOKEN.fullmatch(self.language) is None or not self.parser_version:
            raise IndexingValidationError(_ERR_PARSE)
        if _TOKEN.fullmatch(self.error_code) is None or not isinstance(
            cast("object", self.recoverable), bool
        ):
            raise IndexingValidationError(_ERR_PARSE)


@dataclass(frozen=True, slots=True)
class IndexedFile:
    """Atomic persistence unit for one independently parsed file."""

    file: SourceFile
    revision: FileRevision
    symbols: tuple[CodeSymbol, ...]
    symbol_revisions: tuple[SymbolRevision, ...]
    occurrences: tuple[SymbolOccurrence, ...]
    failures: tuple[ParseFailure, ...] = ()

    def __post_init__(self) -> None:
        """Validate the atomic file aggregate and all contained references."""
        if self.revision.file_id != self.file.id:
            raise IndexingValidationError(_ERR_ENTITY)
        if len({item.id for item in self.symbols}) != len(self.symbols):
            raise IndexingValidationError(_ERR_ENTITY)
        self._validate_semantics()

    def _validate_semantics(self) -> None:
        """Require closed references, provenance ownership, and parse-state coherence."""
        symbol_ids = {item.id for item in self.symbols}
        if any(item.repository_id != self.file.repository_id for item in self.symbols):
            raise IndexingValidationError(_ERR_ENTITY)
        if any(item.symbol_id not in symbol_ids for item in self.symbol_revisions):
            raise IndexingValidationError(_ERR_ENTITY)
        if any(item.file_revision_id != self.revision.id for item in self.symbol_revisions):
            raise IndexingValidationError(_ERR_ENTITY)
        if any(item.file_revision_id != self.revision.id for item in self.occurrences):
            raise IndexingValidationError(_ERR_ENTITY)
        if any(item.target_symbol_id not in symbol_ids for item in self.occurrences):
            raise IndexingValidationError(_ERR_ENTITY)
        if any(item.file_revision_id != self.revision.id for item in self.failures):
            raise IndexingValidationError(_ERR_ENTITY)
        requires_failure = self.revision.status in {ParseStatus.RECOVERED, ParseStatus.FAILED}
        if requires_failure != bool(self.failures):
            raise IndexingValidationError(_ERR_PARSE)
        if self.revision.status in {ParseStatus.FAILED, ParseStatus.LEXICAL_ONLY} and (
            self.symbols or self.symbol_revisions or self.occurrences
        ):
            raise IndexingValidationError(_ERR_PARSE)

    def preferred_occurrences(self) -> tuple[SymbolOccurrence, ...]:
        """Select highest-priority compatible facts while retaining all evidence."""
        selected: dict[tuple[OccurrenceRole, SourceSpan], SymbolOccurrence] = {}
        for item in sorted(self.occurrences, key=lambda value: (int(value.priority), value.id)):
            selected[(item.role, item.span)] = item
        return tuple(sorted(selected.values(), key=lambda item: (item.span.start_byte, item.id)))

    def preferred_symbol_revisions(self) -> tuple[SymbolRevision, ...]:
        """Select precise definitions by span while retaining every provenance row."""
        selected: dict[SourceSpan, SymbolRevision] = {}
        for item in sorted(
            self.symbol_revisions, key=lambda value: (int(value.priority), value.id)
        ):
            selected[item.span] = item
        return tuple(sorted(selected.values(), key=lambda item: (item.span.start_byte, item.id)))


def content_digest(source: bytes) -> str:
    """Hash exact bytes without line-ending or Unicode normalization."""
    return hashlib.sha256(source).hexdigest()


def stable_identity(namespace: str, document: Mapping[str, object]) -> str:
    """Public stable identity helper for adapters mapping external symbols."""
    return _identity(namespace, document)


def _semantic_evidence(  # noqa: PLR0913 -- Shared validation binds all evidence coordinates.
    evidence_id: str,
    symbol_id: str,
    file_revision_id: str,
    source: SemanticSource,
    priority: SemanticPriority,
    source_identity: str,
) -> None:
    for value in (evidence_id, symbol_id, file_revision_id):
        _digest(value)
    _enum(source, SemanticSource)
    _enum(priority, SemanticPriority)
    expected = {
        SemanticSource.LEXICAL: SemanticPriority.LEXICAL,
        SemanticSource.TREE_SITTER: SemanticPriority.TREE_SITTER,
        SemanticSource.SCIP: SemanticPriority.SCIP,
        SemanticSource.COMPILER: SemanticPriority.COMPILER,
    }[source]
    if priority is not expected or not source_identity or len(source_identity) > _MAX_STABLE_KEY:
        raise IndexingValidationError(_ERR_ENTITY)


def _relative_path(value: str) -> None:
    if not value or "\\" in value or "\x00" in value or len(value.encode()) > _MAX_PATH_BYTES:
        raise IndexingValidationError(_ERR_PATH)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(_ERR_PATH)


def _line_starts(source: bytes) -> tuple[int, ...]:
    return (0, *(index + 1 for index, value in enumerate(source) if value == _LF))


def _identity(namespace: str, document: Mapping[str, object]) -> str:
    encoded = json.dumps(
        {"namespace": namespace, **document}, sort_keys=True, separators=(",", ":")
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _span_document(span: SourceSpan) -> dict[str, int]:
    return {
        "end_byte": span.end_byte,
        "end_column": span.end_column,
        "end_line": span.end_line,
        "start_byte": span.start_byte,
        "start_column": span.start_column,
        "start_line": span.start_line,
    }


def _digest(value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise IndexingValidationError(_ERR_ENTITY)


def _opaque(value: object) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_IDENTITY
        or any(ch.isspace() for ch in value)
    ):
        raise IndexingValidationError(_ERR_ENTITY)


def _enum(value: object, enum_type: type[StrEnum | IntEnum]) -> None:
    if not isinstance(value, enum_type):
        raise IndexingValidationError(_ERR_ENTITY)


def _utc(value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise IndexingValidationError(_ERR_ENTITY)
