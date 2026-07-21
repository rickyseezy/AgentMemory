"""IDX-001 domain ports for source discovery, parsing, SCIP, and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.code_entities import (
        CodeSymbol,
        FileRevision,
        IndexedFile,
        LanguageTier,
        SourceSnapshot,
        SymbolOccurrence,
        SymbolRevision,
    )


@dataclass(frozen=True, slots=True)
class SourceArtifact:
    """Repository-relative exact source bytes supplied by a bounded adapter."""

    relative_path: str
    content: bytes


@dataclass(frozen=True, slots=True)
class ParsedSource:
    """Language adapter result before canonical entity construction."""

    language: str
    parser_version: str
    grammar_revision: str
    query_pack_digest: str
    recovered_errors: int
    definitions: tuple[ParsedDefinition, ...]
    occurrences: tuple[ParsedOccurrence, ...]


@dataclass(frozen=True, slots=True)
class ParserDescriptor:
    """Immutable parser coordinates available even when parsing fails."""

    language: str
    tier: LanguageTier
    parser_version: str
    grammar_revision: str
    query_pack_digest: str


@dataclass(frozen=True, slots=True)
class PreciseEvidence:
    """Compiler/SCIP evidence ready for append-only merge."""

    symbols: tuple[CodeSymbol, ...]
    revisions: tuple[SymbolRevision, ...]
    occurrences: tuple[SymbolOccurrence, ...]


@dataclass(frozen=True, slots=True)
class ParsedDefinition:
    """Language-neutral syntactic definition candidate."""

    stable_key: str
    display_name: str
    kind: str
    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int


@dataclass(frozen=True, slots=True)
class ParsedOccurrence:
    """Language-neutral syntactic navigation candidate."""

    target_key: str
    role: str
    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int


class RepositorySnapshotSource(Protocol):
    """Read a bounded immutable view of repository-relative artifacts."""

    async def read(self, scope: AuthorizedScope) -> tuple[SourceArtifact, ...]:
        """Return exact bytes without exposing an absolute host path."""
        ...


class LanguagePluginPort(Protocol):
    """Detect, parse, and extract supported source semantics."""

    def detect(self, relative_path: str, content: bytes) -> str | None:
        """Return a supported language or lexical fallback."""
        ...

    def parse(self, language: str, relative_path: str, content: bytes) -> ParsedSource:
        """Parse one file independently and return content-free structure."""
        ...

    def describe(self, language: str) -> ParserDescriptor:
        """Return immutable parser evidence without parsing source content."""
        ...


class PreciseIndexImporterPort(Protocol):
    """Decode precise external code-intelligence evidence."""

    def map(
        self,
        *,
        repository_id: str,
        file_revision: FileRevision,
        source: bytes,
        payload: bytes,
    ) -> PreciseEvidence:
        """Map bounded external evidence without changing syntactic provenance."""
        ...


class CodeIndexRepository(Protocol):
    """Persist and query immutable source and semantic evidence."""

    async def start_snapshot(
        self, scope: AuthorizedScope, operation_id: str, snapshot: SourceSnapshot
    ) -> SourceSnapshot:
        """Create or replay one exact source snapshot."""
        ...

    async def save_file(self, scope: AuthorizedScope, indexed: IndexedFile) -> IndexedFile:
        """Atomically append one independently parsed file and evidence."""
        ...

    async def merge_precise_evidence(
        self,
        scope: AuthorizedScope,
        file_revision_id: str,
        symbols: tuple[CodeSymbol, ...],
        revisions: tuple[SymbolRevision, ...],
        occurrences: tuple[SymbolOccurrence, ...],
    ) -> None:
        """Append precise evidence without deleting syntactic provenance."""
        ...

    async def list_files(self, scope: AuthorizedScope, snapshot_id: str) -> tuple[IndexedFile, ...]:
        """Read authorized indexed files and all retained evidence."""
        ...
