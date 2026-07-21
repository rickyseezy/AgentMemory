"""IDX-001 snapshot indexing, parser isolation, SCIP merge, and code search use cases."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from agentmemory.indexing.domain.code_entities import (
    CodeSymbol,
    FileRevision,
    IndexedFile,
    LanguageTier,
    OccurrenceRole,
    ParseFailure,
    ParseStatus,
    SemanticPriority,
    SemanticSource,
    SourceFile,
    SourceSnapshot,
    SourceSpan,
    SymbolKind,
    SymbolOccurrence,
    SymbolRevision,
    content_digest,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.ports import ParserDescriptor

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.ports import (
        CodeIndexRepository,
        LanguagePluginPort,
        ParsedSource,
        PreciseIndexImporterPort,
        RepositorySnapshotSource,
        SourceArtifact,
    )

_ERR_ACTION = "code indexing action is not authorized"
_ERR_SCOPE = "code indexing requires one exact project and repository"
_ERR_SOURCE = "source artifact is invalid"
_MAX_ARTIFACTS = 1_000_000
_MAX_SOURCE_BYTES = 64 * 1024 * 1024
_MAX_QUERY = 512
_MAX_RESULTS = 100
_MAX_GRAMMAR_REVISION = 128
_OPERATION_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_LANGUAGE = re.compile(r"^[a-z][a-z0-9_+.-]{0,63}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_EMPTY_DIGEST = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True, slots=True)
class IndexRepositorySnapshotCommand:
    """Index one immutable repository/working-tree coordinate."""

    operation_id: str
    scope: AuthorizedScope
    commit_id: str | None
    working_digest: str
    created_at: datetime

    def __post_init__(self) -> None:
        """Reject ambiguous operation replay identities before any adapter call."""
        if _OPERATION_ID.fullmatch(self.operation_id) is None:
            raise IndexingValidationError(_ERR_SOURCE)


@dataclass(frozen=True, slots=True)
class IndexSnapshotResult:
    """Content-free result including independent file failure coverage."""

    snapshot: SourceSnapshot
    file_count: int
    indexed_count: int
    recovered_count: int
    failed_count: int


@dataclass(frozen=True, slots=True)
class IndexRepositorySnapshotHandler:
    """Parse every source independently and persist immutable evidence per file."""

    source: RepositorySnapshotSource
    plugin: LanguagePluginPort
    repository: CodeIndexRepository

    async def execute(self, command: IndexRepositorySnapshotCommand) -> IndexSnapshotResult:
        """Authorize, capture the snapshot, isolate parser failures, and report coverage."""
        _require_action(command.scope, "indexing.snapshot")
        project_id, repository_id = _exact_scope(command.scope)
        snapshot = SourceSnapshot.create(
            brain_id=command.scope.brain_id.value,
            project_id=project_id,
            repository_id=repository_id,
            commit_id=command.commit_id,
            working_digest=command.working_digest,
            created_at=command.created_at,
        )
        snapshot = await self.repository.start_snapshot(
            command.scope, command.operation_id, snapshot
        )
        artifacts = await self.source.read(command.scope)
        if len(artifacts) > _MAX_ARTIFACTS:
            raise IndexingValidationError(_ERR_SOURCE)
        indexed_count = 0
        recovered_count = 0
        failed_count = 0
        for artifact in sorted(artifacts, key=lambda item: item.relative_path):
            indexed = self._index_file(snapshot, repository_id, artifact)
            await self.repository.save_file(command.scope, indexed)
            if indexed.revision.status is ParseStatus.FAILED:
                failed_count += 1
            else:
                indexed_count += 1
                if indexed.revision.status is ParseStatus.RECOVERED:
                    recovered_count += 1
        return IndexSnapshotResult(
            snapshot, len(artifacts), indexed_count, recovered_count, failed_count
        )

    def _index_file(
        self, snapshot: SourceSnapshot, repository_id: str, artifact: SourceArtifact
    ) -> IndexedFile:
        return index_source_artifact(self.plugin, snapshot, repository_id, artifact)


def index_source_artifact(  # noqa: PLR0911 -- Failures are closed file-scoped evidence.
    plugin: LanguagePluginPort,
    snapshot: SourceSnapshot,
    repository_id: str,
    artifact: SourceArtifact,
) -> IndexedFile:
    """Index one exact artifact for full and incremental orchestrators alike."""
    source_file = SourceFile.create(repository_id, artifact.relative_path)
    if len(artifact.content) > _MAX_SOURCE_BYTES:
        return _failed_file(
            source_file,
            snapshot,
            artifact.content,
            _failure_descriptor("unknown"),
            "source_too_large",
        )
    try:
        language = plugin.detect(artifact.relative_path, artifact.content)
    except Exception:  # noqa: BLE001 -- Detector code is an untrusted plugin boundary.
        return _failed_file(
            source_file,
            snapshot,
            artifact.content,
            _failure_descriptor("unknown"),
            "detector_crash",
        )
    if language is None:
        return _failed_file(
            source_file,
            snapshot,
            artifact.content,
            _failure_descriptor("binary", parser_version="detector-v1"),
            "unsupported_encoding",
        )
    try:
        descriptor = plugin.describe(language)
    except Exception:  # noqa: BLE001 -- Descriptor code is an untrusted plugin boundary.
        return _failed_file(
            source_file,
            snapshot,
            artifact.content,
            _failure_descriptor(language),
            "descriptor_crash",
        )
    if not _valid_descriptor(descriptor):
        return _failed_file(
            source_file,
            snapshot,
            artifact.content,
            _failure_descriptor(language),
            "descriptor_crash",
        )
    try:
        parsed = plugin.parse(language, artifact.relative_path, artifact.content)
    except Exception:  # noqa: BLE001 -- One parser failure must not abort sibling files.
        return _failed_file(
            source_file,
            snapshot,
            artifact.content,
            descriptor,
            "parser_crash",
        )
    try:
        return _parsed_file(source_file, snapshot, artifact.content, descriptor, parsed)
    except Exception:  # noqa: BLE001 -- Invalid plugin DTOs remain file-scoped evidence.
        return _failed_file(
            source_file,
            snapshot,
            artifact.content,
            descriptor,
            "parser_output_invalid",
        )


@dataclass(frozen=True, slots=True)
class ImportScipCommand:
    """Merge precise SCIP evidence into one existing file revision."""

    scope: AuthorizedScope
    file_revision: FileRevision
    source: bytes
    payload: bytes


@dataclass(frozen=True, slots=True)
class ImportScipHandler:
    """Append SCIP evidence without deleting Tree-sitter provenance."""

    importer: PreciseIndexImporterPort
    repository: CodeIndexRepository

    async def execute(self, command: ImportScipCommand) -> None:
        """Authorize, verify source bytes, map precise evidence, and append it."""
        _require_action(command.scope, "indexing.scip.import")
        _, repository_id = _exact_scope(command.scope)
        if content_digest(command.source) != command.file_revision.content_digest:
            raise IndexingValidationError(_ERR_SOURCE)
        evidence = self.importer.map(
            repository_id=repository_id,
            file_revision=command.file_revision,
            source=command.source,
            payload=command.payload,
        )
        await self.repository.merge_precise_evidence(
            command.scope,
            command.file_revision.id,
            evidence.symbols,
            evidence.revisions,
            evidence.occurrences,
        )


@dataclass(frozen=True, slots=True)
class FindCodeEntitiesQuery:
    """Find indexed code symbols and navigation facts in one snapshot."""

    scope: AuthorizedScope
    snapshot_id: str
    term: str
    limit: int = 50


@dataclass(frozen=True, slots=True)
class CodeSearchHit:
    """Authorized content-free code navigation result."""

    symbol_id: str
    display_name: str
    kind: SymbolKind
    file_id: str
    file_revision_id: str
    relative_path: str
    span: SourceSpan | None
    source: SemanticSource | None


@dataclass(frozen=True, slots=True)
class FindCodeEntitiesHandler:
    """Search persisted symbols and expose highest-priority authorized definitions."""

    repository: CodeIndexRepository

    async def execute(self, query: FindCodeEntitiesQuery) -> tuple[CodeSearchHit, ...]:
        """Return stable, bounded, case-insensitive code symbol matches."""
        _require_action(query.scope, "indexing.search")
        if (
            not query.term.strip()
            or len(query.term) > _MAX_QUERY
            or not 1 <= query.limit <= _MAX_RESULTS
        ):
            raise IndexingValidationError(_ERR_SOURCE)
        needle = query.term.casefold()
        files = await self.repository.list_files(query.scope, query.snapshot_id)
        hits: list[CodeSearchHit] = []
        for indexed in files:
            preferred = {item.symbol_id: item for item in indexed.preferred_symbol_revisions()}
            for symbol in indexed.symbols:
                if (
                    needle not in symbol.display_name.casefold()
                    and needle not in symbol.stable_key.casefold()
                ):
                    continue
                evidence = preferred.get(symbol.id)
                hits.append(
                    CodeSearchHit(
                        symbol.id,
                        symbol.display_name,
                        symbol.kind,
                        indexed.file.id,
                        indexed.revision.id,
                        indexed.file.relative_path,
                        None if evidence is None else evidence.span,
                        None if evidence is None else evidence.source,
                    )
                )
        return tuple(
            sorted(hits, key=lambda item: (item.relative_path, item.display_name, item.symbol_id))[
                : query.limit
            ]
        )


def _parsed_file(
    source_file: SourceFile,
    snapshot: SourceSnapshot,
    source: bytes,
    descriptor: ParserDescriptor,
    parsed: ParsedSource,
) -> IndexedFile:
    if descriptor.tier is LanguageTier.LEXICAL:
        status = ParseStatus.LEXICAL_ONLY
    else:
        status = ParseStatus.RECOVERED if parsed.recovered_errors else ParseStatus.SUCCEEDED
    revision = FileRevision.create(
        file_id=source_file.id,
        snapshot_id=snapshot.id,
        content_digest=content_digest(source),
        byte_length=len(source),
        language=parsed.language,
        language_tier=descriptor.tier,
        parser_version=parsed.parser_version,
        grammar_revision=parsed.grammar_revision,
        query_pack_digest=parsed.query_pack_digest,
        status=status,
        error_count=parsed.recovered_errors,
    )
    symbols: dict[str, CodeSymbol] = {}
    revisions: list[SymbolRevision] = []
    occurrences: list[SymbolOccurrence] = []
    for definition in parsed.definitions:
        span = _span(definition, source)
        kind = SymbolKind(definition.kind)
        symbol = CodeSymbol.create(
            source_file.repository_id, definition.stable_key, definition.display_name, kind
        )
        symbols[symbol.id] = symbol
        source_identity = f"{parsed.parser_version}:{parsed.query_pack_digest}:{definition.kind}"
        revisions.append(
            SymbolRevision.create(
                symbol_id=symbol.id,
                file_revision_id=revision.id,
                span=span,
                source=SemanticSource.TREE_SITTER,
                priority=SemanticPriority.TREE_SITTER,
                source_identity=source_identity,
            )
        )
        occurrences.append(
            SymbolOccurrence.create(
                file_revision_id=revision.id,
                target_symbol_id=symbol.id,
                role=OccurrenceRole.DEFINITION,
                span=span,
                source=SemanticSource.TREE_SITTER,
                priority=SemanticPriority.TREE_SITTER,
                source_identity=source_identity,
            )
        )
    for occurrence in parsed.occurrences:
        span = _span(occurrence, source)
        symbol = CodeSymbol.create(
            source_file.repository_id,
            occurrence.target_key,
            _display_from_span(source, span),
            SymbolKind.UNKNOWN,
        )
        symbols.setdefault(symbol.id, symbol)
        role = OccurrenceRole(occurrence.role)
        occurrences.append(
            SymbolOccurrence.create(
                file_revision_id=revision.id,
                target_symbol_id=symbol.id,
                role=role,
                span=span,
                source=SemanticSource.TREE_SITTER,
                priority=SemanticPriority.TREE_SITTER,
                source_identity=f"{parsed.parser_version}:{parsed.query_pack_digest}:{role.value}",
            )
        )
    failures = (
        (
            ParseFailure.create(
                file_revision_id=revision.id,
                language=parsed.language,
                parser_version=parsed.parser_version,
                error_code="syntax_recovered",
                recoverable=True,
            ),
        )
        if parsed.recovered_errors
        else ()
    )
    return IndexedFile(
        source_file,
        revision,
        tuple(sorted(symbols.values(), key=lambda item: item.id)),
        tuple(sorted(set(revisions), key=lambda item: item.id)),
        tuple(sorted(set(occurrences), key=lambda item: item.id)),
        failures,
    )


def _failed_file(
    source_file: SourceFile,
    snapshot: SourceSnapshot,
    source: bytes,
    descriptor: ParserDescriptor,
    error_code: str,
) -> IndexedFile:
    revision = FileRevision.create(
        file_id=source_file.id,
        snapshot_id=snapshot.id,
        content_digest=content_digest(source),
        byte_length=len(source),
        language=descriptor.language,
        language_tier=descriptor.tier,
        parser_version=descriptor.parser_version,
        grammar_revision=descriptor.grammar_revision,
        query_pack_digest=descriptor.query_pack_digest,
        status=ParseStatus.FAILED,
        error_count=1,
    )
    failure = ParseFailure.create(
        file_revision_id=revision.id,
        language=descriptor.language,
        parser_version=descriptor.parser_version,
        error_code=error_code,
        recoverable=False,
    )
    return IndexedFile(source_file, revision, (), (), (), (failure,))


def _failure_descriptor(
    language: str, *, parser_version: str = "unavailable-v1"
) -> ParserDescriptor:
    """Create bounded fallback provenance without trusting plugin-returned coordinates."""
    safe_language = language if _LANGUAGE.fullmatch(language) is not None else "unknown"
    return ParserDescriptor(
        safe_language,
        LanguageTier.LEXICAL,
        parser_version,
        "unavailable-v1",
        _EMPTY_DIGEST,
    )


def _valid_descriptor(descriptor: object) -> bool:
    """Validate the otherwise framework-free adapter DTO before canonical construction."""
    return (
        isinstance(descriptor, ParserDescriptor)
        and _LANGUAGE.fullmatch(descriptor.language) is not None
        and isinstance(cast("object", descriptor.tier), LanguageTier)
        and bool(descriptor.parser_version)
        and 0 < len(descriptor.grammar_revision) <= _MAX_GRAMMAR_REVISION
        and _SHA256.fullmatch(descriptor.query_pack_digest) is not None
    )


def _span(value: object, source: bytes) -> SourceSpan:
    fields = (
        "start_byte",
        "end_byte",
        "start_line",
        "start_column",
        "end_line",
        "end_column",
    )
    try:
        coordinates = tuple(getattr(value, field) for field in fields)
        span = SourceSpan(*coordinates)
    except (AttributeError, TypeError, IndexingValidationError) as error:
        raise IndexingValidationError(_ERR_SOURCE) from error
    span.validate_source(source)
    return span


def _display_from_span(source: bytes, span: SourceSpan) -> str:
    try:
        value = source[span.start_byte : span.end_byte].decode()
    except UnicodeDecodeError as error:
        raise IndexingValidationError(_ERR_SOURCE) from error
    if not value:
        raise IndexingValidationError(_ERR_SOURCE)
    return value


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _exact_scope(scope: AuthorizedScope) -> tuple[str, str]:
    if len(scope.project_ids) != 1 or len(scope.repository_ids) != 1:
        raise IndexingAuthorizationError(_ERR_SCOPE)
    return scope.project_ids[0].value, scope.repository_ids[0].value
