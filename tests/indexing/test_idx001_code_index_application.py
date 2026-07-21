"""IDX-001 snapshot orchestration, crash isolation, SCIP merge, and search tests."""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.scip_import import ScipEvidenceMapper
from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import TreeSitterLanguagePlugin
from agentmemory.indexing.application.code_index import (
    FindCodeEntitiesHandler,
    FindCodeEntitiesQuery,
    ImportScipCommand,
    ImportScipHandler,
    IndexRepositorySnapshotCommand,
    IndexRepositorySnapshotHandler,
)
from agentmemory.indexing.domain.code_entities import (
    IndexedFile,
    LanguageTier,
    ParseStatus,
    SemanticSource,
    SourceSnapshot,
)
from agentmemory.indexing.domain.errors import IndexingAuthorizationError, IndexingValidationError
from agentmemory.indexing.domain.ports import (
    ParsedOccurrence,
    ParsedSource,
    ParserDescriptor,
    SourceArtifact,
)
from tests.graph.test_gra004_temporal_truth_application import (
    _scope,  # pyright: ignore[reportPrivateUsage]
)
from tests.graph.test_gra004_temporal_truth_domain import NOW

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.indexing.domain.code_entities import (
        CodeSymbol,
        SymbolOccurrence,
        SymbolRevision,
    )


@pytest.mark.asyncio
async def test_snapshot_parser_crash_and_binary_failure_are_isolated_per_file() -> None:
    repository = _Repository()
    source = _Source(
        (
            SourceArtifact("src/good.py", b"def hello():\n    return 1\n"),
            SourceArtifact("src/crash.py", b"def crash(): pass\n"),
            SourceArtifact("assets/binary.dat", b"\xff\xfe"),
        )
    )
    plugin = _CrashPlugin(TreeSitterLanguagePlugin())
    result = await IndexRepositorySnapshotHandler(source, plugin, repository).execute(
        _command("indexing.snapshot")
    )
    assert result.file_count == 3
    assert result.indexed_count == 1
    assert result.failed_count == 2
    assert [item.file.relative_path for item in repository.files] == [
        "assets/binary.dat",
        "src/crash.py",
        "src/good.py",
    ]
    assert repository.files[0].failures[0].error_code == "unsupported_encoding"
    assert repository.files[1].failures[0].error_code == "parser_crash"
    assert repository.files[2].revision.status is ParseStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_detector_and_descriptor_failures_are_isolated_from_sibling_files() -> None:
    repository = _Repository()
    result = await IndexRepositorySnapshotHandler(
        _Source(
            (
                SourceArtifact("src/detector.py", b"def detector(): pass\n"),
                SourceArtifact("src/descriptor.ts", b"export const value = 1;\n"),
                SourceArtifact("src/good.py", b"def good(): pass\n"),
            )
        ),
        _BoundaryFailurePlugin(TreeSitterLanguagePlugin()),
        repository,
    ).execute(_command("indexing.snapshot"))

    assert result.indexed_count == 1
    assert result.failed_count == 2
    assert [item.failures[0].error_code for item in repository.files[:2]] == [
        "descriptor_crash",
        "detector_crash",
    ]
    assert repository.files[2].revision.status is ParseStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_recovered_syntax_remains_searchable_and_visible() -> None:
    repository = _Repository()
    result = await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("broken.py", b"def hello(\n    pass\n"),)),
        TreeSitterLanguagePlugin(),
        repository,
    ).execute(_command("indexing.snapshot"))
    assert result.indexed_count == 1
    assert result.recovered_count == 1
    assert repository.files[0].revision.status is ParseStatus.RECOVERED
    assert repository.files[0].failures[0].recoverable


@pytest.mark.asyncio
async def test_unknown_utf8_source_is_explicitly_lexical_only() -> None:
    repository = _Repository()
    await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("notes.unknown", b"plain text\n"),)),
        TreeSitterLanguagePlugin(),
        repository,
    ).execute(_command("indexing.snapshot"))
    assert repository.files[0].revision.status is ParseStatus.LEXICAL_ONLY
    assert repository.files[0].symbols == ()


@pytest.mark.asyncio
async def test_scip_merge_preserves_syntax_and_search_prefers_precise_definition() -> None:
    repository = _Repository()
    source = b"def hello():\n    return 1\n"
    indexed = await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("main.py", source),)),
        TreeSitterLanguagePlugin(),
        repository,
    ).execute(_command("indexing.snapshot"))
    file_revision = repository.files[0].revision
    symbol = "scip-python python example 1.0 main/hello()."
    payload = json.dumps(
        {
            "relative_path": "main.py",
            "language": "python",
            "position_encoding": "UTF8CodeUnitOffsetFromLineStart",
            "occurrences": [{"range": [0, 4, 9], "symbol": symbol, "symbol_roles": 1}],
            "symbols": [{"symbol": symbol, "display_name": "hello", "kind": "Function"}],
        }
    ).encode()
    await ImportScipHandler(ScipEvidenceMapper(), repository).execute(
        ImportScipCommand(_scope("indexing.scip.import"), file_revision, source, payload)
    )
    stored = repository.files[0]
    assert any(item.source is SemanticSource.TREE_SITTER for item in stored.symbol_revisions)
    assert any(item.source is SemanticSource.SCIP for item in stored.symbol_revisions)
    assert any(item.source is SemanticSource.SCIP for item in stored.preferred_symbol_revisions())

    hits = await FindCodeEntitiesHandler(repository).execute(
        FindCodeEntitiesQuery(_scope("indexing.search"), indexed.snapshot.id, "hello", limit=10)
    )
    assert hits
    assert any(item.source is SemanticSource.SCIP for item in hits)


@pytest.mark.asyncio
async def test_indexing_authorizes_before_reading_source_or_repository() -> None:
    source = _Source(())
    repository = _Repository()
    with pytest.raises(IndexingAuthorizationError):
        await IndexRepositorySnapshotHandler(
            source, TreeSitterLanguagePlugin(), repository
        ).execute(_command("indexing.search"))
    assert source.read_count == 0
    assert repository.snapshot is None


def test_snapshot_command_rejects_ambiguous_operation_identity() -> None:
    with pytest.raises(IndexingValidationError):
        IndexRepositorySnapshotCommand(
            "contains spaces", _scope("indexing.snapshot"), None, "d" * 64, NOW
        )


@pytest.mark.asyncio
async def test_snapshot_and_import_bounds_fail_before_persistence() -> None:
    repository = _Repository()
    artifact = SourceArtifact("main.py", b"pass\n")
    with pytest.raises(IndexingValidationError, match="source artifact"):
        await IndexRepositorySnapshotHandler(
            _Source((artifact,) * 1_000_001), TreeSitterLanguagePlugin(), repository
        ).execute(_command("indexing.snapshot"))
    assert repository.files == []

    oversized_repository = _Repository()
    oversized = await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("large.py", b"x" * (64 * 1024 * 1024 + 1)),)),
        TreeSitterLanguagePlugin(),
        oversized_repository,
    ).execute(_command("indexing.snapshot"))
    assert oversized.failed_count == 1
    assert oversized_repository.files[0].failures[0].error_code == "source_too_large"

    indexed_repository = _Repository()
    source = b"def hello(): pass\n"
    await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("main.py", source),)),
        TreeSitterLanguagePlugin(),
        indexed_repository,
    ).execute(_command("indexing.snapshot"))
    with pytest.raises(IndexingValidationError, match="source artifact"):
        await ImportScipHandler(ScipEvidenceMapper(), indexed_repository).execute(
            ImportScipCommand(
                _scope("indexing.scip.import"),
                indexed_repository.files[0].revision,
                b"different bytes",
                b"{}",
            )
        )


@pytest.mark.asyncio
async def test_search_rejects_invalid_queries_and_skips_nonmatching_symbols() -> None:
    repository = _Repository()
    indexed = await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("main.py", b"def hello(): pass\n"),)),
        TreeSitterLanguagePlugin(),
        repository,
    ).execute(_command("indexing.snapshot"))
    handler = FindCodeEntitiesHandler(repository)
    for query in (
        FindCodeEntitiesQuery(_scope("indexing.search"), indexed.snapshot.id, "   "),
        FindCodeEntitiesQuery(_scope("indexing.search"), indexed.snapshot.id, "x" * 513),
        FindCodeEntitiesQuery(_scope("indexing.search"), indexed.snapshot.id, "hello", 101),
    ):
        with pytest.raises(IndexingValidationError, match="source artifact"):
            await handler.execute(query)
    assert (
        await handler.execute(
            FindCodeEntitiesQuery(_scope("indexing.search"), indexed.snapshot.id, "absent")
        )
        == ()
    )


@pytest.mark.asyncio
async def test_syntactic_occurrences_are_indexed_and_invalid_display_spans_fail_closed() -> None:
    repository = _Repository()
    await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("main.py", b"foo()\n"),)),
        _OccurrencePlugin(3),
        repository,
    ).execute(_command("indexing.snapshot"))
    assert repository.files[0].occurrences[0].role.value == "call"

    for content, end_byte in ((b"foo\n", 0), (b"\xff\n", 1)):
        failed_repository = _Repository()
        result = await IndexRepositorySnapshotHandler(
            _Source((SourceArtifact("invalid.py", content),)),
            _OccurrencePlugin(end_byte),
            failed_repository,
        ).execute(_command("indexing.snapshot"))
        assert result.failed_count == 1
        assert failed_repository.files[0].failures[0].error_code == "parser_output_invalid"


@pytest.mark.asyncio
async def test_exact_scope_is_mandatory_for_indexing() -> None:
    empty_scope = replace(_scope("indexing.snapshot"), members=())
    with pytest.raises(IndexingAuthorizationError, match="exact project"):
        await IndexRepositorySnapshotHandler(
            _Source(()), TreeSitterLanguagePlugin(), _Repository()
        ).execute(replace(_command("indexing.snapshot"), scope=empty_scope))


def _command(action: str) -> IndexRepositorySnapshotCommand:
    return IndexRepositorySnapshotCommand(
        "idx-operation-1", _scope(action), "abc123", "d" * 64, NOW
    )


@dataclass
class _Source:
    artifacts: tuple[SourceArtifact, ...]
    read_count: int = 0

    async def read(self, scope: AuthorizedScope) -> tuple[SourceArtifact, ...]:
        del scope
        self.read_count += 1
        return self.artifacts


@dataclass
class _CrashPlugin:
    delegate: TreeSitterLanguagePlugin

    def detect(self, relative_path: str, content: bytes) -> str | None:
        return self.delegate.detect(relative_path, content)

    def describe(self, language: str) -> ParserDescriptor:
        return self.delegate.describe(language)

    def parse(self, language: str, relative_path: str, content: bytes) -> ParsedSource:
        if relative_path == "src/crash.py":
            message = "native parser crashed with secret source text"
            raise RuntimeError(message)
        return self.delegate.parse(language, relative_path, content)


@dataclass
class _BoundaryFailurePlugin:
    delegate: TreeSitterLanguagePlugin

    def detect(self, relative_path: str, content: bytes) -> str | None:
        if relative_path == "src/detector.py":
            message = "detector failed with private host diagnostics"
            raise RuntimeError(message)
        return self.delegate.detect(relative_path, content)

    def describe(self, language: str) -> ParserDescriptor:
        if language == "typescript":
            message = "descriptor failed with private host diagnostics"
            raise RuntimeError(message)
        return self.delegate.describe(language)

    def parse(self, language: str, relative_path: str, content: bytes) -> ParsedSource:
        return self.delegate.parse(language, relative_path, content)


@dataclass(frozen=True)
class _OccurrencePlugin:
    end_byte: int

    def detect(self, relative_path: str, content: bytes) -> str | None:
        del relative_path, content
        return "python"

    def describe(self, language: str) -> ParserDescriptor:
        return ParserDescriptor(
            language,
            LanguageTier.STRUCTURAL,
            "test-parser-v1",
            "test-grammar-v1",
            "e" * 64,
        )

    def parse(self, language: str, relative_path: str, content: bytes) -> ParsedSource:
        del relative_path, content
        return ParsedSource(
            language,
            "test-parser-v1",
            "test-grammar-v1",
            "e" * 64,
            0,
            (),
            (
                ParsedOccurrence(
                    "python main foo().", "call", 0, self.end_byte, 0, 0, 0, self.end_byte
                ),
            ),
        )


@dataclass
class _Repository:
    snapshot: SourceSnapshot | None = None
    files: list[IndexedFile] = field(default_factory=list[IndexedFile])

    async def start_snapshot(
        self, scope: AuthorizedScope, operation_id: str, snapshot: SourceSnapshot
    ) -> SourceSnapshot:
        del scope, operation_id
        if self.snapshot is None:
            self.snapshot = snapshot
        return self.snapshot

    async def save_file(self, scope: AuthorizedScope, indexed: IndexedFile) -> IndexedFile:
        del scope
        self.files.append(indexed)
        return indexed

    async def merge_precise_evidence(
        self,
        scope: AuthorizedScope,
        file_revision_id: str,
        symbols: tuple[CodeSymbol, ...],
        revisions: tuple[SymbolRevision, ...],
        occurrences: tuple[SymbolOccurrence, ...],
    ) -> None:
        del scope
        for index, item in enumerate(self.files):
            if item.revision.id != file_revision_id:
                continue
            by_id = {symbol.id: symbol for symbol in (*item.symbols, *symbols)}
            self.files[index] = replace(
                item,
                symbols=tuple(sorted(by_id.values(), key=lambda value: value.id)),
                symbol_revisions=(*item.symbol_revisions, *revisions),
                occurrences=(*item.occurrences, *occurrences),
            )
            return
        message = "file revision missing"
        raise AssertionError(message)

    async def list_files(self, scope: AuthorizedScope, snapshot_id: str) -> tuple[IndexedFile, ...]:
        del scope
        return tuple(item for item in self.files if item.revision.snapshot_id == snapshot_id)
