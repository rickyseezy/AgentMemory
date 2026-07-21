"""IDX-001 immutable code entity and precedence policy tests."""

from dataclasses import replace
from datetime import UTC, datetime
from typing import cast

import pytest

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
    stable_identity,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN = "0198c000-0000-7000-8000-000000000001"
PROJECT = "0198c000-0000-7000-8000-000000000002"
REPOSITORY = "0198c000-0000-7000-8000-000000000003"
DIGEST = "a" * 64


def test_public_stable_identity_is_canonical_and_namespace_scoped() -> None:
    first = stable_identity("scip", {"symbol": "python pkg foo().", "version": 1})
    reordered = stable_identity("scip", {"version": 1, "symbol": "python pkg foo()."})

    assert first == reordered
    assert first != stable_identity("compiler", {"symbol": "python pkg foo().", "version": 1})
    assert first != stable_identity("scip", {"symbol": "python pkg bar().", "version": 1})
    assert len(first) == 64
    assert set(first) <= set("0123456789abcdef")


def test_snapshot_file_and_revision_identities_are_deterministic_and_path_safe() -> None:
    snapshot = SourceSnapshot.create(
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        commit_id="abc123",
        working_digest=DIGEST,
        created_at=NOW,
    )
    assert snapshot == SourceSnapshot.create(
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        commit_id="abc123",
        working_digest=DIGEST,
        created_at=NOW,
    )
    source_file = SourceFile.create(REPOSITORY, "src/café.py")
    revision = _revision(source_file.id, snapshot.id)
    assert revision.status is ParseStatus.SUCCEEDED
    assert revision.error_count == 0

    for path in ("/secret/main.py", "../secret.py", "src\\main.py", "src/./main.py"):
        with pytest.raises(IndexingValidationError, match="path"):
            SourceFile.create(REPOSITORY, path)


def test_unicode_crlf_span_is_validated_against_exact_utf8_bytes() -> None:
    source = "def café():\r\n    return '☕'\r\n".encode()
    start = source.index("café".encode())
    end = start + len("café".encode())
    span = SourceSpan(start, end, 0, start, 0, end)
    span.validate_source(source)
    assert source[span.start_byte : span.end_byte].decode() == "café"

    second_line = source.index(b"return")
    second = SourceSpan(second_line, second_line + 6, 1, 4, 1, 10)
    second.validate_source(source)

    with pytest.raises(IndexingValidationError, match="span"):
        SourceSpan(second_line, second_line + 6, 1, 3, 1, 10).validate_source(source)


def test_precise_occurrence_supersedes_syntax_without_deleting_provenance() -> None:
    source_file = SourceFile.create(REPOSITORY, "src/main.py")
    snapshot = SourceSnapshot.create(
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        commit_id=None,
        working_digest=DIGEST,
        created_at=NOW,
    )
    revision = _revision(source_file.id, snapshot.id)
    symbol = CodeSymbol.create(REPOSITORY, "python src/main.py foo().", "foo", SymbolKind.FUNCTION)
    span = SourceSpan(4, 7, 0, 4, 0, 7)
    syntactic = SymbolOccurrence.create(
        file_revision_id=revision.id,
        target_symbol_id=symbol.id,
        role=OccurrenceRole.CALL,
        span=span,
        source=SemanticSource.TREE_SITTER,
        priority=SemanticPriority.TREE_SITTER,
        source_identity="tree-sitter:python:foo",
    )
    precise = SymbolOccurrence.create(
        file_revision_id=revision.id,
        target_symbol_id=symbol.id,
        role=OccurrenceRole.CALL,
        span=span,
        source=SemanticSource.SCIP,
        priority=SemanticPriority.SCIP,
        source_identity="scip-python python pkg foo().",
    )
    definition = SymbolRevision.create(
        symbol_id=symbol.id,
        file_revision_id=revision.id,
        span=span,
        source=SemanticSource.TREE_SITTER,
        priority=SemanticPriority.TREE_SITTER,
        source_identity="tree-sitter:python:definition.function",
    )
    indexed = IndexedFile(
        source_file,
        revision,
        (symbol,),
        (definition,),
        (precise, syntactic),
    )
    assert indexed.occurrences == (precise, syntactic)
    assert indexed.preferred_occurrences() == (precise,)


def test_recovered_and_failed_parse_evidence_remains_file_scoped() -> None:
    source_file = SourceFile.create(REPOSITORY, "broken.py")
    snapshot = SourceSnapshot.create(
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        commit_id=None,
        working_digest=DIGEST,
        created_at=NOW,
    )
    revision = _revision(source_file.id, snapshot.id, status=ParseStatus.RECOVERED, error_count=2)
    failure = ParseFailure.create(
        file_revision_id=revision.id,
        language="python",
        parser_version="tree-sitter-0.26.0",
        error_code="syntax_recovered",
        recoverable=True,
    )
    assert IndexedFile(source_file, revision, (), (), (), (failure,)).failures == (failure,)

    with pytest.raises(IndexingValidationError, match="parse evidence"):
        _revision(source_file.id, snapshot.id, status=ParseStatus.SUCCEEDED, error_count=1)


def test_source_span_rejects_every_incoherent_coordinate_class() -> None:
    invalid = (
        (True, 1, 0, 0, 0, 1),
        (2, 1, 0, 2, 0, 1),
        (0, 0, 0, 0, 0, 1),
    )
    for coordinates in invalid:
        with pytest.raises(IndexingValidationError, match="span"):
            SourceSpan(*coordinates)

    source = b"a\nb\n"
    invalid_for_source = (
        SourceSpan(0, 9, 0, 0, 0, 9),
        SourceSpan(0, 1, 9, 0, 9, 1),
        SourceSpan(0, 1, 0, 0, 0, 2),
    )
    for candidate in invalid_for_source:
        with pytest.raises(IndexingValidationError, match="span"):
            candidate.validate_source(source)


def test_entity_guards_reject_invalid_identity_parser_and_enum_coordinates() -> None:
    snapshot = SourceSnapshot.create(
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        commit_id=None,
        working_digest=DIGEST,
        created_at=NOW,
    )
    source_file = SourceFile.create(REPOSITORY, "main.py")
    revision = _revision(source_file.id, snapshot.id)
    symbol = CodeSymbol.create(REPOSITORY, "python main foo().", "foo", SymbolKind.FUNCTION)

    invalid_entities = (
        lambda: replace(snapshot, commit_id="bad commit"),
        lambda: replace(snapshot, created_at=NOW.replace(tzinfo=None)),
        lambda: SourceFile("0" * 64, REPOSITORY, "main.py"),
        lambda: SourceFile.create("bad repository", "main.py"),
        lambda: replace(revision, language="INVALID"),
        lambda: replace(revision, grammar_revision=""),
        lambda: replace(revision, byte_length=-1),
        lambda: replace(revision, status=ParseStatus.RECOVERED, error_count=0),
        lambda: replace(revision, language_tier=cast("LanguageTier", "precise")),
        lambda: replace(symbol, stable_key=""),
        lambda: replace(symbol, display_name=""),
        lambda: replace(symbol, kind=cast("SymbolKind", "function")),
    )
    for construct in invalid_entities:
        with pytest.raises(IndexingValidationError):
            construct()


def test_parse_failure_and_semantic_provenance_are_strictly_typed() -> None:
    source_file = SourceFile.create(REPOSITORY, "main.py")
    snapshot = SourceSnapshot.create(
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        commit_id=None,
        working_digest=DIGEST,
        created_at=NOW,
    )
    revision = _revision(source_file.id, snapshot.id)
    symbol = CodeSymbol.create(REPOSITORY, "python main foo().", "foo", SymbolKind.FUNCTION)
    span = SourceSpan(0, 3, 0, 0, 0, 3)
    failure = ParseFailure.create(
        file_revision_id=revision.id,
        language="python",
        parser_version="tree-sitter-0.26.0",
        error_code="parser_crash",
        recoverable=False,
    )

    with pytest.raises(IndexingValidationError, match="parse evidence"):
        replace(failure, language="INVALID")
    with pytest.raises(IndexingValidationError, match="parse evidence"):
        replace(failure, recoverable=cast("bool", 1))
    with pytest.raises(IndexingValidationError, match="code entity"):
        SymbolRevision.create(
            symbol_id=symbol.id,
            file_revision_id=revision.id,
            span=span,
            source=SemanticSource.TREE_SITTER,
            priority=SemanticPriority.SCIP,
            source_identity="mismatched-priority",
        )


def test_indexed_file_rejects_every_cross_aggregate_reference_violation() -> None:
    source_file = SourceFile.create(REPOSITORY, "main.py")
    snapshot = SourceSnapshot.create(
        brain_id=BRAIN,
        project_id=PROJECT,
        repository_id=REPOSITORY,
        commit_id=None,
        working_digest=DIGEST,
        created_at=NOW,
    )
    revision = _revision(source_file.id, snapshot.id)
    symbol = CodeSymbol.create(REPOSITORY, "python main foo().", "foo", SymbolKind.FUNCTION)
    span = SourceSpan(0, 3, 0, 0, 0, 3)
    definition = SymbolRevision.create(
        symbol_id=symbol.id,
        file_revision_id=revision.id,
        span=span,
        source=SemanticSource.TREE_SITTER,
        priority=SemanticPriority.TREE_SITTER,
        source_identity="tree-sitter:def",
    )
    occurrence = SymbolOccurrence.create(
        file_revision_id=revision.id,
        target_symbol_id=symbol.id,
        role=OccurrenceRole.DEFINITION,
        span=span,
        source=SemanticSource.TREE_SITTER,
        priority=SemanticPriority.TREE_SITTER,
        source_identity="tree-sitter:def",
    )
    failure = ParseFailure.create(
        file_revision_id=revision.id,
        language="python",
        parser_version="tree-sitter-0.26.0",
        error_code="syntax_recovered",
        recoverable=True,
    )
    other = "c" * 64

    invalid_aggregates = (
        (
            source_file,
            replace(revision, file_id=other),
            (symbol,),
            (definition,),
            (occurrence,),
            (),
        ),
        (source_file, revision, (symbol, symbol), (definition,), (occurrence,), ()),
        (source_file, revision, (replace(symbol, repository_id=PROJECT),), (), (), ()),
        (source_file, revision, (symbol,), (replace(definition, symbol_id=other),), (), ()),
        (source_file, revision, (symbol,), (replace(definition, file_revision_id=other),), (), ()),
        (source_file, revision, (symbol,), (), (replace(occurrence, file_revision_id=other),), ()),
        (source_file, revision, (symbol,), (), (replace(occurrence, target_symbol_id=other),), ()),
        (source_file, revision, (), (), (), (replace(failure, file_revision_id=other),)),
        (source_file, revision, (), (), (), (failure,)),
        (
            source_file,
            replace(revision, status=ParseStatus.RECOVERED, error_count=1),
            (),
            (),
            (),
            (),
        ),
        (
            source_file,
            replace(revision, status=ParseStatus.FAILED, error_count=1),
            (symbol,),
            (),
            (),
            (
                replace(
                    failure,
                    file_revision_id=replace(revision, status=ParseStatus.FAILED, error_count=1).id,
                ),
            ),
        ),
    )
    for arguments in invalid_aggregates:
        with pytest.raises(IndexingValidationError):
            IndexedFile(*arguments)


def _revision(
    file_id: str,
    snapshot_id: str,
    *,
    status: ParseStatus = ParseStatus.SUCCEEDED,
    error_count: int = 0,
) -> FileRevision:
    return FileRevision.create(
        file_id=file_id,
        snapshot_id=snapshot_id,
        content_digest=content_digest(b"def foo(): pass\n"),
        byte_length=16,
        language="python",
        language_tier=LanguageTier.PRECISE,
        parser_version="tree-sitter-0.26.0",
        grammar_revision="language-pack-v1.13.2:python",
        query_pack_digest="b" * 64,
        status=status,
        error_count=error_count,
    )
