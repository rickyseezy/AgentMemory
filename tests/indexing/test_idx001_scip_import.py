"""IDX-001 SCIP strict decoding, range conversion, and precedence tests."""

import json

import pytest

from agentmemory.indexing.adapters.outbound.scip_import import (
    ScipEvidenceMapper,
    ScipJsonDecoder,
)
from agentmemory.indexing.domain.code_entities import (
    CodeSymbol,
    FileRevision,
    IndexedFile,
    LanguageTier,
    OccurrenceRole,
    ParseStatus,
    SemanticPriority,
    SemanticSource,
    SourceFile,
    SourceSpan,
    SymbolKind,
    SymbolOccurrence,
    content_digest,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

FILE_ID = "a" * 64
SNAPSHOT_ID = "b" * 64
REPOSITORY = "0198c000-0000-7000-8000-000000000003"
SCIP_SYMBOL = "scip-python python example 1.0 main/`🚀foo`()."


@pytest.mark.parametrize(
    ("encoding", "compact"),
    [
        ("UTF8CodeUnitOffsetFromLineStart", [0, 4, 11]),
        ("UTF16CodeUnitOffsetFromLineStart", [0, 4, 9]),
        ("UTF32CodeUnitOffsetFromLineStart", [0, 4, 8]),
    ],
)
def test_scip_encodings_map_unicode_to_exact_utf8_byte_span(
    encoding: str, compact: list[int]
) -> None:
    source = "def 🚀foo():\r\n    return 1\r\n".encode()
    document = ScipJsonDecoder.decode(
        json.dumps(
            {
                "relative_path": "main.py",
                "language": "python",
                "position_encoding": encoding,
                "occurrences": [{"range": compact, "symbol": SCIP_SYMBOL, "symbol_roles": 1}],
                "symbols": [
                    {
                        "symbol": SCIP_SYMBOL,
                        "display_name": "🚀foo",
                        "kind": "Function",
                    }
                ],
            }
        ).encode()
    )
    evidence = ScipEvidenceMapper.map_document(
        repository_id=REPOSITORY,
        file_revision=_revision(source),
        source=source,
        document=document,
    )
    assert evidence.symbols[0].stable_key == SCIP_SYMBOL
    assert evidence.symbols[0].kind is SymbolKind.FUNCTION
    assert evidence.revisions[0].span == SourceSpan(4, 11, 0, 4, 0, 11)
    assert evidence.occurrences[0].source is SemanticSource.SCIP


def test_scip_relationship_and_precise_fact_supersede_syntax_without_deletion() -> None:
    source = b"class Dog: pass\n"
    source_file = SourceFile.create(REPOSITORY, "main.py")
    symbol = "scip-python python example 1.0 main/Dog#"
    interface = "scip-python python example 1.0 main/Animal#"
    document = ScipJsonDecoder.decode(
        json.dumps(
            {
                "relative_path": "main.py",
                "language": "python",
                "position_encoding": "UTF8CodeUnitOffsetFromLineStart",
                "occurrences": [{"range": [0, 6, 9], "symbol": symbol, "symbol_roles": 1}],
                "symbols": [
                    {
                        "symbol": symbol,
                        "display_name": "Dog",
                        "kind": "Class",
                        "relationships": [{"symbol": interface, "is_implementation": True}],
                    }
                ],
            }
        ).encode()
    )
    revision = _revision(source, file_id=source_file.id)
    precise = ScipEvidenceMapper.map_document(
        repository_id=REPOSITORY, file_revision=revision, source=source, document=document
    )
    implementation = next(
        item for item in precise.occurrences if item.role is OccurrenceRole.IMPLEMENTATION
    )
    assert implementation.span == SourceSpan(6, 9, 0, 6, 0, 9)
    inheritance = next(
        item for item in precise.occurrences if item.role is OccurrenceRole.INHERITANCE
    )
    assert inheritance.target_symbol_id == implementation.target_symbol_id

    syntactic_symbol = CodeSymbol.create(
        REPOSITORY, "tree-sitter python main.py class Dog", "Dog", SymbolKind.CLASS
    )
    syntactic = SymbolOccurrence.create(
        file_revision_id=revision.id,
        target_symbol_id=syntactic_symbol.id,
        role=OccurrenceRole.DEFINITION,
        span=SourceSpan(6, 9, 0, 6, 0, 9),
        source=SemanticSource.TREE_SITTER,
        priority=SemanticPriority.TREE_SITTER,
        source_identity="tree-sitter:python:definition.class",
    )
    aggregate = IndexedFile(
        source_file,
        revision,
        (*precise.symbols, syntactic_symbol),
        precise.revisions,
        (*precise.occurrences, syntactic),
    )
    preferred = next(
        item for item in aggregate.preferred_occurrences() if item.role is OccurrenceRole.DEFINITION
    )
    assert preferred.source is SemanticSource.SCIP
    assert syntactic in aggregate.occurrences


def test_scip_decoder_rejects_duplicate_extra_ambiguous_and_invalid_ranges() -> None:
    duplicate = (
        b'{"relative_path":"a.py","relative_path":"b.py","language":"python",'
        b'"position_encoding":"UTF8CodeUnitOffsetFromLineStart","occurrences":[]}'
    )
    with pytest.raises(IndexingValidationError, match="SCIP"):
        ScipJsonDecoder.decode(duplicate)

    with pytest.raises(IndexingValidationError, match="SCIP"):
        ScipJsonDecoder.decode(
            b'{"relative_path":"a.py","language":"python",'
            b'"position_encoding":"UnspecifiedPositionEncoding","occurrences":[]}'
        )

    document = ScipJsonDecoder.decode(
        b'{"relative_path":"a.py","language":"python",'
        b'"position_encoding":"UTF8CodeUnitOffsetFromLineStart",'
        b'"occurrences":[{"range":[3,0,1],"symbol":"local x"}]}'
    )
    with pytest.raises(IndexingValidationError):
        ScipEvidenceMapper.map_document(
            repository_id=REPOSITORY,
            file_revision=_revision(b"x\n"),
            source=b"x\n",
            document=document,
        )


def _revision(source: bytes, *, file_id: str = FILE_ID) -> FileRevision:
    return FileRevision.create(
        file_id=file_id,
        snapshot_id=SNAPSHOT_ID,
        content_digest=content_digest(source),
        byte_length=len(source),
        language="python",
        language_tier=LanguageTier.PRECISE,
        parser_version="tree-sitter-0.26.0+language-pack-1.13.2",
        grammar_revision="26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64",
        query_pack_digest="c" * 64,
        status=ParseStatus.SUCCEEDED,
        error_count=0,
    )
