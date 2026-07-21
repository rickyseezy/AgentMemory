"""Strict SCIP 0.9 JSON mapping with encoding-aware exact byte spans."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from agentmemory.indexing.domain.code_entities import (
    CodeSymbol,
    FileRevision,
    OccurrenceRole,
    SemanticPriority,
    SemanticSource,
    SourceSpan,
    SymbolKind,
    SymbolOccurrence,
    SymbolRevision,
)
from agentmemory.indexing.domain.errors import IndexingValidationError
from agentmemory.indexing.domain.ports import PreciseEvidence

_MAX_SCIP_JSON = 64 * 1024 * 1024
_DEFINITION = 0x1
_IMPORT = 0x2
_SINGLE_LINE_RANGE_LENGTH = 3
_LF = 10
_ERR_SCIP = "SCIP index evidence is invalid"


class ScipPositionEncoding(StrEnum):
    """Supported explicit SCIP position encodings."""

    UTF8 = "UTF8CodeUnitOffsetFromLineStart"
    UTF16 = "UTF16CodeUnitOffsetFromLineStart"
    UTF32 = "UTF32CodeUnitOffsetFromLineStart"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ScipRelationshipModel(_StrictModel):
    """Closed SCIP relationship fields relevant to navigation."""

    symbol: str = Field(min_length=1, max_length=2_048)
    is_reference: bool = False
    is_implementation: bool = False
    is_type_definition: bool = False
    is_definition: bool = False


class ScipSymbolModel(_StrictModel):
    """SCIP symbol identity, kind, and relationships."""

    symbol: str = Field(min_length=1, max_length=2_048)
    display_name: str | None = Field(default=None, max_length=512)
    kind: str = Field(default="UnspecifiedKind", min_length=1, max_length=64)
    relationships: tuple[ScipRelationshipModel, ...] = Field(default=(), max_length=10_000)


class ScipOccurrenceModel(_StrictModel):
    """SCIP occurrence with legacy compact range normalized at the boundary."""

    range: tuple[Annotated[int, Field(ge=0)], ...] = Field(min_length=3, max_length=4)
    symbol: str = Field(min_length=1, max_length=2_048)
    symbol_roles: int = Field(default=0, ge=0, le=0x7F)

    @field_validator("range")
    @classmethod
    def validate_range_length(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        """Accept only SCIP's exact three- or four-integer compact forms."""
        if len(value) not in {3, 4}:
            raise ValueError(_ERR_SCIP)
        return value


class ScipDocumentModel(_StrictModel):
    """One strict, source-free SCIP document projection."""

    relative_path: str = Field(min_length=1, max_length=4_096)
    language: str = Field(min_length=1, max_length=64)
    position_encoding: ScipPositionEncoding
    occurrences: tuple[ScipOccurrenceModel, ...] = Field(max_length=1_000_000)
    symbols: tuple[ScipSymbolModel, ...] = Field(default=(), max_length=1_000_000)


class ScipJsonDecoder:
    """Decode bounded JSON emitted by the pinned SCIP 0.9 CLI."""

    @staticmethod
    def decode(payload: bytes) -> ScipDocumentModel:
        """Reject duplicate keys, invalid UTF-8, extra fields, and ambiguous encoding."""
        if not payload or len(payload) > _MAX_SCIP_JSON:
            raise IndexingValidationError(_ERR_SCIP)
        try:
            document = json.loads(payload, object_pairs_hook=_unique_object)
            return ScipDocumentModel.model_validate(document)
        except (UnicodeDecodeError, json.JSONDecodeError, ValidationError, ValueError) as error:
            raise IndexingValidationError(_ERR_SCIP) from error


class ScipEvidenceMapper:
    """Map SCIP stable symbols and encoded ranges into precise domain evidence."""

    @staticmethod
    def map_document(
        *,
        repository_id: str,
        file_revision: FileRevision,
        source: bytes,
        document: ScipDocumentModel,
    ) -> PreciseEvidence:
        """Preserve SCIP identity and create precise definitions/references/implementations."""
        if document.language != file_revision.language:
            raise IndexingValidationError(_ERR_SCIP)
        symbol_metadata = {item.symbol: item for item in document.symbols}
        symbols: dict[str, CodeSymbol] = {}
        revisions: list[SymbolRevision] = []
        occurrences: list[SymbolOccurrence] = []
        definition_spans: dict[str, SourceSpan] = {}
        for item in document.occurrences:
            span = _span(source, item.range, document.position_encoding)
            display_name = _display_name(source, span, symbol_metadata.get(item.symbol))
            symbol = CodeSymbol.create(
                repository_id,
                item.symbol,
                display_name,
                _kind(symbol_metadata.get(item.symbol)),
            )
            symbols[symbol.id] = symbol
            role = _occurrence_role(item.symbol_roles)
            occurrence = SymbolOccurrence.create(
                file_revision_id=file_revision.id,
                target_symbol_id=symbol.id,
                role=role,
                span=span,
                source=SemanticSource.SCIP,
                priority=SemanticPriority.SCIP,
                source_identity=f"scip-0.9.0:{item.symbol}",
            )
            occurrences.append(occurrence)
            if item.symbol_roles & _DEFINITION:
                definition_spans[item.symbol] = span
                revisions.append(
                    SymbolRevision.create(
                        symbol_id=symbol.id,
                        file_revision_id=file_revision.id,
                        span=span,
                        source=SemanticSource.SCIP,
                        priority=SemanticPriority.SCIP,
                        source_identity=f"scip-0.9.0:{item.symbol}",
                    )
                )
        for metadata in document.symbols:
            definition_span = definition_spans.get(metadata.symbol)
            if definition_span is None:
                continue
            for relationship in metadata.relationships:
                if not relationship.is_implementation:
                    continue
                target = CodeSymbol.create(
                    repository_id,
                    relationship.symbol,
                    _symbol_display_name(relationship.symbol),
                    SymbolKind.UNKNOWN,
                )
                symbols[target.id] = target
                occurrences.append(
                    SymbolOccurrence.create(
                        file_revision_id=file_revision.id,
                        target_symbol_id=target.id,
                        role=OccurrenceRole.IMPLEMENTATION,
                        span=definition_span,
                        source=SemanticSource.SCIP,
                        priority=SemanticPriority.SCIP,
                        source_identity=f"scip-0.9.0:{metadata.symbol}->{relationship.symbol}",
                    )
                )
                if _kind(metadata) in {
                    SymbolKind.CLASS,
                    SymbolKind.INTERFACE,
                    SymbolKind.TRAIT,
                    SymbolKind.TYPE,
                }:
                    occurrences.append(
                        SymbolOccurrence.create(
                            file_revision_id=file_revision.id,
                            target_symbol_id=target.id,
                            role=OccurrenceRole.INHERITANCE,
                            span=definition_span,
                            source=SemanticSource.SCIP,
                            priority=SemanticPriority.SCIP,
                            source_identity=(
                                f"scip-0.9.0:{metadata.symbol}->{relationship.symbol}:inheritance"
                            ),
                        )
                    )
        return PreciseEvidence(
            tuple(sorted(symbols.values(), key=lambda item: item.id)),
            tuple(sorted(set(revisions), key=lambda item: item.id)),
            tuple(sorted(set(occurrences), key=lambda item: item.id)),
        )

    def map(
        self,
        *,
        repository_id: str,
        file_revision: FileRevision,
        source: bytes,
        payload: bytes,
    ) -> PreciseEvidence:
        """Decode strict CLI JSON and map it through the canonical SCIP policy."""
        return self.map_document(
            repository_id=repository_id,
            file_revision=file_revision,
            source=source,
            document=ScipJsonDecoder.decode(payload),
        )


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(_ERR_SCIP)
        result[key] = value
    return result


def _span(source: bytes, compact: tuple[int, ...], encoding: ScipPositionEncoding) -> SourceSpan:
    if len(compact) == _SINGLE_LINE_RANGE_LENGTH:
        start_line, start_character, end_character = compact
        end_line = start_line
    else:
        start_line, start_character, end_line, end_character = compact
    starts = _line_starts(source)
    if start_line >= len(starts) or end_line >= len(starts):
        raise IndexingValidationError(_ERR_SCIP)
    start_column = _byte_column(_line(source, starts, start_line), start_character, encoding)
    end_column = _byte_column(_line(source, starts, end_line), end_character, encoding)
    result = SourceSpan(
        starts[start_line] + start_column,
        starts[end_line] + end_column,
        start_line,
        start_column,
        end_line,
        end_column,
    )
    result.validate_source(source)
    return result


def _line_starts(source: bytes) -> tuple[int, ...]:
    return (0, *(index + 1 for index, value in enumerate(source) if value == _LF))


def _line(source: bytes, starts: tuple[int, ...], line: int) -> bytes:
    end = starts[line + 1] if line + 1 < len(starts) else len(source)
    value = source[starts[line] : end]
    return value.removesuffix(b"\n")


def _byte_column(line: bytes, character: int, encoding: ScipPositionEncoding) -> int:
    if encoding is ScipPositionEncoding.UTF8:
        if character > len(line):
            raise IndexingValidationError(_ERR_SCIP)
        try:
            line[:character].decode("utf-8")
        except UnicodeDecodeError as error:
            raise IndexingValidationError(_ERR_SCIP) from error
        return character
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError as error:
        raise IndexingValidationError(_ERR_SCIP) from error
    units = 0
    byte_offset = 0
    for value in text:
        if units == character:
            return byte_offset
        width = 1 if encoding is ScipPositionEncoding.UTF32 else len(value.encode("utf-16-le")) // 2
        units += width
        byte_offset += len(value.encode())
        if units > character:
            raise IndexingValidationError(_ERR_SCIP)
    if units == character:
        return byte_offset
    raise IndexingValidationError(_ERR_SCIP)


def _occurrence_role(roles: int) -> OccurrenceRole:
    if roles & _DEFINITION:
        return OccurrenceRole.DEFINITION
    if roles & _IMPORT:
        return OccurrenceRole.IMPORT
    return OccurrenceRole.REFERENCE


def _display_name(source: bytes, span: SourceSpan, metadata: ScipSymbolModel | None) -> str:
    if metadata is not None and metadata.display_name:
        return metadata.display_name
    try:
        value = source[span.start_byte : span.end_byte].decode("utf-8")
    except UnicodeDecodeError as error:
        raise IndexingValidationError(_ERR_SCIP) from error
    return value or _symbol_display_name(
        metadata.symbol if metadata is not None else "local unknown"
    )


def _symbol_display_name(symbol: str) -> str:
    descriptor = symbol.rsplit(" ", maxsplit=1)[-1].rstrip("/#.:!)]")
    return descriptor.lstrip("[(`") or "unknown"


def _kind(metadata: ScipSymbolModel | None) -> SymbolKind:
    if metadata is None:
        return SymbolKind.UNKNOWN
    normalized = metadata.kind.removesuffix("Kind").lower()
    aliases = {
        "class": SymbolKind.CLASS,
        "interface": SymbolKind.INTERFACE,
        "enum": SymbolKind.ENUM,
        "function": SymbolKind.FUNCTION,
        "method": SymbolKind.METHOD,
        "constructor": SymbolKind.CONSTRUCTOR,
        "constant": SymbolKind.CONSTANT,
        "field": SymbolKind.FIELD,
        "property": SymbolKind.PROPERTY,
        "type": SymbolKind.TYPE,
        "namespace": SymbolKind.NAMESPACE,
        "module": SymbolKind.MODULE,
        "parameter": SymbolKind.PARAMETER,
        "variable": SymbolKind.VARIABLE,
    }
    return aliases.get(normalized, SymbolKind.UNKNOWN)
