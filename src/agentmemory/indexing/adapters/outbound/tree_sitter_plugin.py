"""Offline-only IDX-001 Tree-sitter adapter with exact grammar/query evidence."""

from __future__ import annotations

import hashlib
import os
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import (
    PackConfig,
    configure,
    get_language,
    get_parser,
    get_tags_query,
)
from tree_sitter_language_pack import (
    downloaded_languages as language_pack_downloaded_languages,
)

from agentmemory.indexing.adapters.outbound.language_catalog import (
    LANGUAGE_BY_EXTENSION,
    LANGUAGE_BY_NAME,
    LANGUAGE_SPECS,
)
from agentmemory.indexing.domain.code_entities import LanguageTier
from agentmemory.indexing.domain.errors import IndexingUnavailableError, IndexingValidationError
from agentmemory.indexing.domain.ports import (
    ParsedDefinition,
    ParsedOccurrence,
    ParsedSource,
    ParserDescriptor,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from tree_sitter import Node

_PARSER_VERSION = "tree-sitter-0.26.0+language-pack-1.13.2"
_ERR_RUNTIME = "certified local language grammar is unavailable"
_ERR_PARSE = "source parser returned invalid evidence"
_MAX_SYMBOL_NAME = 512
_FALLBACK_TAG_QUERIES = {
    "bash": """
      (function_definition name: (word) @name) @definition.function
      (command name: (command_name (word) @name)) @reference.call
    """,
    "powershell": """
      (function_statement (function_name) @name) @definition.function
      (command command_name: (command_name) @name) @reference.call
    """,
}
_OVERRIDE_TAG_QUERIES = {
    "typescript": """
      (function_declaration name: (identifier) @name) @definition.function
      (class_declaration name: (type_identifier) @name) @definition.class
      (interface_declaration name: (type_identifier) @name) @definition.interface
      (method_definition name: (property_identifier) @name) @definition.method
      (call_expression function: (identifier) @name) @reference.call
      (new_expression constructor: (identifier) @name) @reference.implementation
    """,
    "php": """
      (class_declaration name: (name) @name) @definition.class
      (interface_declaration name: (name) @name) @definition.interface
      (method_declaration name: (name) @name) @definition.method
      (function_definition name: (name) @name) @definition.function
      (function_call_expression function: (name) @name) @reference.call
    """,
}


class TreeSitterLanguagePlugin:
    """Detect and parse the release-certified matrix without runtime downloads."""

    def __init__(self, available: frozenset[str] | None = None) -> None:
        """Snapshot preloaded grammar availability; network acquisition is never attempted."""
        self._available = configured_languages() if available is None else available

    def detect(self, relative_path: str, content: bytes) -> str | None:
        """Detect by governed extension, then fall back only for valid UTF-8 text."""
        suffix = PurePosixPath(relative_path).suffix.lower()
        language = LANGUAGE_BY_EXTENSION.get(suffix)
        if language is not None:
            return language
        try:
            content.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return "text"

    def parse(self, language: str, relative_path: str, content: bytes) -> ParsedSource:
        """Parse one file and emit definitions/references with exact byte spans."""
        if language == "text":
            return ParsedSource(
                "text",
                _PARSER_VERSION,
                "lexical-fallback-v1",
                hashlib.sha256(b"").hexdigest(),
                0,
                (),
                (),
            )
        spec = LANGUAGE_BY_NAME.get(language)
        if spec is None:
            raise IndexingValidationError(_ERR_PARSE)
        if language not in self._available:
            raise IndexingUnavailableError(_ERR_RUNTIME)
        runtime_language = _runtime_language(language, relative_path)
        tags = _tags(runtime_language)
        if not tags:
            raise IndexingUnavailableError(_ERR_RUNTIME)
        tree = get_parser(runtime_language).parse(content, encoding="utf8")
        query_digest = hashlib.sha256(tags.encode()).hexdigest()
        matches = QueryCursor(Query(get_language(runtime_language), tags)).matches(tree.root_node)
        definitions = _definitions(relative_path, language, content, matches)
        occurrences = _occurrences(relative_path, language, content, matches, definitions)
        return ParsedSource(
            language,
            _PARSER_VERSION,
            spec.grammar_revision,
            query_digest,
            _error_count(tree.root_node),
            definitions,
            occurrences,
        )

    def describe(self, language: str) -> ParserDescriptor:
        """Return exact grammar and query identities even if a parse later crashes."""
        if language == "text":
            return ParserDescriptor(
                "text",
                LanguageTier.LEXICAL,
                _PARSER_VERSION,
                "lexical-fallback-v1",
                hashlib.sha256(b"").hexdigest(),
            )
        spec = LANGUAGE_BY_NAME.get(language)
        if spec is None:
            raise IndexingValidationError(_ERR_PARSE)
        tags = _tags(language)
        if not tags:
            raise IndexingUnavailableError(_ERR_RUNTIME)
        return ParserDescriptor(
            language,
            spec.tier,
            _PARSER_VERSION,
            spec.grammar_revision,
            hashlib.sha256(tags.encode()).hexdigest(),
        )

    @staticmethod
    def required_languages() -> tuple[str, ...]:
        """Return the exact grammar set that signed images must prefetch."""
        return tuple(item.name for item in LANGUAGE_SPECS)


def _definitions(
    relative_path: str,
    language: str,
    content: bytes,
    matches: list[tuple[int, dict[str, list[Node]]]],
) -> tuple[ParsedDefinition, ...]:
    result: list[ParsedDefinition] = []
    seen: set[tuple[str, int, str]] = set()
    for _, captures in matches:
        name = _name_node(captures)
        definition = next(
            (
                (capture, nodes[0])
                for capture, nodes in captures.items()
                if capture.startswith("definition.") and nodes
            ),
            None,
        )
        if name is None or definition is None:
            continue
        capture, _ = definition
        display_name = _text(content, name)
        kind = _symbol_kind(capture.removeprefix("definition."))
        key = _syntactic_key(language, relative_path, kind, display_name)
        identity = (key, name.start_byte, kind)
        if identity not in seen:
            seen.add(identity)
            result.append(ParsedDefinition(key, display_name, kind, *_coordinates(name)))
    return tuple(sorted(result, key=lambda item: (item.start_byte, item.stable_key)))


def configured_languages() -> frozenset[str]:
    """Configure the image-owned cache before any language-pack registry access."""
    cache = os.environ.get("AGENTMEMORY_GRAMMAR_CACHE")
    if cache:
        configure(PackConfig(cache_dir=cache))
    return frozenset(language_pack_downloaded_languages())


def _runtime_language(language: str, relative_path: str) -> str:
    if language == "typescript" and PurePosixPath(relative_path).suffix.lower() == ".tsx":
        return "tsx"
    return language


def _tags(language: str) -> str | None:
    override_language = "typescript" if language == "tsx" else language
    return (
        _OVERRIDE_TAG_QUERIES.get(override_language)
        or get_tags_query(language)
        or _FALLBACK_TAG_QUERIES.get(language)
    )


def _occurrences(
    relative_path: str,
    language: str,
    content: bytes,
    matches: list[tuple[int, dict[str, list[Node]]]],
    definitions: tuple[ParsedDefinition, ...],
) -> tuple[ParsedOccurrence, ...]:
    local = {item.display_name: item.stable_key for item in definitions}
    result: list[ParsedOccurrence] = []
    seen: set[tuple[str, str, int]] = set()
    for _, captures in matches:
        name = _name_node(captures)
        if name is None:
            continue
        display_name = _text(content, name)
        for capture, nodes in captures.items():
            if not nodes or capture == "name" or capture.startswith("definition."):
                continue
            role = _role(capture)
            if role is None:
                continue
            target = local.get(
                display_name,
                _syntactic_key(language, relative_path, "unresolved", display_name),
            )
            identity = (target, role, name.start_byte)
            if identity not in seen:
                seen.add(identity)
                result.append(ParsedOccurrence(target, role, *_coordinates(name)))
    return tuple(sorted(result, key=lambda item: (item.start_byte, item.target_key, item.role)))


def _name_node(captures: dict[str, list[Node]]) -> Node | None:
    nodes = captures.get("name", [])
    return nodes[0] if nodes else None


def _coordinates(node: Node) -> tuple[int, int, int, int, int, int]:
    return (
        node.start_byte,
        node.end_byte,
        node.start_point.row,
        node.start_point.column,
        node.end_point.row,
        node.end_point.column,
    )


def _text(content: bytes, node: Node) -> str:
    try:
        value = content[node.start_byte : node.end_byte].decode("utf-8")
    except UnicodeDecodeError as error:
        raise IndexingValidationError(_ERR_PARSE) from error
    if not value or len(value) > _MAX_SYMBOL_NAME:
        raise IndexingValidationError(_ERR_PARSE)
    return value


def _error_count(root: Node) -> int:
    return sum(1 for node in _walk(root) if node.is_error or node.is_missing)


def _walk(root: Node) -> Iterable[Node]:
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _syntactic_key(language: str, relative_path: str, kind: str, name: str) -> str:
    return f"tree-sitter {language} {relative_path} {kind} {name}"


def _symbol_kind(value: str) -> str:
    aliases = {
        "variable": "variable",
        "constant": "constant",
        "function": "function",
        "method": "method",
        "class": "class",
        "interface": "interface",
        "module": "module",
        "type": "type",
        "field": "field",
        "property": "property",
        "constructor": "constructor",
        "enum": "enum",
    }
    return aliases.get(value.split(".", maxsplit=1)[0], "unknown")


def _role(capture: str) -> str | None:
    if capture.startswith("reference.call"):
        return "call"
    if capture.startswith("reference.implementation"):
        return "implementation"
    if capture.startswith("reference.inheritance"):
        return "inheritance"
    if capture.startswith("reference.import"):
        return "import"
    if capture.startswith("reference"):
        return "reference"
    return None
