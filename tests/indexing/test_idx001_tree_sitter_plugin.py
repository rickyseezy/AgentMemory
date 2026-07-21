"""IDX-001 real Tree-sitter matrix, span, recovery, and offline tests."""

import pytest
from tree_sitter_language_pack import PackConfig, downloaded_languages

import agentmemory.indexing.adapters.outbound.tree_sitter_plugin as tree_sitter_module
from agentmemory.indexing.adapters.outbound.language_catalog import LANGUAGE_BY_NAME
from agentmemory.indexing.adapters.outbound.tree_sitter_plugin import TreeSitterLanguagePlugin
from agentmemory.indexing.domain.errors import IndexingUnavailableError, IndexingValidationError

FIXTURES = {
    "python": ("src/main.py", "def hello():\r\n    return 1\r\n"),
    "javascript": ("src/main.js", "function hello() { return 1; }\n"),
    "typescript": ("src/main.ts", "function hello(): number { return 1; }\n"),
    "java": ("src/Main.java", "class Hello { void run() {} }\n"),
    "kotlin": ("src/main.kt", "fun hello(): Int = 1\n"),
    "go": ("src/main.go", "package main\nfunc hello() {}\n"),
    "csharp": ("src/Main.cs", "class Hello { void Run() {} }\n"),
    "rust": ("src/main.rs", "fn hello() {}\n"),
    "c": ("src/main.c", "void hello(void) {}\n"),
    "cpp": ("src/main.cpp", "void hello() {}\n"),
    "ruby": ("src/main.rb", "def hello\n  1\nend\n"),
    "php": ("src/main.php", "<?php function hello() { return 1; }\n"),
    "swift": ("src/main.swift", "func hello() -> Int { return 1 }\n"),
    "bash": ("scripts/main.sh", "hello() { echo ok; }\n"),
    "powershell": ("scripts/main.ps1", "function Get-Hello { Write-Output ok }\n"),
}
MATRIX = tuple(
    (language, version) for language, spec in LANGUAGE_BY_NAME.items() for version in spec.versions
)


def test_image_cache_is_configured_before_inventory_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, str | None]] = []

    def inventory() -> list[str]:
        events.append(("inventory", None))
        return ["python", "tsx"]

    def configure_cache(config: PackConfig) -> None:
        events.append(("configure", config.cache_dir))

    monkeypatch.setenv("AGENTMEMORY_GRAMMAR_CACHE", "/opt/agentmemory/grammars")
    monkeypatch.setattr(
        tree_sitter_module,
        "configure",
        configure_cache,
    )
    monkeypatch.setattr(
        tree_sitter_module,
        "language_pack_downloaded_languages",
        inventory,
    )

    assert tree_sitter_module.configured_languages() == frozenset({"python", "tsx"})
    assert events == [
        ("configure", "/opt/agentmemory/grammars"),
        ("inventory", None),
    ]


@pytest.fixture(scope="module")
def plugin() -> TreeSitterLanguagePlugin:
    available = frozenset(downloaded_languages())
    assert set(FIXTURES) <= available
    return TreeSitterLanguagePlugin(available)


@pytest.mark.parametrize(("language", "version"), MATRIX)
def test_every_supported_language_version_produces_exact_definition_evidence(
    plugin: TreeSitterLanguagePlugin, language: str, version: str
) -> None:
    path, source_text = FIXTURES[language]
    source = source_text.encode()
    assert plugin.detect(path, source) == language
    parsed = plugin.parse(language, path, source)
    assert parsed.language == language
    assert parsed.parser_version == "tree-sitter-0.26.0+language-pack-1.13.2"
    assert parsed.grammar_revision == LANGUAGE_BY_NAME[language].grammar_revision
    assert len(parsed.query_pack_digest) == 64
    assert parsed.definitions, f"{language} {version} did not produce definitions"
    for definition in parsed.definitions:
        assert (
            source[definition.start_byte : definition.end_byte].decode() == definition.display_name
        )
        assert definition.end_byte <= len(source)


def test_unicode_and_crlf_preserve_utf8_byte_columns(plugin: TreeSitterLanguagePlugin) -> None:
    source = "def café():\r\n    return '☕'\r\n".encode()
    parsed = plugin.parse("python", "unicode.py", source)
    definition = parsed.definitions[0]
    assert definition.display_name == "café"
    assert definition.start_byte == 4
    assert definition.end_byte == 9
    assert (definition.start_line, definition.start_column) == (0, 4)
    assert (definition.end_line, definition.end_column) == (0, 9)


def test_tsx_uses_the_jsx_capable_typescript_grammar(plugin: TreeSitterLanguagePlugin) -> None:
    source = b"function App(): JSX.Element { return <main>Hello</main>; }\n"
    assert plugin.detect("src/App.tsx", source) == "typescript"
    parsed = plugin.parse("typescript", "src/App.tsx", source)
    assert parsed.recovered_errors == 0
    assert any(item.display_name == "App" for item in parsed.definitions)


def test_syntax_error_recovers_with_visible_error_count(plugin: TreeSitterLanguagePlugin) -> None:
    parsed = plugin.parse("python", "broken.py", b"def hello(\n    pass\n")
    assert parsed.recovered_errors > 0


def test_lexical_fallback_does_not_fabricate_semantic_symbols(
    plugin: TreeSitterLanguagePlugin,
) -> None:
    source = b"some unknown language text\n"
    assert plugin.detect("notes.unknown", source) == "text"
    parsed = plugin.parse("text", "notes.unknown", source)
    assert parsed.definitions == ()
    assert parsed.occurrences == ()
    assert plugin.detect("binary.unknown", b"\xff\xfe") is None


def test_missing_grammar_fails_without_attempting_runtime_download() -> None:
    plugin = TreeSitterLanguagePlugin(frozenset())
    with pytest.raises(IndexingUnavailableError, match="grammar is unavailable"):
        plugin.parse("python", "main.py", b"def hello(): pass\n")


def test_unknown_language_is_rejected_before_native_parser_access() -> None:
    plugin = TreeSitterLanguagePlugin(frozenset())
    with pytest.raises(IndexingValidationError, match="invalid evidence"):
        plugin.parse("unsupported", "main.unknown", b"source\n")
    with pytest.raises(IndexingValidationError, match="invalid evidence"):
        plugin.describe("unsupported")


def test_required_grammar_inventory_matches_complete_support_matrix() -> None:
    assert TreeSitterLanguagePlugin.required_languages() == tuple(LANGUAGE_BY_NAME)
    assert set(FIXTURES) == set(LANGUAGE_BY_NAME)
