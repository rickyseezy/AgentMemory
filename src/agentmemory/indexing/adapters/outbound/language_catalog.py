"""IDX-001 exact supported language matrix and immutable grammar revisions."""

from __future__ import annotations

from dataclasses import dataclass

from agentmemory.indexing.domain.code_entities import LanguageTier


@dataclass(frozen=True, slots=True)
class LanguageSpec:
    """One release-certified language, syntax range, and parser identity."""

    name: str
    tier: LanguageTier
    versions: tuple[str, ...]
    extensions: tuple[str, ...]
    grammar_repository: str
    grammar_revision: str


LANGUAGE_SPECS = (
    LanguageSpec(
        "python",
        LanguageTier.PRECISE,
        ("3.10", "3.11", "3.12", "3.13", "3.14"),
        (".py", ".pyi", ".pyw"),
        "tree-sitter/tree-sitter-python",
        "26855eabccb19c6abf499fbc5b8dc7cc9ab8bc64",
    ),
    LanguageSpec(
        "javascript",
        LanguageTier.PRECISE,
        ("ES2020", "ES2021", "ES2022", "ES2023", "ES2024", "ES2025", "ES2026"),
        (".js", ".jsx", ".mjs", ".cjs"),
        "tree-sitter/tree-sitter-javascript",
        "58404d8cf191d69f2674a8fd507bd5776f46cb11",
    ),
    LanguageSpec(
        "typescript",
        LanguageTier.PRECISE,
        ("5", "6"),
        (".ts", ".tsx", ".mts", ".cts"),
        "tree-sitter/tree-sitter-typescript",
        "75b3874edb2dc714fb1fd77a32013d0f8699989f",
    ),
    LanguageSpec(
        "java",
        LanguageTier.PRECISE,
        ("17", "21", "25"),
        (".java",),
        "tree-sitter/tree-sitter-java",
        "e10607b45ff745f5f876bfa3e94fbcc6b44bdc11",
    ),
    LanguageSpec(
        "kotlin",
        LanguageTier.PRECISE,
        ("1.9", "2.x"),
        (".kt", ".kts"),
        "fwcd/tree-sitter-kotlin",
        "c8ac3d2627240160b999a2c100de3babbdb8f419",
    ),
    LanguageSpec(
        "go",
        LanguageTier.PRECISE,
        ("1.22", "1.23", "1.24", "1.25", "1.26"),
        (".go",),
        "tree-sitter/tree-sitter-go",
        "2346a3ab1bb3857b48b29d779a1ef9799a248cd7",
    ),
    LanguageSpec(
        "csharp",
        LanguageTier.PRECISE,
        (".NET 8", ".NET 9", ".NET 10"),
        (".cs",),
        "tree-sitter/tree-sitter-c-sharp",
        "9150f7d56bb47f1a809fa23623f1ba1413e93fa9",
    ),
    LanguageSpec(
        "rust",
        LanguageTier.STRUCTURAL,
        ("2021", "2024"),
        (".rs",),
        "tree-sitter/tree-sitter-rust",
        "77a3747266f4d621d0757825e6b11edcbf991ca5",
    ),
    LanguageSpec(
        "c",
        LanguageTier.STRUCTURAL,
        ("C11", "C17", "C23"),
        (".c", ".h"),
        "tree-sitter/tree-sitter-c",
        "b780e47fc780ddc8da13afa35a3f4ed5c157823d",
    ),
    LanguageSpec(
        "cpp",
        LanguageTier.STRUCTURAL,
        ("C++17", "C++20", "C++23"),
        (".cpp", ".cxx", ".cc", ".hpp", ".hxx", ".hh"),
        "tree-sitter/tree-sitter-cpp",
        "8b5b49eb196bec7040441bee33b2c9a4838d6967",
    ),
    LanguageSpec(
        "ruby",
        LanguageTier.STRUCTURAL,
        ("3.2", "3.3", "3.4", "3.5"),
        (".rb",),
        "tree-sitter/tree-sitter-ruby",
        "ad907a69da0c8a4f7a943a7fe012712208da6dee",
    ),
    LanguageSpec(
        "php",
        LanguageTier.STRUCTURAL,
        ("8.2", "8.3", "8.4", "8.5"),
        (".php",),
        "tree-sitter/tree-sitter-php",
        "38216983c07bf9e1b56e16acde53b25adaeab61c",
    ),
    LanguageSpec(
        "swift",
        LanguageTier.STRUCTURAL,
        ("5.10", "6.x"),
        (".swift",),
        "alex-pinkus/tree-sitter-swift",
        "28fe3a8a85586aa297524fe6164140b9521dcaff",
    ),
    LanguageSpec(
        "bash",
        LanguageTier.STRUCTURAL,
        ("POSIX", "Bash"),
        (".sh", ".bash"),
        "tree-sitter/tree-sitter-bash",
        "a06c2e4415e9bc0346c6b86d401879ffb44058f7",
    ),
    LanguageSpec(
        "powershell",
        LanguageTier.STRUCTURAL,
        ("7",),
        (".ps1", ".psm1", ".psd1"),
        "airbus-cert/tree-sitter-powershell",
        "e7bd348c49fdfd5c853a146a670965ba516a6239",
    ),
)

LANGUAGE_BY_NAME = {item.name: item for item in LANGUAGE_SPECS}
LANGUAGE_BY_EXTENSION = {
    extension: item.name for item in LANGUAGE_SPECS for extension in item.extensions
}
