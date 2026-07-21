"""IDX-007 immutable evidence and source-link domain TDD tests."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from agentmemory.indexing.domain.code_entities import OccurrenceRole, SemanticSource, SymbolKind
from agentmemory.indexing.domain.errors import IndexingValidationError
from agentmemory.indexing.domain.source_navigation import (
    CheckoutCandidate,
    CheckoutResolution,
    CurrentWorktreeMapping,
    LocalSourceTarget,
    SourceEvidence,
    SourceEvidenceKind,
    SourceLink,
    WorktreeMappingKind,
    span_for_offsets,
)

SOURCE = "def café():\n    return '✓'\n".encode()
COMMIT = "a" * 40


def _evidence() -> SourceEvidence:
    start = SOURCE.index("café".encode())
    return SourceEvidence(
        evidence_id="1" * 64,
        kind=SourceEvidenceKind.DEFINITION,
        brain_id="brain",
        project_id="project",
        repository_id="repository",
        snapshot_id="2" * 64,
        commit_id=COMMIT,
        source_file_id="3" * 64,
        file_revision_id="4" * 64,
        relative_path="src/naïve module.py",
        symbol_id="5" * 64,
        symbol_stable_key="python:function:café",
        symbol_display_name="café",
        symbol_kind=SymbolKind.FUNCTION,
        occurrence_role=None,
        span=span_for_offsets(SOURCE, start, start + len("café".encode())),
        content_digest=__import__("hashlib").sha256(SOURCE).hexdigest(),
        byte_length=len(SOURCE),
        parser_version="tree-sitter-python@1",
        grammar_revision="grammar-commit",
        query_pack_digest="6" * 64,
        semantic_source=SemanticSource.TREE_SITTER,
    )


def test_evidence_exposes_complete_immutable_unicode_safe_revision_link() -> None:
    evidence = _evidence()

    assert evidence.span.start_column == 4
    assert evidence.span.end_column == 9
    assert evidence.immutable_revision_uri == (
        "agentmemory://source/repository/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"
        "src/na%C3%AFve%20module.py?sha256="
        f"{evidence.content_digest}&file_revision={'4' * 64}#bytes=4,9"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("evidence_id", "not-a-digest"),
        ("commit_id", "abc123"),
        ("relative_path", "../escape.py"),
        ("relative_path", "/absolute.py"),
        ("relative_path", "src\\escape.py"),
        ("byte_length", True),
        ("byte_length", 0),
        ("parser_version", ""),
        ("occurrence_role", OccurrenceRole.CALL),
    ],
)
def test_evidence_rejects_ambiguous_or_unsafe_coordinates(field: str, value: Any) -> None:
    with pytest.raises(IndexingValidationError):
        replace(_evidence(), **{field: value})


def test_source_link_requires_checkout_mismatch_and_mapping_state_to_agree() -> None:
    evidence = _evidence()
    mapping = CurrentWorktreeMapping(
        evidence.relative_path,
        evidence.span,
        evidence.content_digest,
        WorktreeMappingKind.EXACT,
    )
    exact = SourceLink(
        evidence=evidence,
        immutable_revision_uri=evidence.immutable_revision_uri,
        checkout_resolution=CheckoutResolution.EXACT,
        checkout_commit_id=COMMIT,
        checkout_dirty=False,
        checkout_mismatch=False,
        historical_blob_available=True,
        current_mapping=mapping,
    )
    assert exact.current_mapping == mapping

    with pytest.raises(IndexingValidationError):
        replace(exact, checkout_mismatch=True)
    with pytest.raises(IndexingValidationError):
        replace(exact, immutable_revision_uri="agentmemory://forged")
    with pytest.raises(IndexingValidationError):
        replace(exact, checkout_resolution=CheckoutResolution.DIFFERENT_UNMAPPED)
    with pytest.raises(IndexingValidationError):
        replace(
            exact,
            checkout_resolution=CheckoutResolution.DIFFERENT_MAPPED,
            checkout_mismatch=True,
            current_mapping=None,
        )


@pytest.mark.parametrize(
    ("commit", "path", "content", "dirty"),
    [
        ("short", "src/main.py", b"source", False),
        (COMMIT, "../escape.py", b"source", False),
        (COMMIT, "src/main.py", "not-bytes", False),
        (COMMIT, "src/main.py", b"source", 1),
    ],
)
def test_checkout_candidate_rejects_untrusted_adapter_values(
    commit: str,
    path: str,
    content: Any,
    dirty: Any,
) -> None:
    with pytest.raises(IndexingValidationError):
        CheckoutCandidate(commit, path, content, checkout_dirty=dirty)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("checkout_commit_id", "short"),
        ("checkout_dirty", 1),
        ("checkout_mismatch", 1),
        ("historical_blob_available", 1),
    ],
)
def test_source_link_rejects_invalid_checkout_metadata(field: str, value: Any) -> None:
    evidence = _evidence()
    mapping = CurrentWorktreeMapping(
        evidence.relative_path,
        evidence.span,
        evidence.content_digest,
        WorktreeMappingKind.EXACT,
    )
    link = SourceLink(
        evidence=evidence,
        immutable_revision_uri=evidence.immutable_revision_uri,
        checkout_resolution=CheckoutResolution.EXACT,
        checkout_commit_id=COMMIT,
        checkout_dirty=False,
        checkout_mismatch=False,
        historical_blob_available=True,
        current_mapping=mapping,
    )
    with pytest.raises(IndexingValidationError):
        replace(link, **{field: value})


def test_local_target_requires_absolute_safe_content_addressed_coordinates() -> None:
    evidence = _evidence()
    target = LocalSourceTarget(
        "/workspace/src/main.py",
        "src/main.py",
        evidence.span,
        evidence.content_digest,
    )
    assert target.absolute_path.startswith("/")
    invalid_values: tuple[tuple[str, Any], ...] = (
        ("absolute_path", "relative/main.py"),
        ("relative_path", "../escape.py"),
        ("content_digest", "invalid"),
    )
    for field, value in invalid_values:
        with pytest.raises(IndexingValidationError):
            replace(target, **{field: value})


def test_span_for_offsets_handles_crlf_unicode_and_trailing_newline() -> None:
    content = "α\r\nβ\n".encode()  # noqa: RUF001 -- Deliberate multibyte coordinate fixture.
    start = content.index("β".encode())
    span = span_for_offsets(content, start, len(content))

    assert (span.start_line, span.start_column) == (1, 0)
    assert (span.end_line, span.end_column) == (2, 0)
    with pytest.raises(IndexingValidationError):
        span_for_offsets(content, start, start)
