"""IDX-007 exact revision verification, mapping, and local-open application tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace

import pytest

from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
from agentmemory.indexing.application.source_navigation import (
    ResolveLocalSourceTargetHandler,
    ResolveLocalSourceTargetQuery,
    ResolveSourceEvidenceHandler,
    ResolveSourceEvidenceQuery,
)
from agentmemory.indexing.domain.code_entities import SemanticSource, SymbolKind
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
)
from agentmemory.indexing.domain.source_navigation import (
    CheckoutCandidate,
    CheckoutResolution,
    SourceEvidence,
    SourceEvidenceKind,
    WorktreeMappingKind,
    span_for_offsets,
)
from tests.indexing.test_idx001_sqlite_code_index import (
    _scope as indexing_scope,  # pyright: ignore[reportPrivateUsage]
)

HISTORICAL = "def café():\n    return 1\n".encode()
FRAGMENT = "café".encode()
OLD_COMMIT = "a" * 40
NEW_COMMIT = "b" * 40


def _evidence() -> SourceEvidence:
    start = HISTORICAL.index(FRAGMENT)
    return SourceEvidence(
        "1" * 64,
        SourceEvidenceKind.DEFINITION,
        "018f0000-0000-7000-8000-000000000001",
        "018f0000-0000-7000-8000-000000000010",
        "018f0000-0000-7000-8000-000000000020",
        "2" * 64,
        OLD_COMMIT,
        "3" * 64,
        "4" * 64,
        "src/old.py",
        "5" * 64,
        "python:function:café",
        "café",
        SymbolKind.FUNCTION,
        None,
        span_for_offsets(HISTORICAL, start, start + len(FRAGMENT)),
        hashlib.sha256(HISTORICAL).hexdigest(),
        len(HISTORICAL),
        "parser@1",
        "grammar",
        "6" * 64,
        SemanticSource.TREE_SITTER,
    )


@dataclass(slots=True)
class _Repository:
    evidence: SourceEvidence | None = field(default_factory=_evidence)
    scopes: list[AuthorizedScope] = field(default_factory=list[AuthorizedScope])

    async def get(self, scope: AuthorizedScope, evidence_id: str) -> SourceEvidence | None:
        self.scopes.append(scope)
        assert evidence_id == "1" * 64
        return self.evidence


@dataclass(slots=True)
class _Content:
    historical_value: bytes | None = HISTORICAL
    candidates: tuple[CheckoutCandidate, ...] = ()

    async def historical(self, evidence: SourceEvidence) -> bytes | None:
        del evidence
        return self.historical_value

    async def checkout_candidates(self, evidence: SourceEvidence) -> tuple[CheckoutCandidate, ...]:
        del evidence
        return self.candidates


@dataclass(slots=True)
class _Paths:
    value: str | None = "/workspace/src/new.py"
    calls: list[tuple[str, str, str]] = field(default_factory=list[tuple[str, str, str]])

    async def resolve(
        self, repository_id: str, relative_path: str, expected_digest: str
    ) -> str | None:
        self.calls.append((repository_id, relative_path, expected_digest))
        return self.value


def _scope(action: str) -> AuthorizedScope:
    return indexing_scope(action)


@pytest.mark.asyncio
async def test_exact_checkout_is_verified_without_false_mismatch() -> None:
    content = _Content(candidates=(CheckoutCandidate(OLD_COMMIT, "src/old.py", HISTORICAL),))

    link = await ResolveSourceEvidenceHandler(_Repository(), content).execute(
        ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
    )

    assert link.checkout_resolution is CheckoutResolution.EXACT
    assert link.checkout_mismatch is False
    assert link.historical_blob_available is True
    assert link.current_mapping is not None
    assert link.current_mapping.kind is WorktreeMappingKind.EXACT


@pytest.mark.asyncio
async def test_dirty_checkout_is_reported_even_when_supporting_file_bytes_are_unchanged() -> None:
    content = _Content(
        candidates=(
            CheckoutCandidate(
                OLD_COMMIT,
                "src/old.py",
                HISTORICAL,
                checkout_dirty=True,
            ),
        )
    )

    link = await ResolveSourceEvidenceHandler(_Repository(), content).execute(
        ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
    )

    assert link.checkout_dirty is True
    assert link.checkout_mismatch is True
    assert link.checkout_resolution is CheckoutResolution.DIFFERENT_MAPPED


@pytest.mark.asyncio
async def test_rename_and_unicode_line_shift_map_only_the_unique_exact_fragment() -> None:
    current = "# shifted\ndef café():\n    return 2\n".encode()
    content = _Content(candidates=(CheckoutCandidate(NEW_COMMIT, "src/new.py", current),))

    link = await ResolveSourceEvidenceHandler(_Repository(), content).execute(
        ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
    )

    assert link.checkout_resolution is CheckoutResolution.DIFFERENT_MAPPED
    assert link.checkout_mismatch is True
    assert link.checkout_commit_id == NEW_COMMIT
    assert link.current_mapping is not None
    assert link.current_mapping.relative_path == "src/new.py"
    assert link.current_mapping.kind is WorktreeMappingKind.RENAMED_AND_SHIFTED
    assert (link.current_mapping.span.start_line, link.current_mapping.span.start_column) == (1, 4)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("path", "content", "expected"),
    [
        ("src/new.py", HISTORICAL, WorktreeMappingKind.RENAMED),
        ("src/old.py", b"# shifted\n" + HISTORICAL, WorktreeMappingKind.SHIFTED),
    ],
)
async def test_pure_rename_and_pure_line_shift_have_distinct_mapping_kinds(
    path: str,
    content: bytes,
    expected: WorktreeMappingKind,
) -> None:
    link = await ResolveSourceEvidenceHandler(
        _Repository(), _Content(candidates=(CheckoutCandidate(NEW_COMMIT, path, content),))
    ).execute(ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64))

    assert link.current_mapping is not None
    assert link.current_mapping.kind is expected


@pytest.mark.asyncio
async def test_fragment_at_byte_zero_remains_a_valid_unique_mapping() -> None:
    current = FRAGMENT + b" = 1\n"
    link = await ResolveSourceEvidenceHandler(
        _Repository(),
        _Content(candidates=(CheckoutCandidate(NEW_COMMIT, "src/old.py", current),)),
    ).execute(ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64))

    assert link.current_mapping is not None
    assert link.current_mapping.span.start_byte == 0


@pytest.mark.asyncio
async def test_duplicate_fragment_or_multiple_candidates_never_points_at_current_lines() -> None:
    duplicated = b"caf\xc3\xa9\nother\ncaf\xc3\xa9\n"
    content = _Content(
        candidates=(
            CheckoutCandidate(NEW_COMMIT, "src/old.py", duplicated),
            CheckoutCandidate(NEW_COMMIT, "src/copy.py", HISTORICAL),
        )
    )

    link = await ResolveSourceEvidenceHandler(_Repository(), content).execute(
        ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
    )

    assert link.checkout_resolution is CheckoutResolution.DIFFERENT_MAPPED
    assert link.current_mapping is not None
    assert link.current_mapping.relative_path == "src/copy.py"

    ambiguous = _Content(
        candidates=(
            CheckoutCandidate(NEW_COMMIT, "src/a.py", HISTORICAL),
            CheckoutCandidate(NEW_COMMIT, "src/b.py", HISTORICAL),
        )
    )
    unresolved = await ResolveSourceEvidenceHandler(_Repository(), ambiguous).execute(
        ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
    )
    assert unresolved.checkout_resolution is CheckoutResolution.DIFFERENT_UNMAPPED
    assert unresolved.current_mapping is None


@pytest.mark.asyncio
async def test_missing_historical_blob_requires_one_exact_checkout_revision() -> None:
    exact = _Content(
        None,
        (CheckoutCandidate(NEW_COMMIT, "src/old.py", HISTORICAL),),
    )
    link = await ResolveSourceEvidenceHandler(_Repository(), exact).execute(
        ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
    )
    assert link.historical_blob_available is False
    assert link.checkout_mismatch is True

    with pytest.raises(IndexingUnavailableError):
        await ResolveSourceEvidenceHandler(_Repository(), _Content(None, ())).execute(
            ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
        )


@pytest.mark.asyncio
async def test_hash_mismatch_missing_evidence_and_wrong_action_fail_closed() -> None:
    with pytest.raises(IndexingConflictError, match="integrity verification"):
        await ResolveSourceEvidenceHandler(
            _Repository(), _Content(b"X" + HISTORICAL[1:], ())
        ).execute(ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64))
    resized = HISTORICAL + b"#"
    resized_evidence = replace(_evidence(), content_digest=hashlib.sha256(resized).hexdigest())
    with pytest.raises(IndexingConflictError, match="integrity verification"):
        await ResolveSourceEvidenceHandler(
            _Repository(resized_evidence), _Content(resized, ())
        ).execute(ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64))
    with pytest.raises(IndexingUnavailableError):
        await ResolveSourceEvidenceHandler(_Repository(None), _Content()).execute(
            ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
        )
    with pytest.raises(IndexingAuthorizationError, match="action is not authorized"):
        await ResolveSourceEvidenceHandler(_Repository(), _Content()).execute(
            ResolveSourceEvidenceQuery(_scope("indexing.search"), "1" * 64)
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "candidates",
    [
        (
            CheckoutCandidate(OLD_COMMIT, "src/old.py", HISTORICAL),
            CheckoutCandidate(NEW_COMMIT, "src/new.py", HISTORICAL),
        ),
        (
            CheckoutCandidate(OLD_COMMIT, "src/old.py", HISTORICAL),
            CheckoutCandidate(OLD_COMMIT, "src/new.py", HISTORICAL, checkout_dirty=True),
        ),
        (
            CheckoutCandidate(OLD_COMMIT, "src/old.py", HISTORICAL),
            CheckoutCandidate(OLD_COMMIT, "src/old.py", HISTORICAL),
        ),
    ],
)
async def test_inconsistent_or_duplicate_checkout_candidates_are_integrity_conflicts(
    candidates: tuple[CheckoutCandidate, ...],
) -> None:
    with pytest.raises(IndexingConflictError, match="integrity verification"):
        await ResolveSourceEvidenceHandler(_Repository(), _Content(candidates=candidates)).execute(
            ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
        )


@pytest.mark.asyncio
async def test_local_open_reauthorizes_and_binds_every_returned_coordinate() -> None:
    current = "# shifted\ndef café():\n    return 2\n".encode()
    repository = _Repository()
    navigation = ResolveSourceEvidenceHandler(
        repository,
        _Content(candidates=(CheckoutCandidate(NEW_COMMIT, "src/new.py", current),)),
    )
    link = await navigation.execute(
        ResolveSourceEvidenceQuery(_scope("indexing.source.navigate"), "1" * 64)
    )
    assert link.current_mapping is not None
    paths = _Paths()
    handler = ResolveLocalSourceTargetHandler(navigation, paths)
    target = await handler.execute(
        ResolveLocalSourceTargetQuery(
            _scope("indexing.source.open"),
            "1" * 64,
            link.immutable_revision_uri,
            link.current_mapping.relative_path,
            link.current_mapping.content_digest,
        )
    )

    assert target.absolute_path == "/workspace/src/new.py"
    assert repository.scopes[-1].action == "indexing.source.navigate"
    assert paths.calls[-1][1] == "src/new.py"

    with pytest.raises(IndexingConflictError):
        await handler.execute(
            ResolveLocalSourceTargetQuery(
                _scope("indexing.source.open"),
                "1" * 64,
                "agentmemory://forged",
                "src/new.py",
                link.current_mapping.content_digest,
            )
        )
