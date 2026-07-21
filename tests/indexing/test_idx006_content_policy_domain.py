"""IDX-006 deterministic content-policy domain acceptance tests."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

import pytest

from agentmemory.indexing.domain.content_policy import (
    IndexContentPolicy,
    IndexPolicyRevision,
    PolicyAction,
    PolicyDisposition,
    PolicyLayer,
    PolicyPhase,
    PolicyRule,
    PolicyRuleSource,
    ReconciliationAction,
    classify_policy_change,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

BRAIN_ID = "018f0000-0000-7000-8000-000000000001"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
POLICY_ID = "018f0000-0000-7000-8000-000000000601"
NOW = datetime(2026, 7, 21, tzinfo=UTC)


def _brain(*rules: tuple[str, PolicyAction], version: int = 1) -> IndexPolicyRevision:
    source = PolicyRuleSource.create(
        PolicyLayer.BRAIN,
        version,
        tuple(
            PolicyRule(PolicyLayer.BRAIN, f"brain.{index}", version, pattern, action)
            for index, (pattern, action) in enumerate(rules, start=1)
        ),
    )
    return IndexPolicyRevision(
        policy_id=POLICY_ID,
        version=version,
        brain_id=BRAIN_ID,
        repository_id=REPOSITORY_ID,
        brain_rules=source,
        max_file_bytes=1024,
        private_block_pairs=(("<agentmemory-private>", "</agentmemory-private>"),),
        exclude_binary=True,
        exclude_generated=True,
        exclude_encrypted=True,
        activated_at=NOW,
    )


def _source(layer: PolicyLayer, text: bytes, version: int = 1) -> PolicyRuleSource:
    return PolicyRuleSource.from_ignore_bytes(layer, version, text)


def test_precedence_is_brain_then_agentmemoryignore_then_private_then_git_default() -> None:
    policy = IndexContentPolicy(
        _brain(("src/forced.py", PolicyAction.INCLUDE)),
        _source(
            PolicyLayer.AGENTMEMORY_IGNORE,
            b"src/**\n!src/private.py\n",
        ),
        _source(PolicyLayer.GITIGNORE, b"src/private.py\nsrc/forced.py\n"),
    )

    forced = policy.evaluate_content(
        "src/forced.py",
        b"\x00encrypted <agentmemory-private>secret</agentmemory-private>",
        NOW,
    )
    agent_excluded = policy.evaluate_path(
        "src/ordinary.py", symlink=False, byte_length=10, decided_at=NOW
    )
    private = policy.evaluate_content(
        "src/private.py",
        b"before <agentmemory-private>secret</agentmemory-private> after",
        NOW,
    )

    assert forced.disposition is PolicyDisposition.INCLUDE
    assert forced.layer is PolicyLayer.BRAIN
    assert forced.rule_id == "brain.1"
    assert agent_excluded.disposition is PolicyDisposition.EXCLUDE
    assert agent_excluded.layer is PolicyLayer.AGENTMEMORY_IGNORE
    assert private.disposition is PolicyDisposition.EXCLUDE
    assert private.layer is PolicyLayer.PRIVATE_BLOCK
    assert private.reason == "private_block"


def test_last_matching_rule_wins_with_root_basename_directory_and_recursive_globs() -> None:
    source = _source(
        PolicyLayer.AGENTMEMORY_IGNORE,
        b"*.log\n/build/\nsecrets/**\n!secrets/example.env\n\\#literal\n",
    )
    policy = IndexContentPolicy(_brain(), source, PolicyRuleSource.empty(PolicyLayer.GITIGNORE))

    assert policy.evaluate_path(
        "nested/app.log", symlink=False, byte_length=1, decided_at=NOW
    ).excluded
    assert policy.evaluate_path(
        "build/output.js", symlink=False, byte_length=1, decided_at=NOW
    ).excluded
    assert policy.evaluate_path(
        "secrets/live.env", symlink=False, byte_length=1, decided_at=NOW
    ).excluded
    assert policy.evaluate_path(
        "secrets/example.env", symlink=False, byte_length=1, decided_at=NOW
    ).included
    assert policy.evaluate_path("#literal", symlink=False, byte_length=1, decided_at=NOW).excluded


@pytest.mark.parametrize(
    "path",
    [
        "",
        "/absolute.py",
        "../escape.py",
        "src/../escape.py",
        "src\\escape.py",
        "src//escape.py",
        "src/./escape.py",
        "nul\x00.py",
    ],
)
def test_unsafe_paths_are_rejected_before_policy_matching(path: str) -> None:
    policy = IndexContentPolicy.production_default(BRAIN_ID, REPOSITORY_ID, NOW)
    with pytest.raises(IndexingValidationError, match="content policy input is invalid"):
        policy.evaluate_path(path, symlink=False, byte_length=1, decided_at=NOW)


def test_symlink_generated_vendor_binary_large_and_encrypted_content_are_excluded() -> None:
    policy = IndexContentPolicy(_brain(), None, None)

    cases = (
        (
            policy.evaluate_path("src/link.py", symlink=True, byte_length=1, decided_at=NOW),
            "symlink",
        ),
        (
            policy.evaluate_path("vendor/library.py", symlink=False, byte_length=1, decided_at=NOW),
            "vendored",
        ),
        (
            policy.evaluate_path("dist/app.js", symlink=False, byte_length=1, decided_at=NOW),
            "generated",
        ),
        (
            policy.evaluate_path("src/large.py", symlink=False, byte_length=1025, decided_at=NOW),
            "oversized",
        ),
        (policy.evaluate_content("src/image.bin", b"abc\x00def", NOW), "binary"),
        (
            policy.evaluate_content("src/config.age", b"age-encryption.org/v1\nbody", NOW),
            "encrypted",
        ),
    )
    assert [(decision.excluded, decision.reason) for decision, _ in cases] == [
        (True, reason) for _, reason in cases
    ]
    assert all(decision.phase in {PolicyPhase.PATH, PolicyPhase.CONTENT} for decision, _ in cases)


def test_decisions_are_content_free_deterministic_and_bind_rule_version_and_source_hash() -> None:
    policy = IndexContentPolicy(
        _brain(("private/**", PolicyAction.EXCLUDE), version=7),
        None,
        None,
    )
    first = policy.evaluate_path(
        "private/credentials.txt", symlink=False, byte_length=12, decided_at=NOW
    )
    second = policy.evaluate_path(
        "private/credentials.txt", symlink=False, byte_length=12, decided_at=NOW
    )

    assert first == second
    assert first.id == second.id
    assert first.rule_version == 7
    assert len(first.source_hash) == 64
    assert b"raw-secret-value" not in first.canonical_bytes


def test_policy_tightening_deletes_and_loosening_reindexes_without_noop_work() -> None:
    included = IndexContentPolicy(_brain(), None, None).evaluate_content(
        "src/app.py", b"print('ok')\n", NOW
    )
    tightened = IndexContentPolicy(
        _brain(("src/**", PolicyAction.EXCLUDE), version=2), None, None
    ).evaluate_content("src/app.py", b"print('ok')\n", NOW)
    loosened = IndexContentPolicy(
        _brain(("src/**", PolicyAction.INCLUDE), version=3), None, None
    ).evaluate_content("src/app.py", b"print('ok')\n", NOW)

    assert classify_policy_change(included, tightened) is ReconciliationAction.DELETE
    assert classify_policy_change(tightened, loosened) is ReconciliationAction.REINDEX
    assert classify_policy_change(loosened, loosened) is None


def test_canonical_revision_and_decision_evidence_are_byte_exact() -> None:
    policy = IndexContentPolicy.production_default(BRAIN_ID, REPOSITORY_ID, NOW)
    decision = policy.evaluate_content("src/é.py", "café".encode(), NOW)

    assert policy.revision.canonical_bytes == (
        b'{"activated_at":1784592000000000,"brain_id":"018f0000-0000-7000-8000-'
        b'000000000001","brain_rules":[],"brain_source_hash":"e3b0c44298fc1c149afbf4c8996'
        b'fb92427ae41e4649b934ca495991b7852b855","exclude_binary":true,"exclude_encrypted":'
        b'true,"exclude_generated":true,"max_file_bytes":2097152,"policy_id":"018f0000-0000-'
        b'7000-8000-000000000601","private_block_pairs":[["<agentmemory-private>","</agent'
        b'memory-private>"],["agentmemory:private:start","agentmemory:private:end"]],"repository'
        b'_id":"018f0000-0000-7000-8000-000000000020","version":1}'
    )
    assert policy.revision.digest == sha256(policy.revision.canonical_bytes).hexdigest()
    assert decision.canonical_bytes == (
        b'{"binary":false,"byte_length":5,"content_hash":"850f7dc43910ff890f8879c0ed26fe'
        b'697c93a067ad93a7d50f466a7028a9bf4e","decided_at":1784592000000000,"disposition"'
        b':"include","encrypted":false,"layer":"default","phase":"content","policy_digest":"'
        b'aa4d5a1022ab50e93c3d0d72f84be58ac231a1f2756b7f72cd6e5a6acd7b8f2a","private":'
        b'false,"reason":"included","relative_path":"src/\xc3\xa9.py","repository_id":"018f0000-0000-'
        b'7000-8000-000000000020","rule_id":"default.included","rule_version":1,"source_hash"'
        b':"aa4d5a1022ab50e93c3d0d72f84be58ac231a1f2756b7f72cd6e5a6acd7b8f2a","symlink"'
        b":false}"
    )
    assert decision.id == sha256(decision.canonical_bytes).hexdigest()


@pytest.mark.parametrize(
    "path",
    [
        "src/client.generated.ts",
        "src/client.min.css",
        "src/client.min.js",
        "src/form.designer.cs",
        "src/service_pb2.py",
    ],
)
def test_every_default_generated_filename_is_excluded(path: str) -> None:
    decision = IndexContentPolicy(_brain(), None, None).evaluate_path(
        path, symlink=False, byte_length=1, decided_at=NOW
    )
    assert decision.excluded
    assert decision.reason == "generated"


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (b"", PolicyDisposition.INCLUDE),
        (b"plain text", PolicyDisposition.INCLUDE),
        (b"plain\ttext\n", PolicyDisposition.INCLUDE),
        (b"PK\x03\x04payload", PolicyDisposition.EXCLUDE),
        (b"PK\x05\x06payload", PolicyDisposition.EXCLUDE),
        (b"\x1f\x8bpayload", PolicyDisposition.EXCLUDE),
        (b"7z\xbc\xaf\x27\x1cpayload", PolicyDisposition.EXCLUDE),
        (b"Rar!\x1a\x07payload", PolicyDisposition.EXCLUDE),
        (b"abc\x00def", PolicyDisposition.EXCLUDE),
        (b"\xff", PolicyDisposition.EXCLUDE),
        (b"\x08", PolicyDisposition.EXCLUDE),
        (b"\x0e", PolicyDisposition.EXCLUDE),
        (b"\x7f", PolicyDisposition.EXCLUDE),
    ],
)
def test_binary_classification_covers_archives_encoding_and_controls(
    content: bytes, expected: PolicyDisposition
) -> None:
    revision = _brain()
    policy = IndexContentPolicy(revision, None, None)
    decision = policy.evaluate_content("src/value.dat", content, NOW)
    assert decision.binary is (expected is PolicyDisposition.EXCLUDE)
    assert decision.disposition is expected


@pytest.mark.parametrize(
    "path",
    [
        "secrets/value.age",
        "secrets/value.ENC",
        "secrets/value.gpg",
        "secrets/value.jks",
        "secrets/value.p12",
        "secrets/value.pfx",
        "secrets/value.pgp",
    ],
)
def test_every_encrypted_suffix_is_detected_case_insensitively(path: str) -> None:
    decision = IndexContentPolicy(_brain(), None, None).evaluate_content(path, b"text", NOW)
    assert decision.encrypted
    assert decision.reason == "encrypted"


@pytest.mark.parametrize(
    "content",
    [
        b"-----BEGIN PGP MESSAGE-----\nbody",
        b"Salted__body",
        b"age-encryption.org/v1\nbody",
    ],
)
def test_every_encrypted_header_is_detected(content: bytes) -> None:
    decision = IndexContentPolicy(_brain(), None, None).evaluate_content(
        "secrets/value.txt", content, NOW
    )
    assert decision.encrypted
    assert decision.reason == "encrypted"


@pytest.mark.parametrize(
    "content",
    [
        b"<agentmemory-private>unterminated",
        b"agentmemory:private:start unterminated",
    ],
)
def test_private_start_markers_fail_closed_when_unterminated(content: bytes) -> None:
    decision = IndexContentPolicy.production_default(BRAIN_ID, REPOSITORY_ID, NOW).evaluate_content(
        "src/value.txt", content, NOW
    )
    assert decision.private
    assert decision.reason == "private_block"


def test_private_end_marker_without_start_is_public() -> None:
    decision = IndexContentPolicy.production_default(BRAIN_ID, REPOSITORY_ID, NOW).evaluate_content(
        "src/value.txt", b"</agentmemory-private>", NOW
    )
    assert not decision.private
    assert decision.included


def test_ignore_parser_preserves_git_line_semantics_and_rule_coordinates() -> None:
    source = _source(
        PolicyLayer.AGENTMEMORY_IGNORE,
        b"# comment\r\n\r\n\\#literal\r\n\\!literal-bang\r\n!released.log\r\n"
        b"trimmed   \r\nescaped\\ \r\n",
    )

    assert [rule.rule_id for rule in source.rules] == [
        "agentmemoryignore.3",
        "agentmemoryignore.4",
        "agentmemoryignore.5",
        "agentmemoryignore.6",
        "agentmemoryignore.7",
    ]
    assert [(rule.pattern, rule.action) for rule in source.rules] == [
        ("#literal", PolicyAction.EXCLUDE),
        ("!literal-bang", PolicyAction.EXCLUDE),
        ("released.log", PolicyAction.INCLUDE),
        ("trimmed", PolicyAction.EXCLUDE),
        ("escaped ", PolicyAction.EXCLUDE),
    ]


@pytest.mark.parametrize(
    "pattern",
    ["", "!unsafe", "bad\\path", "bad\x00path", ".", "..", "a/./b", "a/../b"],
)
def test_invalid_brain_rule_patterns_are_rejected(pattern: str) -> None:
    with pytest.raises(IndexingValidationError, match="content policy input is invalid"):
        PolicyRule(PolicyLayer.BRAIN, "brain.invalid", 1, pattern, PolicyAction.EXCLUDE)


def test_oversized_ignore_rule_and_source_are_rejected() -> None:
    with pytest.raises(IndexingValidationError, match="content policy input is invalid"):
        _source(PolicyLayer.AGENTMEMORY_IGNORE, (b"a" * 1025) + b"\n")
    with pytest.raises(IndexingValidationError, match="content policy input is invalid"):
        _source(PolicyLayer.AGENTMEMORY_IGNORE, b"a" * (256 * 1024 + 1))


@pytest.mark.parametrize(
    ("pattern", "matching", "not_matching"),
    [
        ("*.log", "nested/app.log", "nested/app.log.txt"),
        ("/root.txt", "root.txt", "nested/root.txt"),
        ("build/", "build/output.js", "builder/output.js"),
        ("src/*.py", "src/app.py", "src/nested/app.py"),
        ("src/**/test?.py", "src/a/b/test1.py", "src/a/b/test12.py"),
        ("docs/**", "docs/a/b.md", "src/docs/a.md"),
        ("**/generated.py", "a/b/generated.py", "a/b/generated.js"),
        ("file[0-9].txt", "file7.txt", "filex.txt"),
        ("file[!0-9].txt", "filex.txt", "file7.txt"),
        ("literal[.txt", "literal[.txt", "literalx.txt"),
    ],
)
def test_git_style_glob_matrix(pattern: str, matching: str, not_matching: str) -> None:
    rule = PolicyRule(PolicyLayer.BRAIN, "brain.glob", 1, pattern, PolicyAction.EXCLUDE)
    assert rule.matches(matching)
    assert not rule.matches(not_matching)


def test_content_decision_copies_all_explicit_and_gitignore_evidence_fields() -> None:
    brain_policy = IndexContentPolicy(_brain(("src/forced.py", PolicyAction.INCLUDE)), None, None)
    forced = brain_policy.evaluate_content("src/forced.py", b"\x00", NOW)
    assert (
        forced.phase,
        forced.disposition,
        forced.reason,
        forced.layer,
        forced.rule_id,
        forced.rule_version,
        forced.source_hash,
        forced.byte_length,
        forced.binary,
        forced.encrypted,
        forced.private,
        forced.symlink,
    ) == (
        PolicyPhase.CONTENT,
        PolicyDisposition.INCLUDE,
        "explicit_include",
        PolicyLayer.BRAIN,
        "brain.1",
        1,
        brain_policy.revision.brain_rules.source_hash,
        1,
        False,
        False,
        False,
        False,
    )
    assert forced.content_hash == sha256(b"\x00").hexdigest()

    git = _source(PolicyLayer.GITIGNORE, b"src/ignored.enc\n")
    ignored = IndexContentPolicy(_brain(), None, git).evaluate_content(
        "src/ignored.enc", b"\x00", NOW
    )
    assert ignored.layer is PolicyLayer.GITIGNORE
    assert ignored.phase is PolicyPhase.CONTENT
    assert ignored.binary
    assert ignored.encrypted
    assert not ignored.private


def test_policy_change_rejects_cross_repository_or_cross_path_comparisons() -> None:
    policy = IndexContentPolicy(_brain(), None, None)
    first = policy.evaluate_content("src/a.py", b"a", NOW)
    other_path = policy.evaluate_content("src/b.py", b"a", NOW)
    other_repository = IndexContentPolicy(
        IndexPolicyRevision.production_default(
            BRAIN_ID, "018f0000-0000-7000-8000-000000000021", NOW
        ),
        None,
        None,
    ).evaluate_content("src/a.py", b"a", NOW)
    with pytest.raises(IndexingValidationError, match="content policy input is invalid"):
        classify_policy_change(first, other_path)
    with pytest.raises(IndexingValidationError, match="content policy input is invalid"):
        classify_policy_change(first, other_repository)
