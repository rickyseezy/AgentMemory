"""PF-005 encrypted checkpoint codec and source boundary security tests."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentmemory.indexing.adapters.outbound import sqlite_checkpoint_source as source
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.incremental import PriorIndexedUnit
from agentmemory.indexing.domain.incremental_ports import RepositoryManifestEntry
from agentmemory.operations.adapters.outbound import sqlite_mcp_session as session_codec
from agentmemory.operations.adapters.outbound import sqlite_mcp_workspace_scope as workspace_scope
from agentmemory.operations.adapters.outbound import sqlite_workspace_checkpoint as codec
from agentmemory.operations.adapters.outbound import workspace_checkpoint_ingestion as ingestion
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from agentmemory.operations.domain.workspace_checkpoint import (
    WorkspaceCheckpointBatch,
    WorkspaceCheckpointChange,
)

_SESSION = Uuid7Id("019d2b4e-7a10-7def-8abc-0123456789ab")
_WORKSPACE = Sha256Digest("a" * 64)
_KEY = bytearray(b"k" * 32)


def test_pf005_checkpoint_codec_authenticates_every_envelope_coordinate() -> None:
    batch = _batch()
    row = _encrypted_row(batch)
    assert codec._decrypt_row(dict(row), bytearray(_KEY)) == batch

    mutations: list[tuple[str, object]] = [
        ("aad_sha256", b"x" * 32),
        ("algorithm", "AES-128-GCM"),
        ("canonical_sha256", b"x" * 32),
        ("session_id", "019d2b4e-7a11-7def-8abc-0123456789ab"),
        ("workspace_fingerprint", b"b" * 32),
        ("partial", 1),
        ("change_count", 2),
    ]
    for key, value in mutations:
        changed = dict(row)
        changed[key] = value
        with pytest.raises(ValueError, match=r"^$"):
            codec._decrypt_row(changed, bytearray(_KEY))


@pytest.mark.parametrize(
    "payload",
    [
        b"[]",
        b'{"session_id":"x"}',
        b'{"session_id":"x","session_id":"y"}',
        b'{"session_id":1,"workspace_fingerprint":"a","batch_digest":"",'
        b'"partial":false,"changes":[]}',
        b'{"session_id":"019d2b4e-7a10-7def-8abc-0123456789ab",'
        b'"workspace_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"batch_digest":"foreign","partial":false,"changes":[]}',
        b'{"session_id":"019d2b4e-7a10-7def-8abc-0123456789ab",'
        b'"workspace_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"batch_digest":"","partial":0,"changes":[]}',
        b'{"session_id":"019d2b4e-7a10-7def-8abc-0123456789ab",'
        b'"workspace_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"batch_digest":"","partial":false,"changes":{}}',
    ],
)
def test_pf005_checkpoint_decoder_rejects_noncanonical_documents(payload: bytes) -> None:
    with pytest.raises((TypeError, ValueError)):
        codec._decode_batch(payload, "b" * 64)


@pytest.mark.parametrize(
    "document",
    [
        "not-an-object",
        {"relative_path": "a"},
        {
            "relative_path": "a",
            "sha256": "b" * 64,
            "content_base64": "",
            "deleted": 0,
        },
        {
            "relative_path": "a",
            "sha256": "b" * 64,
            "content_base64": "!invalid!",
            "deleted": False,
        },
    ],
)
def test_pf005_checkpoint_change_decoder_rejects_type_shape_and_base64(
    document: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        codec._decode_change(document)


def test_pf005_checkpoint_primitive_decoders_fail_closed() -> None:
    with pytest.raises(ValueError, match=r"^$"):
        codec._unique_object([("a", 1), ("a", 2)])
    with pytest.raises(TypeError):
        codec._required_string(1)
    with pytest.raises(ValueError, match=r"^$"):
        codec._blob({"value": "not-bytes"}, "value")
    with pytest.raises(ValueError, match=r"^$"):
        codec._blob({"value": b"x"}, "value", 32)
    for value in (True, "1"):
        with pytest.raises(TypeError):
            codec._integer({"value": value}, "value")
    with pytest.raises(ValueError, match=r"^$"):
        codec._microseconds("not-a-date")
    with pytest.raises(ValueError, match=r"^$"):
        codec._microseconds(datetime(2026, 7, 22, tzinfo=UTC).replace(tzinfo=None))
    assert codec._microseconds(datetime(2026, 7, 22, tzinfo=UTC)) > 0


def test_pf005_checkpoint_source_rejects_missing_foreign_and_malformed_rows() -> None:
    for target_value in (None, "not-a-digest"):
        with pytest.raises(IndexingValidationError):
            source._target(target_value)
    with pytest.raises(IndexingUnavailableError):
        source._require_target_row(None, "repository")
    with pytest.raises(IndexingAuthorizationError):
        source._require_target_row({"repository_id": "foreign"}, "repository")  # type: ignore[arg-type]
    target_row = {"repository_id": "repository"}
    resolved_target = source._require_target_row(cast("Any", target_row), "repository")
    assert resolved_target["repository_id"] == "repository"

    invalid_rows: tuple[Any, ...] = (
        None,
        {"repository_id": "foreign", "disposition": "event", "deleted": 0},
        {"repository_id": "repository", "disposition": "excluded", "deleted": 0},
        {"repository_id": "repository", "disposition": "event", "deleted": 1},
    )
    for row in invalid_rows:
        with pytest.raises(IndexingAuthorizationError):
            source._require_source_row(row, "repository")

    with pytest.raises(ValueError, match=r"^$"):
        source._blob(cast("Any", {"value": "bad"}), "value")
    with pytest.raises(ValueError, match=r"^$"):
        source._blob(cast("Any", {"value": b"x"}), "value", 32)
    for integer_value in (True, "1"):
        with pytest.raises(TypeError):
            source._integer(integer_value)
    with pytest.raises(ValueError, match=r"^$"):
        source._text(cast("Any", {"value": ""}), "value")


def test_pf005_checkpoint_source_derives_deterministic_delta_and_generated_policy() -> None:
    unchanged = _prior("same.py", "1" * 64)
    modified = _prior("modified.py", "2" * 64)
    deleted = _prior("deleted.py", "3" * 64)
    current = {
        "same.py": RepositoryManifestEntry(
            relative_path="same.py", content_digest="1" * 64, byte_length=1, generated=False
        ),
        "modified.py": RepositoryManifestEntry(
            relative_path="modified.py",
            content_digest="4" * 64,
            byte_length=1,
            generated=False,
        ),
        "added.py": RepositoryManifestEntry(
            relative_path="added.py", content_digest="5" * 64, byte_length=1, generated=False
        ),
    }
    rows: tuple[Any, ...] = (
        _source_row("same.py", disposition="event"),
        _source_row("modified.py", disposition="event"),
        _source_row("added.py", disposition="event"),
        _source_row("deleted.py", disposition="event", deleted=1),
        _source_row("excluded.py", disposition="excluded"),
    )
    deltas = source._target_deltas(rows, (unchanged, modified, deleted), current)
    assert tuple((item.kind.value, item.relative_path) for item in deltas) == (
        ("add", "added.py"),
        ("delete", "deleted.py"),
        ("modify", "modified.py"),
    )
    assert source._generated("vendor/package.js")
    assert source._generated("src/output.generated.go")
    assert not source._generated("src/service.py")


def test_pf005_workspace_scope_helpers_reject_ambiguity_and_invalid_time() -> None:
    project = "019d2b4e-7a15-7def-8abc-0123456789ab"
    repository = "019d2b4e-7a16-7def-8abc-0123456789ab"
    checkout = "019d2b4e-7a17-7def-8abc-0123456789ab"
    scoped = workspace_scope._single_scope(
        cast("Any", [{"project_id": project, "repository_id": repository, "checkout_id": checkout}])
    )
    assert scoped.checkout_id is not None
    repository_only = workspace_scope._single_scope(
        cast("Any", [{"project_id": project, "repository_id": repository, "checkout_id": None}])
    )
    assert repository_only.checkout_id is None
    for rows in (
        [],
        [
            {"project_id": project, "repository_id": repository, "checkout_id": checkout},
            {
                "project_id": "019d2b4e-7a18-7def-8abc-0123456789ab",
                "repository_id": repository,
                "checkout_id": checkout,
            },
        ],
    ):
        with pytest.raises(OperationError) as ambiguous:
            workspace_scope._single_scope(rows)  # type: ignore[arg-type]
        assert ambiguous.value.code is ErrorCode.CONFLICT
    assert workspace_scope._optional_digest(None) is None
    assert workspace_scope._optional_digest("a" * 64) == b"\xaa" * 32
    with pytest.raises(ValueError, match=r"^$"):
        workspace_scope._microseconds(datetime(2026, 7, 22, tzinfo=UTC).replace(tzinfo=None))
    assert workspace_scope._microseconds(datetime(2026, 7, 22, tzinfo=UTC)) > 0


def test_pf005_workspace_ingestion_primitive_guards_reject_wrong_types() -> None:
    assert ingestion._policy_document(None) is None
    for text_value in (None, ""):
        with pytest.raises(ValueError, match=r"^$"):
            ingestion._required_text(text_value)
    with pytest.raises(ValueError, match=r"^$"):
        ingestion._blob({"value": "bad"}, "value")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match=r"^$"):
        ingestion._blob({"value": b"x"}, "value", 32)  # type: ignore[arg-type]
    for integer_value in (True, "1"):
        with pytest.raises(TypeError):
            ingestion._integer(integer_value)
    with pytest.raises(ValueError, match=r"^$"):
        ingestion._microseconds(datetime(2026, 7, 22, tzinfo=UTC).replace(tzinfo=None))
    with pytest.raises(ValueError, match=r"^$"):
        ingestion._microseconds(datetime(2026, 7, 22, tzinfo=timezone(timedelta(hours=1))))
    assert ingestion._microseconds(datetime(2026, 7, 22, tzinfo=UTC)) > 0


def test_pf005_session_snapshot_codec_rejects_shape_type_and_time_substitution() -> None:
    for document in ("[]", "{}", '{"schema_version":2}'):
        with pytest.raises((TypeError, KeyError)):
            session_codec._record_mapping(document)
    with pytest.raises(OperationError) as malformed:
        session_codec._decode_record("{}")
    assert malformed.value.code is ErrorCode.INTEGRITY_VIOLATION

    for timestamp in ("2026-07-22T00:00:00+00:00", "2026-07-22T00:00:00Z"):
        with pytest.raises(ValueError, match=r"^$"):
            session_codec._parse_timestamp(timestamp)
    for string_value in (None, 1):
        with pytest.raises(TypeError):
            session_codec._string(string_value)
    for integer_value in (None, "1", True):
        with pytest.raises(TypeError):
            session_codec._integer(integer_value)
    assert session_codec._optional_string(None) is None
    assert session_codec._optional_string("value") == "value"
    assert session_codec._optional_str(None) is None
    with pytest.raises(OperationError):
        session_codec._require_str(1)
    boolean_value = True
    with pytest.raises(OperationError):
        session_codec._require_int(boolean_value)
    with pytest.raises(OperationError):
        session_codec._require_bytes(b"short")


def _source_row(
    path: str,
    *,
    disposition: str,
    deleted: int = 0,
) -> dict[str, object]:
    return {"relative_path": path, "disposition": disposition, "deleted": deleted}


def _prior(path: str, content_digest: str) -> PriorIndexedUnit:
    return PriorIndexedUnit(
        path,
        "6" * 64,
        "7" * 64,
        content_digest,
        "8" * 64,
    )


def _batch() -> WorkspaceCheckpointBatch:
    content = b"safe\n"
    change = WorkspaceCheckpointChange(
        relative_path="src/main.py",
        sha256=Sha256Digest(hashlib.sha256(content).hexdigest()),
        content=content,
        deleted=False,
    )
    canonical = json.dumps(
        {
            "session_id": _SESSION.value,
            "workspace_fingerprint": _WORKSPACE.value,
            "batch_digest": "",
            "partial": False,
            "changes": [change.document()],
        },
        separators=(",", ":"),
    ).encode()
    digest = Sha256Digest(hashlib.sha256(canonical).hexdigest())
    return WorkspaceCheckpointBatch(
        session_id=_SESSION,
        workspace_fingerprint=_WORKSPACE,
        batch_digest=digest,
        partial=False,
        changes=(change,),
    )


def _encrypted_row(batch: WorkspaceCheckpointBatch) -> dict[str, object]:
    canonical = batch.canonical_bytes()
    aad = codec._aad(batch)
    nonce = b"n" * 12
    return {
        "batch_digest": bytes.fromhex(batch.batch_digest.value),
        "session_id": batch.session_id.value,
        "workspace_fingerprint": bytes.fromhex(batch.workspace_fingerprint.value),
        "aad_sha256": hashlib.sha256(aad).digest(),
        "algorithm": "AES-256-GCM",
        "nonce": nonce,
        "ciphertext": AESGCM(bytes(_KEY)).encrypt(nonce, canonical, aad),
        "canonical_sha256": hashlib.sha256(canonical).digest(),
        "partial": 0,
        "change_count": len(batch.changes),
    }
