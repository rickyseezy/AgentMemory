"""IDX-007 real SQLite evidence lookup, policy visibility, and revocation tests."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.indexing.adapters.outbound.sqlite_code_index import SqliteCodeIndexRepository
from agentmemory.indexing.adapters.outbound.sqlite_source_navigation import (
    SqliteSourceEvidenceRepository,
    _blob,  # pyright: ignore[reportPrivateUsage]
)
from agentmemory.indexing.application.code_index import (
    IndexRepositorySnapshotCommand,
    IndexRepositorySnapshotHandler,
)
from agentmemory.indexing.domain.code_entities import (
    OccurrenceRole,
    SemanticPriority,
    SemanticSource,
    SymbolOccurrence,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.ports import SourceArtifact
from agentmemory.indexing.domain.source_navigation import SourceEvidenceKind
from tests.core.support import NOW, FixedClock, migrated_store
from tests.indexing.test_idx001_sqlite_code_index import (
    REPOSITORY_ID,
    SOURCE,
    _Plugin,  # pyright: ignore[reportPrivateUsage]
    _scope,  # pyright: ignore[reportPrivateUsage]
    _seed,  # pyright: ignore[reportPrivateUsage]
    _Source,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

COMMIT = "a" * 40


async def _indexed(store: SqliteCoreStore) -> tuple[str, str]:
    await _seed(store)
    result = await IndexRepositorySnapshotHandler(
        _Source((SourceArtifact("src/main.py", SOURCE),)),
        _Plugin(),
        SqliteCodeIndexRepository(store, FixedClock()),
    ).execute(
        IndexRepositorySnapshotCommand(
            "idx007-index",
            _scope("indexing.snapshot"),
            COMMIT,
            "d" * 64,
            NOW,
        )
    )
    files = await SqliteCodeIndexRepository(store, FixedClock()).list_files(
        _scope("indexing.search"), result.snapshot.id
    )
    return result.snapshot.id, files[0].symbol_revisions[0].id


@pytest.mark.asyncio
@pytest.mark.integration
async def test_repository_returns_complete_definition_evidence_under_current_scope(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        snapshot_id, evidence_id = await _indexed(store)
        evidence = await SqliteSourceEvidenceRepository(store, FixedClock()).get(
            _scope("indexing.source.navigate"), evidence_id
        )

        assert evidence is not None
        assert evidence.kind is SourceEvidenceKind.DEFINITION
        assert evidence.snapshot_id == snapshot_id
        assert evidence.commit_id == COMMIT
        assert evidence.repository_id == REPOSITORY_ID
        assert evidence.relative_path == "src/main.py"
        assert evidence.symbol_display_name == "hello"
        assert evidence.span.start_byte == 4
        assert evidence.content_digest == hashlib.sha256(SOURCE).hexdigest()
        assert evidence.parser_version == "test-parser-1"

        files = await SqliteCodeIndexRepository(store, FixedClock()).list_files(
            _scope("indexing.search"), snapshot_id
        )
        occurrence = SymbolOccurrence.create(
            file_revision_id=files[0].revision.id,
            target_symbol_id=files[0].symbols[0].id,
            role=OccurrenceRole.CALL,
            span=files[0].symbol_revisions[0].span,
            source=SemanticSource.TREE_SITTER,
            priority=SemanticPriority.TREE_SITTER,
            source_identity="test-parser-1:call",
        )
        await SqliteCodeIndexRepository(store, FixedClock()).merge_precise_evidence(
            _scope("indexing.scip.import"),
            files[0].revision.id,
            (),
            (),
            (occurrence,),
        )
        occurrence_evidence = await SqliteSourceEvidenceRepository(store, FixedClock()).get(
            _scope("indexing.source.navigate"), occurrence.id
        )
        assert occurrence_evidence is not None
        assert occurrence_evidence.kind is SourceEvidenceKind.OCCURRENCE
        assert occurrence_evidence.occurrence_role is OccurrenceRole.CALL
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_repository_hides_policy_invalidated_evidence_and_rejects_revoked_access(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        _snapshot_id, evidence_id = await _indexed(store)
        now = round(NOW.timestamp() * 1_000_000)
        scope = _scope("indexing.source.navigate")
        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO index_content_policy_versions(policy_digest,operation_id,"
                    "policy_id,policy_version,brain_id,repository_id,principal_id,"
                    "scope_fingerprint,document_json,activated_at) VALUES(:policy,'policy-op',"
                    "'policy-id',1,:brain,:repository,:principal,:scope,'{}',:now)"
                ),
                {
                    "repository": REPOSITORY_ID,
                    "brain": scope.brain_id.value,
                    "principal": scope.principal_id.value,
                    "scope": bytes.fromhex(scope.scope_fingerprint),
                    "policy": "7" * 64,
                    "now": now,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO index_policy_changes(change_id,operation_id,brain_id,"
                    "repository_id,previous_policy_digest,current_policy_digest,delete_count,"
                    "reindex_count,activated_at) VALUES(:change,'change-op',:brain,:repository,"
                    "NULL,:policy,1,0,:now)"
                ),
                {
                    "change": "8" * 64,
                    "brain": scope.brain_id.value,
                    "repository": REPOSITORY_ID,
                    "policy": "7" * 64,
                    "now": now,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO index_policy_reconciliation_items(item_id,change_id,"
                    "repository_id,ordinal,relative_path,action,policy_digest,created_at) "
                    "VALUES(:item,:change,:repository,0,'src/main.py','delete',:policy,:now)"
                ),
                {
                    "item": "9" * 64,
                    "change": "8" * 64,
                    "repository": REPOSITORY_ID,
                    "policy": "7" * 64,
                    "now": now,
                },
            )
            await connection.execute(
                text(
                    "INSERT INTO index_policy_derivative_invalidations(item_id,repository_id,"
                    "relative_path,semantic_ids_json,dependent_fact_ids_json,"
                    "assertion_evidence_ids_json,invalidated_at) VALUES(:item,:repository,"
                    "'src/main.py','[]','[]','[]',:now)"
                ),
                {"item": "9" * 64, "repository": REPOSITORY_ID, "now": now},
            )
        repository = SqliteSourceEvidenceRepository(store, FixedClock())
        assert await repository.get(_scope("indexing.source.navigate"), evidence_id) is None

        async with store.engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO index_policy_decisions(decision_id,repository_id,relative_path,"
                    "phase,disposition,reason,layer,rule_id,rule_version,source_hash,policy_digest,"
                    "byte_length,content_hash,is_binary,is_encrypted,is_private,is_symlink,"
                    "decided_at,decision_json) VALUES(:decision,:repository,'src/main.py',"
                    "'content','include','default_include','default','default.include',1,:source,"
                    ":policy,:length,:content,0,0,0,0,:decided,'{}')"
                ),
                {
                    "decision": "6" * 64,
                    "repository": REPOSITORY_ID,
                    "source": "5" * 64,
                    "policy": "7" * 64,
                    "length": len(SOURCE),
                    "content": hashlib.sha256(SOURCE).hexdigest(),
                    "decided": now + 1,
                },
            )
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:expired"),
                {"expired": round((NOW + timedelta(microseconds=1)).timestamp() * 1_000_000)},
            )
        revoked = SqliteSourceEvidenceRepository(store, FixedClock(NOW + timedelta(seconds=1)))
        with pytest.raises(IndexingAuthorizationError):
            await revoked.get(_scope("indexing.source.navigate"), evidence_id)
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_repository_rejects_wrong_action_and_malformed_evidence_id(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        repository = SqliteSourceEvidenceRepository(store, FixedClock())
        with pytest.raises(IndexingAuthorizationError):
            await repository.get(_scope("indexing.search"), "1" * 64)
        with pytest.raises(IndexingValidationError):
            await repository.get(_scope("indexing.source.navigate"), "not-a-digest")
    finally:
        await store.close()


def test_sqlite_blob_decoder_accepts_driver_shapes_and_rejects_other_values() -> None:
    assert _blob(b"bytes") == b"bytes"
    assert _blob(memoryview(b"view")) == b"view"
    assert _blob(bytearray(b"array")) == b"array"
    with pytest.raises(IndexingValidationError):
        _blob("not-a-blob")
