"""ADP-004 hookless-host evidence invariants."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID

import pytest

from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.domain.generic_adapter import (
    CandidateCausalAssociation,
    CausalAssociationKind,
    DecodedTranscriptRecord,
    FileChangeKind,
    FileObservation,
    FileSnapshotEntry,
    GitChangeKind,
    GitObservation,
    GitState,
    KnowledgeStatus,
    ProcessExecutionResult,
    ProcessObservation,
    SourceCompletion,
    TranscriptChunk,
    TranscriptRole,
    TranscriptSource,
    UnavailableLifecycleProvenance,
    WorkspaceSnapshot,
    stable_evidence_uuid7,
    uuid7_occurred_at,
)

if TYPE_CHECKING:
    from collections.abc import Callable

SESSION_ID = "018f0000-0000-7000-8000-000000000111"
OTHER_SESSION_ID = "018f0000-0001-7000-8000-000000000111"
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)
DIGEST_A = hashlib.sha256(b"a").hexdigest()
DIGEST_B = hashlib.sha256(b"b").hexdigest()


def association() -> CandidateCausalAssociation:
    return CandidateCausalAssociation(SESSION_ID, NOW, NOW + timedelta(seconds=2))


def chunk() -> TranscriptChunk:
    return TranscriptChunk(
        DIGEST_A,
        TranscriptSource.IMPORT,
        4,
        17,
        "safe output",
        TranscriptRole.ASSISTANT,
        NOW,
        SourceCompletion.COMPLETE,
        UnavailableLifecycleProvenance(),
        association(),
    )


def test_transcript_identity_is_bound_to_session_source_digest_and_stable_offsets() -> None:
    original = chunk()
    repeated = replace(
        original,
        content="redacted differently",
        observed_role=TranscriptRole.UNKNOWN,
        occurred_at=NOW + timedelta(days=1),
    )

    assert repeated.chunk_sha256 == original.chunk_sha256
    assert repeated.event_id == original.event_id
    assert UUID(original.event_id).version == 7
    assert original.event_id == stable_evidence_uuid7(original.chunk_sha256)


def test_transcript_identity_is_session_scoped_and_uuid_time_is_deterministic() -> None:
    original = chunk()
    other_session = replace(
        original,
        causal_association=CandidateCausalAssociation(OTHER_SESSION_ID, NOW, NOW),
    )

    assert other_session.event_id != original.event_id
    expected_milliseconds = UUID(SESSION_ID).int >> 80
    assert uuid7_occurred_at(SESSION_ID).timestamp() == expected_milliseconds / 1_000


def test_transcript_payload_labels_unavailable_lifecycle_provenance_unknown() -> None:
    document = json.loads(chunk().payload_bytes())

    assert document["prompt_provenance"] == "unknown"
    assert document["turn_provenance"] == "unknown"
    assert document["tool_provenance"] == "unknown"
    assert document["causal_association"]["kind"] == "candidate"
    assert "hidden_reasoning" not in document


def test_generic_adapter_cannot_claim_hidden_lifecycle_knowledge_or_causation() -> None:
    with pytest.raises(IngestionValidationError, match="must_remain_unknown"):
        UnavailableLifecycleProvenance(prompt=KnowledgeStatus("unknown"), turn="known")  # type: ignore[arg-type]
    with pytest.raises(IngestionValidationError, match="authoritative_forbidden"):
        replace(association(), kind=CausalAssociationKind.AUTHORITATIVE)


@pytest.mark.parametrize(
    "entry",
    [
        FileSnapshotEntry("src/a.py", DIGEST_A, 4),
        FileSnapshotEntry("unicodé/file name.txt", DIGEST_B, 0),
    ],
)
def test_file_snapshot_accepts_normalized_relative_paths(entry: FileSnapshotEntry) -> None:
    assert not entry.relative_path.startswith("/")


@pytest.mark.parametrize("path", ["/etc/passwd", "../secret", "a/../../secret", "a/../b"])
def test_file_snapshot_rejects_paths_outside_workspace(path: str) -> None:
    with pytest.raises(IngestionValidationError, match="relative_path"):
        FileSnapshotEntry(path, DIGEST_A, 1)


def test_file_rename_requires_same_digest_and_different_path() -> None:
    before = FileSnapshotEntry("old.txt", DIGEST_A, 1)
    after = FileSnapshotEntry("new.txt", DIGEST_A, 1)
    observed = FileObservation(FileChangeKind.RENAMED, after, before, NOW, association())

    assert observed.event_id != replace(observed, occurred_at=NOW + timedelta(days=1)).event_id
    assert json.loads(observed.payload_bytes())["causal_association"]["kind"] == "candidate"
    with pytest.raises(IngestionValidationError, match="shape_mismatch"):
        FileObservation(
            FileChangeKind.RENAMED,
            replace(after, content_sha256=DIGEST_B),
            before,
            NOW,
            association(),
        )


def test_git_observation_requires_a_real_transition_and_is_retry_stable() -> None:
    before = GitState("a" * 40, "main", DIGEST_A)
    after = GitState("b" * 40, "feature", DIGEST_A)
    observed = GitObservation(GitChangeKind.COMMIT, before, after, NOW, association())

    assert observed.event_id != replace(observed, occurred_at=NOW + timedelta(hours=1)).event_id
    assert json.loads(observed.payload_bytes())["previous"]["commit_sha"] == "a" * 40
    with pytest.raises(IngestionValidationError, match="no_transition"):
        GitObservation(GitChangeKind.COMMIT, after, after, NOW, association())


def test_process_observation_retains_only_bounded_digests_and_completion() -> None:
    observed = ProcessObservation(
        "python",
        DIGEST_A,
        0,
        DIGEST_B,
        DIGEST_A,
        NOW,
        NOW + timedelta(seconds=1),
        SourceCompletion.COMPLETE,
        association(),
    )
    document = json.loads(observed.payload_bytes())

    assert document["executable"] == "python"
    assert document["exit_code"] == 0
    assert "argv" not in document
    assert "stdout" not in document
    assert "stderr" not in document
    with pytest.raises(IngestionValidationError, match="exit_code"):
        replace(observed, exit_code=None)


def test_abrupt_process_may_have_no_exit_code() -> None:
    observed = ProcessObservation(
        "agent",
        DIGEST_A,
        None,
        DIGEST_B,
        DIGEST_A,
        NOW,
        NOW,
        SourceCompletion.ABRUPT,
        association(),
    )

    assert json.loads(observed.payload_bytes())["completion"] == "abrupt"


@pytest.mark.parametrize(
    "record",
    [
        lambda: DecodedTranscriptRecord(-1, 2, "safe", TranscriptRole.UNKNOWN, NOW),
        lambda: DecodedTranscriptRecord(0, 2, "", TranscriptRole.UNKNOWN, NOW),
        lambda: DecodedTranscriptRecord(0, 2, "bad\x00text", TranscriptRole.UNKNOWN, NOW),
        lambda: DecodedTranscriptRecord(
            0,
            2,
            "safe",
            TranscriptRole.UNKNOWN,
            NOW.replace(tzinfo=None),
        ),
    ],
)
def test_decoded_transcript_record_rejects_invalid_ranges_content_and_time(
    record: Callable[[], object],
) -> None:
    with pytest.raises(IngestionValidationError):
        record()


def test_candidate_association_rejects_reverse_window_invalid_session_and_local_time() -> None:
    with pytest.raises(IngestionValidationError, match="invalid_order"):
        CandidateCausalAssociation(SESSION_ID, NOW, NOW - timedelta(microseconds=1))
    with pytest.raises(IngestionValidationError, match="invalid_uuid7"):
        CandidateCausalAssociation("not-a-session", NOW, NOW)
    with pytest.raises(IngestionValidationError, match="not_utc"):
        CandidateCausalAssociation(SESSION_ID, NOW.replace(tzinfo=None), NOW)


def test_transcript_chunk_rejects_invalid_range_and_content_bounds() -> None:
    valid = chunk()
    with pytest.raises(IngestionValidationError, match="byte_range"):
        replace(valid, byte_end=valid.byte_start)
    with pytest.raises(IngestionValidationError, match="content"):
        replace(valid, content="")
    with pytest.raises(IngestionValidationError, match="content"):
        replace(valid, content="x" * 32_769)


def test_file_snapshot_rejects_negative_size_and_invalid_digest() -> None:
    with pytest.raises(IngestionValidationError, match="size_bytes"):
        FileSnapshotEntry("a.txt", DIGEST_A, -1)
    with pytest.raises(IngestionValidationError, match="invalid_digest"):
        FileSnapshotEntry("a.txt", "0" * 64, 1)


def test_git_state_rejects_invalid_commit_and_branch() -> None:
    with pytest.raises(IngestionValidationError, match="commit_sha"):
        GitState("not-a-commit", "main", DIGEST_A)
    with pytest.raises(IngestionValidationError, match="branch_name"):
        GitState("a" * 40, "", DIGEST_A)
    with pytest.raises(IngestionValidationError, match="branch_name"):
        GitState("a" * 40, "bad\x00branch", DIGEST_A)


def test_process_observation_rejects_executable_time_and_exit_code_bounds() -> None:
    observed = ProcessObservation(
        "agent",
        DIGEST_A,
        0,
        DIGEST_B,
        DIGEST_A,
        NOW,
        NOW,
        SourceCompletion.COMPLETE,
        association(),
    )
    with pytest.raises(IngestionValidationError, match="executable"):
        replace(observed, executable="path/agent")
    with pytest.raises(IngestionValidationError, match="invalid_order"):
        replace(observed, ended_at=NOW - timedelta(microseconds=1))
    with pytest.raises(IngestionValidationError, match="out_of_range"):
        replace(observed, exit_code=2**31)


def test_workspace_snapshot_rejects_noncanonical_entries_and_negative_exclusions() -> None:
    first = FileSnapshotEntry("a", DIGEST_A, 1)
    second = FileSnapshotEntry("b", DIGEST_B, 1)
    with pytest.raises(IngestionValidationError, match="not_canonical"):
        WorkspaceSnapshot((second, first), NOW, 0)
    with pytest.raises(IngestionValidationError, match="out_of_range"):
        WorkspaceSnapshot((first,), NOW, -1)


def test_process_execution_result_rejects_unsafe_shape() -> None:
    valid = ProcessExecutionResult(
        "agent",
        DIGEST_A,
        0,
        b"out",
        b"err",
        NOW,
        NOW,
        SourceCompletion.COMPLETE,
    )
    with pytest.raises(IngestionValidationError, match="executable"):
        replace(valid, executable="../agent")
    with pytest.raises(IngestionValidationError, match="too_large"):
        replace(valid, stdout=b"x" * (16 * 1024 * 1024 + 1))
    with pytest.raises(IngestionValidationError, match="invalid_order"):
        replace(valid, ended_at=NOW - timedelta(microseconds=1))
    with pytest.raises(IngestionValidationError, match="exit_code"):
        replace(valid, exit_code=None)


def test_stable_evidence_uuid_rejects_non_digest() -> None:
    with pytest.raises(IngestionValidationError, match="invalid_digest"):
        stable_evidence_uuid7("not-a-digest")
