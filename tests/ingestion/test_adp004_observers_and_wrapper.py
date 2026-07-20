"""ADP-004 production observers and generic process-wrapper end-to-end tests."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.ingestion.adapters.generic_observers import (
    ArgvProcessExecutor,
    LocalFileObserver,
    SubprocessGitObserver,
    WorkspacePrivacyPolicy,
)
from agentmemory.ingestion.adapters.generic_transcript import (
    RegexSensitiveTextRedactor,
    StrictTranscriptDecoder,
)
from agentmemory.ingestion.application.generic_adapter import (
    GENERIC_CHECKPOINT_TOOL,
    CheckpointGenericTaskCommand,
    CheckpointGenericTaskHandler,
    GenericEventFactory,
    GenericProcessWrapper,
    RunGenericProcessCommand,
    diff_git,
    diff_workspace,
)
from agentmemory.ingestion.domain.agent_event import AgentEvent, EventFamily
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.domain.generic_adapter import (
    CandidateCausalAssociation,
    FileChangeKind,
    FileSnapshotEntry,
    GitChangeKind,
    GitState,
    SourceCompletion,
    TranscriptEncoding,
    WorkspaceSnapshot,
)
from tests.ingestion.test_adp004_transcript_and_application import context

if TYPE_CHECKING:
    from pathlib import Path

NOW = datetime(2026, 7, 20, 14, 0, tzinfo=UTC)
CHECKPOINT_ID = "018f0000-0000-7000-8000-000000000222"


class IncrementingClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        current = self.value
        self.value += timedelta(milliseconds=1)
        return current


class RecordingAdapter:
    def __init__(self) -> None:
        self.events: list[AgentEvent] = []
        self._seen: set[str] = set()

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        disposition = (
            AppendDisposition.DUPLICATE
            if event.event_id in self._seen
            else AppendDisposition.ACCEPTED
        )
        self._seen.add(event.event_id)
        self.events.append(event)
        return AppendAgentEventResult(event.event_id, disposition, 1)


@dataclass
class SequenceGitObserver:
    states: list[GitState | None]

    async def observe(self, root: Path) -> GitState | None:
        del root
        return self.states.pop(0)


def _digest(character: str) -> str:
    return character * 64


def _association() -> CandidateCausalAssociation:
    return CandidateCausalAssociation(context().session_id, NOW, NOW + timedelta(seconds=1))


def test_file_observer_excludes_private_ignored_symlink_and_oversized_files(tmp_path: Path) -> None:
    (tmp_path / "visible.txt").write_text("visible", encoding="utf-8")
    (tmp_path / ".env").write_text("TOKEN=never", encoding="utf-8")
    (tmp_path / "ignored").mkdir()
    (tmp_path / "ignored" / "output.txt").write_text("ignored", encoding="utf-8")
    (tmp_path / "large.bin").write_bytes(b"12345")
    (tmp_path / ".agentmemoryignore").write_text("ignored/**\n", encoding="utf-8")
    outside = tmp_path.parent / f"{tmp_path.name}-outside.txt"
    outside.write_text("outside", encoding="utf-8")
    (tmp_path / "outside-link").symlink_to(outside)
    policy = WorkspacePrivacyPolicy.from_workspace(tmp_path)
    policy = replace(policy, maximum_file_bytes=4)

    snapshot = LocalFileObserver(IncrementingClock(), policy).snapshot(tmp_path)

    assert [entry.relative_path for entry in snapshot.entries] == []
    assert snapshot.excluded_count >= 5
    outside.unlink()


def test_file_observer_rejects_a_file_replaced_between_metadata_and_secure_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "visible.txt"
    target.write_bytes(b"one")
    real_open = os.open
    replaced = False

    def replace_before_open(path: os.PathLike[str] | str, flags: int) -> int:
        nonlocal replaced
        if not replaced and os.fspath(path) == os.fspath(target):
            replaced = True
            target.unlink()
            target.write_bytes(b"different")
        return real_open(path, flags)

    monkeypatch.setattr(os, "open", replace_before_open)

    snapshot = LocalFileObserver(IncrementingClock(), WorkspacePrivacyPolicy()).snapshot(tmp_path)

    assert snapshot.entries == ()
    assert snapshot.excluded_count == 1


def test_workspace_diff_detects_change_add_delete_and_unambiguous_rename() -> None:
    previous = WorkspaceSnapshot(
        (
            FileSnapshotEntry("change.txt", _digest("a"), 1),
            FileSnapshotEntry("delete.txt", _digest("b"), 1),
            FileSnapshotEntry("old.txt", _digest("c"), 1),
        ),
        NOW,
        0,
    )
    current = WorkspaceSnapshot(
        (
            FileSnapshotEntry("add.txt", _digest("d"), 1),
            FileSnapshotEntry("change.txt", _digest("e"), 2),
            FileSnapshotEntry("new.txt", _digest("c"), 1),
        ),
        NOW + timedelta(seconds=1),
        0,
    )

    observations = diff_workspace(previous, current, _association())

    assert {item.kind for item in observations} == {
        FileChangeKind.CHANGED,
        FileChangeKind.DELETED,
        FileChangeKind.RENAMED,
    }
    assert len([item for item in observations if item.kind is FileChangeKind.CHANGED]) == 2
    renamed = next(item for item in observations if item.kind is FileChangeKind.RENAMED)
    assert renamed.previous is not None
    assert renamed.previous.relative_path == "old.txt"
    assert renamed.current is not None
    assert renamed.current.relative_path == "new.txt"


def test_git_diff_covers_initial_state_branch_checkout_and_absent_repository() -> None:
    association = _association()
    before = GitState("a" * 40, "main", _digest("a"))
    after = GitState("a" * 40, "feature", _digest("b"))

    assert diff_git(before, None, NOW, association) == ()
    assert [item.kind for item in diff_git(None, before, NOW, association)] == [
        GitChangeKind.COMMIT
    ]
    assert [item.kind for item in diff_git(before, after, NOW, association)] == [
        GitChangeKind.BRANCH,
        GitChangeKind.CHECKOUT,
    ]


@pytest.mark.parametrize(
    ("argv", "timeout_seconds", "code"),
    [
        ((), None, "argv"),
        (("agent", ""), None, "argv"),
        (("agent", "bad\x00argument"), None, "argv"),
        (("agent",), 0, "timeout_seconds"),
        (("agent",), 86_401, "timeout_seconds"),
    ],
)
def test_run_command_rejects_unsafe_argv_and_timeout(
    tmp_path: Path,
    argv: tuple[str, ...],
    timeout_seconds: float | None,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError, match=code):
        RunGenericProcessCommand(
            argv,
            tmp_path,
            None,
            timeout_seconds,
            TranscriptEncoding.UTF8,
            context(),
        )


@pytest.mark.asyncio
async def test_git_observer_uses_real_repository_and_detects_commit(tmp_path: Path) -> None:
    _git_setup(tmp_path)
    observer = SubprocessGitObserver()
    first = await observer.observe(tmp_path)
    assert first is not None
    (tmp_path / "tracked.txt").write_text("second", encoding="utf-8")
    _run_git(tmp_path, "add", "tracked.txt")
    _run_git(tmp_path, "commit", "-m", "second")
    second = await observer.observe(tmp_path)

    assert second is not None
    assert second.commit_sha != first.commit_sha
    changes = diff_git(first, second, NOW, _association())
    assert [change.kind for change in changes] == [GitChangeKind.COMMIT]
    non_repository = tmp_path.parent / f"{tmp_path.name}-not-a-repository"
    non_repository.mkdir()
    assert await observer.observe(non_repository) is None
    non_repository.rmdir()


@pytest.mark.asyncio
@pytest.mark.e2e
async def test_process_wrapper_captures_all_observable_channels_and_redacts_persistence(
    tmp_path: Path,
) -> None:
    (tmp_path / "visible.txt").write_text("before", encoding="utf-8")
    before_git = GitState("a" * 40, "main", _digest("a"))
    after_git = GitState("b" * 40, "main", _digest("a"))
    clock = IncrementingClock()
    adapter = RecordingAdapter()
    wrapper = GenericProcessWrapper(
        ArgvProcessExecutor(clock),
        LocalFileObserver(clock, WorkspacePrivacyPolicy()),
        SequenceGitObserver([before_git, after_git]),
        StrictTranscriptDecoder(),
        RegexSensitiveTextRedactor(),
        adapter,
    )
    program = (
        "import sys;from pathlib import Path;"
        "Path('visible.txt').write_text('after', encoding='utf-8');"
        "Path('.env').write_text('TOKEN=private', encoding='utf-8');"
        "print('token=super-secret-value');"
        "print('token=super-secret-value', file=sys.stderr)"
    )

    result = await wrapper.execute(
        RunGenericProcessCommand(
            (sys.executable, "-c", program),
            tmp_path,
            None,
            10,
            TranscriptEncoding.UTF8,
            context(),
        )
    )

    assert result.execution.exit_code == 0
    assert b"super-secret-value" in result.execution.stdout
    assert result.file_observation_count == 1
    assert result.git_observation_count == 1
    assert result.transcript_event_count == 2
    assert [event.event_type for event in adapter.events] == [
        EventFamily.SESSION_STARTED,
        EventFamily.TRANSCRIPT_CHUNK_OBSERVED,
        EventFamily.TRANSCRIPT_CHUNK_OBSERVED,
        EventFamily.FILE_CHANGED,
        EventFamily.GIT_COMMIT_OBSERVED,
        EventFamily.COMMAND_COMPLETED,
        EventFamily.SESSION_COMPLETED,
    ]
    canonical_payloads = b"".join(
        event.payload.value for event in adapter.events if event.payload is not None
    )
    assert b"super-secret-value" not in canonical_payloads
    assert b"TOKEN=private" not in canonical_payloads
    assert all(event.causation_id is None for event in adapter.events)
    transcripts = [
        event
        for event in adapter.events
        if event.event_type is EventFamily.TRANSCRIPT_CHUNK_OBSERVED
    ]
    assert transcripts[0].event_id != transcripts[1].event_id
    assert {
        json.loads(event.payload.value)["source_channel"]
        for event in transcripts
        if event.payload is not None
    } == {"stdout", "stderr"}


@pytest.mark.asyncio
@pytest.mark.resilience
async def test_process_timeout_is_captured_as_abrupt_termination(tmp_path: Path) -> None:
    clock = IncrementingClock()
    adapter = RecordingAdapter()
    wrapper = GenericProcessWrapper(
        ArgvProcessExecutor(clock, termination_grace_seconds=0.2),
        LocalFileObserver(clock, WorkspacePrivacyPolicy()),
        SequenceGitObserver([None, None]),
        StrictTranscriptDecoder(),
        RegexSensitiveTextRedactor(),
        adapter,
    )

    result = await wrapper.execute(
        RunGenericProcessCommand(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            tmp_path,
            None,
            0.01,
            TranscriptEncoding.UTF8,
            context(),
        )
    )

    assert result.execution.completion is SourceCompletion.ABRUPT
    assert result.execution.exit_code is None
    completed = next(
        event for event in adapter.events if event.event_type is EventFamily.SESSION_COMPLETED
    )
    assert completed.payload is not None
    assert json.loads(completed.payload.value)["source_completion"] == "abrupt"


@pytest.mark.asyncio
async def test_process_executor_tees_output_without_changing_captured_bytes(tmp_path: Path) -> None:
    stdout_sink = io.BytesIO()
    stderr_sink = io.BytesIO()
    executor = ArgvProcessExecutor(
        IncrementingClock(),
        stdout_sink=stdout_sink,
        stderr_sink=stderr_sink,
    )

    result = await executor.execute(
        (
            sys.executable,
            "-c",
            "import sys; print('out'); print('err', file=sys.stderr)",
        ),
        tmp_path,
        None,
        10,
    )

    assert result.stdout == b"out\n"
    assert result.stderr == b"err\n"
    assert stdout_sink.getvalue() == result.stdout
    assert stderr_sink.getvalue() == result.stderr


@pytest.mark.asyncio
async def test_explicit_checkpoint_tool_redacts_and_is_idempotent() -> None:
    adapter = RecordingAdapter()
    handler = CheckpointGenericTaskHandler(RegexSensitiveTextRedactor(), adapter)
    command = CheckpointGenericTaskCommand(
        CHECKPOINT_ID,
        "token=private-value next step",
        context(),
    )

    first = await handler.execute(command)
    second = await handler.execute(command)

    assert GENERIC_CHECKPOINT_TOOL["name"] == "agentmemory_checkpoint"
    assert first.disposition is AppendDisposition.ACCEPTED
    assert second.disposition is AppendDisposition.DUPLICATE
    assert adapter.events[0] == adapter.events[1]
    assert adapter.events[0].event_type is EventFamily.TASK_CHECKPOINTED
    assert adapter.events[0].payload is not None
    assert b"private-value" not in adapter.events[0].payload.value
    assert json.loads(adapter.events[0].payload.value)["turn_provenance"] == "unknown"


@pytest.mark.parametrize(
    ("checkpoint_id", "summary", "code"),
    [
        ("", "safe", "checkpoint_id"),
        ("not-a-uuid", "safe", "checkpoint_id"),
        ("018f0000-0000-4000-8000-000000000222", "safe", "checkpoint_id"),
        (CHECKPOINT_ID, "", "summary"),
        (CHECKPOINT_ID, "bad\x00summary", "summary"),
        (CHECKPOINT_ID, "x" * 32_769, "summary"),
    ],
)
def test_checkpoint_command_rejects_invalid_identity_and_summary(
    checkpoint_id: str,
    summary: str,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError, match=code):
        CheckpointGenericTaskCommand(checkpoint_id, summary, context())


def test_checkpoint_requires_task_scoped_context() -> None:
    taskless = replace(context(), task_id=None)

    with pytest.raises(IngestionValidationError, match="task_id"):
        GenericEventFactory(taskless).checkpoint(
            checkpoint_id=CHECKPOINT_ID,
            summary="safe",
            occurred_at=NOW,
            causal_association=_association(),
        )


def _git_setup(root: Path) -> None:
    _run_git(root, "init")
    _run_git(root, "config", "user.email", "agentmemory@example.invalid")
    _run_git(root, "config", "user.name", "AgentMemory Test")
    (root / "tracked.txt").write_text("first", encoding="utf-8")
    _run_git(root, "add", "tracked.txt")
    _run_git(root, "commit", "-m", "first")


def _run_git(root: Path, *arguments: str) -> None:
    git = shutil.which("git")
    assert git is not None
    subprocess.run(  # noqa: S603 -- test invokes the resolved Git binary with fixed call sites.
        (git, "-C", str(root), *arguments),
        check=True,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env={"LC_ALL": "C", "PATH": os.environ["PATH"]},
    )
