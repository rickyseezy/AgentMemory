"""ADP-004 transcript decoding, redaction, and generic application use cases."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from agentmemory.ingestion.adapters.generic_manifest import build_generic_adapter_manifest
from agentmemory.ingestion.adapters.generic_transcript import (
    RegexSensitiveTextRedactor,
    StrictTranscriptDecoder,
)
from agentmemory.ingestion.application.generic_adapter import (
    GenericAdapterContext,
    GenericEventFactory,
    ImportTranscriptCommand,
    TranscriptImporter,
)
from agentmemory.ingestion.domain.agent_event import (
    AgentEvent,
    AgentEventIdentity,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
)
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.generic_adapter import (
    CandidateCausalAssociation,
    FileChangeKind,
    FileObservation,
    FileSnapshotEntry,
    GitChangeKind,
    GitObservation,
    GitState,
    ProcessObservation,
    SourceCompletion,
    TranscriptEncoding,
    TranscriptFormat,
    TranscriptSource,
)
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    CORRELATION_ID,
    DIGEST,
    NOW,
    ORDERING_KEY,
    PRINCIPAL_ID,
    PROJECT_ID,
    REPOSITORY_ID,
    SESSION_ID,
)

TASK_ID = "018f0000-0000-7000-8000-000000000211"


class RecordingAdapter:
    def __init__(self) -> None:
        self.events: list[AgentEvent] = []
        self._seen: set[str] = set()

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        self.events.append(event)
        disposition = (
            AppendDisposition.DUPLICATE
            if event.event_id in self._seen
            else AppendDisposition.ACCEPTED
        )
        self._seen.add(event.event_id)
        return AppendAgentEventResult(event.event_id, disposition, 1)


def context() -> GenericAdapterContext:
    return GenericAdapterContext(
        AgentEventIdentity(
            BRAIN_ID,
            PRINCIPAL_ID,
            PROJECT_ID,
            REPOSITORY_ID,
            None,
            "main",
            "a" * 40,
        ),
        build_generic_adapter_manifest(adapter_version="1.0.0", adapter_digest=DIGEST),
        SESSION_ID,
        TASK_ID,
        CORRELATION_ID,
        ORDERING_KEY,
        Classification.LOCAL_ONLY,
        "default",
    )


@pytest.mark.parametrize("source", [b"", b"x" * (16 * 1024 * 1024 + 1)])
def test_transcript_import_command_rejects_empty_or_unbounded_sources(source: bytes) -> None:
    with pytest.raises(IngestionValidationError, match="invalid_size"):
        ImportTranscriptCommand(
            source,
            TranscriptFormat.PLAIN_TEXT,
            TranscriptEncoding.UTF8,
            SourceCompletion.COMPLETE,
            TranscriptSource.IMPORT,
            NOW,
            context(),
        )


def test_transcript_import_command_rejects_local_default_occurrence_time() -> None:
    with pytest.raises(IngestionValidationError, match="not_utc"):
        ImportTranscriptCommand(
            b"safe",
            TranscriptFormat.PLAIN_TEXT,
            TranscriptEncoding.UTF8,
            SourceCompletion.COMPLETE,
            TranscriptSource.IMPORT,
            NOW.replace(tzinfo=None),
            context(),
        )


@pytest.mark.parametrize(
    ("encoding", "source", "expected_start"),
    [
        (TranscriptEncoding.UTF8, b"hello\nworld", 0),
        (TranscriptEncoding.UTF8_BOM, b"\xef\xbb\xbfhello\nworld", 3),
        (TranscriptEncoding.UTF16_LE, b"\xff\xfe" + "hello\nworld".encode("utf-16-le"), 2),
        (TranscriptEncoding.UTF16_BE, b"\xfe\xff" + "hello\nworld".encode("utf-16-be"), 2),
    ],
)
def test_plain_transcript_formats_and_encodings_have_original_byte_offsets(
    encoding: TranscriptEncoding,
    source: bytes,
    expected_start: int,
) -> None:
    records = StrictTranscriptDecoder().decode(source, TranscriptFormat.PLAIN_TEXT, encoding, NOW)

    assert [record.content for record in records] == ["hello", "world"]
    assert records[0].byte_start == expected_start
    assert records[-1].byte_end == len(source)


def test_json_lines_and_array_preserve_explicit_role_and_utc_timestamp() -> None:
    json_lines = (
        b'{"content":"hello","role":"user","timestamp":"2026-07-20T10:12:13Z"}\n'
        b'{"content":"done","role":"assistant"}'
    )
    array = b'[{"role":"system","content":"rules"},{"role":"tool","content":"output"}]'
    decoder = StrictTranscriptDecoder()

    line_records = decoder.decode(
        json_lines,
        TranscriptFormat.JSON_LINES,
        TranscriptEncoding.UTF8,
        NOW,
    )
    array_records = decoder.decode(
        array,
        TranscriptFormat.JSON_ARRAY,
        TranscriptEncoding.UTF8,
        NOW,
    )

    assert line_records[0].observed_role.value == "user"
    assert line_records[0].occurred_at == datetime(2026, 7, 20, 10, 12, 13, tzinfo=UTC)
    assert line_records[1].occurred_at == NOW
    assert [item.observed_role.value for item in array_records] == ["system", "tool"]
    assert array_records[0].byte_start == 1
    assert array_records[-1].byte_end == len(array) - 1


@pytest.mark.parametrize(
    ("source", "encoding", "code"),
    [
        (b"\xef\xbb\xbfhello", TranscriptEncoding.UTF8, "bom_mismatch"),
        (b"hello", TranscriptEncoding.UTF8_BOM, "bom_required"),
        (b"\xff", TranscriptEncoding.UTF8, "invalid_bytes"),
    ],
)
def test_decoder_refuses_encoding_guessing(
    source: bytes,
    encoding: TranscriptEncoding,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError, match=code):
        StrictTranscriptDecoder().decode(source, TranscriptFormat.PLAIN_TEXT, encoding, NOW)


def test_decoder_rejects_hidden_reasoning_fields_in_structured_transcripts() -> None:
    source = b'{"content":"safe","hidden_reasoning":"never persist"}\n'

    with pytest.raises(IngestionValidationError, match="unsafe_record"):
        StrictTranscriptDecoder().decode(
            source,
            TranscriptFormat.JSON_LINES,
            TranscriptEncoding.UTF8,
            NOW,
        )


@pytest.mark.parametrize(
    ("source", "transcript_format", "code"),
    [
        (b"\n\r\n", TranscriptFormat.PLAIN_TEXT, "no_records"),
        (b"{}", TranscriptFormat.JSON_ARRAY, "json_array_required"),
        (b"[invalid]", TranscriptFormat.JSON_ARRAY, "invalid_json"),
        (b'[{"content":"safe"}', TranscriptFormat.JSON_ARRAY, "invalid_json_array"),
        (b'[{"content":"safe"}] trailing', TranscriptFormat.JSON_ARRAY, "trailing_data"),
        (b"not-json\n", TranscriptFormat.JSON_LINES, "invalid_json"),
        (b"42\n", TranscriptFormat.JSON_LINES, "unsafe_record"),
        (b'{"content":42}\n', TranscriptFormat.JSON_LINES, "invalid_record"),
        (b'{"content":"safe","role":42}\n', TranscriptFormat.JSON_LINES, "invalid_record"),
        (b'{"content":"safe","role":"invented"}\n', TranscriptFormat.JSON_LINES, "unsupported"),
        (b'{"content":"safe","timestamp":42}\n', TranscriptFormat.JSON_LINES, "invalid"),
        (
            b'{"content":"safe","timestamp":"not-a-time"}\n',
            TranscriptFormat.JSON_LINES,
            "invalid",
        ),
        (
            b'{"content":"safe","timestamp":"2026-07-20T12:00:00"}\n',
            TranscriptFormat.JSON_LINES,
            "not_utc",
        ),
        (
            b'{"content":"safe","metadata":[{"scratchpad":"private"}]}\n',
            TranscriptFormat.JSON_LINES,
            "unsafe_record",
        ),
        (b'{"content":""}\n', TranscriptFormat.JSON_LINES, "invalid_size"),
    ],
)
def test_decoder_fails_closed_for_malformed_or_unsafe_structured_sources(
    source: bytes,
    transcript_format: TranscriptFormat,
    code: str,
) -> None:
    with pytest.raises(IngestionValidationError, match=code):
        StrictTranscriptDecoder().decode(
            source,
            transcript_format,
            TranscriptEncoding.UTF8,
            NOW,
        )


def test_decoder_rejects_oversized_records() -> None:
    source = ("x" * 32_769).encode()

    with pytest.raises(IngestionValidationError, match="invalid_size"):
        StrictTranscriptDecoder().decode(
            source,
            TranscriptFormat.PLAIN_TEXT,
            TranscriptEncoding.UTF8,
            NOW,
        )


@pytest.mark.parametrize(
    "patterns",
    [
        tuple("x" for _ in range(33)),
        ("",),
        ("x" * 513,),
        ("[",),
    ],
)
def test_redactor_rejects_unbounded_or_invalid_custom_patterns(
    patterns: tuple[str, ...],
) -> None:
    with pytest.raises((ValueError, re.error)):
        RegexSensitiveTextRedactor(patterns)


def test_redactor_removes_well_known_and_configured_secrets_idempotently() -> None:
    source = (
        "api_key=sk-abcdefghijklmnopqrstuvwxyz "
        "Authorization: Bearer abcdefghijklmnop "
        "ghp_abcdefghijklmnopqrstuvwxyz secret-customer-42"
    )
    redactor = RegexSensitiveTextRedactor((r"secret-customer-[0-9]+",))

    redacted = redactor.redact(source)

    assert "sk-abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "abcdefghijklmnop" not in redacted
    assert "ghp_abcdefghijklmnopqrstuvwxyz" not in redacted
    assert "secret-customer-42" not in redacted
    assert redactor.redact(redacted) == redacted


@pytest.mark.asyncio
async def test_reimporting_same_transcript_is_idempotent_and_never_persists_secret() -> None:
    source = b'{"role":"user","content":"token=secret-value"}\n'
    adapter = RecordingAdapter()
    importer = TranscriptImporter(
        StrictTranscriptDecoder(),
        RegexSensitiveTextRedactor(),
        adapter,
    )
    command = ImportTranscriptCommand(
        source,
        TranscriptFormat.JSON_LINES,
        TranscriptEncoding.UTF8,
        SourceCompletion.COMPLETE,
        TranscriptSource.IMPORT,
        None,
        context(),
    )

    first = await importer.execute(command)
    second = await importer.execute(command)

    assert first.event_ids == second.event_ids
    assert adapter.events[0] == adapter.events[1]
    assert [result.disposition for result in first.results] == [AppendDisposition.ACCEPTED]
    assert [result.disposition for result in second.results] == [AppendDisposition.DUPLICATE]
    assert adapter.events[0].event_type is EventFamily.TRANSCRIPT_CHUNK_OBSERVED
    assert adapter.events[0].provenance.model_id == "unknown"
    assert adapter.events[0].provenance.turn_id is None
    assert adapter.events[0].provenance.capture_method is CaptureMethod.INFERRED
    payload = adapter.events[0].payload
    assert payload is not None
    assert b"secret-value" not in payload.value
    assert json.loads(payload.value)["prompt_provenance"] == "unknown"


def test_generic_manifest_is_honest_about_hookless_lifecycle_gaps() -> None:
    manifest = context().manifest

    unsupported = (
        CaptureCapability.PROMPT_CONTENT,
        CaptureCapability.TURN_LIFECYCLE,
        CaptureCapability.TOOL_LIFECYCLE,
    )
    assert all(
        manifest.availability_for(capability).status is CaptureMethod.UNSUPPORTED
        for capability in unsupported
    )
    assert (
        manifest.availability_for(CaptureCapability.TASK_LIFECYCLE).status
        is CaptureMethod.EXPLICIT_TOOL_ONLY
    )
    assert EventFamily.PROMPT_RECEIVED not in manifest.supported_families


def test_factory_maps_file_git_process_and_checkpoint_to_existing_capabilities() -> None:
    factory = GenericEventFactory(context())
    association = CandidateCausalAssociation(SESSION_ID, NOW, NOW + timedelta(seconds=1))
    before_file = FileSnapshotEntry("old.txt", hashlib.sha256(b"same").hexdigest(), 4)
    after_file = FileSnapshotEntry("new.txt", before_file.content_sha256, 4)
    before_git = GitState("a" * 40, "main", hashlib.sha256(b"checkout").hexdigest())
    after_git = replace(before_git, commit_sha="b" * 40)
    process = ProcessObservation(
        "agent",
        hashlib.sha256(b"argv").hexdigest(),
        0,
        hashlib.sha256(b"stdout").hexdigest(),
        hashlib.sha256(b"stderr").hexdigest(),
        NOW,
        NOW + timedelta(seconds=1),
        SourceCompletion.COMPLETE,
        association,
    )

    events = [
        factory.file(
            FileObservation(FileChangeKind.RENAMED, after_file, before_file, NOW, association)
        ),
        factory.git(GitObservation(GitChangeKind.COMMIT, before_git, after_git, NOW, association)),
        factory.process(process),
        factory.checkpoint(
            checkpoint_id="checkpoint-1",
            summary="safe summary",
            occurred_at=NOW,
            causal_association=association,
        ),
    ]

    assert [event.event_type for event in events] == [
        EventFamily.FILE_RENAMED,
        EventFamily.GIT_COMMIT_OBSERVED,
        EventFamily.COMMAND_COMPLETED,
        EventFamily.TASK_CHECKPOINTED,
    ]
    assert [event.provenance.capture_method for event in events] == [
        CaptureMethod.INFERRED,
        CaptureMethod.INFERRED,
        CaptureMethod.INFERRED,
        CaptureMethod.EXPLICIT_TOOL_ONLY,
    ]
    assert all(event.causation_id is None for event in events)


@pytest.mark.asyncio
async def test_factory_rejects_evidence_not_declared_by_manifest() -> None:
    manifest = build_generic_adapter_manifest(adapter_version="1.0.0", adapter_digest=DIGEST)
    unavailable = replace(
        manifest,
        supported_families=tuple(
            family
            for family in manifest.supported_families
            if family is not EventFamily.TRANSCRIPT_CHUNK_OBSERVED
        ),
    )
    adapter = RecordingAdapter()
    importer = TranscriptImporter(StrictTranscriptDecoder(), RegexSensitiveTextRedactor(), adapter)
    command = ImportTranscriptCommand(
        b"hello",
        TranscriptFormat.PLAIN_TEXT,
        TranscriptEncoding.UTF8,
        SourceCompletion.COMPLETE,
        TranscriptSource.IMPORT,
        NOW,
        replace(context(), manifest=unavailable),
    )

    with pytest.raises(IngestionAuthorizationError):
        await importer.execute(command)
    assert not adapter.events
