"""Use cases for vendor-neutral hosts without native lifecycle hooks."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.agent_event import (
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    Classification,
    EventFamily,
    required_capability,
)
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
    ProcessExecutionResult,
    ProcessObservation,
    SourceCompletion,
    TranscriptChunk,
    TranscriptEncoding,
    TranscriptFormat,
    TranscriptSource,
    UnavailableLifecycleProvenance,
    WorkspaceSnapshot,
    stable_evidence_uuid7,
    uuid7_occurred_at,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.ingestion.domain.adapter_capability import AdapterCapabilityManifest
    from agentmemory.ingestion.domain.capture import AppendAgentEventResult
    from agentmemory.ingestion.domain.ports import (
        AgentAdapterPort,
        GitObserver,
        ProcessExecutor,
        SensitiveTextRedactor,
        TranscriptDecoder,
        WorkspaceObserver,
    )

_MAX_PROCESS_SECONDS = 86_400
_MAX_CHECKPOINT_SUMMARY_BYTES = 32_768


@dataclass(frozen=True, slots=True)
class GenericAdapterContext:
    """Authenticated session/scope and immutable generic-adapter provenance."""

    identity: AgentEventIdentity
    manifest: AdapterCapabilityManifest
    session_id: str
    task_id: str | None
    correlation_id: str
    ordering_key: str
    classification: Classification
    retention_policy_id: str


@dataclass(frozen=True, slots=True)
class ImportTranscriptCommand:
    """Import one immutable transcript source through the generic adapter."""

    source: bytes
    transcript_format: TranscriptFormat
    encoding: TranscriptEncoding
    completion: SourceCompletion
    source_channel: TranscriptSource
    default_occurred_at: datetime | None
    context: GenericAdapterContext

    def __post_init__(self) -> None:
        """Reject empty/unbounded input and ambient local times."""
        if not self.source or len(self.source) > 16 * 1024 * 1024:
            field = "source"
            raise IngestionValidationError.single(field, "invalid_size")
        if self.default_occurred_at is not None and (
            self.default_occurred_at.tzinfo is None
            or self.default_occurred_at.utcoffset() != UTC.utcoffset(None)
        ):
            field = "default_occurred_at"
            raise IngestionValidationError.single(field, "not_utc")


@dataclass(frozen=True, slots=True)
class TranscriptImportResult:
    """Content-free import receipt with per-event durable outcomes."""

    source_sha256: str
    event_ids: tuple[str, ...]
    results: tuple[AppendAgentEventResult, ...]


@dataclass(frozen=True, slots=True)
class GenericEventFactory:
    """Translate generic observations without host-name or vendor conditionals."""

    context: GenericAdapterContext

    def transcript(self, chunk: TranscriptChunk) -> AgentEvent:
        """Create one redacted transcript artifact observation."""
        return self._event(
            event_id=chunk.event_id,
            family=EventFamily.TRANSCRIPT_CHUNK_OBSERVED,
            subject=f"session/{self.context.session_id}/transcript/{chunk.chunk_sha256}",
            occurred_at=chunk.occurred_at,
            source_sha256=chunk.chunk_sha256,
            payload=chunk.payload_bytes(),
            task_id=self.context.task_id,
        )

    def file(self, observation: FileObservation) -> AgentEvent:
        """Create one content-free filesystem delta event."""
        family = {
            FileChangeKind.CHANGED: EventFamily.FILE_CHANGED,
            FileChangeKind.DELETED: EventFamily.FILE_DELETED,
            FileChangeKind.RENAMED: EventFamily.FILE_RENAMED,
        }[observation.kind]
        entry = observation.current or observation.previous
        if entry is None:  # pragma: no cover - domain shape invariant.
            raise AssertionError
        return self._event(
            event_id=observation.event_id,
            family=family,
            subject=f"repository/{self.context.identity.repository_id}/file/{entry.relative_path}",
            occurred_at=observation.occurred_at,
            source_sha256=observation.evidence_sha256,
            payload=observation.payload_bytes(),
            task_id=self.context.task_id,
        )

    def git(self, observation: GitObservation) -> AgentEvent:
        """Create one Git state transition event."""
        family = {
            GitChangeKind.COMMIT: EventFamily.GIT_COMMIT_OBSERVED,
            GitChangeKind.BRANCH: EventFamily.BRANCH_CHANGED,
            GitChangeKind.CHECKOUT: EventFamily.CHECKOUT_CHANGED,
        }[observation.kind]
        return self._event(
            event_id=observation.event_id,
            family=family,
            subject=f"repository/{self.context.identity.repository_id}/git",
            occurred_at=observation.occurred_at,
            source_sha256=observation.evidence_sha256,
            payload=observation.payload_bytes(),
            task_id=self.context.task_id,
        )

    def process(self, observation: ProcessObservation) -> AgentEvent:
        """Create one content-free command completion event."""
        return self._event(
            event_id=observation.event_id,
            family=EventFamily.COMMAND_COMPLETED,
            subject=f"session/{self.context.session_id}/process/{observation.evidence_sha256}",
            occurred_at=observation.ended_at,
            source_sha256=observation.evidence_sha256,
            payload=observation.payload_bytes(),
            task_id=self.context.task_id,
        )

    def checkpoint(
        self,
        *,
        checkpoint_id: str,
        summary: str,
        occurred_at: datetime,
        causal_association: CandidateCausalAssociation,
    ) -> AgentEvent:
        """Create one user/agent-explicit checkpoint without inferred lifecycle facts."""
        if self.context.task_id is None:
            field = "task_id"
            raise IngestionValidationError.single(field, "required")
        source_sha256 = _framed_digest(
            "agentmemory-explicit-checkpoint-v1",
            checkpoint_id,
            self.context.task_id,
        )
        payload = _canonical_payload(
            {
                "causal_association": causal_association.as_document(),
                "checkpoint_id": checkpoint_id,
                "summary": summary,
                **UnavailableLifecycleProvenance().as_document(),
            }
        )
        return self._event(
            event_id=stable_evidence_uuid7(source_sha256),
            family=EventFamily.TASK_CHECKPOINTED,
            subject=f"task/{self.context.task_id}",
            occurred_at=occurred_at,
            source_sha256=source_sha256,
            payload=payload,
            task_id=self.context.task_id,
        )

    def session(
        self,
        *,
        started: bool,
        occurred_at: datetime,
        source_sha256: str,
        completion: SourceCompletion,
    ) -> AgentEvent:
        """Create inferred wrapper session boundary evidence."""
        family = EventFamily.SESSION_STARTED if started else EventFamily.SESSION_COMPLETED
        event_sha256 = _framed_digest(family.value, source_sha256, self.context.session_id)
        payload = _canonical_payload(
            {
                "source_completion": completion.value,
                **UnavailableLifecycleProvenance().as_document(),
            }
        )
        return self._event(
            event_id=stable_evidence_uuid7(event_sha256),
            family=family,
            subject=f"session/{self.context.session_id}",
            occurred_at=occurred_at,
            source_sha256=event_sha256,
            payload=payload,
            task_id=self.context.task_id,
        )

    def _event(  # noqa: PLR0913 -- canonical evidence fields are deliberately explicit.
        self,
        *,
        event_id: str,
        family: EventFamily,
        subject: str,
        occurred_at: datetime,
        source_sha256: str,
        payload: bytes,
        task_id: str | None,
    ) -> AgentEvent:
        manifest = self.context.manifest
        capability = required_capability(family)
        availability = manifest.availability_for(capability)
        if family not in manifest.supported_families or not availability.observable:
            msg = "generic observation exceeds declared adapter capabilities"
            raise IngestionAuthorizationError(msg)
        provenance = AgentEventProvenance(
            agent_host="generic",
            adapter_id=manifest.adapter_id,
            adapter_version=manifest.adapter_version,
            adapter_digest=manifest.adapter_digest,
            model_id="unknown",
            session_id=self.context.session_id,
            task_id=task_id,
            turn_id=None,
            subagent_id=None,
            capability_manifest_digest=manifest.manifest_sha256,
            capture_method=availability.status,
            source_sha256=source_sha256,
        )
        data = AgentEventData(payload, hashlib.sha256(payload).hexdigest())
        return AgentEvent.create(
            specversion="1.0",
            event_id=event_id,
            source=f"urn:agentmemory:adapter:{manifest.adapter_id}",
            event_type=family,
            subject=subject,
            occurred_at=occurred_at,
            datacontenttype="application/json",
            dataschema=family.dataschema,
            identity=self.context.identity,
            provenance=provenance,
            correlation_id=self.context.correlation_id,
            causation_id=None,
            ordering_key=self.context.ordering_key,
            sequence=None,
            classification=self.context.classification,
            retention_policy_id=self.context.retention_policy_id,
            capture_capabilities=(capability,),
            payload=data,
            payload_reference=None,
        )


@dataclass(frozen=True, slots=True)
class TranscriptImporter:
    """Decode, redact, translate, and durably capture transcript chunks."""

    decoder: TranscriptDecoder
    redactor: SensitiveTextRedactor
    adapter: AgentAdapterPort

    async def execute(self, command: ImportTranscriptCommand) -> TranscriptImportResult:
        """Import every source range idempotently without persisting unredacted text."""
        source_sha256 = hashlib.sha256(command.source).hexdigest()
        records = self.decoder.decode(
            command.source,
            command.transcript_format,
            command.encoding,
            command.default_occurred_at or uuid7_occurred_at(command.context.session_id),
        )
        association = CandidateCausalAssociation(
            command.context.session_id,
            min(record.occurred_at for record in records),
            max(record.occurred_at for record in records),
        )
        factory = GenericEventFactory(command.context)
        events = tuple(
            factory.transcript(
                TranscriptChunk(
                    source_sha256,
                    command.source_channel,
                    record.byte_start,
                    record.byte_end,
                    self.redactor.redact(record.content),
                    record.observed_role,
                    record.occurred_at,
                    command.completion,
                    UnavailableLifecycleProvenance(),
                    association,
                )
            )
            for record in records
        )
        results = tuple([await self.adapter.execute(event) for event in events])
        return TranscriptImportResult(
            source_sha256,
            tuple(event.event_id for event in events),
            results,
        )


@dataclass(frozen=True, slots=True)
class RunGenericProcessCommand:
    """Run one hookless agent command in an exact workspace."""

    argv: tuple[str, ...]
    cwd: Path
    stdin: bytes | None
    timeout_seconds: float | None
    transcript_encoding: TranscriptEncoding
    context: GenericAdapterContext

    def __post_init__(self) -> None:
        """Reject shell strings, invalid bounds, and missing executable vectors."""
        if not self.argv or any(not value or "\x00" in value for value in self.argv):
            field = "argv"
            raise IngestionValidationError.single(field, "invalid")
        if (
            self.timeout_seconds is not None
            and not 0 < self.timeout_seconds <= _MAX_PROCESS_SECONDS
        ):
            field = "timeout_seconds"
            raise IngestionValidationError.single(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class GenericProcessRunResult:
    """Child output plus content-free durable capture acknowledgements."""

    execution: ProcessExecutionResult
    acknowledgements: tuple[AppendAgentEventResult, ...]
    file_observation_count: int
    git_observation_count: int
    transcript_event_count: int


@dataclass(frozen=True, slots=True)
class GenericProcessWrapper:
    """Capture process, transcript, file, Git, and session evidence for hookless hosts."""

    process_executor: ProcessExecutor
    file_observer: WorkspaceObserver
    git_observer: GitObserver
    transcript_decoder: TranscriptDecoder
    redactor: SensitiveTextRedactor
    adapter: AgentAdapterPort

    async def execute(self, command: RunGenericProcessCommand) -> GenericProcessRunResult:
        """Run an argv vector and capture every directly observable channel."""
        before_files = self.file_observer.snapshot(command.cwd)
        before_git = await self.git_observer.observe(command.cwd)
        command_sha256 = _framed_digest("agentmemory-process-argv-v1", *command.argv)
        factory = GenericEventFactory(command.context)
        acknowledgements: list[AppendAgentEventResult] = []
        started = factory.session(
            started=True,
            occurred_at=before_files.observed_at,
            source_sha256=command_sha256,
            completion=SourceCompletion.COMPLETE,
        )
        acknowledgements.append(await self.adapter.execute(started))
        execution = await self.process_executor.execute(
            command.argv,
            command.cwd,
            command.stdin,
            command.timeout_seconds,
        )
        after_files = self.file_observer.snapshot(command.cwd)
        after_git = await self.git_observer.observe(command.cwd)
        association = CandidateCausalAssociation(
            command.context.session_id,
            execution.started_at,
            execution.ended_at,
        )
        transcript_count = 0
        importer = TranscriptImporter(self.transcript_decoder, self.redactor, self.adapter)
        for source_channel, output in (
            (TranscriptSource.STDOUT, execution.stdout),
            (TranscriptSource.STDERR, execution.stderr),
        ):
            if not output:
                continue
            imported = await importer.execute(
                ImportTranscriptCommand(
                    output,
                    TranscriptFormat.PLAIN_TEXT,
                    command.transcript_encoding,
                    execution.completion,
                    source_channel,
                    execution.ended_at,
                    command.context,
                )
            )
            acknowledgements.extend(imported.results)
            transcript_count += len(imported.event_ids)
        file_observations = diff_workspace(before_files, after_files, association)
        acknowledgements.extend(
            [
                await self.adapter.execute(factory.file(observation))
                for observation in file_observations
            ]
        )
        git_observations = diff_git(before_git, after_git, execution.ended_at, association)
        acknowledgements.extend(
            [
                await self.adapter.execute(factory.git(observation))
                for observation in git_observations
            ]
        )
        acknowledgements.append(
            await self.adapter.execute(factory.process(execution.observation(association)))
        )
        completed = factory.session(
            started=False,
            occurred_at=execution.ended_at,
            source_sha256=execution.observation(association).evidence_sha256,
            completion=execution.completion,
        )
        acknowledgements.append(await self.adapter.execute(completed))
        return GenericProcessRunResult(
            execution,
            tuple(acknowledgements),
            len(file_observations),
            len(git_observations),
            transcript_count,
        )


@dataclass(frozen=True, slots=True)
class CheckpointGenericTaskCommand:
    """Record one explicit hookless-host task checkpoint."""

    checkpoint_id: str
    summary: str
    context: GenericAdapterContext

    def __post_init__(self) -> None:
        """Require bounded opaque identity and summary text."""
        try:
            uuid7_occurred_at(self.checkpoint_id)
        except IngestionValidationError as error:
            field = "checkpoint_id"
            raise IngestionValidationError.single(field, "invalid_uuid7") from error
        if (
            not self.summary
            or len(self.summary.encode()) > _MAX_CHECKPOINT_SUMMARY_BYTES
            or "\x00" in self.summary
        ):
            field = "summary"
            raise IngestionValidationError.single(field, "invalid")


@dataclass(frozen=True, slots=True)
class CheckpointGenericTaskHandler:
    """Redact and capture an explicit checkpoint through AgentAdapterPort."""

    redactor: SensitiveTextRedactor
    adapter: AgentAdapterPort

    async def execute(self, command: CheckpointGenericTaskCommand) -> AppendAgentEventResult:
        """Persist one explicit-tool-only checkpoint with unknown hidden provenance."""
        occurred_at = uuid7_occurred_at(command.checkpoint_id)
        association = CandidateCausalAssociation(
            command.context.session_id,
            occurred_at,
            occurred_at,
        )
        event = GenericEventFactory(command.context).checkpoint(
            checkpoint_id=command.checkpoint_id,
            summary=self.redactor.redact(command.summary),
            occurred_at=occurred_at,
            causal_association=association,
        )
        return await self.adapter.execute(event)


GENERIC_CHECKPOINT_TOOL: dict[str, object] = {
    "annotations": {
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
        "readOnlyHint": False,
    },
    "description": (
        "Persist a redacted explicit task checkpoint for a hookless agent host. "
        "checkpoint_id must be a client-generated UUIDv7 and reused unchanged for retries."
    ),
    "inputSchema": {
        "additionalProperties": False,
        "properties": {
            "checkpoint_id": {"format": "uuid", "type": "string"},
            "summary": {"maxLength": 32768, "minLength": 1, "type": "string"},
        },
        "required": ["checkpoint_id", "summary"],
        "type": "object",
    },
    "name": "agentmemory_checkpoint",
    "outputSchema": {
        "additionalProperties": False,
        "properties": {
            "event_id": {"type": "string"},
            "status": {"enum": ["accepted", "duplicate"], "type": "string"},
        },
        "required": ["event_id", "status"],
        "type": "object",
    },
}


def diff_workspace(
    previous: WorkspaceSnapshot,
    current: WorkspaceSnapshot,
    association: CandidateCausalAssociation,
) -> tuple[FileObservation, ...]:
    """Return deterministic add/change/delete/rename evidence between snapshots."""
    before = {entry.relative_path: entry for entry in previous.entries}
    after = {entry.relative_path: entry for entry in current.entries}
    deleted = {path: entry for path, entry in before.items() if path not in after}
    added = {path: entry for path, entry in after.items() if path not in before}
    observations: list[FileObservation] = []
    deleted_by_digest = _unique_by_digest(deleted)
    added_by_digest = _unique_by_digest(added)
    for digest in sorted(set(deleted_by_digest) & set(added_by_digest)):
        old_path, old_entry = deleted_by_digest[digest]
        new_path, new_entry = added_by_digest[digest]
        observations.append(
            FileObservation(
                FileChangeKind.RENAMED,
                new_entry,
                old_entry,
                current.observed_at,
                association,
            )
        )
        del deleted[old_path]
        del added[new_path]
    observations.extend(
        FileObservation(
            FileChangeKind.CHANGED,
            after[path],
            before[path],
            current.observed_at,
            association,
        )
        for path in sorted(set(before) & set(after))
        if before[path] != after[path]
    )
    observations.extend(
        FileObservation(
            FileChangeKind.CHANGED,
            added[path],
            None,
            current.observed_at,
            association,
        )
        for path in sorted(added)
    )
    observations.extend(
        FileObservation(
            FileChangeKind.DELETED,
            None,
            deleted[path],
            current.observed_at,
            association,
        )
        for path in sorted(deleted)
    )
    return tuple(
        sorted(
            observations,
            key=lambda item: (item.kind.value, _observation_path(item)),
        )
    )


def diff_git(
    previous: GitState | None,
    current: GitState | None,
    occurred_at: datetime,
    association: CandidateCausalAssociation,
) -> tuple[GitObservation, ...]:
    """Return observable Git transitions in deterministic family order."""
    if current is None:
        return ()
    observations: list[GitObservation] = []
    if previous is None or previous.commit_sha != current.commit_sha:
        observations.append(
            GitObservation(GitChangeKind.COMMIT, previous, current, occurred_at, association)
        )
    if previous is not None and previous.branch_name != current.branch_name:
        observations.append(
            GitObservation(GitChangeKind.BRANCH, previous, current, occurred_at, association)
        )
    if previous is not None and previous.checkout_fingerprint != current.checkout_fingerprint:
        observations.append(
            GitObservation(GitChangeKind.CHECKOUT, previous, current, occurred_at, association)
        )
    return tuple(observations)


def _unique_by_digest(
    entries: dict[str, FileSnapshotEntry],
) -> dict[str, tuple[str, FileSnapshotEntry]]:
    counts: dict[str, int] = {}
    for entry in entries.values():
        counts[entry.content_sha256] = counts.get(entry.content_sha256, 0) + 1
    return {
        entry.content_sha256: (path, entry)
        for path, entry in entries.items()
        if counts[entry.content_sha256] == 1
    }


def _observation_path(observation: FileObservation) -> str:
    entry = observation.current or observation.previous
    return "" if entry is None else entry.relative_path


def _framed_digest(namespace: str, *parts: str) -> str:
    framed = bytearray()
    for part in (namespace, *parts):
        encoded = part.encode()
        framed.extend(len(encoded).to_bytes(8, "big"))
        framed.extend(encoded)
    return hashlib.sha256(framed).hexdigest()


def _canonical_payload(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
