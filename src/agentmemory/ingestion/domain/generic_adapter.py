"""Vendor-neutral evidence model for hosts without lifecycle hooks."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from uuid import UUID

from agentmemory.ingestion.domain.errors import IngestionValidationError

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UUID_VERSION = 7
_MAX_TRANSCRIPT_CHUNK_BYTES = 32_768
_MAX_PATH_BYTES = 4_096
_MAX_LABEL = 256


class KnowledgeStatus(StrEnum):
    """Whether lifecycle provenance is actually available to the generic adapter."""

    UNKNOWN = "unknown"


class CausalAssociationKind(StrEnum):
    """Strength of a relationship emitted by an observer."""

    CANDIDATE = "candidate"
    AUTHORITATIVE = "authoritative"


class CausalAssociationBasis(StrEnum):
    """Observable basis for a non-authoritative relationship."""

    SESSION_TIME_WINDOW = "session_time_window"


class SourceCompletion(StrEnum):
    """Whether the evidence source ended normally or was interrupted."""

    COMPLETE = "complete"
    ABRUPT = "abrupt"


class TranscriptFormat(StrEnum):
    """Closed transcript formats supported by the importer."""

    PLAIN_TEXT = "plain_text"
    JSON_LINES = "json_lines"
    JSON_ARRAY = "json_array"


class TranscriptEncoding(StrEnum):
    """Closed, deterministic transcript encodings."""

    UTF8 = "utf-8"
    UTF8_BOM = "utf-8-sig"
    UTF16_LE = "utf-16-le"
    UTF16_BE = "utf-16-be"


class TranscriptRole(StrEnum):
    """A role label explicitly present in source material, never an inferred lifecycle fact."""

    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class TranscriptSource(StrEnum):
    """Observable channel that supplied transcript bytes."""

    IMPORT = "import"
    STDERR = "stderr"
    STDOUT = "stdout"


class FileChangeKind(StrEnum):
    """Observable workspace delta type."""

    CHANGED = "changed"
    DELETED = "deleted"
    RENAMED = "renamed"


class GitChangeKind(StrEnum):
    """Observable Git state transition."""

    COMMIT = "commit"
    BRANCH = "branch"
    CHECKOUT = "checkout"


@dataclass(frozen=True, slots=True)
class DecodedTranscriptRecord:
    """One explicit transcript record and its original source byte range."""

    byte_start: int
    byte_end: int
    content: str
    observed_role: TranscriptRole
    occurred_at: datetime

    def __post_init__(self) -> None:
        """Require stable nonempty ranges and UTC occurrence time."""
        if self.byte_start < 0 or self.byte_end <= self.byte_start:
            field = "byte_range"
            raise _validation(field, "invalid")
        if not self.content or "\x00" in self.content:
            field = "content"
            raise _validation(field, "invalid")
        _require_utc(self.occurred_at, "occurred_at")


@dataclass(frozen=True, slots=True)
class UnavailableLifecycleProvenance:
    """Explicit unknown labels for signals a hookless host cannot expose."""

    prompt: KnowledgeStatus = KnowledgeStatus.UNKNOWN
    turn: KnowledgeStatus = KnowledgeStatus.UNKNOWN
    tool: KnowledgeStatus = KnowledgeStatus.UNKNOWN

    def __post_init__(self) -> None:
        """Fail closed if a caller attempts to fabricate lifecycle knowledge."""
        values = (self.prompt, self.turn, self.tool)
        if any(value is not KnowledgeStatus.UNKNOWN for value in values):
            field = "lifecycle_provenance"
            raise _validation(
                field,
                "generic_lifecycle_provenance_must_remain_unknown",
            )

    def as_document(self) -> dict[str, str]:
        """Return the canonical explicit-unknown representation."""
        return {
            "prompt_provenance": self.prompt.value,
            "tool_provenance": self.tool.value,
            "turn_provenance": self.turn.value,
        }


@dataclass(frozen=True, slots=True)
class CandidateCausalAssociation:
    """Time/session correlation that never claims authoritative causation."""

    session_id: str
    window_started_at: datetime
    window_ended_at: datetime
    kind: CausalAssociationKind = CausalAssociationKind.CANDIDATE
    basis: CausalAssociationBasis = CausalAssociationBasis.SESSION_TIME_WINDOW

    def __post_init__(self) -> None:
        """Require one bounded UTC window and candidate-only semantics."""
        _require_uuid7(self.session_id, "session_id")
        _require_utc(self.window_started_at, "window_started_at")
        _require_utc(self.window_ended_at, "window_ended_at")
        if self.window_ended_at < self.window_started_at:
            field = "window"
            raise _validation(field, "invalid_order")
        if self.kind is not CausalAssociationKind.CANDIDATE:
            field = "causal_association"
            raise _validation(field, "authoritative_forbidden")

    def as_document(self) -> dict[str, str]:
        """Return content-free, explainable association evidence."""
        return {
            "basis": self.basis.value,
            "kind": self.kind.value,
            "session_id": self.session_id,
            "window_ended_at": _format_time(self.window_ended_at),
            "window_started_at": _format_time(self.window_started_at),
        }


@dataclass(frozen=True, slots=True)
class TranscriptChunk:
    """One redacted transcript range identified solely by source digest and byte offsets."""

    source_sha256: str
    source_channel: TranscriptSource
    byte_start: int
    byte_end: int
    content: str
    observed_role: TranscriptRole
    occurred_at: datetime
    completion: SourceCompletion
    lifecycle: UnavailableLifecycleProvenance
    causal_association: CandidateCausalAssociation

    def __post_init__(self) -> None:
        """Reject unstable ranges, unsafe text, or mismatched session windows."""
        _require_digest(self.source_sha256, "source_sha256")
        if self.byte_start < 0 or self.byte_end <= self.byte_start:
            field = "byte_range"
            raise _validation(field, "invalid")
        encoded = self.content.encode("utf-8")
        if not encoded or len(encoded) > _MAX_TRANSCRIPT_CHUNK_BYTES or "\x00" in self.content:
            field = "content"
            raise _validation(field, "invalid")
        _require_utc(self.occurred_at, "occurred_at")
        if self.causal_association.session_id == "":  # pragma: no cover - nested invariant.
            field = "causal_association"
            raise _validation(field, "invalid")

    @property
    def chunk_sha256(self) -> str:
        """Return the normative session-scoped stable source-range identity."""
        return _framed_digest(
            "agentmemory-transcript-chunk-v1",
            self.causal_association.session_id,
            self.source_channel.value,
            self.source_sha256,
            str(self.byte_start),
            str(self.byte_end),
        )

    @property
    def event_id(self) -> str:
        """Return a deterministic RFC 9562 UUIDv7-shaped event identity for idempotent reimport."""
        return stable_evidence_uuid7(self.chunk_sha256)

    def payload_bytes(self) -> bytes:
        """Serialize redacted evidence with explicit unknown lifecycle provenance."""
        document: dict[str, object] = {
            "causal_association": self.causal_association.as_document(),
            "chunk_sha256": self.chunk_sha256,
            "content": self.content,
            "observed_role": self.observed_role.value,
            "source_completion": self.completion.value,
            "source_channel": self.source_channel.value,
            "source_offset": {"end": self.byte_end, "start": self.byte_start},
            "source_sha256": self.source_sha256,
            **self.lifecycle.as_document(),
        }
        return _canonical_json(document)


@dataclass(frozen=True, slots=True, order=True)
class FileSnapshotEntry:
    """Content-free observation of one policy-authorized workspace file."""

    relative_path: str
    content_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        """Require a normalized relative POSIX path and verified-looking metadata."""
        path = PurePosixPath(self.relative_path)
        if (
            not self.relative_path
            or path.is_absolute()
            or ".." in path.parts
            or str(path) != self.relative_path
            or len(self.relative_path.encode()) > _MAX_PATH_BYTES
        ):
            field = "relative_path"
            raise _validation(field, "invalid")
        _require_digest(self.content_sha256, "content_sha256")
        if self.size_bytes < 0:
            field = "size_bytes"
            raise _validation(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class FileObservation:
    """One deterministic filesystem delta with candidate-only causality."""

    kind: FileChangeKind
    current: FileSnapshotEntry | None
    previous: FileSnapshotEntry | None
    occurred_at: datetime
    causal_association: CandidateCausalAssociation

    def __post_init__(self) -> None:
        """Require a shape that precisely matches the declared delta kind."""
        _require_utc(self.occurred_at, "occurred_at")
        valid = {
            FileChangeKind.CHANGED: self.current is not None,
            FileChangeKind.DELETED: self.current is None and self.previous is not None,
            FileChangeKind.RENAMED: (
                self.current is not None
                and self.previous is not None
                and self.current.relative_path != self.previous.relative_path
                and self.current.content_sha256 == self.previous.content_sha256
            ),
        }
        if not valid[self.kind]:
            field = "file_observation"
            raise _validation(field, "shape_mismatch")

    @property
    def evidence_sha256(self) -> str:
        """Return a retry-stable identity from before/after metadata."""
        return _framed_digest(
            "agentmemory-file-observation-v1",
            self.kind.value,
            _entry_token(self.previous),
            _entry_token(self.current),
            _format_time(self.occurred_at),
            self.causal_association.session_id,
        )

    @property
    def event_id(self) -> str:
        """Return the deterministic canonical event identity."""
        return stable_evidence_uuid7(self.evidence_sha256)

    def payload_bytes(self) -> bytes:
        """Serialize metadata without file content or authoritative causality."""
        return _canonical_json(
            {
                "causal_association": self.causal_association.as_document(),
                "change_kind": self.kind.value,
                "current": _entry_document(self.current),
                "evidence_sha256": self.evidence_sha256,
                "previous": _entry_document(self.previous),
            }
        )


@dataclass(frozen=True, slots=True)
class GitState:
    """Directly observed repository state at one point in time."""

    commit_sha: str
    branch_name: str | None
    checkout_fingerprint: str

    def __post_init__(self) -> None:
        """Validate Git and checkout evidence without treating paths as identity."""
        if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", self.commit_sha) is None:
            field = "commit_sha"
            raise _validation(field, "invalid")
        if self.branch_name is not None and (
            not self.branch_name or len(self.branch_name) > _MAX_LABEL or "\x00" in self.branch_name
        ):
            field = "branch_name"
            raise _validation(field, "invalid")
        _require_digest(self.checkout_fingerprint, "checkout_fingerprint")


@dataclass(frozen=True, slots=True)
class GitObservation:
    """One state transition emitted as observable evidence, never as causation."""

    kind: GitChangeKind
    previous: GitState | None
    current: GitState
    occurred_at: datetime
    causal_association: CandidateCausalAssociation

    def __post_init__(self) -> None:
        """Require an actual transition matching the declared kind."""
        _require_utc(self.occurred_at, "occurred_at")
        changed = {
            GitChangeKind.COMMIT: self.previous is None
            or self.previous.commit_sha != self.current.commit_sha,
            GitChangeKind.BRANCH: self.previous is not None
            and self.previous.branch_name != self.current.branch_name,
            GitChangeKind.CHECKOUT: self.previous is not None
            and self.previous.checkout_fingerprint != self.current.checkout_fingerprint,
        }
        if not changed[self.kind]:
            field = "git_observation"
            raise _validation(field, "no_transition")

    @property
    def evidence_sha256(self) -> str:
        """Return stable identity for the exact before/after state."""
        return _framed_digest(
            "agentmemory-git-observation-v1",
            self.kind.value,
            _git_token(self.previous),
            _git_token(self.current),
            _format_time(self.occurred_at),
            self.causal_association.session_id,
        )

    @property
    def event_id(self) -> str:
        """Return the deterministic canonical event identity."""
        return stable_evidence_uuid7(self.evidence_sha256)

    def payload_bytes(self) -> bytes:
        """Serialize Git transition and candidate correlation evidence."""
        return _canonical_json(
            {
                "causal_association": self.causal_association.as_document(),
                "change_kind": self.kind.value,
                "current": _git_document(self.current),
                "evidence_sha256": self.evidence_sha256,
                "previous": _git_document(self.previous),
            }
        )


@dataclass(frozen=True, slots=True)
class ProcessObservation:
    """Bounded, content-free result of one argv-based child process."""

    executable: str
    argv_sha256: str
    exit_code: int | None
    stdout_sha256: str
    stderr_sha256: str
    started_at: datetime
    ended_at: datetime
    completion: SourceCompletion
    causal_association: CandidateCausalAssociation

    def __post_init__(self) -> None:
        """Validate process evidence without retaining arguments or output content."""
        if (
            not self.executable
            or "/" in self.executable
            or "\\" in self.executable
            or len(self.executable) > _MAX_LABEL
        ):
            field = "executable"
            raise _validation(field, "invalid")
        for value, field in (
            (self.argv_sha256, "argv_sha256"),
            (self.stdout_sha256, "stdout_sha256"),
            (self.stderr_sha256, "stderr_sha256"),
        ):
            _require_digest(value, field)
        _require_utc(self.started_at, "started_at")
        _require_utc(self.ended_at, "ended_at")
        if self.ended_at < self.started_at:
            field = "process_window"
            raise _validation(field, "invalid_order")
        if self.completion is SourceCompletion.COMPLETE and self.exit_code is None:
            field = "exit_code"
            raise _validation(field, "required")
        if self.exit_code is not None and not -(2**31) <= self.exit_code < 2**31:
            field = "exit_code"
            raise _validation(field, "out_of_range")

    @property
    def evidence_sha256(self) -> str:
        """Return retry-stable content-free process identity."""
        return _framed_digest(
            "agentmemory-process-observation-v1",
            self.argv_sha256,
            self.stdout_sha256,
            self.stderr_sha256,
            self.completion.value,
            str(self.exit_code),
            _format_time(self.started_at),
            _format_time(self.ended_at),
            self.causal_association.session_id,
        )

    @property
    def event_id(self) -> str:
        """Return the deterministic canonical event identity."""
        return stable_evidence_uuid7(self.evidence_sha256)

    def payload_bytes(self) -> bytes:
        """Serialize process metadata without argv or transcript content."""
        return _canonical_json(
            {
                "argv_sha256": self.argv_sha256,
                "causal_association": self.causal_association.as_document(),
                "completion": self.completion.value,
                "ended_at": _format_time(self.ended_at),
                "evidence_sha256": self.evidence_sha256,
                "executable": self.executable,
                "exit_code": self.exit_code,
                "started_at": _format_time(self.started_at),
                "stderr_sha256": self.stderr_sha256,
                "stdout_sha256": self.stdout_sha256,
            }
        )


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    """Deterministic policy-filtered filesystem state at one instant."""

    entries: tuple[FileSnapshotEntry, ...]
    observed_at: datetime
    excluded_count: int

    def __post_init__(self) -> None:
        """Require canonical unique paths, UTC time, and a valid exclusion count."""
        canonical = tuple(sorted(self.entries, key=lambda entry: entry.relative_path))
        paths = tuple(entry.relative_path for entry in self.entries)
        if canonical != self.entries or len(paths) != len(set(paths)):
            field = "entries"
            raise _validation(field, "not_canonical")
        _require_utc(self.observed_at, "observed_at")
        if self.excluded_count < 0:
            field = "excluded_count"
            raise _validation(field, "out_of_range")


@dataclass(frozen=True, slots=True)
class ProcessExecutionResult:
    """Transient child-process bytes and observable termination metadata."""

    executable: str
    argv_sha256: str
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    started_at: datetime
    ended_at: datetime
    completion: SourceCompletion

    def __post_init__(self) -> None:
        """Require bounded transient output and consistent completion evidence."""
        if not self.executable or "/" in self.executable or "\\" in self.executable:
            field = "executable"
            raise _validation(field, "invalid")
        _require_digest(self.argv_sha256, "argv_sha256")
        if len(self.stdout) > 16 * 1024 * 1024 or len(self.stderr) > 16 * 1024 * 1024:
            field = "process_output"
            raise _validation(field, "too_large")
        _require_utc(self.started_at, "started_at")
        _require_utc(self.ended_at, "ended_at")
        if self.ended_at < self.started_at:
            field = "process_window"
            raise _validation(field, "invalid_order")
        if self.completion is SourceCompletion.COMPLETE and self.exit_code is None:
            field = "exit_code"
            raise _validation(field, "required")

    def observation(
        self,
        association: CandidateCausalAssociation,
    ) -> ProcessObservation:
        """Reduce transient bytes to content-free durable process evidence."""
        return ProcessObservation(
            executable=self.executable,
            argv_sha256=self.argv_sha256,
            exit_code=self.exit_code,
            stdout_sha256=hashlib.sha256(self.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(self.stderr).hexdigest(),
            started_at=self.started_at,
            ended_at=self.ended_at,
            completion=self.completion,
            causal_association=association,
        )


def stable_evidence_uuid7(evidence_sha256: str) -> str:
    """Map a stable evidence digest to a canonical UUIDv7 without ambient state."""
    _require_digest(evidence_sha256, "evidence_sha256")
    material = bytes.fromhex(evidence_sha256)
    timestamp = int.from_bytes(material[:6], "big")
    random_a = int.from_bytes(material[6:8], "big") & 0x0FFF
    random_b = int.from_bytes(material[8:16], "big") & ((1 << 62) - 1)
    value = (timestamp << 80) | (0x7 << 76) | (random_a << 64) | (0b10 << 62) | random_b
    return str(UUID(int=value))


def uuid7_occurred_at(value: str) -> datetime:
    """Return the canonical UTC millisecond encoded by a UUIDv7 identity."""
    _require_uuid7(value, "uuid7")
    timestamp_milliseconds = UUID(value).int >> 80
    return datetime.fromtimestamp(timestamp_milliseconds / 1_000, tz=UTC)


def _framed_digest(namespace: str, *parts: str) -> str:
    encoded = bytearray()
    for part in (namespace, *parts):
        value = part.encode()
        encoded.extend(len(value).to_bytes(8, "big"))
        encoded.extend(value)
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json(document: dict[str, object]) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()


def _entry_token(entry: FileSnapshotEntry | None) -> str:
    if entry is None:
        return "none"
    return f"{entry.relative_path}\0{entry.content_sha256}\0{entry.size_bytes}"


def _entry_document(entry: FileSnapshotEntry | None) -> dict[str, object] | None:
    if entry is None:
        return None
    return {
        "content_sha256": entry.content_sha256,
        "relative_path": entry.relative_path,
        "size_bytes": entry.size_bytes,
    }


def _git_token(state: GitState | None) -> str:
    if state is None:
        return "none"
    return f"{state.commit_sha}\0{state.branch_name}\0{state.checkout_fingerprint}"


def _git_document(state: GitState | None) -> dict[str, str | None] | None:
    if state is None:
        return None
    return {
        "branch_name": state.branch_name,
        "checkout_fingerprint": state.checkout_fingerprint,
        "commit_sha": state.commit_sha,
    }


def _require_digest(value: str, field: str) -> None:
    if _DIGEST.fullmatch(value) is None or set(value) == {"0"}:
        raise _validation(field, "invalid_digest")


def _require_uuid7(value: str, field: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as error:
        raise _validation(field, "invalid_uuid7") from error
    if str(parsed) != value or parsed.version != _UUID_VERSION:
        raise _validation(field, "invalid_uuid7")


def _require_utc(value: datetime, field: str) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise _validation(field, "not_utc")


def _format_time(value: datetime) -> str:
    _require_utc(value, "time")
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _validation(field: str, code: str) -> IngestionValidationError:
    return IngestionValidationError.single(field, code)
