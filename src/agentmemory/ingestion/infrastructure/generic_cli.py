"""Installable command-line surface for the vendor-neutral generic adapter."""

from __future__ import annotations

import argparse
import asyncio
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Annotated
from uuid import uuid7

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentmemory.ingestion.adapters.generic_http import HttpGenericAgentAdapter
from agentmemory.ingestion.adapters.generic_manifest import build_generic_adapter_manifest
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
from agentmemory.ingestion.adapters.inbound.generic_mcp import GenericCheckpointMcpServer
from agentmemory.ingestion.adapters.outbound.offline_spool import (
    EncryptedSqliteSpool,
    SpoolingAgentAdapter,
    SqliteOfflineSpoolRepository,
)
from agentmemory.ingestion.adapters.outbound.spool_batch_http import HttpSpoolBatchUploader
from agentmemory.ingestion.application.generic_adapter import (
    CheckpointGenericTaskCommand,
    CheckpointGenericTaskHandler,
    GenericAdapterContext,
    GenericProcessWrapper,
    ImportTranscriptCommand,
    RunGenericProcessCommand,
    TranscriptImporter,
)
from agentmemory.ingestion.application.reconcile_spool import (
    ReconcileSpoolCommand,
    ReconcileSpoolHandler,
)
from agentmemory.ingestion.application.spool_worker import (
    SpoolRecoveryPolicy,
    SpoolRecoveryWorker,
)
from agentmemory.ingestion.domain.agent_event import AgentEventIdentity, Classification
from agentmemory.ingestion.domain.generic_adapter import (
    SourceCompletion,
    TranscriptEncoding,
    TranscriptFormat,
    TranscriptSource,
)
from agentmemory.ingestion.infrastructure.spool_recovery_cli import EventRecoveryScheduler
from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_document,
    read_protected_file,
    zero_secret,
)
from agentmemory.operations.domain.errors import OperationError
from agentmemory.shared.clock import SystemClock

_CONFIG_MAX_BYTES = 16_384
_SUMMARY_MAX_BYTES = 32_768

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.adapter_capability import AdapterCapabilityManifest
    from agentmemory.ingestion.domain.agent_event import AgentEvent
    from agentmemory.ingestion.domain.capture import AppendAgentEventResult
    from agentmemory.ingestion.domain.ports import AgentAdapterPort
    from agentmemory.ingestion.domain.spool_reconciliation import SpoolRecord, SpoolUploadResult


class GenericAdapterConfig(BaseModel):
    """Strict launcher-written scope and release configuration."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    endpoint: str
    credential_file: Path
    spool_database: Path
    spool_key_file: Path
    brain_id: str
    principal_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None = None
    branch_name: str | None = None
    commit_sha: str | None = None
    session_id: str
    task_id: str | None = None
    correlation_id: str | None = None
    ordering_key: str | None = None
    classification: Classification = Classification.LOCAL_ONLY
    retention_policy_id: str = "default"
    adapter_version: str
    adapter_digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    redaction_patterns: tuple[str, ...] = ()
    maximum_spool_records: Annotated[int, Field(ge=1, le=100_000)] = 10_000
    maximum_spool_bytes: Annotated[int, Field(ge=98_304, le=1_073_741_824)] = 67_108_864
    maximum_batch_items: Annotated[int, Field(ge=1, le=100)] = 100
    maximum_batch_bytes: Annotated[int, Field(ge=98_304, le=1_048_576)] = 1_048_576
    lease_seconds: Annotated[float, Field(ge=1.0, le=300.0)] = 30.0
    upload_timeout_seconds: Annotated[float, Field(gt=0.0, lt=300.0)] = 10.0
    retry_interval_seconds: Annotated[float, Field(ge=0.05, le=60.0)] = 1.0
    idle_interval_seconds: Annotated[float, Field(ge=0.05, le=60.0)] = 2.0
    maximum_immediate_batches: Annotated[int, Field(ge=1, le=100)] = 10

    @model_validator(mode="after")
    def require_timeout_inside_lease(self) -> GenericAdapterConfig:
        """Keep every upload inside the lease that can authorize its local erasure."""
        if self.upload_timeout_seconds >= self.lease_seconds:
            msg = "upload timeout must be shorter than the recovery lease"
            raise ValueError(msg)
        return self

    def context(self) -> GenericAdapterContext:
        """Convert launcher claims to the same validated canonical domain values."""
        manifest = build_generic_adapter_manifest(
            adapter_version=self.adapter_version,
            adapter_digest=self.adapter_digest,
        )
        return GenericAdapterContext(
            AgentEventIdentity(
                self.brain_id,
                self.principal_id,
                self.project_id,
                self.repository_id,
                self.checkout_id,
                self.branch_name,
                self.commit_sha,
            ),
            manifest,
            self.session_id,
            self.task_id,
            self.correlation_id or self.session_id,
            self.ordering_key or self.session_id,
            self.classification,
            self.retention_policy_id,
        )


def main() -> None:
    """Execute the selected generic integration and preserve child exit status."""
    try:
        exit_code = asyncio.run(_run(create_generic_cli_parser().parse_args()))
    except (
        OSError,
        OperationError,
        RuntimeError,
        ValueError,
        ValidationError,
        httpx.HTTPError,
    ) as error:
        message = f"AgentMemory generic adapter operation failed: {type(error).__name__}\n"
        sys.stderr.write(message)
        raise SystemExit(2) from error
    raise SystemExit(exit_code)


async def _run(arguments: argparse.Namespace) -> int:
    config = load_generic_adapter_config(Path(arguments.config))
    spool = EncryptedSqliteSpool(
        config.spool_database,
        config.spool_key_file,
        maximum_records=config.maximum_spool_records,
        maximum_bytes=config.maximum_spool_bytes,
    )
    await asyncio.to_thread(spool.initialize)
    credential = read_protected_file(config.credential_file, frozenset({32}))
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            return await _run_with_recovery(arguments, config, bytes(credential), spool, client)
    finally:
        zero_secret(credential)


@dataclass(frozen=True, slots=True)
class _RegisteredGenericAdapter:
    transport: HttpGenericAgentAdapter
    manifest: AdapterCapabilityManifest

    async def execute(self, event: AgentEvent) -> AppendAgentEventResult:
        await self.transport.ensure_registered(self.manifest)
        return await self.transport.execute(event)


@dataclass(frozen=True, slots=True)
class _RegisteringBatchUploader:
    transport: HttpGenericAgentAdapter
    uploader: HttpSpoolBatchUploader
    manifest: AdapterCapabilityManifest

    async def upload(self, records: tuple[SpoolRecord, ...]) -> tuple[SpoolUploadResult, ...]:
        await self.transport.ensure_registered(self.manifest)
        return await self.uploader.upload(records)


async def _run_with_recovery(
    arguments: argparse.Namespace,
    config: GenericAdapterConfig,
    credential: bytes,
    spool: EncryptedSqliteSpool,
    client: httpx.AsyncClient,
) -> int:
    context = config.context()
    transport = HttpGenericAgentAdapter(client, config.endpoint, credential)
    adapter = SpoolingAgentAdapter(
        _RegisteredGenericAdapter(transport, context.manifest),
        spool,
    )
    scheduler = EventRecoveryScheduler()
    worker = SpoolRecoveryWorker(
        ReconcileSpoolHandler(
            SqliteOfflineSpoolRepository(spool),
            _RegisteringBatchUploader(
                transport,
                HttpSpoolBatchUploader(client, config.endpoint, credential),
                context.manifest,
            ),
            SystemClock(),
        ),
        scheduler,
        SpoolRecoveryPolicy(
            config.retry_interval_seconds,
            config.idle_interval_seconds,
            config.maximum_immediate_batches,
        ),
    )
    recovery = asyncio.create_task(
        worker.run(
            ReconcileSpoolCommand(
                f"generic-{uuid7()}",
                config.maximum_batch_items,
                config.maximum_batch_bytes,
                config.lease_seconds,
                config.upload_timeout_seconds,
            )
        )
    )
    try:
        return await _execute_operation(arguments, config, context, adapter)
    finally:
        scheduler.stop()
        await recovery


async def _execute_operation(
    arguments: argparse.Namespace,
    config: GenericAdapterConfig,
    context: GenericAdapterContext,
    adapter: SpoolingAgentAdapter,
) -> int:
    if arguments.operation == "wrap":
        return await _wrap(arguments, config, context, adapter)
    if arguments.operation == "import-transcript":
        return await _import_transcript(arguments, config, context, adapter)
    if arguments.operation == "checkpoint":
        return await _checkpoint(arguments, config, context, adapter)
    return await _serve_mcp(config, context, adapter)


async def _wrap(
    arguments: argparse.Namespace,
    config: GenericAdapterConfig,
    context: GenericAdapterContext,
    adapter: AgentAdapterPort,
) -> int:
    cwd = await asyncio.to_thread(Path(arguments.cwd).resolve, strict=True)
    policy = await asyncio.to_thread(WorkspacePrivacyPolicy.from_workspace, cwd)
    clock = SystemClock()
    wrapper = GenericProcessWrapper(
        ArgvProcessExecutor(
            clock,
            inherit_stdin=True,
            stdout_sink=sys.stdout.buffer,
            stderr_sink=sys.stderr.buffer,
        ),
        LocalFileObserver(clock, policy),
        SubprocessGitObserver(),
        StrictTranscriptDecoder(),
        RegexSensitiveTextRedactor(config.redaction_patterns),
        adapter,
    )
    argv = tuple(arguments.argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    result = await wrapper.execute(
        RunGenericProcessCommand(
            argv,
            cwd,
            None,
            arguments.timeout,
            TranscriptEncoding(arguments.encoding),
            context,
        )
    )
    if result.execution.completion is SourceCompletion.ABRUPT:
        return 124
    return result.execution.exit_code or 0


async def _import_transcript(
    arguments: argparse.Namespace,
    config: GenericAdapterConfig,
    context: GenericAdapterContext,
    adapter: AgentAdapterPort,
) -> int:
    source = await asyncio.to_thread(Path(arguments.path).read_bytes)
    await TranscriptImporter(
        StrictTranscriptDecoder(),
        RegexSensitiveTextRedactor(config.redaction_patterns),
        adapter,
    ).execute(
        ImportTranscriptCommand(
            source,
            TranscriptFormat(arguments.format),
            TranscriptEncoding(arguments.encoding),
            SourceCompletion(arguments.completion),
            TranscriptSource.IMPORT,
            None,
            context,
        )
    )
    return 0


async def _checkpoint(
    arguments: argparse.Namespace,
    config: GenericAdapterConfig,
    context: GenericAdapterContext,
    adapter: AgentAdapterPort,
) -> int:
    summary_bytes = await asyncio.to_thread(
        read_protected_document,
        Path(arguments.summary_file),
        _SUMMARY_MAX_BYTES,
    )
    summary = summary_bytes.decode("utf-8", errors="strict")
    await CheckpointGenericTaskHandler(
        RegexSensitiveTextRedactor(config.redaction_patterns),
        adapter,
    ).execute(
        CheckpointGenericTaskCommand(
            arguments.checkpoint_id,
            summary,
            context,
        )
    )
    return 0


async def _serve_mcp(
    config: GenericAdapterConfig,
    context: GenericAdapterContext,
    adapter: AgentAdapterPort,
) -> int:
    await GenericCheckpointMcpServer(
        CheckpointGenericTaskHandler(
            RegexSensitiveTextRedactor(config.redaction_patterns),
            adapter,
        ),
        context,
    ).serve(sys.stdin.buffer, sys.stdout.buffer)
    return 0


def load_generic_adapter_config(path: Path) -> GenericAdapterConfig:
    """Load one owner-only strict launcher context document."""
    raw = read_protected_document(path, _CONFIG_MAX_BYTES)
    return GenericAdapterConfig.model_validate_json(raw, strict=True)


def create_generic_cli_parser() -> argparse.ArgumentParser:
    """Build the deterministic command-line contract for testing and invocation."""
    parser = argparse.ArgumentParser(prog="agentmemory-generic")
    parser.add_argument("--config", required=True, help="Launcher-written owner-only context file")
    subcommands = parser.add_subparsers(dest="operation", required=True)
    wrap = subcommands.add_parser("wrap", help="Run and observe a hookless agent process")
    wrap.add_argument("--cwd", default=".")
    wrap.add_argument("--timeout", type=float)
    wrap.add_argument(
        "--encoding",
        choices=[item.value for item in TranscriptEncoding],
        default="utf-8",
    )
    wrap.add_argument("argv", nargs=argparse.REMAINDER)
    transcript = subcommands.add_parser("import-transcript", help="Import a transcript file")
    transcript.add_argument("path")
    transcript.add_argument(
        "--format",
        choices=[item.value for item in TranscriptFormat],
        required=True,
    )
    transcript.add_argument(
        "--encoding",
        choices=[item.value for item in TranscriptEncoding],
        required=True,
    )
    transcript.add_argument(
        "--completion",
        choices=[item.value for item in SourceCompletion],
        default=SourceCompletion.COMPLETE.value,
    )
    checkpoint = subcommands.add_parser("checkpoint", help="Persist an explicit checkpoint")
    checkpoint.add_argument(
        "--checkpoint-id",
        required=True,
        help="Client-generated UUIDv7; reuse it for an exact retry",
    )
    checkpoint.add_argument("--summary-file", required=True)
    subcommands.add_parser("mcp", help="Serve the explicit checkpoint tool over MCP stdio")
    return parser
