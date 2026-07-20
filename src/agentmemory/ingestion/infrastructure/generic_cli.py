"""Installable command-line surface for the vendor-neutral generic adapter."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Annotated

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

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
from agentmemory.ingestion.application.generic_adapter import (
    CheckpointGenericTaskCommand,
    CheckpointGenericTaskHandler,
    GenericAdapterContext,
    GenericProcessWrapper,
    ImportTranscriptCommand,
    RunGenericProcessCommand,
    TranscriptImporter,
)
from agentmemory.ingestion.domain.agent_event import AgentEventIdentity, Classification
from agentmemory.ingestion.domain.generic_adapter import (
    SourceCompletion,
    TranscriptEncoding,
    TranscriptFormat,
    TranscriptSource,
)
from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_document,
    read_protected_file,
    zero_secret,
)
from agentmemory.operations.domain.errors import OperationError
from agentmemory.shared.clock import SystemClock

_CONFIG_MAX_BYTES = 16_384
_SUMMARY_MAX_BYTES = 32_768


class GenericAdapterConfig(BaseModel):
    """Strict launcher-written scope and release configuration."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    endpoint: str
    credential_file: Path
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
    credential = read_protected_file(config.credential_file, frozenset({32}))
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            adapter = HttpGenericAgentAdapter(client, config.endpoint, bytes(credential))
            context = config.context()
            await adapter.ensure_registered(context.manifest)
            if arguments.operation == "wrap":
                return await _wrap(arguments, config, context, adapter)
            if arguments.operation == "import-transcript":
                return await _import_transcript(arguments, config, context, adapter)
            if arguments.operation == "checkpoint":
                return await _checkpoint(arguments, config, context, adapter)
            return await _serve_mcp(config, context, adapter)
    finally:
        zero_secret(credential)


async def _wrap(
    arguments: argparse.Namespace,
    config: GenericAdapterConfig,
    context: GenericAdapterContext,
    adapter: HttpGenericAgentAdapter,
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
    adapter: HttpGenericAgentAdapter,
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
    adapter: HttpGenericAgentAdapter,
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
    adapter: HttpGenericAgentAdapter,
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
