"""Launcher-supervised local spool recovery composition and command surface."""

from __future__ import annotations

import argparse
import asyncio
import signal
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, cast
from uuid import uuid7

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from agentmemory.ingestion.adapters.outbound.offline_spool import (
    EncryptedSqliteSpool,
    SqliteOfflineSpoolRepository,
)
from agentmemory.ingestion.adapters.outbound.spool_batch_http import HttpSpoolBatchUploader
from agentmemory.ingestion.application.reconcile_spool import (
    ReconcileSpoolCommand,
    ReconcileSpoolHandler,
)
from agentmemory.ingestion.application.spool_worker import (
    SpoolRecoveryPolicy,
    SpoolRecoveryWorker,
)
from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_document,
    read_protected_file,
    zero_secret,
)
from agentmemory.shared.clock import SystemClock

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import FrameType

_CONFIG_MAX_BYTES = 16_384


class SpoolRecoveryConfig(BaseModel):
    """Strict owner-only launcher configuration for local interruption recovery."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    endpoint: str
    credential_file: Path
    spool_database: Path
    spool_key_file: Path
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
    def require_timeout_inside_lease(self) -> SpoolRecoveryConfig:
        """Ensure an upload cannot outlive the durable lease that authorizes its ACK."""
        if self.upload_timeout_seconds >= self.lease_seconds:
            msg = "upload timeout must be shorter than the recovery lease"
            raise ValueError(msg)
        return self


class EventRecoveryScheduler:
    """Translate launcher shutdown and bounded delays into the application port."""

    def __init__(self) -> None:
        """Start in the running state with no process-global side effects."""
        self._stopped = asyncio.Event()

    def stop(self) -> None:
        """Request idempotent graceful worker shutdown."""
        self._stopped.set()

    async def wait(self, seconds: float) -> bool:
        """Return False after the retry delay or True immediately on shutdown."""
        if self._stopped.is_set():
            return True
        try:
            async with asyncio.timeout(seconds):
                await self._stopped.wait()
        except TimeoutError:
            return False
        return True


def load_spool_recovery_config(path: Path) -> SpoolRecoveryConfig:
    """Load only an owner-private bounded launcher document."""
    raw = read_protected_document(path, _CONFIG_MAX_BYTES)
    return SpoolRecoveryConfig.model_validate_json(raw, strict=True)


async def run_configured_recovery(
    config: SpoolRecoveryConfig,
    client: httpx.AsyncClient,
    scheduler: EventRecoveryScheduler,
    worker_id: str,
) -> None:
    """Compose the release worker from strict config and protected local secrets."""
    spool = EncryptedSqliteSpool(
        config.spool_database,
        config.spool_key_file,
        maximum_records=config.maximum_spool_records,
        maximum_bytes=config.maximum_spool_bytes,
    )
    await asyncio.to_thread(spool.initialize)
    credential = read_protected_file(config.credential_file, frozenset({32}))
    try:
        handler = ReconcileSpoolHandler(
            SqliteOfflineSpoolRepository(spool),
            HttpSpoolBatchUploader(client, config.endpoint, bytes(credential)),
            SystemClock(),
        )
        await SpoolRecoveryWorker(
            handler,
            scheduler,
            SpoolRecoveryPolicy(
                config.retry_interval_seconds,
                config.idle_interval_seconds,
                config.maximum_immediate_batches,
            ),
        ).run(
            ReconcileSpoolCommand(
                worker_id,
                config.maximum_batch_items,
                config.maximum_batch_bytes,
                config.lease_seconds,
                config.upload_timeout_seconds,
            )
        )
    finally:
        zero_secret(credential)


def main() -> None:
    """Run the supervised recovery worker with stable content-free failure output."""
    parser = argparse.ArgumentParser(prog="agentmemory-spool-worker")
    parser.add_argument("--config", required=True, help="Launcher-written owner-only config file")
    arguments = parser.parse_args()
    try:
        asyncio.run(_run(Path(arguments.config)))
    except (OSError, RuntimeError, ValueError, ValidationError, httpx.HTTPError) as error:
        sys.stderr.write(f"AgentMemory spool recovery failed: {type(error).__name__}\n")
        raise SystemExit(2) from error


async def _run(config_path: Path) -> None:
    config = await asyncio.to_thread(load_spool_recovery_config, config_path)
    scheduler = EventRecoveryScheduler()
    restore_signals = _install_shutdown_signals(scheduler)
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(config.upload_timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        ) as client:
            await run_configured_recovery(
                config,
                client,
                scheduler,
                f"launcher-{uuid7()}",
            )
    finally:
        restore_signals()


def _install_shutdown_signals(scheduler: EventRecoveryScheduler) -> Callable[[], None]:
    loop = asyncio.get_running_loop()
    native: list[signal.Signals] = []
    fallback: list[tuple[signal.Signals, object]] = []

    def request_stop(_: int | None = None, __: FrameType | None = None) -> None:
        loop.call_soon_threadsafe(scheduler.stop)

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, request_stop)
            native.append(signum)
        except NotImplementedError, RuntimeError:
            previous = signal.getsignal(signum)
            signal.signal(signum, request_stop)
            fallback.append((signum, previous))

    def restore() -> None:
        for signum in native:
            loop.remove_signal_handler(signum)
        for signum, previous in fallback:
            signal.signal(signum, cast("signal.Handlers", previous))

    return restore
