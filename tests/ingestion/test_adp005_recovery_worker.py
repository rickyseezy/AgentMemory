"""ADP-005 launcher-supervised automatic recovery composition tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import override

import httpx
import pytest
from pydantic import ValidationError

from agentmemory.ingestion.adapters.inbound.agent_event_schema import AgentEventEnvelopeV1
from agentmemory.ingestion.adapters.outbound.offline_spool import EncryptedSqliteSpool
from agentmemory.ingestion.application.spool_worker import SpoolRecoveryPolicy
from agentmemory.ingestion.domain.errors import IngestionValidationError
from agentmemory.ingestion.infrastructure.spool_recovery_cli import (
    EventRecoveryScheduler,
    SpoolRecoveryConfig,
    load_spool_recovery_config,
    run_configured_recovery,
)
from agentmemory.operations.domain.errors import OperationError
from tests.core.support import write_secret
from tests.ingestion.adp002_support import EVENT_ID, NOW, event


class _StopAfterTwoDelays(EventRecoveryScheduler):
    def __init__(self) -> None:
        super().__init__()
        self.delays: list[float] = []

    @override
    async def wait(self, seconds: float) -> bool:
        self.delays.append(seconds)
        return len(self.delays) == 2


def _configured_spool(tmp_path: Path) -> tuple[SpoolRecoveryConfig, EncryptedSqliteSpool]:
    tmp_path.chmod(0o700)
    credential_file = tmp_path / "credential"
    key_file = tmp_path / "spool-key"
    write_secret(credential_file, b"c" * 32)
    write_secret(key_file, b"k" * 32)
    config = SpoolRecoveryConfig(
        endpoint="http://127.0.0.1:9411",
        credential_file=credential_file,
        spool_database=tmp_path / "spool.sqlite3",
        spool_key_file=key_file,
        retry_interval_seconds=0.05,
        idle_interval_seconds=0.06,
    )
    spool = EncryptedSqliteSpool(
        config.spool_database,
        config.spool_key_file,
        maximum_records=config.maximum_spool_records,
        maximum_bytes=config.maximum_spool_bytes,
    )
    spool.initialize()
    return config, spool


@pytest.mark.asyncio
async def test_supervised_worker_uploads_after_core_restart_and_erases_only_after_ack(
    tmp_path: Path,
) -> None:
    config, spool = _configured_spool(tmp_path)
    canonical = AgentEventEnvelopeV1.from_domain(event()).to_canonical_json()
    assert spool.enqueue(EVENT_ID, event().ordering_key, 1, canonical)
    requests = 0

    async def transport(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        document = json.loads(request.content)
        assert document["events"][0]["time"] == NOW.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if requests == 1:
            return httpx.Response(503)
        return httpx.Response(
            200,
            json={
                "results": [
                    {
                        "event_id": EVENT_ID,
                        "status": "accepted",
                        "ingested_at_microseconds": 2_000_000,
                        "clock_skew_microseconds": -123,
                    }
                ]
            },
        )

    scheduler = _StopAfterTwoDelays()
    async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
        await run_configured_recovery(config, client, scheduler, "worker-one")

    assert requests == 2
    assert scheduler.delays == [0.05, 0.06]
    assert spool.count_pending() == 0


@pytest.mark.asyncio
async def test_event_scheduler_stops_without_waiting_for_retry_delay() -> None:
    scheduler = EventRecoveryScheduler()
    scheduler.stop()

    assert await scheduler.wait(60.0)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SpoolRecoveryPolicy(retry_interval_seconds=0.0),
        lambda: SpoolRecoveryPolicy(idle_interval_seconds=61.0),
        lambda: SpoolRecoveryPolicy(maximum_immediate_batches=0),
    ],
)
def test_recovery_policy_rejects_busy_or_unbounded_scheduling(factory: object) -> None:
    assert callable(factory)
    with pytest.raises(IngestionValidationError):
        factory()


def test_recovery_config_is_loaded_only_from_owner_private_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    config_path = tmp_path / "recovery.json"
    document = {
        "endpoint": "http://127.0.0.1:9411",
        "credential_file": str(tmp_path / "credential"),
        "spool_database": str(tmp_path / "spool.sqlite3"),
        "spool_key_file": str(tmp_path / "spool-key"),
    }
    write_secret(config_path, json.dumps(document).encode())

    loaded = load_spool_recovery_config(config_path)

    assert loaded.endpoint == "http://127.0.0.1:9411"
    config_path.chmod(0o644)
    with pytest.raises(OperationError, match="protected secret source is unsafe"):
        load_spool_recovery_config(config_path)


def test_recovery_config_refuses_upload_timeout_outside_lease() -> None:
    with pytest.raises(ValidationError, match="upload timeout"):
        SpoolRecoveryConfig(
            endpoint="http://127.0.0.1:9411",
            credential_file=Path("credential"),
            spool_database=Path("spool.sqlite3"),
            spool_key_file=Path("spool-key"),
            lease_seconds=10.0,
            upload_timeout_seconds=10.0,
        )
