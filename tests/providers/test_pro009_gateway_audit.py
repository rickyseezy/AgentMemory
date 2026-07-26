"""PRO-009 protected content-free gateway audit tests."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import asyncio
import os
from pathlib import Path

import pytest

from agentmemory.providers.adapters import gateway_audit
from agentmemory.providers.adapters.gateway_audit import (
    AppendOnlyProviderEgressTelemetry,
)
from agentmemory.providers.domain.containment import ProviderEgressDecisionFact
from agentmemory.providers.domain.errors import ProviderContainmentDependencyError
from tests.core.support import digest


def fact(index: int) -> ProviderEgressDecisionFact:
    return ProviderEgressDecisionFact(
        permit_digest=digest(f"permit-{index}").value,
        operation_id=f"provider-operation-{index}",
        destination_fingerprint=digest("destination").value,
        outcome_code="succeeded",
        request_bytes=128,
        response_bytes=256,
        status_code=200,
        occurred_at_microseconds=index,
    )


@pytest.mark.asyncio
async def test_audit_appends_complete_canonical_content_free_facts(tmp_path: Path) -> None:
    path = tmp_path / "provider-egress.jsonl"
    recorder = AppendOnlyProviderEgressTelemetry(path)

    await asyncio.gather(*(recorder.record_egress(fact(index)) for index in range(10)))

    lines = path.read_bytes().splitlines()
    assert len(lines) == 10
    assert all(line.startswith(b'{"destination_fingerprint"') for line in lines)
    assert b"secret" not in path.read_bytes()
    assert b"credential" not in path.read_bytes()
    assert b"vector" not in path.read_bytes()
    assert path.stat().st_mode & 0o077 == 0


@pytest.mark.asyncio
async def test_audit_rejects_symlink_or_unsafe_existing_file(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"do-not-touch")
    path = tmp_path / "provider-egress.jsonl"
    path.symlink_to(outside)
    with pytest.raises(ProviderContainmentDependencyError, match="unavailable"):
        await AppendOnlyProviderEgressTelemetry(path).record_egress(fact(1))
    assert outside.read_bytes() == b"do-not-touch"

    path.unlink()
    path.write_bytes(b"existing\n")
    path.chmod(0o640)
    with pytest.raises(ProviderContainmentDependencyError, match="unavailable"):
        await AppendOnlyProviderEgressTelemetry(path).record_egress(fact(1))


def test_audit_requires_an_absolute_journal_path() -> None:
    with pytest.raises(ValueError, match="unavailable"):
        AppendOnlyProviderEgressTelemetry(Path("relative.jsonl"))


@pytest.mark.asyncio
async def test_audit_rejects_an_oversized_fact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gateway_audit, "_MAX_FACT_BYTES", 1)

    with pytest.raises(ProviderContainmentDependencyError, match="unavailable"):
        await AppendOnlyProviderEgressTelemetry(tmp_path / "audit.jsonl").record_egress(fact(1))


def test_audit_supports_platform_without_nofollow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "audit.jsonl"
    monkeypatch.delattr(os, "O_NOFOLLOW")

    AppendOnlyProviderEgressTelemetry(path)._append(b"{}\n")

    assert path.read_bytes() == b"{}\n"


def test_audit_rejects_a_nonprogressing_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = AppendOnlyProviderEgressTelemetry(tmp_path / "audit.jsonl")

    def no_write(_descriptor: int, _payload: object) -> int:
        return 0

    monkeypatch.setattr(os, "write", no_write)

    with pytest.raises(OSError, match=r"^$"):
        recorder._append(b"{}\n")
