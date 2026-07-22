"""PF-003 real SQLite registration, authorization, audit, and outbox tests."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.extensions.adapters.sqlite_registry import (
    SqliteAdapterRegistrationAuthorization,
    SqliteAdapterRegistrationUnitOfWork,
    SqliteAdapterRegistrationUnitOfWorkFactory,
    _datetime,
    _object,
    _protocol,
)
from agentmemory.extensions.application.register_adapter import (
    RegisterAdapterCommand,
    RegisterAdapterHandler,
)
from agentmemory.extensions.domain.errors import (
    AdapterAuthorizationError,
    AdapterConflictError,
    AdapterStorageError,
)
from agentmemory.extensions.domain.models import (
    AdapterCapability,
    AdapterKind,
    AdapterManifest,
    AdapterPermission,
    AdapterProbeEvidence,
    ProtocolVersion,
)
from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from tests.core.support import (
    BRAIN_ID,
    GRANT_ID,
    NOW,
    OWNER_ID,
    FixedClock,
    bootstrap_request,
    migrated_store,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


def _manifest() -> AdapterManifest:
    return AdapterManifest.create(
        schema_version=1,
        adapter_id="go-reference-agent",
        adapter_version="1.0.0",
        kind=AdapterKind.AGENT,
        package_digest="a" * 64,
        signature_digest="b" * 64,
        signer_identity="approved-publisher",
        protocol_min=ProtocolVersion(1, 0),
        protocol_max=ProtocolVersion(1, 2),
        capabilities=(AdapterCapability.AGENT_EVENT_CAPTURE,),
        requested_permissions=(AdapterPermission.CANONICAL_EVENT_WRITE,),
    )


def _command(operation_id: str = "pf003-register-1") -> RegisterAdapterCommand:
    return RegisterAdapterCommand(
        operation_id=operation_id,
        brain_id=BRAIN_ID,
        actor_id=OWNER_ID,
        grant_id=GRANT_ID,
        manifest=_manifest(),
        requested_at=NOW,
    )


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_pf003_sqlite_registration_is_atomic_replayable_audited_and_scoped(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
            bootstrap_request()
        )
        handler = _handler(store)
        registered = await handler.execute(_command())
        assert await handler.execute(_command()) == registered

        second = _command("pf003-register-2")
        assert await handler.execute(second) == registered
        assert await handler.execute(second) == registered

        async with store.engine.connect() as connection:
            registration_count = (
                await connection.execute(
                    text("SELECT COUNT(*) FROM adapter_extension_registrations")
                )
            ).scalar_one()
            operation_count = (
                await connection.execute(text("SELECT COUNT(*) FROM adapter_extension_operations"))
            ).scalar_one()
            audit = (
                await connection.execute(
                    text(
                        "SELECT actor_id,brain_id,action,after_hash FROM audit_events "
                        "WHERE action='adapter.registration.activate'"
                    )
                )
            ).one()
            outbox = (
                await connection.execute(
                    text(
                        "SELECT topic,payload,payload_sha256 FROM outbox_messages "
                        "WHERE topic='adapter.registration.activated.v1'"
                    )
                )
            ).one()
        assert registration_count == 1
        assert operation_count == 2
        assert audit[0:3] == (OWNER_ID, BRAIN_ID, "adapter.registration.activate")
        assert bytes(audit[3]).hex() == registered.registration_digest
        assert outbox[0] == "adapter.registration.activated.v1"
        assert registered.registration_id in str(outbox[1])
        assert b"secret" not in str(outbox[1]).encode()

        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE principals SET status='revoked' WHERE id=:actor"),
                {"actor": OWNER_ID},
            )
        with pytest.raises(AdapterAuthorizationError):
            await handler.execute(_command("pf003-register-after-revocation"))
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf003_sqlite_rejects_operation_and_version_substitution(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
            bootstrap_request()
        )
        handler = _handler(store)
        await handler.execute(_command())
        conflicting = RegisterAdapterCommand(
            operation_id="pf003-register-1",
            brain_id=BRAIN_ID,
            actor_id=OWNER_ID,
            grant_id=GRANT_ID,
            manifest=AdapterManifest.create(
                schema_version=1,
                adapter_id="go-reference-agent",
                adapter_version="1.0.0",
                kind=AdapterKind.AGENT,
                package_digest="c" * 64,
                signature_digest="b" * 64,
                signer_identity="approved-publisher",
                protocol_min=ProtocolVersion(1, 0),
                protocol_max=ProtocolVersion(1, 2),
                capabilities=(AdapterCapability.AGENT_EVENT_CAPTURE,),
                requested_permissions=(AdapterPermission.CANONICAL_EVENT_WRITE,),
            ),
            requested_at=NOW,
        )
        with pytest.raises(AdapterConflictError):
            await handler.execute(conflicting)
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_pf003_sqlite_uow_guards_lifecycle_and_brain_boundary(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    try:
        unit = SqliteAdapterRegistrationUnitOfWork(store)
        with pytest.raises(RuntimeError, match="not active"):
            _ = unit.repository
        with pytest.raises(RuntimeError, match="not active"):
            _ = unit.audit
        with pytest.raises(RuntimeError, match="not active"):
            _ = unit.outbox
        with pytest.raises(RuntimeError, match="not active"):
            await unit.commit()

        async with unit:
            assert (
                await unit.repository.get_version(
                    "018f0000-0000-7000-8000-000000000399",
                    "missing",
                    "1.0.0",
                )
                is None
            )
            await unit.commit()
            with pytest.raises(AdapterConflictError, match="already committed"):
                await unit.commit()
        with pytest.raises(RuntimeError, match="not active"):
            _ = unit.repository
    finally:
        await store.close()


@pytest.mark.parametrize(
    "operation",
    [
        lambda: _object(b"[]"),
        lambda: _object(b"not-json"),
        lambda: _protocol("01.0"),
        lambda: _protocol("1.x"),
        lambda: _datetime("2026-07-22T14:00:00+01:00"),
        lambda: _datetime("not-a-timeZ"),
    ],
)
def test_pf003_sqlite_codec_rejects_noncanonical_or_malformed_storage(
    operation: Callable[[], object],
) -> None:
    with pytest.raises((AdapterStorageError, ValueError)):
        operation()


@dataclass
class _TrustAndPermissions:
    async def verify(self, manifest: AdapterManifest) -> None:
        assert manifest.package_digest == "a" * 64

    async def approve(self, manifest: AdapterManifest) -> None:
        assert manifest.requested_permissions == (AdapterPermission.CANONICAL_EVENT_WRITE,)


@dataclass
class _Probe:
    async def probe(
        self,
        manifest: AdapterManifest,
        negotiated_protocol: ProtocolVersion,
    ) -> AdapterProbeEvidence:
        return AdapterProbeEvidence.create(
            manifest=manifest,
            negotiated_protocol=negotiated_protocol,
            observed_capabilities=manifest.capabilities,
            runtime_digest="c" * 64,
            probed_at=NOW,
        )


@dataclass
class _Identities:
    next_value: int = 0x330

    def new(self) -> str:
        self.next_value += 1
        return f"018f0000-0000-7000-8000-{self.next_value:012x}"


def _handler(store: SqliteCoreStore) -> RegisterAdapterHandler:
    policy = _TrustAndPermissions()
    return RegisterAdapterHandler(
        unit_of_work=SqliteAdapterRegistrationUnitOfWorkFactory(store),
        authorization=SqliteAdapterRegistrationAuthorization(store),
        trust=policy,
        permissions=policy,
        probe=_Probe(),
        identities=_Identities(),
        supported_protocol_min=ProtocolVersion(1, 0),
        supported_protocol_max=ProtocolVersion(1, 2),
    )
