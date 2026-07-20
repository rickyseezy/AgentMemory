"""ADP-003 real SQLite manifest, observation, warning, and admission tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

from agentmemory.ingestion.adapters.outbound.sqlite_capabilities import (
    SqliteAdapterCapabilityQueryRepository,
    SqliteAdapterCapabilityUnitOfWorkFactory,
    SystemIngestionIdentityGenerator,
)
from agentmemory.ingestion.adapters.outbound.sqlite_capture import (
    SqliteAdapterCapabilityRegistry,
)
from agentmemory.ingestion.application.adapter_capabilities import (
    ObserveAdapterCapabilitiesCommand,
    ObserveAdapterCapabilitiesHandler,
    RegisterAgentAdapterCommand,
    RegisterAgentAdapterHandler,
)
from agentmemory.ingestion.domain.adapter_capability import EvidenceAvailability
from agentmemory.ingestion.domain.agent_event import CaptureCapability, CaptureMethod
from agentmemory.ingestion.domain.errors import IngestionConflictError
from tests.core.support import FixedClock, migrated_store
from tests.ingestion.adp002_support import NOW, descriptor


def _migration_config(tmp_path: Path) -> tuple[Config, str]:
    database_path = tmp_path / "migration.sqlite3"
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    return configuration, f"sqlite:///{database_path}"


@pytest.mark.migration
def test_adp003_migration_upgrades_downgrades_and_reapplies(tmp_path: Path) -> None:
    configuration, database_url = _migration_config(tmp_path)
    alembic_command.upgrade(configuration, "0007_adp002_durable_capture")
    engine = create_engine(database_url)
    try:
        before = inspect(engine)
        assert "manifest_format" not in {
            item["name"] for item in before.get_columns("agent_adapter_manifests")
        }
        alembic_command.upgrade(configuration, "0008_adp003_adapter_capabilities")
        upgraded = inspect(engine)
        assert "agent_adapter_capability_observations" in upgraded.get_table_names()
        assert "capability_manifest_sha256" in {
            item["name"] for item in upgraded.get_columns("agent_event_envelopes")
        }
        alembic_command.downgrade(configuration, "0007_adp002_durable_capture")
        downgraded = inspect(engine)
        assert "agent_adapter_capability_observations" not in downgraded.get_table_names()
        alembic_command.upgrade(configuration, "0008_adp003_adapter_capabilities")
    finally:
        engine.dispose()


@pytest.mark.migration
def test_migration_rejects_conflicting_legacy_adapter_versions_before_ddl(
    tmp_path: Path,
) -> None:
    configuration, database_url = _migration_config(tmp_path)
    alembic_command.upgrade(configuration, "0007_adp002_durable_capture")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            for digest in (b"a" * 32, b"b" * 32):
                connection.execute(
                    text(
                        "INSERT INTO agent_adapter_manifests "
                        "(adapter_id, adapter_version, adapter_digest, manifest_sha256, "
                        "descriptor_json, status, created_at, schema_version) VALUES "
                        "('agentmemory.codex', '1.0.0', :digest, :manifest, '{}', "
                        "'active', 1, 1)"
                    ),
                    {"digest": digest, "manifest": digest},
                )
        with pytest.raises(RuntimeError, match="conflicting immutable"):
            alembic_command.upgrade(
                configuration,
                "0008_adp003_adapter_capabilities",
            )
        columns = {
            item["name"] for item in inspect(engine).get_columns("agent_adapter_manifests")
        }
        assert "manifest_format" not in columns
    finally:
        engine.dispose()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.migration
async def test_registration_observation_warning_audit_and_idempotency_are_atomic(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    identities = SystemIngestionIdentityGenerator()
    factory = SqliteAdapterCapabilityUnitOfWorkFactory(store, FixedClock(NOW), identities)
    register = RegisterAgentAdapterHandler(factory, identities, FixedClock(NOW))
    observe = ObserveAdapterCapabilitiesHandler(factory, identities, FixedClock(NOW))
    configured = descriptor()
    try:
        created = await register.execute(RegisterAgentAdapterCommand("register-1", configured))
        duplicate = await register.execute(RegisterAgentAdapterCommand("register-1", configured))
        unchanged = await register.execute(RegisterAgentAdapterCommand("register-2", configured))
        assert created.disposition.value == "registered"
        assert duplicate.disposition.value == "duplicate"
        assert unchanged.disposition.value == "unchanged"

        denied = tuple(
            EvidenceAvailability(
                item.capability,
                (
                    CaptureMethod.PERMISSION_DENIED
                    if item.capability is CaptureCapability.SESSION_LIFECYCLE
                    else item.status
                ),
            )
            for item in configured.evidence_availability
        )
        permission_loss = await observe.execute(
            ObserveAdapterCapabilitiesCommand(
                "observe-3",
                configured.adapter_id,
                configured.adapter_version,
                configured.adapter_digest,
                configured.manifest_sha256,
                denied,
            )
        )
        assert permission_loss.warnings[0].code == "permission_lost"

        async with store.engine.connect() as connection:
            counts = (
                (
                    await connection.execute(
                        text("SELECT COUNT(*) FROM agent_adapter_manifests")
                    )
                ).scalar_one(),
                (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM "
                            "agent_adapter_capability_observations"
                        )
                    )
                ).scalar_one(),
                (
                    await connection.execute(
                        text(
                            "SELECT COUNT(*) FROM "
                            "agent_adapter_compatibility_warnings"
                        )
                    )
                ).scalar_one(),
                (
                    await connection.execute(
                        text("SELECT COUNT(*) FROM agent_adapter_capability_commands")
                    )
                ).scalar_one(),
            )
            assert counts == (1, 2, 1, 3)
            assert (
                await connection.execute(
                    text(
                        "SELECT COUNT(*) FROM audit_events "
                        "WHERE action LIKE 'agent_adapter.%'"
                    )
                )
            ).scalar_one() == 3

        queries = SqliteAdapterCapabilityQueryRepository(store.engine)
        queried = await queries.get(
            configured.adapter_id,
            configured.adapter_version,
        )
        assert queried is not None
        assert queried.observation.revision == 2
        assert not queried.availability_for(CaptureCapability.SESSION_LIFECYCLE).observable
        assert await queries.list_active() == (queried,)
        warnings = await queries.warnings(
            configured.adapter_id,
            configured.adapter_version,
            maximum=1,
        )
        assert warnings[0].code == "permission_lost"
        registered = await SqliteAdapterCapabilityRegistry(store.engine).get(
            configured.adapter_id,
            configured.adapter_version,
            configured.adapter_digest,
        )
        assert not registered.authorizes(
            configured.supported_families[0],
            CaptureMethod.NATIVE,
        )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_concurrent_version_registration_is_exactly_once(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    identities = SystemIngestionIdentityGenerator()
    factory = SqliteAdapterCapabilityUnitOfWorkFactory(store, FixedClock(NOW), identities)
    handler = RegisterAgentAdapterHandler(factory, identities, FixedClock(NOW))
    configured = descriptor()
    try:
        results = await asyncio.gather(
            *(
                handler.execute(
                    RegisterAgentAdapterCommand(f"register-{index}", configured)
                )
                for index in range(8)
            )
        )
        assert sum(item.disposition.value == "registered" for item in results) == 1
        assert sum(item.disposition.value == "unchanged" for item in results) == 7
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(
                    text("SELECT COUNT(*) FROM agent_adapter_capability_observations")
                )
            ).scalar_one() == 1
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_manifest_version_is_immutable_and_operation_reuse_conflicts(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    identities = SystemIngestionIdentityGenerator()
    factory = SqliteAdapterCapabilityUnitOfWorkFactory(store, FixedClock(NOW), identities)
    handler = RegisterAgentAdapterHandler(factory, identities, FixedClock(NOW))
    configured = descriptor()
    try:
        await handler.execute(RegisterAgentAdapterCommand("register-1", configured))
        with pytest.raises(IngestionConflictError):
            await handler.execute(
                RegisterAgentAdapterCommand(
                    "register-1",
                    configured.__class__.create(
                        adapter_id=configured.adapter_id,
                        adapter_version=configured.adapter_version,
                        adapter_digest=configured.adapter_digest,
                        schema_major=1,
                        supported_families=configured.supported_families,
                        evidence_availability=tuple(
                            EvidenceAvailability(
                                item.capability,
                                (
                                    CaptureMethod.INFERRED
                                    if item.capability is CaptureCapability.SESSION_LIFECYCLE
                                    else item.status
                                ),
                            )
                            for item in configured.evidence_availability
                        ),
                    ),
                )
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.migration
async def test_downgrade_refuses_to_delete_capability_evidence(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    identities = SystemIngestionIdentityGenerator()
    configured = descriptor()
    try:
        await RegisterAgentAdapterHandler(
            SqliteAdapterCapabilityUnitOfWorkFactory(
                store,
                FixedClock(NOW),
                identities,
            ),
            identities,
            FixedClock(NOW),
        ).execute(RegisterAgentAdapterCommand("register-1", configured))
    finally:
        await store.close()
    database_path = tmp_path / "agentmemory.sqlite3"
    migrations = Path(__file__).parents[2] / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database_path}")
    with pytest.raises(RuntimeError, match="downgrade refused"):
        alembic_command.downgrade(configuration, "0007_adp002_durable_capture")
