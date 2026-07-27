"""PRO-010 relational authority, trigger, and downgrade-safety tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from agentmemory.providers.adapters.sqlite_observability import (
    SqliteProviderObservabilityRepository,
)
from tests.core.support import migrated_store
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro004_sqlite_embedding_spaces import seed_active_provider
from tests.providers.test_pro010_observability_domain import pricing

if TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.asyncio
@pytest.mark.integration
async def test_migration_head_installs_complete_observability_authority(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    try:
        async with store.engine.connect() as connection:
            head = (
                await connection.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar_one()
            tables = {
                str(row[0])
                for row in (
                    await connection.execute(
                        text("SELECT name FROM sqlite_master WHERE type='table'")
                    )
                ).all()
            }
            triggers = {
                str(row[0])
                for row in (
                    await connection.execute(
                        text("SELECT name FROM sqlite_master WHERE type='trigger'")
                    )
                ).all()
            }
        assert head == "0043_pro010_provider_observability"
        assert {
            "provider_pricing_snapshots",
            "active_provider_pricing",
            "provider_budget_policies",
            "active_provider_budget_policies",
            "provider_budget_accounts",
            "provider_budget_reservations",
            "provider_operation_facts",
            "provider_drift_canaries",
            "provider_drift_probe_state",
            "provider_drift_observations",
            "provider_generation_write_suspensions",
            "provider_observability_alerts",
            "provider_observability_operations",
        } <= tables
        assert {
            "trg_provider_operation_facts_immutable_update",
            "trg_provider_drift_observations_immutable_delete",
            "trg_provider_work_items_drift_write_guard",
        } <= triggers
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_downgrade_refuses_to_destroy_pricing_authority(tmp_path: Path) -> None:
    database = tmp_path / "agentmemory.sqlite3"
    store = migrated_store(tmp_path)
    try:
        await seed_active_provider(store)
        snapshot = pricing()
        await SqliteProviderObservabilityRepository(store).publish_pricing(
            scope("provider.observability.pricing.publish"),
            "pro010-pricing-downgrade",
            snapshot.snapshot_id,
            snapshot,
        )
    finally:
        await store.close()

    configuration = Config("migrations/relational/alembic.ini")
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    with pytest.raises(RuntimeError, match="PRO-010 downgrade refused"):
        command.downgrade(configuration, "0042_pro009_provider_containment")
    engine = create_engine(f"sqlite:///{database}")
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0043_pro010_provider_observability"
            )
    finally:
        engine.dispose()
