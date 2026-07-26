"""PRO-009 relational migration and downgrade-safety tests."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text

from agentmemory.providers.adapters.sqlite_containment import SqliteProviderContainmentRepository
from tests.core.support import NOW, digest, migrated_store
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro004_sqlite_embedding_spaces import seed_active_provider
from tests.providers.test_pro009_sqlite_containment import active_policy

if TYPE_CHECKING:
    from pathlib import Path


def micros(seconds: int = 0) -> int:
    return round((NOW + timedelta(seconds=seconds)).timestamp() * 1_000_000)


@pytest.mark.asyncio
@pytest.mark.integration
async def test_migration_head_installs_complete_containment_schema(tmp_path: Path) -> None:
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
        assert head == "0042_pro009_provider_containment"
        assert {
            "provider_egress_policies",
            "provider_egress_operations",
            "provider_egress_permits",
            "provider_runtime_facts",
            "provider_egress_decisions",
        }.issubset(tables)
        assert "active_provider_egress_policies" in tables
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_downgrade_refuses_to_destroy_containment_authority(tmp_path: Path) -> None:
    database = tmp_path / "agentmemory.sqlite3"
    store = migrated_store(tmp_path)
    try:
        await seed_active_provider(store)
        await SqliteProviderContainmentRepository(store).publish(
            scope("provider.containment.manage"),
            "pro009-policy-downgrade",
            digest("policy-downgrade").value,
            active_policy(),
            micros(3),
        )
    finally:
        await store.close()
    config = Config("migrations/relational/alembic.ini")
    config.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    with pytest.raises(RuntimeError, match="PRO-009 downgrade refused"):
        command.downgrade(config, "0041_pro008_embedding_migrations")
    engine = create_engine(f"sqlite:///{database}")
    try:
        with engine.connect() as connection:
            assert (
                connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
                == "0042_pro009_provider_containment"
            )
    finally:
        engine.dispose()
