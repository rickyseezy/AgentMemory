"""PRO-001 real SQLite migration, profile, audit, and outbox tests."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from datetime import timedelta
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from alembic import command as alembic_command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from agentmemory.operations.adapters.outbound.sqlite_uow import SqliteUnitOfWorkFactory
from agentmemory.operations.application.commands.bootstrap_local_brain import (
    BootstrapLocalBrainHandler,
)
from agentmemory.providers.adapters.sqlite_profiles import SqliteProviderProfileRepository
from agentmemory.providers.adapters.strict_json import loads, require_object
from agentmemory.providers.domain.errors import (
    ProviderModelDriftError,
    ProviderProfileAuthorizationError,
    ProviderProfileConflictError,
)
from agentmemory.providers.domain.profiles import ProviderProbeEvidence, ProviderProfileStatus
from tests.core.support import NOW, FixedClock, bootstrap_request, digest, migrated_store
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    manifest,
    probe_result,
    remote_configuration,
    scope,
)

if TYPE_CHECKING:
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore


def _alembic(database: Path) -> Config:
    root = Path(__file__).resolve().parents[2]
    if not (root / "migrations").is_dir():
        # mutmut executes copied tests from <repo>/mutants while migrations remain at repo root.
        root = root.parent
    migrations = root / "migrations" / "relational"
    configuration = Config(str(migrations / "alembic.ini"))
    configuration.set_main_option("script_location", str(migrations))
    configuration.set_main_option("sqlalchemy.url", f"sqlite:///{database}")
    return configuration


async def _seed(store: SqliteCoreStore) -> None:
    await BootstrapLocalBrainHandler(SqliteUnitOfWorkFactory(store, FixedClock())).execute(
        bootstrap_request()
    )


def test_pro001_migration_round_trip_constraints_and_empty_downgrade(tmp_path: Path) -> None:
    database = tmp_path / "migration.sqlite3"
    configuration = _alembic(database)
    alembic_command.upgrade(configuration, "0031_idx006_content_policy")
    alembic_command.upgrade(configuration, "0032_pro001_provider_profiles")
    with closing(sqlite3.connect(database)) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        triggers = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            ).fetchall()
        }
        foreign_keys = connection.execute("PRAGMA foreign_key_list('provider_profiles')").fetchall()
        probe_foreign_keys = connection.execute(
            "PRAGMA foreign_key_list('provider_probe_evidence')"
        ).fetchall()
    assert {
        "provider_profiles",
        "provider_profile_revisions",
        "provider_probe_evidence",
        "provider_profile_operations",
    } <= tables
    assert "trg_provider_profile_revisions_immutable_update" in triggers
    assert "trg_provider_probe_evidence_immutable_delete" in triggers
    assert any(str(row[2]) == "provider_probe_evidence" for row in foreign_keys)
    assert {(str(row[2]), str(row[3]), str(row[4])) for row in probe_foreign_keys} >= {
        ("provider_profile_revisions", "profile_id", "profile_id"),
        ("provider_profile_revisions", "profile_version", "version"),
    }
    alembic_command.downgrade(configuration, "0031_idx006_content_policy")
    alembic_command.upgrade(configuration, "head")


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_sqlite_profile_lifecycle_is_replayable_audited_and_secret_value_free(  # noqa: PLR0915
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    database = tmp_path / "agentmemory.sqlite3"
    provider_manifest = manifest()
    configuration = remote_configuration()
    repository = SqliteProviderProfileRepository(store)
    create_scope = scope("provider.profile.create")
    probe_scope = scope("provider.profile.probe")
    read_scope = scope("provider.profile.read")
    try:
        await _seed(store)
        draft = await repository.create(
            create_scope,
            "pro001-create-1",
            PROFILE_ID,
            configuration,
            provider_manifest.digest,
            NOW,
        )
        assert draft.status is ProviderProfileStatus.DRAFT
        assert (
            await repository.create(
                create_scope,
                "pro001-create-1",
                PROFILE_ID,
                configuration,
                provider_manifest.digest,
                NOW,
            )
            == draft
        )
        with pytest.raises(ProviderProfileConflictError):
            await repository.create(
                create_scope,
                "pro001-create-1",
                PROFILE_ID,
                remote_configuration(model_id="different-model"),
                provider_manifest.digest,
                NOW,
            )

        first_evidence = ProviderProbeEvidence.create(
            PROFILE_ID,
            provider_manifest.digest,
            probe_result(),
            NOW + timedelta(seconds=1),
        )
        active = await repository.activate(
            probe_scope,
            "pro001-probe-1",
            1,
            first_evidence,
        )
        assert active.status is ProviderProfileStatus.ACTIVE
        assert active.version == 2
        assert await repository.get(read_scope, PROFILE_ID, NOW + timedelta(seconds=1)) == active
        assert (
            await repository.find_operation(
                create_scope,
                "pro001-create-1",
                "create",
                None,
                NOW + timedelta(seconds=1),
            )
            == draft
        )
        assert (
            await repository.find_operation(
                probe_scope,
                "pro001-probe-1",
                "probe",
                PROFILE_ID,
                NOW + timedelta(seconds=1),
            )
            == active
        )

        second_evidence = ProviderProbeEvidence.create(
            PROFILE_ID,
            provider_manifest.digest,
            probe_result(),
            NOW + timedelta(seconds=2),
        )
        refreshed = await repository.activate(
            probe_scope,
            "pro001-probe-2",
            2,
            second_evidence,
        )
        assert refreshed.version == 3
        with pytest.raises(ProviderProfileConflictError):
            await repository.activate(
                probe_scope,
                "pro001-probe-stale",
                2,
                ProviderProbeEvidence.create(
                    PROFILE_ID,
                    provider_manifest.digest,
                    probe_result(),
                    NOW + timedelta(seconds=3),
                ),
            )
        with pytest.raises(ProviderModelDriftError):
            await repository.activate(
                probe_scope,
                "pro001-probe-drift",
                3,
                ProviderProbeEvidence.create(
                    PROFILE_ID,
                    provider_manifest.digest,
                    probe_result(fingerprint=digest("drifted-model").value),
                    NOW + timedelta(seconds=3),
                ),
            )

        async with store.engine.connect() as connection:
            counts = {
                name: int(
                    (
                        await connection.execute(
                            text(f"SELECT COUNT(*) FROM {name}")  # noqa: S608 -- Closed names.
                        )
                    ).scalar_one()
                )
                for name in (
                    "provider_profiles",
                    "provider_profile_revisions",
                    "provider_probe_evidence",
                    "provider_profile_operations",
                )
            }
            outbox = (
                (
                    await connection.execute(
                        text(
                            "SELECT topic,payload,payload_sha256 FROM outbox_messages "
                            "WHERE topic LIKE 'am.local.%.provider.profile-%' "
                            "ORDER BY created_at,id"
                        )
                    )
                )
                .mappings()
                .all()
            )
            audits = (
                (
                    await connection.execute(
                        text(
                            "SELECT action,previous_hash,event_hash FROM audit_events "
                            "WHERE action LIKE 'provider.profile.%' ORDER BY sequence"
                        )
                    )
                )
                .mappings()
                .all()
            )
            documents = (
                (
                    await connection.execute(
                        text(
                            "SELECT document_json FROM provider_profile_revisions ORDER BY version"
                        )
                    )
                )
                .scalars()
                .all()
            )
        assert counts == {
            "provider_profiles": 1,
            "provider_profile_revisions": 3,
            "provider_probe_evidence": 2,
            "provider_profile_operations": 3,
        }
        assert [str(row["topic"]) for row in outbox] == [
            f"am.local.{configuration.brain_id}.provider.profile-created.v1",
            f"am.local.{configuration.brain_id}.provider.profile-activated.v1",
            f"am.local.{configuration.brain_id}.provider.profile-activated.v1",
        ]
        for row in outbox:
            payload = str(row["payload"]).encode()
            assert _digest_bytes(payload) == bytes(row["payload_sha256"])
            event = require_object(loads(payload))
            assert event["specversion"] == "1.0"
            assert isinstance(event["id"], str)
            assert event["id"].startswith("provider-profile-outbox-")
            assert event["type"] == row["topic"]
            assert b"secret://" not in payload
            assert b"approval://" not in payload
            assert b"policy://" not in payload
        assert [str(row["action"]) for row in audits] == [
            "provider.profile.created",
            "provider.profile.activated",
            "provider.profile.activated",
        ]
        assert bytes(audits[1]["previous_hash"]) == bytes(audits[0]["event_hash"])
        assert bytes(audits[2]["previous_hash"]) == bytes(audits[1]["event_hash"])
        persisted = b"".join(bytes(document) for document in documents)
        assert b"secret://providers/openai-production" in persisted
        assert b"sk-pro001-credential-value" not in persisted

        async with store.engine.begin() as connection:
            with pytest.raises(IntegrityError, match="immutable provider evidence"):
                await connection.execute(
                    text("UPDATE provider_profile_revisions SET status='draft'")
                )
            with pytest.raises(IntegrityError, match="immutable provider evidence"):
                await connection.execute(text("DELETE FROM provider_probe_evidence"))

        expires = NOW + timedelta(seconds=4)
        async with store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET valid_to=:expires"),
                {"expires": round(expires.timestamp() * 1_000_000)},
            )
        with pytest.raises(ProviderProfileAuthorizationError):
            await repository.get(read_scope, PROFILE_ID, NOW + timedelta(seconds=5))
    finally:
        await store.close()

    with pytest.raises(RuntimeError, match="PRO-001 downgrade refused"):
        alembic_command.downgrade(_alembic(database), "0031_idx006_content_policy")


def _digest_bytes(value: bytes) -> bytes:
    """Return SHA-256 bytes without weakening assertions to a text conversion."""
    return hashlib.sha256(value).digest()
