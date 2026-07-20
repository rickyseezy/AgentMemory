"""ING-005 SQLite policy history and content-free decision tests."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.sqlite_privacy import (
    SqliteCapturePolicyDecisionRepository,
    SqliteCapturePolicyRepository,
)
from agentmemory.ingestion.application.privacy import CapturePolicyCommand, CapturePolicyPipeline
from agentmemory.ingestion.domain.agent_event import Classification
from agentmemory.ingestion.domain.errors import IngestionConflictError, IngestionValidationError
from agentmemory.ingestion.domain.privacy import (
    AllowedEgressRoute,
    CaptureDisposition,
    CapturePolicy,
    EgressDestination,
    SensitiveAction,
)
from tests.core.support import BRAIN_ID, FixedClock, migrated_store
from tests.ingestion.adp002_support import EVENT_ID, PRINCIPAL_ID, REPOSITORY_ID
from tests.ingestion.test_adp002_sqlite_capture import seed_capture_authority

if TYPE_CHECKING:
    from pathlib import Path


NOW_US = round(FixedClock().now().timestamp() * 1_000_000)


def destination() -> EgressDestination:
    return EgressDestination(
        "cohere",
        "https://api.cohere.example",
        "eu",
        "embed-v4",
        "embedding",
    )


@pytest.mark.asyncio
@pytest.mark.integration
async def test_default_policy_resolves_without_writes_and_historical_activation_is_exact(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteCapturePolicyRepository(store)
    try:
        await seed_capture_authority(store)
        default = await repository.resolve(BRAIN_ID, REPOSITORY_ID, None)
        assert default == CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID)
        async with store.engine.connect() as connection:
            assert (
                await connection.execute(text("SELECT COUNT(*) FROM capture_policy_versions"))
            ).scalar_one() == 0

        revision_one = CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID)
        await repository.activate(revision_one, NOW_US)
        await repository.activate(revision_one, NOW_US)
        revision_two = replace(
            revision_one,
            policy_id="018f0000-0000-7000-8000-000000000402",
            version=2,
            secret_action=SensitiveAction.LOCAL_ONLY,
        )
        await repository.activate(revision_two, NOW_US + 1)
        assert await repository.resolve(BRAIN_ID, REPOSITORY_ID, None) == revision_two
        assert await repository.resolve(BRAIN_ID, REPOSITORY_ID, 1) == revision_one
        async with store.engine.connect() as connection:
            rows = (
                (
                    await connection.execute(
                        text(
                            "SELECT policy_version,status,document_json "
                            "FROM capture_policy_versions ORDER BY policy_version"
                        )
                    )
                )
                .mappings()
                .all()
            )
        assert [(row["policy_version"], row["status"]) for row in rows] == [
            (1, "superseded"),
            (2, "active"),
        ]
        assert rows[0]["document_json"] == revision_one.canonical_bytes.decode()
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_repository_policy_cannot_weaken_brain_policy_or_skip_a_revision(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    repository = SqliteCapturePolicyRepository(store)
    try:
        await seed_capture_authority(store)
        brain = CapturePolicy.secure_default(BRAIN_ID, None)
        await repository.activate(brain, NOW_US)
        route = AllowedEgressRoute(
            destination(),
            (Classification.CONFIDENTIAL, Classification.INTERNAL, Classification.PUBLIC),
        )
        weakening = replace(
            CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID),
            egress_routes=(route,),
        )
        with pytest.raises(IngestionValidationError) as captured:
            await repository.activate(weakening, NOW_US + 1)
        assert captured.value.code_for("policy") == "repository_weakening"

        with pytest.raises(IngestionConflictError):
            await repository.activate(
                replace(
                    CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID),
                    policy_id="018f0000-0000-7000-8000-000000000403",
                    version=2,
                ),
                NOW_US + 2,
            )
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_decision_receipt_is_content_free_idempotent_and_conflict_detecting(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    policies = SqliteCapturePolicyRepository(store)
    decisions = SqliteCapturePolicyDecisionRepository(store)
    raw_secret = b'{"value":"password=hunter22"}'
    try:
        await seed_capture_authority(store)
        result = await CapturePolicyPipeline(policies).execute(
            CapturePolicyCommand(
                BRAIN_ID,
                REPOSITORY_ID,
                bytearray(raw_secret),
                "application/json",
                "src/service.py",
                Classification.INTERNAL,
            )
        )
        assert result.disposition is CaptureDisposition.SANITIZED
        await decisions.record(EVENT_ID, BRAIN_ID, PRINCIPAL_ID, result, NOW_US)
        await decisions.record(EVENT_ID, BRAIN_ID, PRINCIPAL_ID, result, NOW_US + 1)
        async with store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT disposition,policy_version,input_sha256,output_sha256,"
                            "finding_counts_json,stage_evidence_json FROM privacy_decisions"
                        )
                    )
                )
                .mappings()
                .one()
            )
        serialized = json.dumps(dict(row), default=str)
        assert "hunter22" not in serialized
        assert "password" not in serialized
        assert row["disposition"] == "sanitized"
        assert len(row["input_sha256"]) == 32
        assert len(row["output_sha256"]) == 32
        assert json.loads(str(row["finding_counts_json"]))["secret"] == 1
        assert len(json.loads(str(row["stage_evidence_json"]))) == 6

        conflicting = replace(result, reason_code="different_reason")
        with pytest.raises(IngestionConflictError):
            await decisions.record(EVENT_ID, BRAIN_ID, PRINCIPAL_ID, conflicting, NOW_US + 2)
    finally:
        await store.close()
