"""ING-005 end-to-end capture privacy and durable-boundary acceptance tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest
from sqlalchemy import text

from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    SqliteWrappedBrainKeyProvider,
    decrypt_agent_event,
)
from agentmemory.ingestion.adapters.outbound.sqlite_privacy import SqliteCapturePolicyRepository
from agentmemory.ingestion.application.capture_agent_event import (
    read_payload_bytes,
    source_path_for_policy,
)
from agentmemory.ingestion.domain.agent_event import (
    AgentEvent,
    AgentEventData,
    CaptureCapability,
    Classification,
    EventFamily,
    PayloadReference,
)
from agentmemory.ingestion.domain.capture import AppendDisposition, EncryptedAgentEvent
from agentmemory.ingestion.domain.privacy import CapturePolicy, SensitiveAction
from tests.core.support import FixedClock, migrated_store, write_secret
from tests.ingestion.adp002_support import (
    BRAIN_ID,
    NOW,
    REPOSITORY_ID,
    event,
)
from tests.ingestion.test_adp002_sqlite_capture import capture_handler, seed_capture_authority

if TYPE_CHECKING:
    from pathlib import Path


_SANITIZED_EVENT_ID = "018f0000-0000-7000-8000-000000000151"
_EXCLUDED_EVENT_ID = "018f0000-0000-7000-8000-000000000152"
_LOCAL_EVENT_ID = "018f0000-0000-7000-8000-000000000153"
_SECRET = "sk-abcdefghijklmnopqrstuvwxyz123456"  # noqa: S105 -- Detection fixture.
_RAW_SECRET = json.dumps(
    {"token": _SECRET},
    separators=(",", ":"),
    sort_keys=True,
).encode()
_SANITIZED = b'{"token":"[REDACTED:SECRET]"}'


class PayloadReader:
    """Return exact test content for a referenced-payload policy read."""

    async def read(self, reference: PayloadReference) -> bytes:
        assert reference.size_bytes == len(_RAW_SECRET)
        return _RAW_SECRET


def _secret_event(event_id: str, sequence: int) -> AgentEvent:
    return replace(
        event(event_id=event_id, sequence=sequence),
        payload=AgentEventData(_RAW_SECRET, hashlib.sha256(_RAW_SECRET).hexdigest()),
    )


@pytest.mark.asyncio
async def test_payload_reader_handles_inline_and_referenced_content() -> None:
    inline = event()
    if inline.payload is None:
        raise AssertionError
    assert await read_payload_bytes(inline, PayloadReader()) == inline.payload.value
    digest = hashlib.sha256(_RAW_SECRET).hexdigest()
    referenced = replace(
        inline,
        payload=None,
        payload_reference=PayloadReference(
            f"cas://sha256/{digest}",
            digest,
            len(_RAW_SECRET),
        ),
    )
    assert await read_payload_bytes(referenced, PayloadReader()) == _RAW_SECRET


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (None, "session/fixture"),
        (b"[]", "session/fixture"),
        (b'{"path":"src/current.py"}', "src/current.py"),
        (b'{"new_path":"src/new.py","path":1}', "src/new.py"),
        (b'{"old_path":"src/old.py"}', "src/old.py"),
        (b'{"status":"unknown"}', "session/fixture"),
    ],
)
def test_file_source_path_uses_closed_precedence_or_subject(
    payload: bytes | None,
    expected: str,
) -> None:
    reference_digest = hashlib.sha256(_RAW_SECRET).hexdigest()
    source = replace(
        event(),
        event_type=EventFamily.FILE_CHANGED,
        dataschema=EventFamily.FILE_CHANGED.dataschema,
        subject="session/fixture",
        capture_capabilities=(CaptureCapability.FILE_OBSERVATION,),
        payload=(
            None
            if payload is None
            else AgentEventData(payload, hashlib.sha256(payload).hexdigest())
        ),
        payload_reference=(
            PayloadReference(
                f"cas://sha256/{reference_digest}",
                reference_digest,
                len(_RAW_SECRET),
            )
            if payload is None
            else None
        ),
    )
    assert source_path_for_policy(source) == expected


def test_non_file_event_has_no_policy_source_path() -> None:
    assert source_path_for_policy(event()) is None


async def _encrypted_event(store: object, event_id: str) -> tuple[str, EncryptedAgentEvent]:
    from agentmemory.operations.adapters.outbound.sqlite_store import (  # noqa: PLC0415
        SqliteCoreStore,
    )

    assert isinstance(store, SqliteCoreStore)
    async with store.engine.connect() as connection:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT e.classification,x.envelope_version,x.algorithm,x.brain_key_id,"
                        "x.data_key_id,x.payload_nonce,x.ciphertext,x.wrapped_data_key_nonce,"
                        "x.wrapped_data_key,x.aad_sha256,x.canonical_sha256 "
                        "FROM agent_events e JOIN agent_event_envelopes x "
                        "ON x.event_id=e.event_id WHERE e.event_id=:event"
                    ),
                    {"event": event_id},
                )
            )
            .mappings()
            .one()
        )
    return str(row["classification"]), EncryptedAgentEvent(
        int(row["envelope_version"]),
        str(row["algorithm"]),
        str(row["brain_key_id"]),
        str(row["data_key_id"]),
        bytes(row["payload_nonce"]),
        bytes(row["ciphertext"]),
        bytes(row["wrapped_data_key_nonce"]),
        bytes(row["wrapped_data_key"]),
        bytes(row["aad_sha256"]).hex(),
        bytes(row["canonical_sha256"]).hex(),
    )


async def _decrypt_payload(
    store: object,
    key_file: Path,
    event_id: str,
) -> tuple[str, bytes]:
    from agentmemory.operations.adapters.outbound.sqlite_store import (  # noqa: PLC0415
        SqliteCoreStore,
    )

    assert isinstance(store, SqliteCoreStore)
    classification, encrypted = await _encrypted_event(store, event_id)
    key = await SqliteWrappedBrainKeyProvider(store, key_file, FixedClock(NOW)).current(BRAIN_ID)
    plaintext = decrypt_agent_event(
        encrypted,
        key,
        event_id=event_id,
        brain_id=BRAIN_ID,
        classification=classification,
    )
    payload = json.dumps(
        json.loads(plaintext)["data"],
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return classification, payload


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_secret_is_redacted_before_canonical_encryption_and_atomic_receipt(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        result = await capture_handler(store, key_file).execute(
            _secret_event(_SANITIZED_EVENT_ID, 1)
        )
        assert result.disposition is AppendDisposition.ACCEPTED
        classification, payload = await _decrypt_payload(store, key_file, _SANITIZED_EVENT_ID)
        assert classification == Classification.RESTRICTED.value
        assert payload == _SANITIZED
        assert _SECRET.encode() not in payload

        async with store.engine.connect() as connection:
            receipt = (
                (
                    await connection.execute(
                        text(
                            "SELECT disposition,classification,egress_decision,output_sha256,"
                            "finding_counts_json,stage_evidence_json FROM privacy_decisions "
                            "WHERE subject_id=:event"
                        ),
                        {"event": _SANITIZED_EVENT_ID},
                    )
                )
                .mappings()
                .one()
            )
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM agent_events),"
                        "(SELECT COUNT(*) FROM outbox_messages),"
                        "(SELECT COUNT(*) FROM audit_events "
                        "WHERE action='agent_event.appended')"
                    )
                )
            ).one()
        assert tuple(counts) == (1, 1, 1)
        assert receipt["disposition"] == "sanitized"
        assert receipt["classification"] == "restricted"
        assert receipt["egress_decision"] == "deny"
        assert bytes(receipt["output_sha256"]) == hashlib.sha256(_SANITIZED).digest()
        assert json.loads(str(receipt["finding_counts_json"]))["secret"] == 1
        assert len(json.loads(str(receipt["stage_evidence_json"]))) == 6
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_excluded_secret_persists_only_content_free_policy_evidence(tmp_path: Path) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        policies = SqliteCapturePolicyRepository(store)
        await policies.activate(
            replace(
                CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID),
                secret_action=SensitiveAction.EXCLUDE,
            ),
            round(NOW.timestamp() * 1_000_000),
        )
        result = await capture_handler(store, key_file).execute(
            _secret_event(_EXCLUDED_EVENT_ID, 1)
        )
        assert result.disposition is AppendDisposition.IGNORED

        async with store.engine.connect() as connection:
            counts = (
                await connection.execute(
                    text(
                        "SELECT (SELECT COUNT(*) FROM agent_events),"
                        "(SELECT COUNT(*) FROM agent_event_envelopes),"
                        "(SELECT COUNT(*) FROM outbox_messages),"
                        "(SELECT COUNT(*) FROM audit_events "
                        "WHERE action='agent_event.appended'),"
                        "(SELECT COUNT(*) FROM privacy_decisions)"
                    )
                )
            ).one()
            receipt = (
                (
                    await connection.execute(
                        text("SELECT * FROM privacy_decisions WHERE subject_id=:event"),
                        {"event": _EXCLUDED_EVENT_ID},
                    )
                )
                .mappings()
                .one()
            )
        assert tuple(counts) == (0, 0, 0, 0, 1)
        assert receipt["disposition"] == "excluded"
        assert receipt["egress_decision"] == "deny"
        assert receipt["output_sha256"] is None
        assert _SECRET not in json.dumps(dict(receipt), default=str)
    finally:
        await store.close()
    assert _SECRET.encode() not in (tmp_path / "agentmemory.sqlite3").read_bytes()


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_local_only_secret_is_encrypted_without_redaction_and_never_egress_eligible(
    tmp_path: Path,
) -> None:
    store = migrated_store(tmp_path)
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"i" * 32)
    try:
        await seed_capture_authority(store)
        await SqliteCapturePolicyRepository(store).activate(
            replace(
                CapturePolicy.secure_default(BRAIN_ID, REPOSITORY_ID),
                secret_action=SensitiveAction.LOCAL_ONLY,
            ),
            round(NOW.timestamp() * 1_000_000),
        )
        result = await capture_handler(store, key_file).execute(_secret_event(_LOCAL_EVENT_ID, 1))
        assert result.disposition is AppendDisposition.ACCEPTED
        classification, payload = await _decrypt_payload(store, key_file, _LOCAL_EVENT_ID)
        assert classification == Classification.LOCAL_ONLY.value
        assert payload == _RAW_SECRET
        async with store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT p.disposition,p.egress_decision,x.ciphertext "
                            "FROM privacy_decisions p JOIN agent_event_envelopes x "
                            "ON x.event_id=p.subject_id WHERE p.subject_id=:event"
                        ),
                        {"event": _LOCAL_EVENT_ID},
                    )
                )
                .mappings()
                .one()
            )
        assert row["disposition"] == "local_only"
        assert row["egress_decision"] == "deny"
        assert _SECRET.encode() not in bytes(row["ciphertext"])
    finally:
        await store.close()
    assert _SECRET.encode() not in (tmp_path / "agentmemory.sqlite3").read_bytes()
