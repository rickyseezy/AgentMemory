"""Reviewed AES-256-GCM event envelope and Brain key wrapping adapters."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol
from uuid import uuid7

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from agentmemory.ingestion.domain.capture import EncryptedAgentEvent
from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.operations.adapters.outbound.protected_file import read_protected_file, zero_secret

if TYPE_CHECKING:
    from pathlib import Path

    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_KEY_BYTES = 32
_NONCE_BYTES = 12
_ALGORITHM = "AES-256-GCM"
_ERR_KEY_STORAGE = "Brain key storage is unavailable"
_ERR_KEY_INTEGRITY = "Brain key wrapper integrity failed"
_ERR_KEY_SCOPE = "Brain key scope is unavailable"
_ERR_EVENT_INTEGRITY = "AgentEvent envelope integrity failed"


@dataclass(frozen=True, slots=True)
class BrainEncryptionKey:
    """Short-lived unwrapped Brain key material returned by a key provider."""

    key_id: str
    material: bytes

    def __post_init__(self) -> None:
        """Require an identified 256-bit BKEK."""
        if not self.key_id or len(self.material) != _KEY_BYTES:
            msg = "Brain encryption key is invalid"
            raise ValueError(msg)


class BrainKeyProvider(Protocol):
    """Resolve the current per-Brain random key-encryption key."""

    async def current(self, brain_id: str) -> BrainEncryptionKey:
        """Return current key material or raise a safe dependency failure."""
        ...


@dataclass(frozen=True, slots=True)
class AesGcmAgentEventEncryptor:
    """Envelope-encrypt each canonical event under a random per-object DEK."""

    keys: BrainKeyProvider

    async def encrypt(
        self,
        *,
        event_id: str,
        brain_id: str,
        classification: str,
        plaintext: bytes,
    ) -> EncryptedAgentEvent:
        """Encrypt content and wrap its random DEK under the Brain BKEK."""
        brain_key = await self.keys.current(brain_id)
        data_key = bytearray(AESGCM.generate_key(bit_length=256))
        data_key_id = str(uuid7())
        payload_nonce = os.urandom(_NONCE_BYTES)
        wrapped_nonce = os.urandom(_NONCE_BYTES)
        aad = _canonical_json(
            {
                "algorithm": _ALGORITHM,
                "brain_id": brain_id,
                "brain_key_id": brain_key.key_id,
                "classification": classification,
                "data_key_id": data_key_id,
                "envelope_version": 1,
                "event_id": event_id,
            }
        )
        wrapping_aad = _canonical_json(
            {
                "brain_id": brain_id,
                "brain_key_id": brain_key.key_id,
                "data_key_id": data_key_id,
                "purpose": "agent-event-dek-wrap-v1",
            }
        )
        try:
            ciphertext = AESGCM(bytes(data_key)).encrypt(payload_nonce, plaintext, aad)
            wrapped = AESGCM(brain_key.material).encrypt(
                wrapped_nonce,
                bytes(data_key),
                wrapping_aad,
            )
        finally:
            zero_secret(data_key)
        return EncryptedAgentEvent(
            envelope_version=1,
            algorithm=_ALGORITHM,
            brain_key_id=brain_key.key_id,
            data_key_id=data_key_id,
            payload_nonce=payload_nonce,
            ciphertext=ciphertext,
            wrapped_data_key_nonce=wrapped_nonce,
            wrapped_data_key=wrapped,
            aad_sha256=hashlib.sha256(aad).hexdigest(),
            canonical_sha256=hashlib.sha256(plaintext).hexdigest(),
        )


class SqliteWrappedBrainKeyProvider:
    """Lazily create/load random BKEKs wrapped by the protected installation key."""

    def __init__(
        self,
        store: SqliteCoreStore,
        installation_key_file: Path,
        clock: Clock,
        wrapping_key_id: str = "installation-root:v1",
    ) -> None:
        """Bind the canonical store and protected installation root key source."""
        self._store = store
        self._installation_key_file = installation_key_file
        self._clock = clock
        self._wrapping_key_id = wrapping_key_id

    async def current(self, brain_id: str) -> BrainEncryptionKey:
        """Serialize first creation and authenticate every persisted key wrapper."""
        async with self._store.write_lock:
            installation_key = await asyncio.to_thread(
                read_protected_file,
                self._installation_key_file,
                frozenset({_KEY_BYTES}),
            )
            try:
                return await self._load_or_create(brain_id, bytes(installation_key))
            finally:
                zero_secret(installation_key)

    async def _load_or_create(self, brain_id: str, installation_key: bytes) -> BrainEncryptionKey:
        try:
            async with self._store.engine.connect() as connection:
                await connection.exec_driver_sql("BEGIN IMMEDIATE")
                row = (
                    (
                        await connection.execute(
                            text(
                                "SELECT key_id, wrapping_key_id, nonce, ciphertext, aad_sha256 "
                                "FROM brain_encryption_keys WHERE brain_id = :brain_id"
                            ),
                            {"brain_id": brain_id},
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    result = await self._create(connection, brain_id, installation_key)
                    await connection.commit()
                    return result
                await connection.rollback()
        except (SQLAlchemyError, OSError) as error:
            raise IngestionDependencyError(_ERR_KEY_STORAGE) from error
        key_id = str(row["key_id"])
        aad = _brain_key_aad(brain_id, key_id, str(row["wrapping_key_id"]))
        if not _same_digest(row["aad_sha256"], hashlib.sha256(aad).digest()):
            raise IngestionDependencyError(_ERR_KEY_INTEGRITY)
        try:
            material = AESGCM(installation_key).decrypt(
                bytes(row["nonce"]),
                bytes(row["ciphertext"]),
                aad,
            )
        except Exception as error:
            raise IngestionDependencyError(_ERR_KEY_INTEGRITY) from error
        return BrainEncryptionKey(key_id, material)

    async def _create(
        self,
        connection: AsyncConnection,
        brain_id: str,
        installation_key: bytes,
    ) -> BrainEncryptionKey:
        execute = connection.execute
        brain = (
            await execute(
                text("SELECT 1 FROM brains WHERE id = :brain_id AND status = 'active'"),
                {"brain_id": brain_id},
            )
        ).first()
        if brain is None:
            raise IngestionDependencyError(_ERR_KEY_SCOPE)
        key_id = str(uuid7())
        material = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(_NONCE_BYTES)
        aad = _brain_key_aad(brain_id, key_id, self._wrapping_key_id)
        ciphertext = AESGCM(installation_key).encrypt(nonce, material, aad)
        now = round(self._clock.now().timestamp() * 1_000_000)
        await execute(
            text(
                "INSERT INTO brain_encryption_keys "
                "(brain_id, key_id, envelope_version, algorithm, wrapping_key_id, nonce, "
                "ciphertext, aad_sha256, created_at, schema_version) VALUES "
                "(:brain_id, :key_id, 1, :algorithm, :wrapping_key_id, :nonce, "
                ":ciphertext, :aad, :created_at, 1)"
            ),
            {
                "brain_id": brain_id,
                "key_id": key_id,
                "algorithm": _ALGORITHM,
                "wrapping_key_id": self._wrapping_key_id,
                "nonce": nonce,
                "ciphertext": ciphertext,
                "aad": hashlib.sha256(aad).digest(),
                "created_at": now,
            },
        )
        return BrainEncryptionKey(key_id, material)


def decrypt_agent_event_for_test(
    encrypted: EncryptedAgentEvent,
    brain_key: BrainEncryptionKey,
    *,
    event_id: str,
    brain_id: str,
    classification: str,
) -> bytes:
    """Authenticate/decrypt an envelope for conformance and recovery tests."""
    aad = _canonical_json(
        {
            "algorithm": encrypted.algorithm,
            "brain_id": brain_id,
            "brain_key_id": encrypted.brain_key_id,
            "classification": classification,
            "data_key_id": encrypted.data_key_id,
            "envelope_version": encrypted.envelope_version,
            "event_id": event_id,
        }
    )
    wrapping_aad = _canonical_json(
        {
            "brain_id": brain_id,
            "brain_key_id": encrypted.brain_key_id,
            "data_key_id": encrypted.data_key_id,
            "purpose": "agent-event-dek-wrap-v1",
        }
    )
    try:
        data_key = bytearray(
            AESGCM(brain_key.material).decrypt(
                encrypted.wrapped_data_key_nonce,
                encrypted.wrapped_data_key,
                wrapping_aad,
            )
        )
    except Exception as error:
        raise IngestionDependencyError(_ERR_EVENT_INTEGRITY) from error
    try:
        try:
            return AESGCM(bytes(data_key)).decrypt(
                encrypted.payload_nonce,
                encrypted.ciphertext,
                aad,
            )
        except Exception as error:
            raise IngestionDependencyError(_ERR_EVENT_INTEGRITY) from error
    finally:
        zero_secret(data_key)


def _brain_key_aad(brain_id: str, key_id: str, wrapping_key_id: str) -> bytes:
    return _canonical_json(
        {
            "brain_id": brain_id,
            "brain_key_id": key_id,
            "envelope_version": 1,
            "purpose": "brain-key-wrap-v1",
            "wrapping_key_id": wrapping_key_id,
        }
    )


def _canonical_json(document: dict[str, object]) -> bytes:
    return json.dumps(document, separators=(",", ":"), sort_keys=True).encode()


def _same_digest(value: object, expected: bytes) -> bool:
    return isinstance(value, bytes) and value == expected
