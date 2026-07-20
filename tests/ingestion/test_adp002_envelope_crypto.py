"""ADP-002 AES-GCM envelope conformance tests."""

from __future__ import annotations

import pytest

from agentmemory.ingestion.adapters.outbound.canonical_encoder import CanonicalAgentEventEncoder
from agentmemory.ingestion.adapters.outbound.envelope_crypto import (
    AesGcmAgentEventEncryptor,
    BrainEncryptionKey,
    decrypt_agent_event_for_test,
)
from agentmemory.ingestion.domain.capture import EncryptedAgentEvent
from agentmemory.ingestion.domain.errors import IngestionDependencyError, IngestionValidationError
from tests.ingestion.adp002_support import BRAIN_ID, EVENT_ID, event


class _Keys:
    def __init__(self) -> None:
        self.key = BrainEncryptionKey("brain-key:v1", b"k" * 32)

    async def current(self, brain_id: str) -> BrainEncryptionKey:
        assert brain_id == BRAIN_ID
        return self.key


@pytest.mark.asyncio
async def test_fresh_dek_and_nonces_encrypt_and_authenticate_canonical_event() -> None:
    source = event()
    plaintext = CanonicalAgentEventEncoder().encode(source)
    encryptor = AesGcmAgentEventEncryptor(_Keys())
    first = await encryptor.encrypt(
        event_id=EVENT_ID,
        brain_id=BRAIN_ID,
        classification="internal",
        plaintext=plaintext,
    )
    second = await encryptor.encrypt(
        event_id=EVENT_ID,
        brain_id=BRAIN_ID,
        classification="internal",
        plaintext=plaintext,
    )
    assert first.data_key_id != second.data_key_id
    assert first.payload_nonce != second.payload_nonce
    assert first.wrapped_data_key_nonce != second.wrapped_data_key_nonce
    assert plaintext not in first.ciphertext
    assert (
        decrypt_agent_event_for_test(
            first,
            _Keys().key,
            event_id=EVENT_ID,
            brain_id=BRAIN_ID,
            classification="internal",
        )
        == plaintext
    )


@pytest.mark.asyncio
async def test_tampered_ciphertext_and_wrong_scope_fail_authentication() -> None:
    plaintext = CanonicalAgentEventEncoder().encode(event())
    encrypted = await AesGcmAgentEventEncryptor(_Keys()).encrypt(
        event_id=EVENT_ID,
        brain_id=BRAIN_ID,
        classification="internal",
        plaintext=plaintext,
    )
    with pytest.raises(IngestionDependencyError, match="envelope integrity failed"):
        decrypt_agent_event_for_test(
            encrypted,
            _Keys().key,
            event_id=EVENT_ID,
            brain_id="018f0000-0000-7000-8000-000000000999",
            classification="internal",
        )


def _valid_envelope() -> EncryptedAgentEvent:
    return EncryptedAgentEvent(
        1,
        "AES-256-GCM",
        "brain:v1",
        "018f0000-0000-7000-8000-000000000777",
        b"n" * 12,
        b"c" * 17,
        b"w" * 12,
        b"d" * 48,
        "a" * 64,
        "b" * 64,
    )


@pytest.mark.parametrize(
    "case",
    [
        "version",
        "algorithm",
        "key-id",
        "payload-nonce",
        "wrapped-nonce",
        "ciphertext",
        "aad",
        "canonical",
    ],
)
def test_encrypted_envelope_rejects_every_invalid_structural_branch(case: str) -> None:
    with pytest.raises(IngestionValidationError):
        _invalid_envelope(_valid_envelope(), case)


def _invalid_envelope(value: EncryptedAgentEvent, case: str) -> EncryptedAgentEvent:
    return EncryptedAgentEvent(
        2 if case == "version" else value.envelope_version,
        "custom" if case == "algorithm" else value.algorithm,
        value.brain_key_id,
        "invalid" if case == "key-id" else value.data_key_id,
        b"short" if case == "payload-nonce" else value.payload_nonce,
        b"short" if case == "ciphertext" else value.ciphertext,
        b"short" if case == "wrapped-nonce" else value.wrapped_data_key_nonce,
        value.wrapped_data_key,
        "invalid" if case == "aad" else value.aad_sha256,
        "invalid" if case == "canonical" else value.canonical_sha256,
    )


@pytest.mark.parametrize("material", [b"short", b"x" * 33])
def test_brain_key_requires_exactly_256_bits(material: bytes) -> None:
    with pytest.raises(ValueError, match="Brain encryption key is invalid"):
        BrainEncryptionKey("brain:v1", material)
