"""PRO-009 encrypted gateway credential-vault qualification tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentmemory.providers.adapters.credential_vault import (
    EncryptedProviderCredentialVault,
)
from agentmemory.providers.adapters.strict_json import canonical_bytes
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)
from tests.providers.test_pro009_containment_application import (
    PROFILE_ATTESTATION_ID,
    PROFILE_ID,
    permit,
)

_ENCRYPTION_KEY = b"e" * 32
_HMAC_KEY = b"h" * 32
_NONCE = bytes(range(12))
_PLAINTEXT = b"opaque-provider-key"


def _entry(  # noqa: PLR0913 -- Test factory exposes each authenticated coordinate.
    *,
    profile_id: str = PROFILE_ID,
    attestation_id: str = PROFILE_ATTESTATION_ID,
    header_name: str = "Authorization",
    prefix: str = "Bearer ",
    nonce: bytes = _NONCE,
    plaintext: bytes = _PLAINTEXT,
    encryption_key: bytes = _ENCRYPTION_KEY,
) -> dict[str, object]:
    aad = canonical_bytes(
        {
            "attestation_id": attestation_id,
            "header_name": header_name,
            "prefix": prefix,
            "profile_id": profile_id,
            "schema_version": 1,
        }
    )
    ciphertext = AESGCM(encryption_key).encrypt(nonce, plaintext, aad)
    return {
        "attestation_id": attestation_id,
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "header_name": header_name,
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "prefix": prefix,
        "profile_id": profile_id,
    }


def _write_vault(
    root: Path,
    *,
    entries: object | None = None,
    encryption_key: bytes = _ENCRYPTION_KEY,
    hmac_key: bytes = _HMAC_KEY,
) -> tuple[Path, Path, Path]:
    document_file = root / "credential-vault.json"
    encryption_key_file = root / "credential-vault-key"
    hmac_key_file = root / "credential-vault-hmac-key"
    unsigned: dict[str, object] = {
        "entries": entries if entries is not None else [_entry()],
        "schema_version": 1,
    }
    document_file.write_bytes(
        canonical_bytes(
            {
                **unsigned,
                "hmac_sha256": hmac.digest(
                    hmac_key,
                    canonical_bytes(unsigned),
                    hashlib.sha256,
                ).hex(),
            }
        )
    )
    encryption_key_file.write_bytes(encryption_key)
    hmac_key_file.write_bytes(hmac_key)
    for path in (document_file, encryption_key_file, hmac_key_file):
        path.chmod(0o600)
    return document_file, encryption_key_file, hmac_key_file


def _vault(root: Path) -> EncryptedProviderCredentialVault:
    return EncryptedProviderCredentialVault(*_write_vault(root))


@pytest.mark.asyncio
async def test_vault_resolves_only_exact_attested_profile_and_zeroizes_result(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)

    credential = await vault.resolve(permit())

    assert credential.header_name == "Authorization"
    assert credential.text() == "Bearer opaque-provider-key"
    assert "opaque-provider-key" not in repr(credential)
    assert "opaque-provider-key" not in repr(vault)
    credential.destroy()
    assert credential.value == bytearray(len(b"Bearer opaque-provider-key"))


@pytest.mark.asyncio
async def test_vault_denies_unbound_profile_without_disclosing_inventory(
    tmp_path: Path,
) -> None:
    vault = _vault(tmp_path)

    with pytest.raises(ProviderContainmentDeniedError, match="denied"):
        await vault.resolve(
            replace(
                permit(),
                profile_id="018f0000-0000-7000-8000-000000000999",
            )
        )


@pytest.mark.asyncio
async def test_vault_reauthenticates_snapshot_on_every_resolution(tmp_path: Path) -> None:
    document_file, encryption_key_file, hmac_key_file = _write_vault(tmp_path)
    vault = EncryptedProviderCredentialVault(
        document_file,
        encryption_key_file,
        hmac_key_file,
    )
    document_file.write_bytes(document_file.read_bytes().replace(b"Bearer ", b"Basic  "))

    with pytest.raises(ProviderContainmentDependencyError, match="unavailable"):
        await vault.resolve(permit())


@pytest.mark.parametrize("target", ["document", "encryption", "hmac"])
def test_vault_rejects_symlinked_or_non_owner_only_projection(
    tmp_path: Path,
    target: str,
) -> None:
    paths = list(_write_vault(tmp_path))
    index = {"document": 0, "encryption": 1, "hmac": 2}[target]
    original = paths[index]
    outside = tmp_path / f"{target}-outside"
    outside.write_bytes(original.read_bytes())
    outside.chmod(0o600)
    original.unlink()
    original.symlink_to(outside)

    with pytest.raises(ProviderContainmentValidationError, match="vault"):
        EncryptedProviderCredentialVault(*paths)

    original.unlink()
    original.write_bytes(outside.read_bytes())
    original.chmod(0o640)
    with pytest.raises(ProviderContainmentValidationError, match="vault"):
        EncryptedProviderCredentialVault(*paths)


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_encryption_key",
        "wrong_hmac_key",
        "unknown_root",
        "unknown_entry",
        "duplicate_identity",
        "unsorted",
        "entries_not_list",
        "empty_entries",
        "non_string_signature",
        "noncanonical_base64",
        "invalid_header",
        "invalid_profile",
        "invalid_attestation",
    ],
)
def test_vault_rejects_tamper_ambiguity_and_open_ended_metadata(  # noqa: C901, PLR0912
    tmp_path: Path,
    mutation: str,
) -> None:
    first = _entry()
    second = _entry(
        profile_id="018f0000-0000-7000-8000-000000000902",
        nonce=bytes(range(1, 13)),
    )
    entries: object = [first]
    encryption_key = _ENCRYPTION_KEY
    hmac_key = _HMAC_KEY
    if mutation == "wrong_encryption_key":
        encryption_key = b"x" * 32
    elif mutation == "wrong_hmac_key":
        hmac_key = b"x" * 32
    elif mutation == "unknown_entry":
        first["ambient"] = "authority"
    elif mutation == "duplicate_identity":
        entries = [first, dict(first)]
    elif mutation == "unsorted":
        entries = [second, first]
    elif mutation == "entries_not_list":
        entries = "not-a-list"
    elif mutation == "empty_entries":
        entries = []
    elif mutation == "noncanonical_base64":
        first["nonce_b64"] = f"{first['nonce_b64']}="
    elif mutation == "invalid_header":
        first["header_name"] = "Cookie"
    elif mutation == "invalid_profile":
        first["profile_id"] = "not-a-uuid"
    elif mutation == "invalid_attestation":
        first["attestation_id"] = "A" * 64

    document_file, encryption_key_file, hmac_key_file = _write_vault(
        tmp_path,
        entries=entries,
        encryption_key=encryption_key,
        hmac_key=hmac_key,
    )
    if mutation == "wrong_hmac_key":
        hmac_key_file.write_bytes(_HMAC_KEY)
    if mutation == "unknown_root":
        content = document_file.read_bytes()
        document_file.write_bytes(content[:-1] + b',"ambient":"authority"}')
    if mutation == "non_string_signature":
        document_file.write_bytes(
            canonical_bytes(
                {
                    "entries": [first],
                    "hmac_sha256": 7,
                    "schema_version": 1,
                }
            )
        )

    with pytest.raises(ProviderContainmentValidationError, match="vault"):
        EncryptedProviderCredentialVault(
            document_file,
            encryption_key_file,
            hmac_key_file,
        )


def test_vault_document_contains_only_ciphertext_not_plaintext(tmp_path: Path) -> None:
    document_file, _, _ = _write_vault(tmp_path)

    document = document_file.read_bytes()

    assert _PLAINTEXT not in document
    assert b"opaque-provider-key" not in document


def test_vault_rejects_relative_or_aliased_projection_paths(tmp_path: Path) -> None:
    document_file, encryption_key_file, hmac_key_file = _write_vault(tmp_path)
    with pytest.raises(ProviderContainmentValidationError, match="vault"):
        EncryptedProviderCredentialVault(
            Path("relative"),
            encryption_key_file,
            hmac_key_file,
        )
    with pytest.raises(ProviderContainmentValidationError, match="vault"):
        EncryptedProviderCredentialVault(
            document_file,
            encryption_key_file,
            encryption_key_file,
        )
