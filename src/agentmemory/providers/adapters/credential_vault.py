"""Authenticated encrypted provider credential vault confined to the gateway."""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from agentmemory.providers.adapters.protected_file import (
    read_capability,
    read_provider_document,
    zero,
)
from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.containment import ProviderGatewayCredential
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.providers.domain.containment import ProviderEgressPermit

_MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
_MAX_ENTRIES = 10_000
_MAX_PREFIX_BYTES = 32
_MAX_CREDENTIAL_BYTES = 4096
_NONCE_BYTES = 12
_AEAD_TAG_BYTES = 16
_DIGEST_CHARS = 64
_UUID_VERSION = 7
_ASCII_SPACE = 0x20
_ASCII_TILDE = 0x7E
_ROOT_FIELDS = frozenset({"schema_version", "entries", "hmac_sha256"})
_ENTRY_FIELDS = frozenset(
    {
        "profile_id",
        "attestation_id",
        "header_name",
        "prefix",
        "nonce_b64",
        "ciphertext_b64",
    }
)
_HEADERS = frozenset({"Authorization", "X-Goog-Api-Key", "X-Api-Key"})
_ERR_DENIED = "provider credential access is denied"
_ERR_INVALID = "provider credential vault is invalid"
_ERR_UNAVAILABLE = "provider credential vault is unavailable"


@dataclass(frozen=True, slots=True)
class _VaultEntry:
    profile_id: str
    attestation_id: str
    header_name: str
    prefix: bytes
    nonce: bytes
    ciphertext: bytes

    @property
    def identity(self) -> tuple[str, str]:
        return self.profile_id, self.attestation_id

    @property
    def aad(self) -> bytes:
        return canonical_bytes(
            {
                "attestation_id": self.attestation_id,
                "header_name": self.header_name,
                "prefix": self.prefix.decode("ascii"),
                "profile_id": self.profile_id,
                "schema_version": 1,
            }
        )


class EncryptedProviderCredentialVault:
    """Resolve one attested credential without exposing plaintext outside gateway memory."""

    def __init__(
        self,
        document_file: Path,
        encryption_key_file: Path,
        hmac_key_file: Path,
    ) -> None:
        """Store only absolute protected-file references."""
        paths = (document_file, encryption_key_file, hmac_key_file)
        if any(not path.is_absolute() for path in paths) or len(set(paths)) != len(paths):
            raise ProviderContainmentValidationError(_ERR_INVALID)
        self._document_file = document_file
        self._encryption_key_file = encryption_key_file
        self._hmac_key_file = hmac_key_file
        self._validate()

    async def resolve(self, permit: ProviderEgressPermit) -> ProviderGatewayCredential:
        """Authenticate the complete snapshot and decrypt only the exact bound entry."""
        try:
            raw, encryption_key, hmac_key = self._read()
        except (OSError, PermissionError, ValueError) as error:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
        plaintext: bytearray | None = None
        combined: bytearray | None = None
        try:
            try:
                entries = _parse_entries(bytes(raw), bytes(hmac_key))
            except (
                StrictJsonError,
                KeyError,
                TypeError,
                UnicodeError,
                ValueError,
                ProviderContainmentValidationError,
            ) as error:
                raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
            entry = _bound_entry(
                entries,
                permit.profile_id,
                permit.profile_attestation_id,
            )
            plaintext = _decrypt_entry(entry, bytes(encryption_key))
            combined = bytearray(entry.prefix)
            combined.extend(plaintext)
            credential = ProviderGatewayCredential(
                header_name=entry.header_name,
                value=combined,
            )
            combined = None
            return credential
        finally:
            zero(raw)
            zero(encryption_key)
            zero(hmac_key)
            if plaintext is not None:
                zero(plaintext)
            if combined is not None:
                zero(combined)

    def _validate(self) -> None:
        try:
            raw, encryption_key, hmac_key = self._read()
        except (OSError, PermissionError, ValueError) as error:
            raise ProviderContainmentValidationError(_ERR_INVALID) from error
        try:
            entries = _parse_entries(bytes(raw), bytes(hmac_key))
            for entry in entries:
                plaintext = _decrypt_entry(entry, bytes(encryption_key))
                zero(plaintext)
        except (
            InvalidTag,
            StrictJsonError,
            KeyError,
            TypeError,
            UnicodeError,
            ValueError,
            ProviderContainmentDependencyError,
            ProviderContainmentValidationError,
        ) as error:
            raise ProviderContainmentValidationError(_ERR_INVALID) from error
        finally:
            zero(raw)
            zero(encryption_key)
            zero(hmac_key)

    def _read(self) -> tuple[bytearray, bytearray, bytearray]:
        raw = read_provider_document(self._document_file, _MAX_DOCUMENT_BYTES)
        try:
            encryption_key = read_capability(self._encryption_key_file)
        except Exception:
            zero(raw)
            raise
        try:
            hmac_key = read_capability(self._hmac_key_file)
        except Exception:
            zero(raw)
            zero(encryption_key)
            raise
        return raw, encryption_key, hmac_key


def _parse_entries(raw: bytes, hmac_key: bytes) -> tuple[_VaultEntry, ...]:
    root = require_object(loads(raw))
    if frozenset(root) != _ROOT_FIELDS or root.get("schema_version") != 1:
        raise ValueError
    signature = _string(root, "hmac_sha256")
    unsigned = {name: value for name, value in root.items() if name != "hmac_sha256"}
    expected = hmac.digest(hmac_key, canonical_bytes(unsigned), hashlib.sha256).hex()
    if not hmac.compare_digest(signature, expected):
        raise ValueError
    raw_entries = root["entries"]
    if not isinstance(raw_entries, list):
        raise TypeError
    entry_values = cast("list[object]", raw_entries)
    if not 1 <= len(entry_values) <= _MAX_ENTRIES:
        raise TypeError
    entries: list[_VaultEntry] = []
    for raw_entry in entry_values:
        document = require_object(raw_entry)
        if frozenset(document) != _ENTRY_FIELDS:
            raise ValueError
        profile_id = _string(document, "profile_id")
        try:
            profile = UUID(profile_id)
        except ValueError as error:
            raise ValueError from error
        attestation_id = _string(document, "attestation_id")
        header_name = _string(document, "header_name")
        prefix = _string(document, "prefix").encode("ascii")
        nonce = _base64(document, "nonce_b64")
        ciphertext = _base64(document, "ciphertext_b64")
        if (
            profile.version != _UUID_VERSION
            or str(profile) != profile_id
            or len(attestation_id) != _DIGEST_CHARS
            or any(value not in "0123456789abcdef" for value in attestation_id)
            or header_name not in _HEADERS
            or len(prefix) > _MAX_PREFIX_BYTES
            or any(value < _ASCII_SPACE or value > _ASCII_TILDE for value in prefix)
            or len(nonce) != _NONCE_BYTES
            or not _AEAD_TAG_BYTES + 1 <= len(ciphertext) <= _MAX_CREDENTIAL_BYTES + _AEAD_TAG_BYTES
        ):
            raise ValueError
        entries.append(
            _VaultEntry(
                profile_id,
                attestation_id,
                header_name,
                prefix,
                nonce,
                ciphertext,
            )
        )
    identities = [entry.identity for entry in entries]
    if identities != sorted(set(identities)):
        raise ValueError
    return tuple(entries)


def _string(document: dict[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError
    return value


def _base64(document: dict[str, object], key: str) -> bytes:
    encoded = _string(document, key)
    decoded = base64.b64decode(encoded, validate=True)
    if base64.b64encode(decoded).decode("ascii") != encoded:
        raise ValueError
    return decoded


def _bound_entry(
    entries: tuple[_VaultEntry, ...],
    profile_id: str,
    attestation_id: str,
) -> _VaultEntry:
    for entry in entries:
        if entry.identity == (profile_id, attestation_id):
            return entry
    raise ProviderContainmentDeniedError(_ERR_DENIED)


def _decrypt_entry(entry: _VaultEntry, encryption_key: bytes) -> bytearray:
    try:
        plaintext = bytearray(
            AESGCM(encryption_key).decrypt(
                entry.nonce,
                entry.ciphertext,
                entry.aad,
            )
        )
    except InvalidTag as error:
        raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
    if not 1 <= len(plaintext) <= _MAX_CREDENTIAL_BYTES - len(entry.prefix) or any(
        value < _ASCII_SPACE or value > _ASCII_TILDE for value in plaintext
    ):
        zero(plaintext)
        raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE)
    return plaintext
