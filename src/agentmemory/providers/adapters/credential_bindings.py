"""Authenticated strict loader for gateway credential-to-attestation bindings."""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, cast

from agentmemory.providers.adapters.credential_broker import ProviderCredentialBinding
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
from agentmemory.providers.domain.errors import ProviderContainmentValidationError

if TYPE_CHECKING:
    from pathlib import Path

_MAX_DOCUMENT_BYTES = 256 * 1024
_FIELDS = frozenset({"schema_version", "bindings", "hmac_sha256"})
_BINDING_FIELDS = frozenset({"profile_id", "attestation_id", "file_name", "header_name", "prefix"})
_ERR_BINDINGS = "provider credential bindings are invalid"


def load_authenticated_credential_bindings(
    document_file: Path,
    hmac_key_file: Path,
) -> dict[tuple[str, str], ProviderCredentialBinding]:
    """Verify and parse the complete closed credential binding snapshot."""
    raw = read_provider_document(document_file, _MAX_DOCUMENT_BYTES)
    key = read_capability(hmac_key_file)
    try:
        result = _parse(bytes(raw), bytes(key))
    except (
        StrictJsonError,
        KeyError,
        TypeError,
        UnicodeError,
        ValueError,
        ProviderContainmentValidationError,
    ) as error:
        raise ProviderContainmentValidationError(_ERR_BINDINGS) from error
    finally:
        zero(raw)
        zero(key)
    return result


def _parse(
    raw: bytes,
    key: bytes,
) -> dict[tuple[str, str], ProviderCredentialBinding]:
    root = require_object(loads(raw))
    if frozenset(root) != _FIELDS or root.get("schema_version") != 1:
        raise ValueError
    signature = _string(root, "hmac_sha256")
    unsigned = {key_name: value for key_name, value in root.items() if key_name != "hmac_sha256"}
    expected = hmac.digest(key, canonical_bytes(unsigned), hashlib.sha256).hex()
    if not hmac.compare_digest(signature, expected):
        raise ValueError
    values = root["bindings"]
    if not isinstance(values, list) or not values:
        raise TypeError
    result: dict[tuple[str, str], ProviderCredentialBinding] = {}
    order: list[tuple[str, str]] = []
    for raw_binding in cast("list[object]", values):
        document = require_object(raw_binding)
        if frozenset(document) != _BINDING_FIELDS:
            raise ValueError
        binding = ProviderCredentialBinding(
            profile_id=_string(document, "profile_id"),
            attestation_id=_string(document, "attestation_id"),
            file_name=_string(document, "file_name"),
            header_name=_string(document, "header_name"),
            prefix=_string(document, "prefix").encode("ascii"),
        )
        identity = binding.profile_id, binding.attestation_id
        if identity in result:
            raise ValueError
        order.append(identity)
        result[identity] = binding
    if order != sorted(order):
        raise ValueError
    return result


def _string(document: dict[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str):
        raise TypeError
    return value
