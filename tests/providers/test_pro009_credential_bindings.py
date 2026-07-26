"""PRO-009 authenticated gateway credential binding document tests."""

from __future__ import annotations

import hashlib
import hmac
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.providers.adapters.credential_bindings import (
    load_authenticated_credential_bindings,
)
from agentmemory.providers.adapters.strict_json import canonical_bytes
from agentmemory.providers.domain.errors import ProviderContainmentValidationError
from tests.providers.test_pro009_containment_application import (
    PROFILE_ATTESTATION_ID,
    PROFILE_ID,
)

if TYPE_CHECKING:
    from pathlib import Path

_KEY = b"k" * 32


def write_document(tmp_path: Path, unsigned: dict[str, object]) -> tuple[Path, Path]:
    signature = hmac.digest(_KEY, canonical_bytes(unsigned), hashlib.sha256).hex()
    document = tmp_path / "bindings.json"
    document.write_bytes(canonical_bytes({**unsigned, "hmac_sha256": signature}))
    document.chmod(0o600)
    key = tmp_path / "bindings.key"
    key.write_bytes(_KEY)
    key.chmod(0o600)
    return document, key


def unsigned() -> dict[str, object]:
    return {
        "schema_version": 1,
        "bindings": [
            {
                "attestation_id": PROFILE_ATTESTATION_ID,
                "file_name": "openai.key",
                "header_name": "Authorization",
                "prefix": "Bearer ",
                "profile_id": PROFILE_ID,
            }
        ],
    }


def test_loader_authenticates_and_returns_exact_closed_binding(tmp_path: Path) -> None:
    document, key = write_document(tmp_path, unsigned())

    bindings = load_authenticated_credential_bindings(document, key)

    assert set(bindings) == {(PROFILE_ID, PROFILE_ATTESTATION_ID)}
    assert bindings[(PROFILE_ID, PROFILE_ATTESTATION_ID)].file_name == "openai.key"


@pytest.mark.parametrize(
    "change",
    [
        {"schema_version": 2},
        {"unexpected": True},
        {"bindings": []},
    ],
)
def test_loader_rejects_unknown_empty_or_version_drift(
    tmp_path: Path,
    change: dict[str, object],
) -> None:
    value = {**unsigned(), **change}
    document, key = write_document(tmp_path, value)
    with pytest.raises(ProviderContainmentValidationError, match="invalid"):
        load_authenticated_credential_bindings(document, key)


def test_loader_rejects_tamper_wrong_key_or_unsafe_file(tmp_path: Path) -> None:
    document, key = write_document(tmp_path, unsigned())
    document.write_bytes(document.read_bytes().replace(b"openai.key", b"cohere.key"))
    with pytest.raises(ProviderContainmentValidationError):
        load_authenticated_credential_bindings(document, key)

    document, key = write_document(tmp_path, unsigned())
    key.write_bytes(b"x" * 32)
    with pytest.raises(ProviderContainmentValidationError):
        load_authenticated_credential_bindings(document, key)

    document, key = write_document(tmp_path, unsigned())
    document.chmod(0o640)
    with pytest.raises(PermissionError):
        load_authenticated_credential_bindings(document, key)


@pytest.mark.parametrize(
    "mutation",
    ["unknown_binding_field", "duplicate_identity", "unsorted", "non_string"],
)
def test_loader_rejects_ambiguous_or_wrong_typed_bindings(
    tmp_path: Path,
    mutation: str,
) -> None:
    raw_bindings = cast("list[dict[str, object]]", unsigned()["bindings"])
    first = dict(raw_bindings[0])
    second: dict[str, object] = {
        **first,
        "profile_id": "018f0000-0000-7000-8000-000000000902",
    }
    bindings: list[object] = [first]
    if mutation == "unknown_binding_field":
        first["ambient"] = "authority"
    elif mutation == "duplicate_identity":
        bindings = [first, dict(first)]
    elif mutation == "unsorted":
        bindings = [second, first]
    else:
        first["file_name"] = 7
    document, key = write_document(
        tmp_path,
        {"schema_version": 1, "bindings": bindings},
    )

    with pytest.raises(ProviderContainmentValidationError, match="invalid"):
        load_authenticated_credential_bindings(document, key)
