"""Protected-file, authentication, configuration, key, and egress tests."""

from __future__ import annotations

# pyright: reportPrivateUsage=false
import hashlib
import hmac
import json
import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from agentmemory.operations.adapters.inbound.authentication import ApiAuthenticator
from agentmemory.operations.adapters.outbound import protected_file
from agentmemory.operations.adapters.outbound.egress_attestation import (
    AuthenticatedEgressAttestationCheck,
    _parse_time,
)
from agentmemory.operations.adapters.outbound.key_access import InstallationKeyAccessCheck
from agentmemory.operations.adapters.outbound.protected_file import (
    read_protected_document,
    read_protected_file,
    require_private_directory,
    zero_secret,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.value_objects import format_rfc3339_microseconds
from agentmemory.operations.infrastructure.configuration import CoreSettings
from tests.core.support import NOW, FixedClock, binding, digest, write_secret


def _attestation_payload(key: bytes, **overrides: object) -> bytes:
    readiness_binding = binding()
    network_id = digest("internal-network").value
    record: dict[str, object] = {
        "schema_version": 1,
        "operation_id": readiness_binding.operation_id.value,
        "plan_digest": readiness_binding.plan_digest.value,
        "release_id": readiness_binding.release_id.value,
        "generation_id": readiness_binding.generation_id.value,
        "internal_network_id": network_id,
        "core_network_ids": [network_id],
        "external_network_ids": [],
        "gateway_enabled": False,
        "inspected_at": format_rfc3339_microseconds(NOW),
    }
    record.update(overrides)
    canonical = json.dumps(record, separators=(",", ":"), sort_keys=True).encode()
    record["hmac_sha256"] = hmac.digest(key, canonical, hashlib.sha256).hex()
    return json.dumps(record, separators=(",", ":"), sort_keys=True).encode()


def test_protected_file_requires_owner_only_regular_exact_length(tmp_path: Path) -> None:
    path = tmp_path / "secret"
    write_secret(path, bytes(range(32)))
    secret = read_protected_file(path, frozenset({32}))
    assert secret == bytearray(range(32))
    zero_secret(secret)
    assert secret == bytearray(32)

    path.chmod(0o644)
    with pytest.raises(OperationError) as raised:
        read_protected_file(path, frozenset({32}))
    assert raised.value.code is ErrorCode.FORBIDDEN


def test_protected_file_rejects_links_wrong_lengths_and_bad_policy(tmp_path: Path) -> None:
    target = tmp_path / "target"
    link = tmp_path / "link"
    write_secret(target, b"short")
    link.symlink_to(target)
    with pytest.raises(OperationError):
        read_protected_file(link, frozenset({5}))
    with pytest.raises(OperationError):
        read_protected_file(target, frozenset({32}))
    with pytest.raises(ValueError, match="length policy"):
        read_protected_file(target, frozenset())


def test_protected_file_rejects_multiply_linked_secret(tmp_path: Path) -> None:
    target = tmp_path / "target"
    alias = tmp_path / "alias"
    write_secret(target, bytes(range(32)))
    alias.hardlink_to(target)
    with pytest.raises(OperationError) as raised:
        read_protected_file(target, frozenset({32}))
    assert raised.value.code is ErrorCode.FORBIDDEN


@pytest.mark.parametrize("optional_flag", ["O_NOFOLLOW", "O_CLOEXEC"])
def test_protected_file_preserves_descriptor_policy_without_optional_flags(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    optional_flag: str,
) -> None:
    path = tmp_path / "secret"
    write_secret(path, b"s" * 32)
    monkeypatch.delattr(os, optional_flag)
    assert protected_file.read_protected_file(path, frozenset({32})) == b"s" * 32


@pytest.mark.parametrize(
    "reads",
    [
        (bytearray(b"s" * 31),),
        (bytearray(b"s" * 32), bytearray(b"t" * 32)),
    ],
)
def test_protected_file_rejects_descriptor_length_and_content_races(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reads: tuple[bytearray, ...],
) -> None:
    path = tmp_path / "secret"
    write_secret(path, b"s" * 32)
    remaining = list(reads)

    def next_read(descriptor: int, maximum_length: int) -> bytearray:
        del descriptor, maximum_length
        return remaining.pop(0)

    monkeypatch.setattr(protected_file, "_read_descriptor", next_read)
    with pytest.raises(OperationError) as raised:
        protected_file.read_protected_file(path, frozenset({32}))
    assert raised.value.code is ErrorCode.INTEGRITY_VIOLATION


def test_protected_document_is_bounded_and_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "control.json"
    write_secret(path, b'{"ready":true}')
    assert read_protected_document(path, 128) == b'{"ready":true}'
    with pytest.raises(OperationError):
        read_protected_document(path, 4)
    with pytest.raises(ValueError, match="length policy"):
        read_protected_document(path, 0)


def test_private_directory_must_exist_be_owner_only_and_not_a_link(tmp_path: Path) -> None:
    private = tmp_path / "private"
    private.mkdir(mode=0o700)
    require_private_directory(private)
    private.chmod(0o755)
    with pytest.raises(OperationError):
        require_private_directory(private)
    private.chmod(0o700)
    link = tmp_path / "private-link"
    link.symlink_to(private, target_is_directory=True)
    with pytest.raises(OperationError):
        require_private_directory(link)
    missing = tmp_path / "missing"
    with pytest.raises(OperationError):
        require_private_directory(missing)


@pytest.mark.asyncio
async def test_api_authenticator_requires_exact_lowercase_bearer(tmp_path: Path) -> None:
    credential = bytes(range(32))
    path = tmp_path / "api-credential"
    write_secret(path, credential)
    authenticator = ApiAuthenticator(path)
    await authenticator.authenticate(f"Bearer {credential.hex()}")
    for invalid in (None, "", f"bearer {credential.hex()}", f"Bearer {credential.hex().upper()}"):
        with pytest.raises(OperationError) as raised:
            await authenticator.authenticate(invalid)
        assert raised.value.code is ErrorCode.UNAUTHENTICATED


@pytest.mark.asyncio
async def test_installation_key_check_uses_protected_hmac_key(tmp_path: Path) -> None:
    key_file = tmp_path / "installation-key"
    write_secret(key_file, b"k" * 32)
    result = await InstallationKeyAccessCheck(key_file, "v1").verify(binding())
    assert result == "installation_key:v1:usable"


@pytest.mark.asyncio
async def test_egress_attestation_accepts_fresh_authentic_default_denied_state(
    tmp_path: Path,
) -> None:
    key = b"i" * 32
    key_file = tmp_path / "installation-key"
    attestation_file = tmp_path / "egress.json"
    write_secret(key_file, key)
    write_secret(attestation_file, _attestation_payload(key))
    result = await AuthenticatedEgressAttestationCheck(
        attestation_file,
        key_file,
        FixedClock(),
    ).verify_default_denied(binding())
    assert (
        result
        == f"internal_network:{digest('internal-network').value}:external_count:0:gateway:false"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"operation_id": "different"},
        {"external_network_ids": ["external"]},
        {"gateway_enabled": True},
        {"core_network_ids": []},
        {"inspected_at": "2026-07-14T07:00:00Z"},
    ],
)
async def test_egress_attestation_rejects_wrong_binding_policy_or_age(
    tmp_path: Path,
    overrides: dict[str, object],
) -> None:
    key = b"i" * 32
    key_file = tmp_path / "installation-key"
    attestation_file = tmp_path / "egress.json"
    write_secret(key_file, key)
    write_secret(attestation_file, _attestation_payload(key, **overrides))
    check = AuthenticatedEgressAttestationCheck(attestation_file, key_file, FixedClock())
    with pytest.raises((OperationError, ValueError)):
        await check.verify_default_denied(binding())


@pytest.mark.asyncio
async def test_egress_attestation_rejects_tampered_signature(tmp_path: Path) -> None:
    key_file = tmp_path / "installation-key"
    attestation_file = tmp_path / "egress.json"
    write_secret(key_file, b"i" * 32)
    write_secret(attestation_file, _attestation_payload(b"wrong-key" * 4))
    check = AuthenticatedEgressAttestationCheck(attestation_file, key_file, FixedClock())
    with pytest.raises(ValueError, match="authentication failed"):
        await check.verify_default_denied(binding())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "payload",
    [b"{", b"[]", b'{"schema_version":1}'],
)
async def test_egress_attestation_rejects_invalid_json_and_schema_shapes(
    tmp_path: Path,
    payload: bytes,
) -> None:
    key_file = tmp_path / "installation-key"
    attestation_file = tmp_path / "egress.json"
    write_secret(key_file, b"i" * 32)
    write_secret(attestation_file, payload)
    check = AuthenticatedEgressAttestationCheck(attestation_file, key_file, FixedClock())
    with pytest.raises(ValueError, match="attestation"):
        await check.verify_default_denied(binding())


@pytest.mark.parametrize("raw", [None, "not-a-timeZ"])
def test_egress_attestation_rejects_non_rfc3339_times(raw: object) -> None:
    with pytest.raises(ValueError, match="time is invalid"):
        _parse_time(raw)


@pytest.mark.asyncio
async def test_installation_key_check_rejects_all_zero_material(tmp_path: Path) -> None:
    key_file = tmp_path / "installation-key"
    write_secret(key_file, bytes(32))
    with pytest.raises(RuntimeError, match="all-zero"):
        await InstallationKeyAccessCheck(key_file, "v1").verify(binding())


def test_settings_pin_internal_services_and_derive_selected_port_hosts() -> None:
    settings = CoreSettings(
        embedding_model_revision="embed-sha",
        reranking_model_revision="rerank-sha",
        extraction_model_revision="extract-sha",
        port=12_345,
    )
    assert settings.allowed_hosts == (
        "127.0.0.1:12345",
        "[::1]:12345",
        "localhost:12345",
        "core:12345",
    )
    assert settings.provider_gateway_capability_file == Path(
        "/run/provider-egress/agentmemory_provider_gateway_client_capability"
    )
    assert settings.provider_gateway_permit_hmac_key_file == Path(
        "/run/provider-egress/agentmemory_provider_gateway_permit_hmac_key"
    )
    assert settings.listen_host == "0.0.0.0"  # noqa: S104 -- Certified container bind.
    assert settings.neo4j_database == "neo4j"
    assert "0.0.0.0:12345" not in settings.allowed_hosts
    assert settings.database_path.name == "agentmemory.sqlite3"
    with pytest.raises(ValidationError):
        CoreSettings(
            embedding_model_revision="embed-sha",
            reranking_model_revision="rerank-sha",
            extraction_model_revision="extract-sha",
            embedding_url="https://example.com",  # pyright: ignore[reportArgumentType]
        )
    with pytest.raises(ValidationError):
        CoreSettings(
            embedding_model_revision="embed-sha",
            reranking_model_revision="rerank-sha",
            extraction_model_revision="extract-sha",
            neo4j_database="agentmemory",  # pyright: ignore[reportArgumentType]
        )
