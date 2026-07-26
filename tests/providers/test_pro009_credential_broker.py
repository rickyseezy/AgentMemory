"""PRO-009 gateway-only protected credential broker tests."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from agentmemory.providers.adapters.credential_broker import (
    ProtectedFileProviderCredentialBroker,
    ProviderCredentialBinding,
)
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


def binding(**changes: object) -> ProviderCredentialBinding:
    values: dict[str, object] = {
        "profile_id": PROFILE_ID,
        "attestation_id": PROFILE_ATTESTATION_ID,
        "file_name": "openai.key",
        "header_name": "Authorization",
        "prefix": b"Bearer ",
    }
    values.update(changes)
    return ProviderCredentialBinding(**values)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_broker_reads_only_exact_bound_owner_only_file(tmp_path: Path) -> None:
    path = tmp_path / "openai.key"
    path.write_bytes(b"opaque-key")
    path.chmod(0o600)
    broker = ProtectedFileProviderCredentialBroker(
        tmp_path,
        {(PROFILE_ID, PROFILE_ATTESTATION_ID): binding()},
    )

    credential = await broker.resolve(permit())

    assert credential.header_name == "Authorization"
    assert credential.text() == "Bearer opaque-key"
    assert "opaque-key" not in repr(credential)
    credential.destroy()
    assert credential.value == bytearray(len(b"Bearer opaque-key"))


@pytest.mark.asyncio
async def test_broker_denies_unbound_profile_before_filesystem_access(tmp_path: Path) -> None:
    broker = ProtectedFileProviderCredentialBroker(
        tmp_path,
        {(PROFILE_ID, PROFILE_ATTESTATION_ID): binding()},
    )
    with pytest.raises(ProviderContainmentDeniedError, match="denied"):
        await broker.resolve(
            replace(
                permit(),
                profile_id="018f0000-0000-7000-8000-000000000999",
            )
        )


@pytest.mark.asyncio
async def test_broker_rejects_symlink_or_group_readable_credential(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.write_bytes(b"secret")
    outside.chmod(0o600)
    path = tmp_path / "openai.key"
    path.symlink_to(outside)
    broker = ProtectedFileProviderCredentialBroker(
        tmp_path,
        {(PROFILE_ID, PROFILE_ATTESTATION_ID): binding()},
    )
    with pytest.raises(ProviderContainmentDependencyError, match="unavailable"):
        await broker.resolve(permit())
    path.unlink()
    path.write_bytes(b"secret")
    path.chmod(0o640)
    with pytest.raises(ProviderContainmentDependencyError, match="unavailable"):
        await broker.resolve(permit())
    path.chmod(0o600)


@pytest.mark.parametrize(
    "changed",
    [
        {"file_name": "../secret"},
        {"header_name": "Cookie"},
        {"prefix": b"x\n"},
        {"profile_id": "not-a-uuid"},
    ],
)
def test_binding_rejects_ambient_authority(changed: dict[str, object]) -> None:
    with pytest.raises(ProviderContainmentValidationError):
        binding(**changed)


def test_broker_rejects_relative_empty_or_mismatched_binding_authority(tmp_path: Path) -> None:
    valid = binding()
    for directory, bindings in (
        (
            Path("relative"),
            {(PROFILE_ID, PROFILE_ATTESTATION_ID): valid},
        ),
        (tmp_path, {}),
        (
            tmp_path,
            {("wrong-profile", PROFILE_ATTESTATION_ID): valid},
        ),
    ):
        with pytest.raises(ProviderContainmentValidationError, match="binding"):
            ProtectedFileProviderCredentialBroker(directory, bindings)
