"""PRO-009 production gateway configuration and composition tests."""

from __future__ import annotations

import base64
import hashlib
import hmac
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.routing import APIRoute

from agentmemory.providers.adapters.strict_json import canonical_bytes
from agentmemory.providers.infrastructure.gateway_composition import create_gateway_app
from agentmemory.providers.infrastructure.gateway_configuration import ProviderGatewaySettings


def settings(tmp_path: Path) -> ProviderGatewaySettings:
    capability = tmp_path / "client-capability"
    permit = tmp_path / "permit-hmac"
    vault_key = tmp_path / "vault-key"
    vault_hmac_key = tmp_path / "vault-hmac-key"
    vault = tmp_path / "credential-vault.json"
    audit = tmp_path / "audit" / "egress.jsonl"
    audit.parent.mkdir()
    for path, value in (
        (capability, b"c" * 32),
        (permit, b"p" * 32),
        (vault_key, b"e" * 32),
        (vault_hmac_key, b"h" * 32),
    ):
        path.write_bytes(value)
        path.chmod(0o600)
    profile_id = "018f0000-0000-7000-8000-000000000901"
    attestation_id = hashlib.sha256(b"profile-attestation").hexdigest()
    header_name = "Authorization"
    prefix = "Bearer "
    nonce = bytes(range(12))
    aad = canonical_bytes(
        {
            "attestation_id": attestation_id,
            "header_name": header_name,
            "prefix": prefix,
            "profile_id": profile_id,
            "schema_version": 1,
        }
    )
    ciphertext = AESGCM(b"e" * 32).encrypt(nonce, b"provider-key", aad)
    unsigned: dict[str, object] = {
        "entries": [
            {
                "attestation_id": attestation_id,
                "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
                "header_name": header_name,
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "prefix": prefix,
                "profile_id": profile_id,
            }
        ],
        "schema_version": 1,
    }
    vault.write_bytes(
        canonical_bytes(
            {
                **unsigned,
                "hmac_sha256": hmac.digest(
                    b"h" * 32,
                    canonical_bytes(unsigned),
                    hashlib.sha256,
                ).hex(),
            }
        )
    )
    vault.chmod(0o600)
    return ProviderGatewaySettings(
        client_capability_file=capability,
        permit_hmac_key_file=permit,
        credential_vault_file=vault,
        credential_vault_key_file=vault_key,
        credential_vault_hmac_key_file=vault_hmac_key,
        audit_file=audit,
    )


def test_gateway_settings_accept_only_absolute_closed_runtime_paths(tmp_path: Path) -> None:
    value = settings(tmp_path)

    assert value.listen_host == "0.0.0.0"  # noqa: S104 -- Exact closed listener contract.
    assert value.port == 8080
    assert value.client_capability_file.is_absolute()

    with pytest.raises(ValueError, match="configuration"):
        ProviderGatewaySettings(
            client_capability_file=tmp_path / "capability",
            permit_hmac_key_file=tmp_path / "permit",
            credential_vault_file=tmp_path / "vault",
            credential_vault_key_file=tmp_path / "vault-key",
            credential_vault_hmac_key_file=Path("relative"),
            audit_file=tmp_path / "audit",
        )


def test_production_composition_loads_encrypted_vault_and_exposes_closed_routes(
    tmp_path: Path,
) -> None:
    application = create_gateway_app(settings(tmp_path))

    routes = {route.path for route in application.routes if isinstance(route, APIRoute)}
    assert routes == {"/v1/health", "/v1/provider-operations/execute"}


def test_production_composition_fails_closed_on_tampered_vault_document(
    tmp_path: Path,
) -> None:
    value = settings(tmp_path)
    value.credential_vault_file.write_bytes(
        value.credential_vault_file.read_bytes().replace(
            b"Authorization",
            b"X-Api-Key----",
        )
    )

    with pytest.raises(ValueError, match="vault"):
        create_gateway_app(value)


def test_gateway_image_is_dedicated_nonroot_and_contains_no_model_runtime() -> None:
    root = Path(__file__).resolve().parents[2]
    dockerfile = (root / "deploy/docker/provider-gateway.Dockerfile").read_text()

    assert "USER 10001:10001" in dockerfile
    assert 'ENTRYPOINT ["agentmemory-provider-gateway"]' in dockerfile
    assert 'CMD ["agentmemory-provider-gateway", "healthcheck"]' in dockerfile
    assert "llama.cpp" not in dockerfile
    assert "agentmemory-core" not in dockerfile
