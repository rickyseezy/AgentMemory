"""Closed production configuration for the isolated provider-egress gateway."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Literal, Self, cast

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

if TYPE_CHECKING:
    from collections.abc import Callable

_DEFAULT_SECRET_ROOT = Path("/run/secrets")
_DEFAULT_STATE_ROOT = Path("/var/lib/agentmemory")


class ProviderGatewaySettings(BaseSettings):
    """Only fixed local paths and the internal listener enter gateway composition."""

    model_config = SettingsConfigDict(
        env_prefix="AM_PROVIDER_GATEWAY_",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
    )

    listen_host: Literal["0.0.0.0"] = "0.0.0.0"  # noqa: S104  # nosec B104
    port: Literal[8080] = 8080
    client_capability_file: Path = (
        _DEFAULT_SECRET_ROOT / "agentmemory_provider_gateway_client_capability"
    )
    permit_hmac_key_file: Path = (
        _DEFAULT_SECRET_ROOT / "agentmemory_provider_gateway_permit_hmac_key"
    )
    credential_vault_file: Path = (
        _DEFAULT_SECRET_ROOT / "agentmemory_provider_gateway_credential_vault"
    )
    credential_vault_key_file: Path = (
        _DEFAULT_SECRET_ROOT / "agentmemory_provider_gateway_credential_vault_key"
    )
    credential_vault_hmac_key_file: Path = (
        _DEFAULT_SECRET_ROOT / "agentmemory_provider_gateway_credential_vault_hmac_key"
    )
    audit_file: Path = _DEFAULT_STATE_ROOT / "telemetry/provider-egress.jsonl"

    @model_validator(mode="after")
    def validate_paths(self) -> Self:
        """Reject relative, aliased, duplicate, or root-level runtime authority."""
        paths = (
            self.client_capability_file,
            self.permit_hmac_key_file,
            self.credential_vault_file,
            self.credential_vault_key_file,
            self.credential_vault_hmac_key_file,
            self.audit_file,
        )
        if any(
            not path.is_absolute() or path != Path(str(path)) or path == Path("/") for path in paths
        ) or len(set(paths)) != len(paths):
            msg = "provider gateway configuration is invalid"
            raise ValueError(msg)
        return self

    @classmethod
    def from_environment(cls) -> Self:
        """Load the closed gateway process contract from its environment."""
        factory = cast("Callable[[], Self]", cls)
        return factory()
