"""Protected-file provider credential broker confined to the egress gateway."""

from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING
from uuid import UUID

from agentmemory.providers.adapters.protected_file import (
    read_provider_credential,
    zero,
)
from agentmemory.providers.domain.containment import ProviderGatewayCredential
from agentmemory.providers.domain.errors import (
    ProviderContainmentDeniedError,
    ProviderContainmentDependencyError,
    ProviderContainmentValidationError,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from agentmemory.providers.domain.containment import ProviderEgressPermit

_FILE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_MAX_PREFIX_BYTES = 32
_MAX_CREDENTIAL_BYTES = 4096
_UUID_VERSION = 7
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ASCII_SPACE = 0x20
_ASCII_TILDE = 0x7E
_ERR_BINDING = "provider credential binding is invalid"
_ERR_DENIED = "provider credential access is denied"
_ERR_UNAVAILABLE = "provider credential is unavailable"


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderCredentialBinding:
    """One immutable profile-attestation-to-protected-file mapping."""

    profile_id: str
    attestation_id: str
    file_name: str
    header_name: str
    prefix: bytes

    def __post_init__(self) -> None:
        """Reject traversal, mutable profile aliases, or unbounded header prefixes."""
        try:
            profile = UUID(self.profile_id)
        except (TypeError, ValueError) as error:
            raise ProviderContainmentValidationError(_ERR_BINDING) from error
        try:
            self.prefix.decode("ascii")
        except UnicodeDecodeError as error:
            raise ProviderContainmentValidationError(_ERR_BINDING) from error
        if (
            profile.version != _UUID_VERSION
            or _DIGEST.fullmatch(self.attestation_id) is None
            or _FILE_NAME.fullmatch(self.file_name) is None
            or self.header_name not in {"Authorization", "X-Goog-Api-Key", "X-Api-Key"}
            or len(self.prefix) > _MAX_PREFIX_BYTES
            or any(value < _ASCII_SPACE or value > _ASCII_TILDE for value in self.prefix)
        ):
            raise ProviderContainmentValidationError(_ERR_BINDING)


class ProtectedFileProviderCredentialBroker:
    """Resolve only prebound owner-projected credentials inside one directory."""

    def __init__(
        self,
        directory: Path,
        bindings: Mapping[tuple[str, str], ProviderCredentialBinding],
    ) -> None:
        """Snapshot a closed unique binding set without reading any credential."""
        if not directory.is_absolute() or not bindings:
            raise ProviderContainmentValidationError(_ERR_BINDING)
        copied = dict(bindings)
        if any(key != (value.profile_id, value.attestation_id) for key, value in copied.items()):
            raise ProviderContainmentValidationError(_ERR_BINDING)
        self._directory = directory
        self._bindings = MappingProxyType(copied)

    async def resolve(self, permit: ProviderEgressPermit) -> ProviderGatewayCredential:
        """Read the exact bound secret and return one mutable provider header."""
        binding = self._bindings.get((permit.profile_id, permit.profile_attestation_id))
        if binding is None:
            raise ProviderContainmentDeniedError(_ERR_DENIED)
        path = self._directory / binding.file_name
        try:
            value = read_provider_credential(
                path,
                maximum_bytes=_MAX_CREDENTIAL_BYTES - len(binding.prefix),
            )
        except (OSError, PermissionError, ValueError) as error:
            raise ProviderContainmentDependencyError(_ERR_UNAVAILABLE) from error
        combined = bytearray(binding.prefix)
        try:
            combined.extend(value)
            return ProviderGatewayCredential(
                header_name=binding.header_name,
                value=combined,
            )
        except Exception:
            zero(combined)
            raise
        finally:
            zero(value)
