"""Protected installation-key usability readiness check."""

from __future__ import annotations

import asyncio
import hmac
from typing import TYPE_CHECKING

from agentmemory.operations.adapters.outbound.protected_file import read_protected_file, zero_secret

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.operations.domain.readiness import ReadinessBinding


class InstallationKeyAccessCheck:
    """Prove that Core can read the exact 256-bit installation root key."""

    def __init__(self, key_file: Path, key_version: str) -> None:
        """Store only the protected reference and non-secret version."""
        self._key_file = key_file
        self._key_version = key_version

    async def verify(self, binding: ReadinessBinding) -> str:
        """Validate protected key access without reusing the IRK for another purpose."""
        await asyncio.to_thread(self._verify_sync, binding)
        return f"installation_key:{self._key_version}:usable"

    def _verify_sync(self, binding: ReadinessBinding) -> None:
        key = read_protected_file(self._key_file, frozenset({32}))
        try:
            del binding
            if hmac.compare_digest(key, bytes(32)):
                msg = "installation root key is an invalid all-zero value"
                raise RuntimeError(msg)
        finally:
            zero_secret(key)
