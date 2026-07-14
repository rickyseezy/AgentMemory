"""Per-request protected-file authentication for launcher-to-Core calls."""

from __future__ import annotations

import asyncio
import hmac
import re
from typing import TYPE_CHECKING

from agentmemory.operations.adapters.outbound.protected_file import read_protected_file, zero_secret
from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from pathlib import Path

_BEARER_PATTERN = re.compile(r"^Bearer ([0-9a-f]{64})$")


class ApiAuthenticator:
    """Authenticate a 256-bit opaque credential without retaining it between calls."""

    def __init__(self, credential_file: Path) -> None:
        """Store only the owner-protected secret reference."""
        self._credential_file = credential_file

    async def authenticate(self, authorization: str | None) -> None:
        """Require the lowercase-hex presentation of the exact protected credential."""
        matched = _BEARER_PATTERN.fullmatch(authorization or "")
        supplied = matched.group(1) if matched is not None else ""
        expected = await asyncio.to_thread(
            read_protected_file,
            self._credential_file,
            frozenset({32}),
        )
        try:
            if not supplied or not hmac.compare_digest(supplied, expected.hex()):
                raise OperationError(ErrorCode.UNAUTHENTICATED, "authentication is required")
        finally:
            zero_secret(expected)
