"""Owner-only append-only local audit journal for provider gateway decisions."""

from __future__ import annotations

import asyncio
import os
import stat
from typing import TYPE_CHECKING

from agentmemory.providers.adapters.strict_json import canonical_bytes
from agentmemory.providers.domain.errors import ProviderContainmentDependencyError

if TYPE_CHECKING:
    from pathlib import Path

    from agentmemory.providers.domain.containment import ProviderEgressDecisionFact

_MAX_FACT_BYTES = 4096
_ERR_AUDIT = "provider gateway audit is unavailable"


class AppendOnlyProviderEgressTelemetry:
    """Serialize content-free gateway facts to one protected durable journal."""

    def __init__(self, path: Path) -> None:
        """Store one absolute local journal path and an in-process append lock."""
        if not path.is_absolute():
            raise ValueError(_ERR_AUDIT)
        self._path = path
        self._lock = asyncio.Lock()

    async def record_egress(self, fact: ProviderEgressDecisionFact) -> None:
        """Append and synchronize one canonical fact without content or credentials."""
        payload = canonical_bytes(fact.document) + b"\n"
        if len(payload) > _MAX_FACT_BYTES:
            raise ProviderContainmentDependencyError(_ERR_AUDIT)
        async with self._lock:
            try:
                await asyncio.to_thread(self._append, payload)
            except OSError as error:
                raise ProviderContainmentDependencyError(_ERR_AUDIT) from error

    def _append(self, payload: bytes) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self._path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or metadata.st_gid != os.getegid()
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_nlink != 1
            ):
                raise OSError
            view = memoryview(payload)
            written = 0
            while written < len(payload):
                count = os.write(descriptor, view[written:])
                if count <= 0:
                    raise OSError
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
