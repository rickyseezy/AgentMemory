"""Local path-evidence adapter using a launcher-provisioned Device identity."""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from agentmemory.identity.domain.errors import IdentityDependencyError
from agentmemory.identity.domain.value_objects import DeviceIdentity, Fingerprint, StableId

if TYPE_CHECKING:
    from agentmemory.identity.adapters.outbound.fingerprints import IdentityFingerprinter


@dataclass(frozen=True, slots=True)
class LocalDeviceIdentityAdapter:
    """Derive only keyed volume/path evidence; raw OS machine IDs never enter Core."""

    device_id: StableId
    device_fingerprint: Fingerprint
    verified: bool
    fingerprinter: IdentityFingerprinter

    async def observe(self, path: str) -> DeviceIdentity:
        """Resolve and stat a local workspace without returning the raw path."""
        try:
            logical_path, real_path, device_number, file_number = await asyncio.to_thread(
                _observe_path, path
            )
        except OSError as error:
            raise IdentityDependencyError from error
        volume = self.fingerprinter.opaque("FilesystemVolumeFingerprintV1", str(device_number))
        path_fingerprint = self.fingerprinter.path(
            self.device_id,
            volume.value,
            real_path,
        )
        logical_path_fingerprint = self.fingerprinter.path(
            self.device_id,
            volume.value,
            logical_path,
        )
        file_fingerprint = self.fingerprinter.opaque(
            "FilesystemObjectFingerprintV1",
            f"{device_number}:{file_number}",
        )
        return DeviceIdentity(
            self.device_id,
            self.device_fingerprint,
            volume,
            path_fingerprint,
            self.verified,
            logical_path_fingerprint,
            file_fingerprint,
        )


def _observe_path(path: str) -> tuple[str, str, int, int]:
    logical_path = Path(path).absolute()
    real_path = Path(path).resolve(strict=True)
    metadata = real_path.stat()
    if not real_path.is_dir():
        raise NotADirectoryError
    return os.fspath(logical_path), os.fspath(real_path), metadata.st_dev, metadata.st_ino
