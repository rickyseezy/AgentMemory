"""Local installation/owner/Brain bootstrap domain values."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import DomainValidationError

if TYPE_CHECKING:
    from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest, Uuid7Id

_BRAIN_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")


class BootstrapDisposition(StrEnum):
    """Observable idempotent bootstrap outcome."""

    CREATED = "created"
    ALREADY_INITIALIZED = "already_initialized"


@dataclass(frozen=True, slots=True)
class BootstrapRequest:
    """Exact immutable identity records created for the first local Brain."""

    command_id: OperationId
    installation_id: Uuid7Id
    owner_principal_id: Uuid7Id
    owner_grant_id: Uuid7Id
    owner_subject_digest: Sha256Digest
    brain_id: Uuid7Id
    brain_name: str
    release_digest: Sha256Digest
    generation_id: Uuid7Id

    def __post_init__(self) -> None:
        """Reject names whose normalized identity is ambiguous."""
        if _BRAIN_NAME.fullmatch(self.brain_name) is None:
            msg = "Brain name is invalid"
            raise DomainValidationError(msg)
