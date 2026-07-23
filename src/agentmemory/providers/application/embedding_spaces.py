"""PRO-004 use cases for isolated embedding spaces and atomic vector batches."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.providers.domain.embedding_spaces import (
    EmbeddingSpace,
    IndexGeneration,
    IndexGenerationState,
    VectorWriteBatch,
)
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceValidationError,
)

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.embedding_space_ports import (
        EmbeddingSpaceIdentityGenerator,
        EmbeddingSpaceRepository,
        IndexGenerationProvisioner,
        VectorWriteReceipt,
        VectorWriteRepository,
    )
    from agentmemory.providers.domain.embedding_spaces import (
        EmbeddingSpaceDescriptor,
        VectorRecord,
    )

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_UUID7 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ADMIN_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})
_WRITE_ROLES = frozenset(
    {
        RetrievalRole.OWNER,
        RetrievalRole.ADMIN,
        RetrievalRole.WORKER,
    }
)
_ERR_REQUEST = "embedding space request is invalid"
_ERR_ACTION = "embedding space action is not authorized"


@dataclass(frozen=True, slots=True)
class EnsureIndexGenerationCommand:
    """Ensure one immutable semantic space and its dedicated physical index."""

    operation_id: str
    scope: AuthorizedScope
    profile_id: str
    capability_attestation_id: str
    descriptor: EmbeddingSpaceDescriptor
    requested_at: datetime

    def __post_init__(self) -> None:
        """Require stable idempotency, provider evidence, and UTC time."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or _UUID7.fullmatch(self.profile_id) is None
            or _DIGEST.fullmatch(self.capability_attestation_id) is None
            or not _is_utc(self.requested_at)
        ):
            raise EmbeddingSpaceValidationError(_ERR_REQUEST)

    @property
    def request_digest(self) -> str:
        """Bind idempotency to Brain, provider evidence, and semantic identity."""
        payload = json.dumps(
            {
                "brain_id": self.scope.brain_id.value,
                "capability_attestation_id": self.capability_attestation_id,
                "profile_id": self.profile_id,
                "space_fingerprint": self.descriptor.immutable_fingerprint,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True, slots=True)
class EnsureIndexGenerationHandler:
    """Reserve canonically, provision derived schema, then publish writability."""

    repository: EmbeddingSpaceRepository
    provisioner: IndexGenerationProvisioner
    identities: EmbeddingSpaceIdentityGenerator

    async def execute(self, command: EnsureIndexGenerationCommand) -> IndexGeneration:
        """Recover safely from retries without creating mixed physical indexes."""
        _authorize(
            command.scope,
            "provider.embedding_space.ensure",
            _ADMIN_ROLES,
        )
        candidate_space = EmbeddingSpace.create(
            space_id=self.identities.new(),
            profile_id=command.profile_id,
            capability_attestation_id=command.capability_attestation_id,
            descriptor=command.descriptor,
            created_at=command.requested_at,
        )
        candidate_generation = IndexGeneration.create(
            generation_id=self.identities.new(),
            brain_id=command.scope.brain_id.value,
            space=candidate_space,
            state=IndexGenerationState.CREATING,
            created_at=command.requested_at,
        )
        reservation = await self.repository.reserve(
            command.scope,
            command.operation_id,
            command.request_digest,
            candidate_space,
            candidate_generation,
        )
        await self.provisioner.ensure(reservation.space, reservation.generation)
        return await self.repository.complete(
            command.scope,
            command.operation_id,
            reservation.generation.generation_id,
            command.requested_at,
        )


@dataclass(frozen=True, slots=True)
class WriteVectorBatchCommand:
    """Write exact provider results to one compatible physical generation."""

    operation_id: str
    scope: AuthorizedScope
    space: EmbeddingSpace
    generation: IndexGeneration
    records: tuple[VectorRecord, ...]
    requested_at: datetime

    def __post_init__(self) -> None:
        """Validate only boundary coordinates before authorization."""
        if _OPERATION.fullmatch(self.operation_id) is None or not _is_utc(self.requested_at):
            raise EmbeddingSpaceValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class WriteVectorBatchHandler:
    """Authorize and validate the complete batch before entering the repository."""

    repository: VectorWriteRepository

    async def execute(self, command: WriteVectorBatchCommand) -> VectorWriteReceipt:
        """Perform no graph call unless every record matches one immutable space."""
        _authorize(command.scope, "provider.vector.write", _WRITE_ROLES)
        if command.scope.brain_id.value != command.generation.brain_id:
            raise EmbeddingSpaceValidationError(_ERR_REQUEST)
        batch = VectorWriteBatch.create(command.space, command.generation, command.records)
        return await self.repository.write(batch)


def _authorize(
    scope: AuthorizedScope,
    expected_action: str,
    roles: frozenset[RetrievalRole],
) -> None:
    if scope.action != expected_action or scope.role not in roles:
        raise EmbeddingSpaceAuthorizationError(_ERR_ACTION)


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)
