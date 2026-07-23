"""PRO-004 ports for canonical spaces, physical generations, and vector writes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Protocol

from agentmemory.providers.domain.errors import EmbeddingSpaceValidationError

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.embedding_spaces import (
        EmbeddingSpace,
        IndexGeneration,
        VectorWriteBatch,
    )

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_BATCH = 1000
_ERR_INPUT = "embedding space persistence evidence is invalid"


@dataclass(frozen=True, slots=True)
class EmbeddingGenerationReservation:
    """Canonical reservation returned before physical Neo4j provisioning."""

    space: EmbeddingSpace
    generation: IndexGeneration
    request_digest: str
    created: bool

    def __post_init__(self) -> None:
        """Require exact space/generation binding and a content-addressed request."""
        if (
            self.generation.space_id != self.space.space_id
            or self.generation.space_fingerprint != self.space.immutable_fingerprint
            or _DIGEST.fullmatch(self.request_digest) is None
            or type(self.created) is not bool
        ):
            raise EmbeddingSpaceValidationError(_ERR_INPUT)


@dataclass(frozen=True, slots=True)
class VectorWriteReceipt:
    """Content-free proof that one complete vector batch committed."""

    generation_id: str
    space_fingerprint: str
    record_count: int
    batch_digest: str
    committed_at: datetime

    def __post_init__(self) -> None:
        """Reject incomplete write evidence."""
        if (
            any(
                _DIGEST.fullmatch(value) is None
                for value in (self.space_fingerprint, self.batch_digest)
            )
            or not 1 <= self.record_count <= _MAX_BATCH
            or self.committed_at.tzinfo is None
            or self.committed_at.utcoffset() != timedelta(0)
        ):
            raise EmbeddingSpaceValidationError(_ERR_INPUT)


class EmbeddingSpaceRepository(Protocol):
    """Canonical SQLite authority for immutable spaces and generation lifecycle."""

    async def reserve(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        candidate_space: EmbeddingSpace,
        candidate_generation: IndexGeneration,
    ) -> EmbeddingGenerationReservation:
        """Reserve or replay the one generation for a Brain and space."""
        ...

    async def complete(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        generation_id: str,
        completed_at: datetime,
    ) -> IndexGeneration:
        """Mark a physically verified generation ready for population."""
        ...


class IndexGenerationProvisioner(Protocol):
    """Derived Neo4j schema and metadata provisioner."""

    async def ensure(self, space: EmbeddingSpace, generation: IndexGeneration) -> None:
        """Create and prove the exact UUID-derived index contract idempotently."""
        ...


class VectorWriteRepository(Protocol):
    """Atomic, generation-isolated graph vector writer."""

    async def write(self, batch: VectorWriteBatch) -> VectorWriteReceipt:
        """Commit one already validated batch in one Neo4j transaction."""
        ...


class EmbeddingSpaceIdentityGenerator(Protocol):
    """Generate unpredictable RFC 9562 UUIDv7 aggregate identities."""

    def new(self) -> str:
        """Return one fresh identity."""
        ...
