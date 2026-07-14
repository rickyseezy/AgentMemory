"""Narrow dependency capabilities required by PF-001 readiness probes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from decimal import Decimal

    from agentmemory.operations.domain.readiness import ReadinessBinding
    from agentmemory.operations.domain.value_objects import Uuid7Id


@dataclass(frozen=True, slots=True)
class ProviderAttestation:
    """Validated non-secret result of one local provider live probe."""

    role: str
    model_id: str
    model_revision: str
    dimension: int | None
    supports_cancellation: bool
    local_only: bool


@dataclass(frozen=True, slots=True)
class EmbeddingVector:
    """One ordered finite vector from the pinned local embedding space."""

    content_id: str
    values: tuple[float, ...]
    model_id: str
    model_revision: str


@dataclass(frozen=True, slots=True)
class RerankItem:
    """One local reranker result."""

    content_id: str
    score: Decimal


class EmbeddingProviderPort(Protocol):
    """Probe and call the pinned local embedding provider."""

    async def probe(self) -> ProviderAttestation:
        """Validate live capability and immutable model identity."""
        ...

    async def embed_document(self, content_id: str, content: str) -> EmbeddingVector:
        """Embed one bounded local-only readiness document."""
        ...

    async def embed_query(self, content_id: str, content: str) -> EmbeddingVector:
        """Embed one bounded local-only readiness query."""
        ...


class RerankingProviderPort(Protocol):
    """Probe the pinned local reranking provider."""

    async def probe(self) -> ProviderAttestation:
        """Validate live reranking capability and model identity."""
        ...

    async def rerank(
        self,
        query: str,
        documents: tuple[tuple[str, str], ...],
    ) -> tuple[RerankItem, ...]:
        """Rerank bounded local-only readiness documents."""
        ...


class ExtractionProviderPort(Protocol):
    """Probe the pinned local extraction provider."""

    async def probe(self) -> ProviderAttestation:
        """Validate local extraction capability and model identity."""
        ...

    async def extract_subject(self, content: str) -> str:
        """Return one bounded deterministic readiness subject."""
        ...


class ProviderIdentityProbePort(Protocol):
    """Execute a cheap live identity probe without model inference."""

    async def probe_identity(self) -> ProviderAttestation:
        """Validate the pinned loaded model identity and readiness metadata."""
        ...


class SemanticSmokeCanonicalPort(Protocol):
    """Persist and remove the canonical source of a readiness canary."""

    async def write(self, binding: ReadinessBinding, canary_id: str, content: str) -> str:
        """Commit canary plus projection intent and return its source digest."""
        ...

    async def delete(self, binding: ReadinessBinding, canary_id: str) -> None:
        """Tombstone and purge the canary idempotently after the probe."""
        ...


class SemanticIndexPort(Protocol):
    """Project, recall, and delete one authorized semantic canary."""

    async def index(
        self,
        binding: ReadinessBinding,
        canary_id: str,
        source_digest: str,
        vector: EmbeddingVector,
    ) -> None:
        """Write an idempotent Brain/generation-scoped vector projection."""
        ...

    async def recall(
        self,
        binding: ReadinessBinding,
        query_vector: EmbeddingVector,
        expected_canary_id: str,
    ) -> tuple[str, ...]:
        """Return only authorized canary IDs ranked inside the active generation."""
        ...

    async def delete(self, binding: ReadinessBinding, canary_id: str) -> None:
        """Remove the readiness projection idempotently."""
        ...


class GraphCompatibilityPort(Protocol):
    """Verify the exact Neo4j server, driver, schema, and index contract."""

    async def verify(self, binding: ReadinessBinding) -> str:
        """Return a canonical non-secret compatibility proof."""
        ...


class ActiveBrainPort(Protocol):
    """Resolve the sole bootstrap Brain for installation-time operations."""

    async def get(self) -> Uuid7Id:
        """Return the exact active local Brain or fail on ambiguity."""
        ...


class EgressAttestationPort(Protocol):
    """Verify the launcher's authenticated runtime network inspection."""

    async def verify_default_denied(self, binding: ReadinessBinding) -> str:
        """Return canonical proof that no external runtime network is attached."""
        ...
