"""Role-aware provider application service."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.providers.domain.models import (
    MAX_BATCH_ITEMS,
    MAX_CONTENT_CHARACTERS,
    MAX_SUBJECT_CHARACTERS,
    ContentItem,
    EmbeddingPurpose,
    EmbeddingResult,
    ProviderIdentity,
    ProviderRole,
    RerankResult,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.ports import InferenceBackend

_QUERY_INSTRUCTION = (
    "Instruct: Retrieve relevant code and persistent project memory for this AgentMemory query\n"
    "Query: "
)


class ProviderService:
    """Expose only the capability assigned to this release-bound process."""

    def __init__(self, identity: ProviderIdentity, backend: InferenceBackend) -> None:
        """Bind an immutable identity to one concrete inference port."""
        self._identity = identity
        self._backend = backend

    @property
    def identity(self) -> ProviderIdentity:
        """Return the immutable loaded-model identity."""
        return self._identity

    async def probe(self, *, test_cancellation: bool) -> ProviderIdentity:
        """Prove model health and, on full readiness, request cancellation."""
        await self._backend.health()
        if test_cancellation:
            await self._backend.verify_cancellation()
        return self._identity

    async def embed(
        self,
        items: tuple[ContentItem, ...],
        purpose: EmbeddingPurpose,
    ) -> tuple[EmbeddingResult, ...]:
        """Generate real vectors with exact order, count, and dimension."""
        self._require_role(ProviderRole.EMBEDDING)
        _require_batch(items)
        contents = tuple(
            _QUERY_INSTRUCTION + item.content
            if purpose is EmbeddingPurpose.RETRIEVAL_QUERY
            else item.content
            for item in items
        )
        vectors = await self._backend.embed(contents)
        if len(vectors) != len(items):
            msg = "embedding backend returned the wrong item count"
            raise RuntimeError(msg)
        return tuple(
            EmbeddingResult(content_id=item.content_id, values=vector)
            for item, vector in zip(items, vectors, strict=True)
        )

    async def rerank(
        self,
        query: str,
        documents: tuple[ContentItem, ...],
    ) -> tuple[RerankResult, ...]:
        """Score every document once and return deterministic descending order."""
        self._require_role(ProviderRole.RERANKING)
        _require_batch(documents)
        if not 1 <= len(query) <= MAX_CONTENT_CHARACTERS:
            msg = "reranking query is invalid"
            raise ValueError(msg)
        content_ids = [document.content_id for document in documents]
        if len(content_ids) != len(set(content_ids)):
            msg = "reranking content identifiers must be unique"
            raise ValueError(msg)
        scores = await self._backend.rerank(
            query,
            tuple(document.content for document in documents),
        )
        if len(scores) != len(documents):
            msg = "reranking backend returned the wrong item count"
            raise RuntimeError(msg)
        results = tuple(
            RerankResult(content_id=document.content_id, score=score)
            for document, score in zip(documents, scores, strict=True)
        )
        return tuple(sorted(results, key=lambda result: (-result.score, result.content_id)))

    async def extract_subject(self, content: str) -> str:
        """Run schema-constrained local extraction and bound the final subject."""
        self._require_role(ProviderRole.EXTRACTION)
        if not 1 <= len(content) <= MAX_CONTENT_CHARACTERS:
            msg = "extraction content is invalid"
            raise ValueError(msg)
        subject = (await self._backend.extract_subject(content)).strip()
        if not 1 <= len(subject) <= MAX_SUBJECT_CHARACTERS or any(
            character in "\x00\r\n" for character in subject
        ):
            msg = "extraction backend returned an invalid subject"
            raise RuntimeError(msg)
        return subject

    def _require_role(self, expected: ProviderRole) -> None:
        if self._identity.role is not expected:
            msg = f"{expected.value} is not enabled in this provider process"
            raise ValueError(msg)


def _require_batch(items: tuple[ContentItem, ...]) -> None:
    if not 1 <= len(items) <= MAX_BATCH_ITEMS:
        msg = "provider batch size is invalid"
        raise ValueError(msg)
