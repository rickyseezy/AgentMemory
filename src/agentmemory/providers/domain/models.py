"""Immutable value objects for the local-provider protocol."""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

EMBEDDING_DIMENSION = 1024
MAX_CONTENT_CHARACTERS = 32_768
MAX_BATCH_ITEMS = 32
MAX_CONTENT_ID_CHARACTERS = 128
MAX_SUBJECT_CHARACTERS = 128


class ProviderRole(StrEnum):
    """Closed default provider roles."""

    EMBEDDING = "embedding"
    RERANKING = "reranking"
    EXTRACTION = "extraction"


class EmbeddingPurpose(StrEnum):
    """Embedding spaces exposed by the protocol."""

    RETRIEVAL_DOCUMENT = "retrieval_document"
    RETRIEVAL_QUERY = "retrieval_query"


@dataclass(frozen=True, slots=True)
class ProviderIdentity:
    """Release-bound identity of one loaded provider process."""

    role: ProviderRole
    model_id: str
    model_revision: str
    dimension: int | None

    def __post_init__(self) -> None:
        """Reject identities that could not be signed into the default BOM."""
        expected_model = {
            ProviderRole.EMBEDDING: "Qwen/Qwen3-Embedding-0.6B",
            ProviderRole.RERANKING: "Qwen/Qwen3-Reranker-0.6B",
            ProviderRole.EXTRACTION: "Qwen/Qwen3-4B-GGUF-Q4_K_M",
        }[self.role]
        if (
            self.model_id != expected_model
            or len(self.model_revision) not in {40, 64}
            or any(character not in "0123456789abcdef" for character in self.model_revision)
            or (self.role is ProviderRole.EMBEDDING and self.dimension != EMBEDDING_DIMENSION)
            or (self.role is not ProviderRole.EMBEDDING and self.dimension is not None)
        ):
            msg = "provider identity is not the release-bound default"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ContentItem:
    """One bounded item with a caller-stable identity."""

    content_id: str
    content: str

    def __post_init__(self) -> None:
        """Enforce the application boundary independently of HTTP validation."""
        if (
            not 1 <= len(self.content_id) <= MAX_CONTENT_ID_CHARACTERS
            or not 1 <= len(self.content) <= MAX_CONTENT_CHARACTERS
            or any(character in "\x00\r" for character in self.content_id)
        ):
            msg = "provider content item is invalid"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class EmbeddingResult:
    """One finite vector in the pinned 1024-dimensional space."""

    content_id: str
    values: tuple[float, ...]

    def __post_init__(self) -> None:
        """Reject backend shape drift before it crosses the protocol."""
        if len(self.values) != EMBEDDING_DIMENSION or not all(
            math.isfinite(value) for value in self.values
        ):
            msg = "embedding result violated the pinned vector space"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class RerankResult:
    """One finite relevance score."""

    content_id: str
    score: float

    def __post_init__(self) -> None:
        """Reject NaN and infinity at the model boundary."""
        if not math.isfinite(self.score):
            msg = "reranking score is not finite"
            raise ValueError(msg)
