from __future__ import annotations

import math
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.providers.application.service import ProviderService
from agentmemory.providers.domain.models import (
    EMBEDDING_DIMENSION,
    ContentItem,
    EmbeddingPurpose,
    EmbeddingResult,
    ProviderIdentity,
    ProviderRole,
    RerankResult,
)

if TYPE_CHECKING:
    from tests.providers.conftest import RecordingBackend

REVISION = "a" * 40


def identity(role: ProviderRole) -> ProviderIdentity:
    return ProviderIdentity(
        role=role,
        model_id={
            ProviderRole.EMBEDDING: "Qwen/Qwen3-Embedding-0.6B",
            ProviderRole.RERANKING: "Qwen/Qwen3-Reranker-0.6B",
            ProviderRole.EXTRACTION: "Qwen/Qwen3-4B-GGUF-Q4_K_M",
        }[role],
        model_revision=REVISION,
        dimension=EMBEDDING_DIMENSION if role is ProviderRole.EMBEDDING else None,
    )


@pytest.mark.parametrize("role", list(ProviderRole))
def test_provider_identity_accepts_only_default_bom(role: ProviderRole) -> None:
    assert identity(role).role is role
    with pytest.raises(ValueError, match="release-bound"):
        ProviderIdentity(role, "wrong", REVISION, None)


@pytest.mark.parametrize(
    ("revision", "dimension"),
    [("short", EMBEDDING_DIMENSION), ("g" * 40, EMBEDDING_DIMENSION), ("a" * 40, 3)],
)
def test_provider_identity_rejects_revision_and_dimension_drift(
    revision: str, dimension: int
) -> None:
    with pytest.raises(ValueError, match="release-bound"):
        ProviderIdentity(
            ProviderRole.EMBEDDING,
            "Qwen/Qwen3-Embedding-0.6B",
            revision,
            dimension,
        )


@pytest.mark.parametrize(
    ("content_id", "content"),
    [("", "x"), ("x" * 129, "x"), ("bad\r", "x"), ("id", ""), ("id", "x" * 32_769)],
)
def test_content_item_rejects_unbounded_values(content_id: str, content: str) -> None:
    with pytest.raises(ValueError, match="content item"):
        ContentItem(content_id, content)


def test_result_values_reject_backend_numeric_drift() -> None:
    assert len(EmbeddingResult("id", (0.0,) * EMBEDDING_DIMENSION).values) == EMBEDDING_DIMENSION
    assert RerankResult("id", 0.5).score == 0.5
    with pytest.raises(ValueError, match="vector space"):
        EmbeddingResult("id", (0.0,))
    with pytest.raises(ValueError, match="vector space"):
        EmbeddingResult("id", (math.nan,) * EMBEDDING_DIMENSION)
    with pytest.raises(ValueError, match="not finite"):
        RerankResult("id", math.inf)


@pytest.mark.asyncio
async def test_probe_runs_health_and_optional_real_cancellation(
    backend: RecordingBackend,
) -> None:
    service = ProviderService(identity(ProviderRole.EMBEDDING), backend)
    assert (await service.probe(test_cancellation=False)).model_revision == REVISION
    assert backend.calls == [("health", None)]
    backend.calls.clear()
    await service.probe(test_cancellation=True)
    assert backend.calls == [("health", None), ("cancel", None)]


@pytest.mark.asyncio
async def test_embedding_applies_query_instruction_and_preserves_identifiers(
    backend: RecordingBackend,
) -> None:
    service = ProviderService(identity(ProviderRole.EMBEDDING), backend)
    items = (ContentItem("b", "query"), ContentItem("a", "other"))
    result = await service.embed(items, EmbeddingPurpose.RETRIEVAL_QUERY)
    assert [item.content_id for item in result] == ["b", "a"]
    call = backend.calls[-1]
    assert call[0] == "embed"
    called_contents = cast("tuple[str, ...]", call[1])
    assert all(content.startswith("Instruct:") for content in called_contents)

    backend.calls.clear()
    await service.embed(items, EmbeddingPurpose.RETRIEVAL_DOCUMENT)
    assert backend.calls[-1] == ("embed", ("query", "other"))


@pytest.mark.asyncio
async def test_embedding_rejects_wrong_role_batch_and_backend_count(
    backend: RecordingBackend,
) -> None:
    with pytest.raises(ValueError, match="not enabled"):
        await ProviderService(identity(ProviderRole.RERANKING), backend).embed(
            (ContentItem("id", "x"),), EmbeddingPurpose.RETRIEVAL_DOCUMENT
        )
    service = ProviderService(identity(ProviderRole.EMBEDDING), backend)
    with pytest.raises(ValueError, match="batch size"):
        await service.embed((), EmbeddingPurpose.RETRIEVAL_DOCUMENT)
    backend.vectors = ((0.0,) * EMBEDDING_DIMENSION,) * 2
    with pytest.raises(RuntimeError, match="wrong item count"):
        await service.embed((ContentItem("id", "x"),), EmbeddingPurpose.RETRIEVAL_DOCUMENT)


@pytest.mark.asyncio
async def test_reranking_returns_finite_descending_stable_results(
    backend: RecordingBackend,
) -> None:
    backend.scores = (0.2, 0.9, 0.9)
    service = ProviderService(identity(ProviderRole.RERANKING), backend)
    result = await service.rerank(
        "query",
        (ContentItem("c", "third"), ContentItem("b", "second"), ContentItem("a", "first")),
    )
    assert [(item.content_id, item.score) for item in result] == [
        ("a", 0.9),
        ("b", 0.9),
        ("c", 0.2),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("query", ["", "q" * 32_769])
async def test_reranking_rejects_invalid_query(query: str, backend: RecordingBackend) -> None:
    service = ProviderService(identity(ProviderRole.RERANKING), backend)
    with pytest.raises(ValueError, match="query"):
        await service.rerank(query, (ContentItem("id", "doc"),))


@pytest.mark.asyncio
async def test_reranking_rejects_role_duplicates_and_count(
    backend: RecordingBackend,
) -> None:
    documents = (ContentItem("same", "one"), ContentItem("same", "two"))
    with pytest.raises(ValueError, match="not enabled"):
        await ProviderService(identity(ProviderRole.EXTRACTION), backend).rerank("q", documents)
    service = ProviderService(identity(ProviderRole.RERANKING), backend)
    with pytest.raises(ValueError, match="unique"):
        await service.rerank("q", documents)
    with pytest.raises(ValueError, match="batch"):
        await service.rerank("q", ())
    backend.scores = (0.1, 0.2)
    with pytest.raises(RuntimeError, match="wrong item count"):
        await service.rerank("q", (ContentItem("id", "doc"),))


@pytest.mark.asyncio
async def test_extraction_bounds_and_normalizes_subject(
    backend: RecordingBackend,
) -> None:
    backend.subject = "  persistent memory  "
    service = ProviderService(identity(ProviderRole.EXTRACTION), backend)
    assert await service.extract_subject("content") == "persistent memory"
    for subject in ("", "x" * 129, "bad\nsubject"):
        backend.subject = subject
        with pytest.raises(RuntimeError, match="invalid subject"):
            await service.extract_subject("content")
    for content in ("", "x" * 32_769):
        with pytest.raises(ValueError, match="content"):
            await service.extract_subject(content)
    with pytest.raises(ValueError, match="not enabled"):
        await ProviderService(identity(ProviderRole.EMBEDDING), backend).extract_subject("x")
