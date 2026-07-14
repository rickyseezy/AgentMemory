"""Live local-provider and deterministic semantic round-trip checks."""

from __future__ import annotations

import asyncio
import hashlib
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from agentmemory.operations.domain.dependency_ports import (
        EmbeddingProviderPort,
        ExtractionProviderPort,
        ProviderIdentityProbePort,
        RerankingProviderPort,
        SemanticIndexPort,
        SemanticSmokeCanonicalPort,
    )
    from agentmemory.operations.domain.readiness import ReadinessBinding

_READINESS_CONTENT = (
    "AgentMemory preserves persistent memory across agent sessions and projects with evidence."
)
_READINESS_QUERY = "Which system preserves persistent memory across agent sessions?"
_EMBEDDING_DIMENSION = 1024


class LocalProviderIdentityCheck:
    """Cheaply prove all pinned local model services are loaded and reachable."""

    def __init__(
        self,
        embeddings: ProviderIdentityProbePort,
        reranker: ProviderIdentityProbePort,
        extractor: ProviderIdentityProbePort,
    ) -> None:
        """Bind one non-inference identity capability per provider role."""
        self._embeddings = embeddings
        self._reranker = reranker
        self._extractor = extractor

    async def verify(self, binding: ReadinessBinding) -> str:
        """Require exact roles, dimension, local-only policy, and pinned revisions."""
        del binding
        embedding, reranking, extraction = await asyncio.gather(
            self._embeddings.probe_identity(),
            self._reranker.probe_identity(),
            self._extractor.probe_identity(),
        )
        if (
            embedding.role != "embedding"
            or embedding.dimension != _EMBEDDING_DIMENSION
            or reranking.role != "reranking"
            or extraction.role != "extraction"
            or not embedding.local_only
            or not reranking.local_only
            or not extraction.local_only
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "local provider identity probe failed",
            )
        revisions = (
            f"{embedding.model_revision}:{reranking.model_revision}:{extraction.model_revision}"
        )
        return f"local_provider_identity:{hashlib.sha256(revisions.encode()).hexdigest()}"


class LocalProviderSetCheck:
    """Verify all three offline roles through live identity and behavior probes."""

    def __init__(
        self,
        embeddings: EmbeddingProviderPort,
        reranker: RerankingProviderPort,
        extractor: ExtractionProviderPort,
    ) -> None:
        """Require independent capability-specific provider ports."""
        self._embeddings = embeddings
        self._reranker = reranker
        self._extractor = extractor

    async def verify(self, binding: ReadinessBinding) -> str:
        """Validate identities, shape/order, dimension, ranking, and extraction behavior."""
        token = _binding_token(binding)
        embedding_attestation, reranking_attestation, extraction_attestation = await asyncio.gather(
            self._embeddings.probe(),
            self._reranker.probe(),
            self._extractor.probe(),
        )
        vector, reranked, subject = await asyncio.gather(
            self._embeddings.embed_document(f"provider-{token}", _READINESS_CONTENT),
            self._reranker.rerank(
                _READINESS_QUERY,
                (
                    ("relevant", _READINESS_CONTENT),
                    ("irrelevant", "A garden has green leaves and seasonal flowers."),
                ),
            ),
            self._extractor.extract_subject(_READINESS_CONTENT),
        )
        if (
            embedding_attestation.role != "embedding"
            or reranking_attestation.role != "reranking"
            or extraction_attestation.role != "extraction"
            or embedding_attestation.dimension != _EMBEDDING_DIMENSION
            or len(vector.values) != _EMBEDDING_DIMENSION
            or not reranked
            or reranked[0].content_id != "relevant"
            or subject.casefold() != "persistent memory"
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION, "local provider behavior probe failed"
            )
        revisions = (
            f"{embedding_attestation.model_revision}:"
            f"{reranking_attestation.model_revision}:"
            f"{extraction_attestation.model_revision}"
        )
        return f"local_providers:{hashlib.sha256(revisions.encode()).hexdigest()}:validated"


class SemanticWriteIndexRecallCheck:
    """Prove canonical write, local embedding, graph index, and authorized recall."""

    def __init__(
        self,
        canonical: SemanticSmokeCanonicalPort,
        embeddings: EmbeddingProviderPort,
        semantic_index: SemanticIndexPort,
    ) -> None:
        """Bind the complete smoke path through application-facing ports."""
        self._canonical = canonical
        self._embeddings = embeddings
        self._semantic_index = semantic_index

    async def verify(self, binding: ReadinessBinding) -> str:
        """Run and clean one deterministic synthetic end-to-end semantic canary."""
        canary_id = f"readiness-semantic-{_binding_token(binding)}"
        indexed = False
        canonical_written = False
        failure: BaseException | None = None
        source_digest = ""
        try:
            source_digest = await self._canonical.write(binding, canary_id, _READINESS_CONTENT)
            canonical_written = True
            document_vector = await self._embeddings.embed_document(canary_id, _READINESS_CONTENT)
            await self._semantic_index.index(binding, canary_id, source_digest, document_vector)
            indexed = True
            query_vector = await self._embeddings.embed_query(
                f"query-{canary_id}", _READINESS_QUERY
            )
            recalled = await self._semantic_index.recall(binding, query_vector, canary_id)
            _require_canary_recalled(recalled, canary_id)
        except asyncio.CancelledError as error:
            failure = error
        except Exception as error:  # noqa: BLE001 -- Preserve port errors until cleanup completes.
            failure = error
        cleanup_failure = await self._cleanup(
            binding,
            canary_id,
            indexed=indexed,
            canonical_written=canonical_written,
        )
        if failure is not None:
            raise failure
        if cleanup_failure is not None:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "semantic canary cleanup failed",
                retryable=False,
            ) from cleanup_failure
        return f"semantic:{source_digest}:write:index:recall:cleanup"

    async def _cleanup(
        self,
        binding: ReadinessBinding,
        canary_id: str,
        *,
        indexed: bool,
        canonical_written: bool,
    ) -> BaseException | None:
        failure: BaseException | None = None
        if indexed:
            failure = await _capture_cleanup(self._semantic_index.delete(binding, canary_id))
        if canonical_written:
            canonical_failure = await _capture_cleanup(self._canonical.delete(binding, canary_id))
            if failure is None:
                failure = canonical_failure
        return failure


def _require_canary_recalled(recalled: tuple[str, ...], canary_id: str) -> None:
    if not recalled or recalled[0] != canary_id:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "semantic canary was not recalled")


async def _capture_cleanup(cleanup: Awaitable[None]) -> BaseException | None:
    try:
        await cleanup
    except asyncio.CancelledError as error:
        return error
    except Exception as error:  # noqa: BLE001 -- Cleanup must report every adapter failure.
        return error
    return None


def _binding_token(binding: ReadinessBinding) -> str:
    return hashlib.sha256(
        f"{binding.operation_id.value}\x00{binding.generation_id.value}".encode()
    ).hexdigest()[:24]
