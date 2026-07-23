"""Certified Cohere embedding and reranking adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.providers.adapters.builtins.base import (
    CertifiedRemoteAdapter,
    ParsedProbe,
    certified_manifest,
    probe_content_ids,
    probe_inputs,
    probe_query,
    require_float,
    require_list,
    require_object,
    require_vector,
)
from agentmemory.providers.domain.capability_probe import EmbeddingProbeBatch, RerankingProbeBatch
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderLimits,
    ProviderOperation,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)

if TYPE_CHECKING:
    from agentmemory.providers.domain.profile_ports import ProviderGatewayTransport

_PURPOSE_MAP = {
    CanonicalPurpose.RETRIEVAL_QUERY: "search_query",
    CanonicalPurpose.RETRIEVAL_DOCUMENT: "search_document",
    CanonicalPurpose.CODE_QUERY: "search_query",
    CanonicalPurpose.CODE_DOCUMENT: "search_document",
    CanonicalPurpose.SEMANTIC_SIMILARITY: "classification",
    CanonicalPurpose.CLASSIFICATION: "classification",
    CanonicalPurpose.CLUSTERING: "clustering",
}
COHERE_MANIFEST = certified_manifest(
    adapter_id="cohere",
    vendor="cohere",
    operations=(ProviderOperation.EMBEDDING, ProviderOperation.RERANKING),
    purposes=tuple(sorted(CanonicalPurpose, key=str)),
    limits=ProviderLimits(96, 8 * 1024 * 1024, 32_000, 1_000_000, 120_000),
)


class CohereProtocol:
    """Map canonical purposes to Cohere v2 input types and strict result shapes."""

    def request(
        self,
        operation: ProviderOperation,
        purpose: CanonicalPurpose,
        model_id: str,
    ) -> tuple[str, dict[str, object]]:
        """Build one Cohere v2 embedding or reranking probe."""
        if operation is ProviderOperation.EMBEDDING:
            return "/v2/embed", {
                "embedding_types": ["float"],
                "input_type": _PURPOSE_MAP[purpose],
                "model": model_id,
                "texts": list(probe_inputs()),
                "truncate": "NONE",
            }
        return "/v2/rerank", {
            "documents": list(probe_inputs()),
            "model": model_id,
            "query": probe_query(),
            "top_n": len(probe_inputs()),
        }

    def parse(
        self,
        operation: ProviderOperation,
        model_id: str,
        response: object,
    ) -> ParsedProbe:
        """Validate Cohere's operation-specific count and numeric response."""
        del model_id
        root = require_object(response)
        if operation is ProviderOperation.EMBEDDING:
            embeddings = require_object(root.get("embeddings"))
            vectors_raw = require_list(embeddings.get("float"), len(probe_inputs()))
            vectors = [require_vector(item) for item in vectors_raw]
            if len({len(vector) for vector in vectors}) != 1:
                raise ValueError
            return ParsedProbe(
                len(vectors[0]),
                VectorDtype.FLOAT32,
                VectorNormalization.PROVIDER_DEFINED,
                SimilarityMetric.COSINE,
                EmbeddingProbeBatch(
                    probe_content_ids(),
                    tuple(vectors),
                    VectorDtype.FLOAT32,
                    VectorNormalization.PROVIDER_DEFINED,
                ),
            )
        rows = require_list(root.get("results"), len(probe_inputs()))
        content_ids: list[str] = []
        scores: list[float] = []
        expected_ids = probe_content_ids()
        for raw in rows:
            row = require_object(raw)
            index = row.get("index")
            if (
                not isinstance(index, int)
                or isinstance(index, bool)
                or not 0 <= index < len(expected_ids)
            ):
                raise TypeError
            content_ids.append(expected_ids[index])
            scores.append(require_float(row.get("relevance_score")))
        if len(set(content_ids)) != len(expected_ids):
            raise ValueError
        return ParsedProbe(
            None,
            None,
            None,
            None,
            RerankingProbeBatch(tuple(content_ids), tuple(scores)),
        )


class CohereProviderAdapter(CertifiedRemoteAdapter):
    """Maintained Cohere built-in over the credential-brokering gateway."""

    def __init__(self, transport: ProviderGatewayTransport) -> None:
        """Bind the certified protocol to the isolated gateway."""
        super().__init__(COHERE_MANIFEST, transport, CohereProtocol())
