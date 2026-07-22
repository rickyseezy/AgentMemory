"""Certified Voyage AI embedding and reranking adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.providers.adapters.builtins.base import (
    CertifiedRemoteAdapter,
    ParsedProbe,
    certified_manifest,
    probe_inputs,
    probe_query,
    require_float,
    require_list,
    require_model,
    require_object,
    require_vector,
)
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

_INPUT_TYPE = {
    CanonicalPurpose.RETRIEVAL_QUERY: "query",
    CanonicalPurpose.RETRIEVAL_DOCUMENT: "document",
    CanonicalPurpose.CODE_QUERY: "query",
    CanonicalPurpose.CODE_DOCUMENT: "document",
    CanonicalPurpose.SEMANTIC_SIMILARITY: None,
    CanonicalPurpose.CLASSIFICATION: None,
    CanonicalPurpose.CLUSTERING: None,
}
VOYAGE_MANIFEST = certified_manifest(
    adapter_id="voyage",
    vendor="voyage",
    operations=(ProviderOperation.EMBEDDING, ProviderOperation.RERANKING),
    purposes=tuple(sorted(CanonicalPurpose, key=str)),
    limits=ProviderLimits(100, 8 * 1024 * 1024, 32_000, 600_000, 120_000),
)


class VoyageProtocol:
    """Map canonical operations to Voyage v1 request and response contracts."""

    def request(
        self,
        operation: ProviderOperation,
        purpose: CanonicalPurpose,
        model_id: str,
    ) -> tuple[str, dict[str, object]]:
        """Build one Voyage embedding or reranking probe."""
        if operation is ProviderOperation.EMBEDDING:
            return "/v1/embeddings", {
                "input": list(probe_inputs()),
                "input_type": _INPUT_TYPE[purpose],
                "model": model_id,
                "output_dtype": "float",
                "truncation": False,
            }
        return "/v1/rerank", {
            "documents": list(probe_inputs()),
            "model": model_id,
            "query": probe_query(),
            "return_documents": False,
            "top_k": len(probe_inputs()),
            "truncation": False,
        }

    def parse(
        self,
        operation: ProviderOperation,
        model_id: str,
        response: object,
    ) -> ParsedProbe:
        """Validate Voyage's exact model, indexes, and numeric response."""
        root = require_object(response)
        require_model(root.get("model"), model_id)
        if operation is ProviderOperation.EMBEDDING:
            rows = require_list(root.get("data"), len(probe_inputs()))
            vectors: list[tuple[float, ...]] = []
            for expected_index, raw in enumerate(rows):
                row = require_object(raw)
                if row.get("index") != expected_index:
                    raise ValueError
                vectors.append(require_vector(row.get("embedding")))
            if len({len(vector) for vector in vectors}) != 1:
                raise ValueError
            return ParsedProbe(
                len(vectors[0]),
                VectorDtype.FLOAT32,
                VectorNormalization.PROVIDER_DEFINED,
                SimilarityMetric.COSINE,
            )
        rows = require_list(root.get("data"), len(probe_inputs()))
        indexes: set[int] = set()
        for raw in rows:
            row = require_object(raw)
            index = row.get("index")
            if not isinstance(index, int) or isinstance(index, bool):
                raise TypeError
            indexes.add(index)
            require_float(row.get("relevance_score"))
        if indexes != set(range(len(probe_inputs()))):
            raise ValueError
        return ParsedProbe(None, None, None, None)


class VoyageProviderAdapter(CertifiedRemoteAdapter):
    """Maintained Voyage built-in over the credential-brokering gateway."""

    def __init__(self, transport: ProviderGatewayTransport) -> None:
        """Bind the certified protocol to the isolated gateway."""
        super().__init__(VOYAGE_MANIFEST, transport, VoyageProtocol())
