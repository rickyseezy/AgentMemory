"""Certified Google Gemini embedding adapter."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.providers.adapters.builtins.base import (
    CertifiedRemoteAdapter,
    ParsedProbe,
    certified_manifest,
    probe_inputs,
    require_list,
    require_object,
    require_vector,
)
from agentmemory.providers.domain.errors import ProviderAdapterError, ProviderErrorCode
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

_TASK_TYPE = {
    CanonicalPurpose.RETRIEVAL_QUERY: "RETRIEVAL_QUERY",
    CanonicalPurpose.RETRIEVAL_DOCUMENT: "RETRIEVAL_DOCUMENT",
    CanonicalPurpose.CODE_QUERY: "CODE_RETRIEVAL_QUERY",
    CanonicalPurpose.CODE_DOCUMENT: "RETRIEVAL_DOCUMENT",
    CanonicalPurpose.SEMANTIC_SIMILARITY: "SEMANTIC_SIMILARITY",
    CanonicalPurpose.CLASSIFICATION: "CLASSIFICATION",
    CanonicalPurpose.CLUSTERING: "CLUSTERING",
}
GOOGLE_MANIFEST = certified_manifest(
    adapter_id="google",
    vendor="google",
    operations=(ProviderOperation.EMBEDDING,),
    purposes=tuple(sorted(CanonicalPurpose, key=str)),
    limits=ProviderLimits(100, 8 * 1024 * 1024, 2048, 204_800, 120_000),
)


class GoogleProtocol:
    """Map canonical purposes to Gemini `batchEmbedContents` task types."""

    def request(
        self,
        operation: ProviderOperation,
        purpose: CanonicalPurpose,
        model_id: str,
    ) -> tuple[str, dict[str, object]]:
        """Build one Gemini batch embedding probe with an explicit task type."""
        if operation is not ProviderOperation.EMBEDDING:
            raise ProviderAdapterError(ProviderErrorCode.UNSUPPORTED_CAPABILITY)
        qualified = model_id if model_id.startswith("models/") else f"models/{model_id}"
        requests = [
            {
                "content": {"parts": [{"text": content}]},
                "model": qualified,
                "taskType": _TASK_TYPE[purpose],
            }
            for content in probe_inputs()
        ]
        return f"/v1beta/{qualified}:batchEmbedContents", {"requests": requests}

    def parse(
        self,
        operation: ProviderOperation,
        model_id: str,
        response: object,
    ) -> ParsedProbe:
        """Validate Gemini's exact response count and finite dimensions."""
        del model_id
        if operation is not ProviderOperation.EMBEDDING:
            raise ValueError
        root = require_object(response)
        embeddings = require_list(root.get("embeddings"), len(probe_inputs()))
        vectors = [require_vector(require_object(item).get("values")) for item in embeddings]
        if len({len(vector) for vector in vectors}) != 1:
            raise ValueError
        return ParsedProbe(
            len(vectors[0]),
            VectorDtype.FLOAT32,
            VectorNormalization.PROVIDER_DEFINED,
            SimilarityMetric.COSINE,
        )


class GoogleProviderAdapter(CertifiedRemoteAdapter):
    """Maintained Google built-in over the credential-brokering gateway."""

    def __init__(self, transport: ProviderGatewayTransport) -> None:
        """Bind the certified protocol to the isolated gateway."""
        super().__init__(GOOGLE_MANIFEST, transport, GoogleProtocol())
