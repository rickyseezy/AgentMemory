"""Bridge pinned PF-001 Qwen sidecars to the PRO-001 profile probe port."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import OperationError
from agentmemory.providers.domain.errors import ProviderAdapterError, ProviderErrorCode
from agentmemory.providers.domain.profiles import (
    ProviderOperation,
    ProviderProbeResult,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)

if TYPE_CHECKING:
    from agentmemory.operations.adapters.outbound.local_provider import (
        LocalEmbeddingHttpAdapter,
        LocalRerankingHttpAdapter,
    )
    from agentmemory.providers.domain.profiles import ProviderProfile


@dataclass(frozen=True, slots=True)
class QwenProfileProbeAdapter:
    """Expose the already authenticated local sidecars through one profile probe."""

    embeddings: LocalEmbeddingHttpAdapter
    reranker: LocalRerankingHttpAdapter

    async def probe(self, profile: ProviderProfile) -> ProviderProbeResult:
        """Probe the selected local role and translate its release attestation."""
        configuration = profile.configuration
        try:
            attestation = (
                await self.embeddings.probe()
                if configuration.operation is ProviderOperation.EMBEDDING
                else await self.reranker.probe()
            )
        except OperationError as error:
            raise ProviderAdapterError(ProviderErrorCode.TRANSIENT_UPSTREAM) from error
        if attestation.model_id != configuration.model_id:
            raise ProviderAdapterError(ProviderErrorCode.MISSING_MODEL)
        fingerprint = hashlib.sha256(
            (
                f"qwen-local\0{attestation.role}\0{attestation.model_id}\0"
                f"{attestation.model_revision}\0{attestation.dimension}"
            ).encode()
        ).hexdigest()
        embedding = configuration.operation is ProviderOperation.EMBEDDING
        return ProviderProbeResult(
            adapter_id="qwen-local",
            model_id=attestation.model_id,
            model_revision=attestation.model_revision,
            revision_fingerprint=fingerprint,
            operation=configuration.operation,
            purposes=configuration.purposes,
            dimension=attestation.dimension if embedding else None,
            dtype=VectorDtype.FLOAT32 if embedding else None,
            normalization=VectorNormalization.L2 if embedding else None,
            similarity=SimilarityMetric.COSINE if embedding else None,
            max_items=32,
            cancellation_verified=attestation.supports_cancellation,
        )
