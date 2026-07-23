"""Bridge pinned PF-001 Qwen sidecars to the PRO-001 profile probe port."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.providers.domain.capability_probe import (
    EmbeddingProbeBatch,
    ProviderProbeSuite,
    RerankingProbeBatch,
    ValidatedProbeBatch,
    VectorValidator,
    probe_canaries,
)
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderProfileValidationError,
)
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
        canaries = probe_canaries()
        suite = ProviderProbeSuite()
        validator = VectorValidator()
        try:
            attestation = (
                await self.embeddings.probe()
                if configuration.operation is ProviderOperation.EMBEDDING
                else await self.reranker.probe()
            )
            validated: list[ValidatedProbeBatch] = []
            for purpose in configuration.purposes:
                if configuration.operation is ProviderOperation.EMBEDDING:
                    vectors = await self.embeddings.embed_probe(
                        purpose.value,
                        tuple((item.content_id, item.content) for item in canaries),
                    )
                    validated.append(
                        validator.validate_embedding(
                            configuration.operation,
                            purpose,
                            canaries,
                            EmbeddingProbeBatch(
                                tuple(item.content_id for item in vectors),
                                tuple(item.values for item in vectors),
                                VectorDtype.FLOAT32,
                                VectorNormalization.L2,
                            ),
                            expected_dimension=attestation.dimension,
                        )
                    )
                else:
                    rankings = await self.reranker.rerank(
                        "AgentMemory provider probe",
                        tuple((item.content_id, item.content) for item in canaries),
                    )
                    validated.append(
                        validator.validate_reranking(
                            purpose,
                            canaries,
                            RerankingProbeBatch(
                                tuple(item.content_id for item in rankings),
                                tuple(float(item.score) for item in rankings),
                            ),
                        )
                    )
        except OperationError as error:
            code = (
                ProviderErrorCode.TIMEOUT
                if error.code is ErrorCode.DEADLINE_EXCEEDED
                else (
                    ProviderErrorCode.MALFORMED_RESPONSE
                    if error.code in {ErrorCode.INTEGRITY_VIOLATION, ErrorCode.VALIDATION}
                    else ProviderErrorCode.TRANSIENT_UPSTREAM
                )
            )
            raise ProviderAdapterError(code) from error
        except ProviderProfileValidationError as error:
            raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE) from error
        if attestation.model_id != configuration.model_id:
            raise ProviderAdapterError(ProviderErrorCode.MISSING_MODEL)
        fingerprint = hashlib.sha256(
            (
                f"qwen-local\0{attestation.role}\0{attestation.model_id}\0"
                f"{attestation.model_revision}\0{attestation.dimension}"
            ).encode()
        ).hexdigest()
        embedding = configuration.operation is ProviderOperation.EMBEDDING
        try:
            suite_result = suite.finalize(
                configuration.operation,
                configuration.purposes,
                tuple(validated),
                cancellation_verified=attestation.supports_cancellation,
            )
        except ProviderProfileValidationError as error:
            raise ProviderAdapterError(ProviderErrorCode.MALFORMED_RESPONSE) from error
        endpoint_fingerprint = hashlib.sha256(
            f"local://{attestation.role}\0{attestation.model_id}\0{attestation.model_revision}".encode()
        ).hexdigest()
        return ProviderProbeResult(
            adapter_id="qwen-local",
            model_id=attestation.model_id,
            model_revision=attestation.model_revision,
            revision_fingerprint=fingerprint,
            endpoint_fingerprint=endpoint_fingerprint,
            operation=configuration.operation,
            purposes=configuration.purposes,
            dimension=attestation.dimension if embedding else None,
            dtype=VectorDtype.FLOAT32 if embedding else None,
            normalization=VectorNormalization.L2 if embedding else None,
            similarity=SimilarityMetric.COSINE if embedding else None,
            max_items=32,
            cancellation_verified=attestation.supports_cancellation,
            suite_digest=suite_result.suite_digest,
            canary_digest=suite_result.canary_digest,
            validation_digest=suite_result.validation_digest,
            validated_batches=suite_result.validated_batches,
        )
