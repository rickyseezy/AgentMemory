"""Certified OpenAI embedding adapter over the AgentMemory egress gateway."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.providers.adapters.builtins.base import (
    CertifiedRemoteAdapter,
    ParsedProbe,
    certified_manifest,
    probe_inputs,
    require_list,
    require_model,
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

_PURPOSES = tuple(sorted(CanonicalPurpose, key=str))
OPENAI_MANIFEST = certified_manifest(
    adapter_id="openai",
    vendor="openai",
    operations=(ProviderOperation.EMBEDDING,),
    purposes=_PURPOSES,
    limits=ProviderLimits(100, 8 * 1024 * 1024, 8192, 300_000, 120_000),
)


class OpenAIProtocol:
    """Translate the canonical profile into OpenAI's `/v1/embeddings` schema."""

    def request(
        self,
        operation: ProviderOperation,
        purpose: CanonicalPurpose,
        model_id: str,
    ) -> tuple[str, dict[str, object]]:
        """Build one purpose-specific OpenAI embedding probe."""
        if operation is not ProviderOperation.EMBEDDING:
            raise ProviderAdapterError(ProviderErrorCode.UNSUPPORTED_CAPABILITY)
        inputs = [f"[{purpose.value}] {value}" for value in probe_inputs()]
        return "/v1/embeddings", {
            "encoding_format": "float",
            "input": inputs,
            "model": model_id,
        }

    def parse(
        self,
        operation: ProviderOperation,
        model_id: str,
        response: object,
    ) -> ParsedProbe:
        """Validate exact model echo, item order, and finite vector shape."""
        if operation is not ProviderOperation.EMBEDDING:
            raise ValueError
        root = require_object(response)
        require_model(root.get("model"), model_id)
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


class OpenAIProviderAdapter(CertifiedRemoteAdapter):
    """Maintained OpenAI built-in with no vendor SDK in Core."""

    def __init__(self, transport: ProviderGatewayTransport) -> None:
        """Bind the certified protocol to the isolated gateway."""
        super().__init__(OPENAI_MANIFEST, transport, OpenAIProtocol())
