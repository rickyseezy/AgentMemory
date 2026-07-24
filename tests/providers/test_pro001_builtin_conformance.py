"""PRO-001 shared built-in provider and gateway conformance tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from decimal import Decimal
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.operations.adapters.outbound.qwen_profile_probe import QwenProfileProbeAdapter
from agentmemory.operations.domain.dependency_ports import (
    EmbeddingVector,
    ProviderAttestation,
    RerankItem,
)
from agentmemory.providers.adapters.builtins.base import (
    CertifiedRemoteAdapter,
    require_list,
    require_vector,
)
from agentmemory.providers.adapters.builtins.base import (
    require_object as require_protocol_object,
)
from agentmemory.providers.adapters.builtins.cohere import CohereProtocol, CohereProviderAdapter
from agentmemory.providers.adapters.builtins.google import GoogleProtocol, GoogleProviderAdapter
from agentmemory.providers.adapters.builtins.openai import OpenAIProtocol, OpenAIProviderAdapter
from agentmemory.providers.adapters.builtins.openai_compatible import (
    OpenAICompatibleProviderAdapter,
)
from agentmemory.providers.adapters.builtins.qwen_local import (
    QWEN_LOCAL_MANIFEST,
    QwenLocalProviderAdapter,
)
from agentmemory.providers.adapters.builtins.registry import CertifiedProviderAdapterRegistry
from agentmemory.providers.adapters.builtins.voyage import VoyageProtocol, VoyageProviderAdapter
from agentmemory.providers.adapters.strict_json import canonical_bytes, loads, require_object
from agentmemory.providers.domain.capability_probe import ProviderProbeSuite
from agentmemory.providers.domain.errors import (
    ProviderAdapterError,
    ProviderErrorCode,
    ProviderProfileConflictError,
)
from agentmemory.providers.domain.profile_ports import (
    ProviderGatewayRequest,
    ProviderGatewayResponse,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderBudget,
    ProviderDataPolicy,
    ProviderExecutionClass,
    ProviderLimits,
    ProviderOperation,
    ProviderProbeResult,
    ProviderProfile,
    ProviderProfileConfiguration,
    ProviderProfileStatus,
    ProviderQuota,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)
from tests.core.support import BRAIN_ID, NOW, digest

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.operations.adapters.outbound.local_provider import (
        LocalEmbeddingHttpAdapter,
        LocalRerankingHttpAdapter,
    )
    from agentmemory.providers.domain.profile_ports import ProviderAdapterPort

PROFILE_ID = "018f0000-0000-7000-8000-000000000711"
MODEL_ID = "test-model-v1"
FINGERPRINT = digest("pro001-conformance-revision").value
ENDPOINT_FINGERPRINT = digest("pro001-conformance-endpoint").value
PURPOSE = (CanonicalPurpose.RETRIEVAL_QUERY,)


@dataclass(slots=True)
class _Gateway:
    """Record exact credential-reference envelopes and return scripted responses."""

    responder: Callable[[ProviderGatewayRequest, int], ProviderGatewayResponse]
    requests: list[ProviderGatewayRequest] = field(default_factory=list[ProviderGatewayRequest])

    async def execute(self, request: ProviderGatewayRequest) -> ProviderGatewayResponse:
        self.requests.append(request)
        return self.responder(request, len(self.requests))


def _configuration(
    adapter_id: str,
    operation: ProviderOperation,
    *,
    purposes: tuple[CanonicalPurpose, ...] = PURPOSE,
) -> ProviderProfileConfiguration:
    return ProviderProfileConfiguration(
        brain_id=BRAIN_ID,
        adapter_id=adapter_id,
        operation=operation,
        model_id=MODEL_ID,
        purposes=purposes,
        limits=ProviderLimits(2, 4096, 128, 256, 1000),
        execution_class=ProviderExecutionClass.REMOTE,
        endpoint_policy_ref=f"policy://providers/{adapter_id}",
        secret_ref=f"secret://providers/{adapter_id}",
        egress_approval_ref=f"approval://providers/{adapter_id}",
        data_policy=ProviderDataPolicy(
            declaration_version="2026-07-01",
            retention_days=30,
            training_allowed=False,
            residency="US",
        ),
        quota=ProviderQuota(60, 1000, 10_000),
        budget=ProviderBudget("USD", 10_000_000),
    )


def _profile(adapter: ProviderAdapterPort, operation: ProviderOperation) -> ProviderProfile:
    return ProviderProfile(
        profile_id=PROFILE_ID,
        configuration=_configuration(adapter.manifest.adapter_id, operation),
        manifest_digest=adapter.manifest.digest,
        status=ProviderProfileStatus.DRAFT,
        version=1,
        created_at=NOW,
        updated_at=NOW,
    )


def _adapter(adapter_id: str, gateway: _Gateway) -> ProviderAdapterPort:
    if adapter_id == "openai":
        return OpenAIProviderAdapter(gateway)
    if adapter_id == "openai-compatible":
        return OpenAICompatibleProviderAdapter(gateway)
    if adapter_id == "cohere":
        return CohereProviderAdapter(gateway)
    if adapter_id == "voyage":
        return VoyageProviderAdapter(gateway)
    if adapter_id == "google":
        return GoogleProviderAdapter(gateway)
    raise AssertionError(adapter_id)


def _valid_body(request: ProviderGatewayRequest) -> bytes:
    request_document = require_object(loads(request.body))
    model_id = request_document.get("model", MODEL_ID)
    if request.adapter_id == "google":
        return canonical_bytes({"embeddings": [{"values": [0.1, 0.2]}, {"values": [0.3, 0.4]}]})
    if request.adapter_id == "cohere":
        if request.path.endswith("/embed"):
            return canonical_bytes({"embeddings": {"float": [[0.1, 0.2], [0.3, 0.4]]}})
        return canonical_bytes(
            {
                "results": [
                    {"index": 1, "relevance_score": 0.9},
                    {"index": 0, "relevance_score": 0.4},
                ]
            }
        )
    if request.path.endswith("/rerank"):
        return canonical_bytes(
            {
                "model": model_id,
                "data": [
                    {"index": 1, "relevance_score": 0.9},
                    {"index": 0, "relevance_score": 0.4},
                ],
            }
        )
    return canonical_bytes(
        {
            "model": model_id,
            "data": [
                {"index": 0, "embedding": [0.1, 0.2]},
                {"index": 1, "embedding": [0.3, 0.4]},
            ],
        }
    )


def _valid_response(request: ProviderGatewayRequest, call: int) -> ProviderGatewayResponse:
    del call
    return ProviderGatewayResponse(
        status_code=200,
        body=_valid_body(request),
        model_revision="revision-2026-07",
        revision_fingerprint=FINGERPRINT,
        endpoint_fingerprint=ENDPOINT_FINGERPRINT,
        cancellation_verified=True,
    )


@pytest.mark.parametrize(
    ("adapter_id", "operation"),
    [
        ("openai", ProviderOperation.EMBEDDING),
        ("openai-compatible", ProviderOperation.EMBEDDING),
        ("cohere", ProviderOperation.EMBEDDING),
        ("cohere", ProviderOperation.RERANKING),
        ("voyage", ProviderOperation.EMBEDDING),
        ("voyage", ProviderOperation.RERANKING),
        ("google", ProviderOperation.EMBEDDING),
    ],
)
@pytest.mark.asyncio
async def test_every_remote_builtin_passes_one_shared_live_conformance_contract(
    adapter_id: str,
    operation: ProviderOperation,
) -> None:
    """Every maintained vendor uses identical activation evidence semantics."""
    gateway = _Gateway(_valid_response)
    adapter = _adapter(adapter_id, gateway)
    result = await adapter.probe(_profile(adapter, operation))
    assert result.adapter_id == adapter_id
    assert result.operation is operation
    assert result.revision_fingerprint == FINGERPRINT
    assert result.cancellation_verified
    if operation is ProviderOperation.EMBEDDING:
        assert result.dimension == 2
        assert result.dtype is VectorDtype.FLOAT32
    else:
        assert result.dimension is None
        assert result.dtype is None
    assert len(gateway.requests) == 1
    request = gateway.requests[0]
    assert request.secret_ref == f"secret://providers/{adapter_id}"
    assert b"credential-value" not in request.body
    assert request.path.startswith("/")


@pytest.mark.asyncio
async def test_protocols_map_canonical_purpose_without_vendor_logic_in_core() -> None:
    gateway = _Gateway(_valid_response)
    cohere = CohereProviderAdapter(gateway)
    await cohere.probe(_profile(cohere, ProviderOperation.EMBEDDING))
    cohere_body = require_object(loads(gateway.requests[-1].body))
    assert cohere_body["input_type"] == "search_query"

    google = GoogleProviderAdapter(gateway)
    await google.probe(_profile(google, ProviderOperation.EMBEDDING))
    google_body = require_object(loads(gateway.requests[-1].body))
    requests = cast("list[object]", google_body["requests"])
    first = require_object(requests[0])
    assert first["taskType"] == "RETRIEVAL_QUERY"


def test_vendor_protocol_requests_are_exact_and_release_stable() -> None:
    """A built-in upgrade cannot silently alter any certified wire request."""
    inputs = [
        "AgentMemory provider probe alpha",
        "AgentMemory provider probe beta",
    ]
    openai_path, openai_body = OpenAIProtocol().request(
        ProviderOperation.EMBEDDING,
        CanonicalPurpose.RETRIEVAL_QUERY,
        MODEL_ID,
    )
    assert openai_path == "/v1/embeddings"
    assert openai_body == {
        "encoding_format": "float",
        "input": [f"[retrieval_query] {value}" for value in inputs],
        "model": MODEL_ID,
    }

    cohere = CohereProtocol()
    assert cohere.request(
        ProviderOperation.EMBEDDING,
        CanonicalPurpose.RETRIEVAL_DOCUMENT,
        MODEL_ID,
    ) == (
        "/v2/embed",
        {
            "embedding_types": ["float"],
            "input_type": "search_document",
            "model": MODEL_ID,
            "texts": inputs,
            "truncate": "NONE",
        },
    )
    assert cohere.request(
        ProviderOperation.RERANKING,
        CanonicalPurpose.RETRIEVAL_QUERY,
        MODEL_ID,
    ) == (
        "/v2/rerank",
        {
            "documents": inputs,
            "model": MODEL_ID,
            "query": "AgentMemory provider probe",
            "top_n": 2,
        },
    )

    voyage = VoyageProtocol()
    assert voyage.request(
        ProviderOperation.EMBEDDING,
        CanonicalPurpose.SEMANTIC_SIMILARITY,
        MODEL_ID,
    ) == (
        "/v1/embeddings",
        {
            "input": inputs,
            "input_type": None,
            "model": MODEL_ID,
            "output_dtype": "float",
            "truncation": False,
        },
    )
    assert voyage.request(
        ProviderOperation.RERANKING,
        CanonicalPurpose.RETRIEVAL_QUERY,
        MODEL_ID,
    ) == (
        "/v1/rerank",
        {
            "documents": inputs,
            "model": MODEL_ID,
            "query": "AgentMemory provider probe",
            "return_documents": False,
            "top_k": 2,
            "truncation": False,
        },
    )

    google = GoogleProtocol()
    google_path, google_body = google.request(
        ProviderOperation.EMBEDDING,
        CanonicalPurpose.CODE_QUERY,
        MODEL_ID,
    )
    assert google_path == f"/v1beta/models/{MODEL_ID}:batchEmbedContents"
    assert google_body == {
        "requests": [
            {
                "content": {"parts": [{"text": value}]},
                "model": f"models/{MODEL_ID}",
                "taskType": "CODE_RETRIEVAL_QUERY",
            }
            for value in inputs
        ]
    }
    assert (
        google.request(
            ProviderOperation.EMBEDDING,
            CanonicalPurpose.CLASSIFICATION,
            f"models/{MODEL_ID}",
        )[0]
        == f"/v1beta/models/{MODEL_ID}:batchEmbedContents"
    )


@pytest.mark.parametrize(
    ("status", "code"),
    [
        (401, ProviderErrorCode.AUTHENTICATION),
        (403, ProviderErrorCode.PERMISSION),
        (404, ProviderErrorCode.MISSING_MODEL),
        (408, ProviderErrorCode.TIMEOUT),
        (413, ProviderErrorCode.OVERSIZED_INPUT),
        (429, ProviderErrorCode.RATE_LIMIT),
        (500, ProviderErrorCode.TRANSIENT_UPSTREAM),
        (418, ProviderErrorCode.INVALID_CONFIGURATION),
    ],
)
@pytest.mark.asyncio
async def test_upstream_errors_use_safe_canonical_codes_without_body_or_secret(
    status: int,
    code: ProviderErrorCode,
) -> None:
    marker = "sk-pro001-upstream-body-must-not-escape"

    def rejected(request: ProviderGatewayRequest, call: int) -> ProviderGatewayResponse:
        del request, call
        return ProviderGatewayResponse(
            status_code=status,
            body=marker.encode(),
            model_revision="revision-1",
            revision_fingerprint=FINGERPRINT,
            endpoint_fingerprint=ENDPOINT_FINGERPRINT,
            cancellation_verified=True,
            retry_after_microseconds=123_456 if status == 429 else None,
        )

    gateway = _Gateway(rejected)
    adapter = OpenAIProviderAdapter(gateway)
    with pytest.raises(ProviderAdapterError) as captured:
        await adapter.probe(_profile(adapter, ProviderOperation.EMBEDDING))
    assert captured.value.code is code
    assert captured.value.retry_after_microseconds == (123_456 if status == 429 else None)
    assert marker not in str(captured.value)
    assert "secret://" not in str(captured.value)


@pytest.mark.parametrize(
    "body",
    [
        b'{"model":"test-model-v1","model":"other","data":[]}',
        b'{"model":"test-model-v1","data":NaN}',
        canonical_bytes({"model": "other-model", "data": []}),
        canonical_bytes(
            {
                "model": MODEL_ID,
                "data": [
                    {"index": 1, "embedding": [0.1, 0.2]},
                    {"index": 0, "embedding": [0.3, 0.4]},
                ],
            }
        ),
        canonical_bytes(
            {
                "model": MODEL_ID,
                "data": [
                    {"index": 0, "embedding": [1, 2]},
                    {"index": 1, "embedding": [3, 4]},
                ],
            }
        ),
        canonical_bytes(
            {
                "model": MODEL_ID,
                "data": [
                    {"index": 0, "embedding": [0.1, 0.2]},
                ],
            }
        ),
    ],
)
@pytest.mark.asyncio
async def test_openai_compatible_deviations_fail_closed(body: bytes) -> None:
    """Compatible endpoints are not allowed permissive coercion or reordered output."""

    def malformed(request: ProviderGatewayRequest, call: int) -> ProviderGatewayResponse:
        del request, call
        return ProviderGatewayResponse(
            status_code=200,
            body=body,
            model_revision="revision-1",
            revision_fingerprint=FINGERPRINT,
            endpoint_fingerprint=ENDPOINT_FINGERPRINT,
            cancellation_verified=True,
        )

    gateway = _Gateway(malformed)
    adapter = OpenAICompatibleProviderAdapter(gateway)
    with pytest.raises(ProviderAdapterError) as captured:
        await adapter.probe(_profile(adapter, ProviderOperation.EMBEDDING))
    assert captured.value.code is ProviderErrorCode.MALFORMED_RESPONSE


@pytest.mark.asyncio
async def test_revision_cancellation_and_dimension_must_be_stable_across_purposes() -> None:
    purposes = (
        CanonicalPurpose.RETRIEVAL_DOCUMENT,
        CanonicalPurpose.RETRIEVAL_QUERY,
    )

    def drift(request: ProviderGatewayRequest, call: int) -> ProviderGatewayResponse:
        return ProviderGatewayResponse(
            status_code=200,
            body=_valid_body(request),
            model_revision=f"revision-{call}",
            revision_fingerprint=digest(f"revision-{call}").value,
            endpoint_fingerprint=ENDPOINT_FINGERPRINT,
            cancellation_verified=True,
        )

    gateway = _Gateway(drift)
    adapter = OpenAIProviderAdapter(gateway)
    drift_profile = replace(
        _profile(adapter, ProviderOperation.EMBEDDING),
        configuration=_configuration("openai", ProviderOperation.EMBEDDING, purposes=purposes),
    )
    with pytest.raises(ProviderAdapterError) as captured:
        await adapter.probe(drift_profile)
    assert captured.value.code is ProviderErrorCode.MODEL_DRIFT

    def endpoint_drift(
        request: ProviderGatewayRequest,
        call: int,
    ) -> ProviderGatewayResponse:
        return replace(
            _valid_response(request, call),
            endpoint_fingerprint=digest(f"endpoint-{call}").value,
        )

    with pytest.raises(ProviderAdapterError) as captured:
        await OpenAIProviderAdapter(_Gateway(endpoint_drift)).probe(drift_profile)
    assert captured.value.code is ProviderErrorCode.MODEL_DRIFT

    def cancelled(request: ProviderGatewayRequest, call: int) -> ProviderGatewayResponse:
        del call
        return replace(_valid_response(request, 1), cancellation_verified=False)

    with pytest.raises(ProviderAdapterError) as captured:
        await OpenAIProviderAdapter(_Gateway(cancelled)).probe(
            _profile(OpenAIProviderAdapter(_Gateway(cancelled)), ProviderOperation.EMBEDDING)
        )
    assert captured.value.code is ProviderErrorCode.CANCELLATION

    def dimension_change(request: ProviderGatewayRequest, call: int) -> ProviderGatewayResponse:
        body = _valid_body(request)
        if call == 2:
            document = require_object(loads(body))
            rows = cast("list[object]", document["data"])
            for row in rows:
                require_object(row)["embedding"] = [0.1, 0.2, 0.3]
            body = canonical_bytes(document)
        return ProviderGatewayResponse(
            status_code=200,
            body=body,
            model_revision="revision-1",
            revision_fingerprint=FINGERPRINT,
            endpoint_fingerprint=ENDPOINT_FINGERPRINT,
            cancellation_verified=True,
        )

    dimension_gateway = _Gateway(dimension_change)
    dimension_adapter = OpenAIProviderAdapter(dimension_gateway)
    with pytest.raises(ProviderAdapterError) as captured:
        await dimension_adapter.probe(
            replace(
                _profile(dimension_adapter, ProviderOperation.EMBEDDING),
                configuration=_configuration(
                    "openai", ProviderOperation.EMBEDDING, purposes=purposes
                ),
            )
        )
    assert captured.value.code is ProviderErrorCode.DIMENSION_MISMATCH


@dataclass(slots=True)
class _Sidecar:
    attestation: ProviderAttestation

    async def probe(self) -> ProviderAttestation:
        return self.attestation

    async def embed_probe(
        self,
        purpose: str,
        items: tuple[tuple[str, str], ...],
    ) -> tuple[EmbeddingVector, ...]:
        del purpose
        values = (1.0,) + (0.0,) * 1023
        return tuple(
            EmbeddingVector(content_id, values, MODEL_ID, "qwen-revision-1")
            for content_id, _ in items
        )

    async def rerank(
        self,
        query: str,
        documents: tuple[tuple[str, str], ...],
    ) -> tuple[RerankItem, ...]:
        del query
        return tuple(
            RerankItem(content_id, Decimal(len(documents) - index))
            for index, (content_id, _) in enumerate(documents)
        )


@pytest.mark.parametrize(
    ("operation", "role", "dimension"),
    [
        (ProviderOperation.EMBEDDING, "embedding", 1024),
        (ProviderOperation.RERANKING, "reranking", None),
    ],
)
@pytest.mark.asyncio
async def test_qwen_local_runtime_bridge_uses_release_attestation(
    operation: ProviderOperation,
    role: str,
    dimension: int | None,
) -> None:
    attestation = ProviderAttestation(
        role=role,
        model_id=MODEL_ID,
        model_revision="qwen-revision-1",
        dimension=dimension,
        supports_cancellation=True,
        local_only=True,
    )
    embedding = cast("LocalEmbeddingHttpAdapter", _Sidecar(attestation))
    reranking = cast("LocalRerankingHttpAdapter", _Sidecar(attestation))
    adapter = QwenLocalProviderAdapter(QwenProfileProbeAdapter(embedding, reranking))
    configuration = ProviderProfileConfiguration(
        brain_id=BRAIN_ID,
        adapter_id="qwen-local",
        operation=operation,
        model_id=MODEL_ID,
        purposes=PURPOSE,
        limits=ProviderLimits(2, 4096, 128, 256, 1000),
        execution_class=ProviderExecutionClass.LOCAL,
    )
    local_profile = ProviderProfile(
        profile_id=PROFILE_ID,
        configuration=configuration,
        manifest_digest=adapter.manifest.digest,
        status=ProviderProfileStatus.DRAFT,
        version=1,
        created_at=NOW,
        updated_at=NOW,
    )
    result = await adapter.probe(local_profile)
    assert result.adapter_id == "qwen-local"
    assert result.operation is operation
    assert result.dimension == dimension
    assert result.cancellation_verified


@pytest.mark.asyncio
async def test_qwen_local_rejects_sidecar_model_or_capability_mismatch() -> None:
    configuration = ProviderProfileConfiguration(
        brain_id=BRAIN_ID,
        adapter_id="qwen-local",
        operation=ProviderOperation.EMBEDDING,
        model_id=MODEL_ID,
        purposes=PURPOSE,
        limits=ProviderLimits(2, 4096, 128, 256, 1000),
        execution_class=ProviderExecutionClass.LOCAL,
    )
    suite = ProviderProbeSuite()
    invalid_result = ProviderProbeResult(
        adapter_id="different-local",
        model_id=MODEL_ID,
        model_revision="revision-1",
        revision_fingerprint=FINGERPRINT,
        endpoint_fingerprint=ENDPOINT_FINGERPRINT,
        operation=ProviderOperation.EMBEDDING,
        purposes=PURPOSE,
        dimension=2,
        dtype=VectorDtype.FLOAT32,
        normalization=VectorNormalization.L2,
        similarity=SimilarityMetric.COSINE,
        max_items=32,
        cancellation_verified=True,
        suite_digest=suite.suite_digest,
        canary_digest=suite.canary_digest,
        validation_digest=digest("invalid-local-validation").value,
        validated_batches=len(PURPOSE),
    )

    @dataclass(frozen=True, slots=True)
    class LocalProbe:
        async def probe(self, profile: ProviderProfile) -> ProviderProbeResult:
            del profile
            return invalid_result

    adapter = QwenLocalProviderAdapter(LocalProbe())
    local_profile = ProviderProfile(
        profile_id=PROFILE_ID,
        configuration=configuration,
        manifest_digest=adapter.manifest.digest,
        status=ProviderProfileStatus.DRAFT,
        version=1,
        created_at=NOW,
        updated_at=NOW,
    )
    with pytest.raises(ProviderAdapterError) as captured:
        await adapter.probe(local_profile)
    assert captured.value.code is ProviderErrorCode.MALFORMED_RESPONSE


def test_certified_registry_is_closed_non_empty_and_unambiguous() -> None:
    gateway = _Gateway(_valid_response)
    openai = OpenAIProviderAdapter(gateway)
    registry = CertifiedProviderAdapterRegistry((openai, CohereProviderAdapter(gateway)))
    assert registry.get("openai") is openai
    with pytest.raises(ProviderAdapterError) as captured:
        registry.get("unknown")
    assert captured.value.code is ProviderErrorCode.UNSUPPORTED_CAPABILITY
    with pytest.raises(ProviderProfileConflictError, match="empty"):
        CertifiedProviderAdapterRegistry(())
    with pytest.raises(ProviderProfileConflictError, match="ambiguous"):
        CertifiedProviderAdapterRegistry((openai, OpenAIProviderAdapter(gateway)))


@pytest.mark.parametrize("protocol", [OpenAIProtocol(), GoogleProtocol()])
def test_embedding_only_protocols_reject_unsupported_operations_directly(
    protocol: OpenAIProtocol | GoogleProtocol,
) -> None:
    with pytest.raises(ProviderAdapterError) as captured:
        protocol.request(ProviderOperation.RERANKING, PURPOSE[0], MODEL_ID)
    assert captured.value.code is ProviderErrorCode.UNSUPPORTED_CAPABILITY
    with pytest.raises(ValueError, match=r"^$"):
        protocol.parse(ProviderOperation.RERANKING, MODEL_ID, {})


def test_vendor_parsers_reject_dimension_index_and_type_disagreement() -> None:
    unequal_openai = {
        "model": MODEL_ID,
        "data": [
            {"index": 0, "embedding": [0.1]},
            {"index": 1, "embedding": [0.2, 0.3]},
        ],
    }
    with pytest.raises(ValueError, match=r"^$"):
        OpenAIProtocol().parse(ProviderOperation.EMBEDDING, MODEL_ID, unequal_openai)
    with pytest.raises(ValueError, match=r"^$"):
        GoogleProtocol().parse(
            ProviderOperation.EMBEDDING,
            MODEL_ID,
            {"embeddings": [{"values": [0.1]}, {"values": [0.2, 0.3]}]},
        )
    with pytest.raises(ValueError, match=r"^$"):
        CohereProtocol().parse(
            ProviderOperation.EMBEDDING,
            MODEL_ID,
            {"embeddings": {"float": [[0.1], [0.2, 0.3]]}},
        )
    with pytest.raises(TypeError):
        CohereProtocol().parse(
            ProviderOperation.RERANKING,
            MODEL_ID,
            {
                "results": [
                    {"index": True, "relevance_score": 0.9},
                    {"index": 0, "relevance_score": 0.4},
                ]
            },
        )
    with pytest.raises(ValueError, match=r"^$"):
        CohereProtocol().parse(
            ProviderOperation.RERANKING,
            MODEL_ID,
            {
                "results": [
                    {"index": 0, "relevance_score": 0.9},
                    {"index": 0, "relevance_score": 0.4},
                ]
            },
        )
    unequal_voyage = {
        "model": MODEL_ID,
        "data": [
            {"index": 0, "embedding": [0.1]},
            {"index": 1, "embedding": [0.2, 0.3]},
        ],
    }
    with pytest.raises(ValueError, match=r"^$"):
        VoyageProtocol().parse(ProviderOperation.EMBEDDING, MODEL_ID, unequal_voyage)
    with pytest.raises(ValueError, match=r"^$"):
        VoyageProtocol().parse(
            ProviderOperation.EMBEDDING,
            MODEL_ID,
            {
                "model": MODEL_ID,
                "data": [
                    {"index": 1, "embedding": [0.1]},
                    {"index": 0, "embedding": [0.2]},
                ],
            },
        )
    with pytest.raises(TypeError):
        VoyageProtocol().parse(
            ProviderOperation.RERANKING,
            MODEL_ID,
            {
                "model": MODEL_ID,
                "data": [
                    {"index": False, "relevance_score": 0.9},
                    {"index": 0, "relevance_score": 0.4},
                ],
            },
        )
    with pytest.raises(ValueError, match=r"^$"):
        VoyageProtocol().parse(
            ProviderOperation.RERANKING,
            MODEL_ID,
            {
                "model": MODEL_ID,
                "data": [
                    {"index": 0, "relevance_score": 0.9},
                    {"index": 0, "relevance_score": 0.4},
                ],
            },
        )


def test_shared_conformance_helpers_and_remote_manifest_fail_closed() -> None:
    with pytest.raises(TypeError):
        require_protocol_object([])
    with pytest.raises(TypeError):
        require_protocol_object({1: "not-a-string-key"})
    with pytest.raises(TypeError):
        require_list({}, 0)
    with pytest.raises(TypeError):
        require_vector("not-a-vector")
    with pytest.raises(ValueError, match=r"^$"):
        require_vector([])
    with pytest.raises(ValueError, match="remote manifest"):
        CertifiedRemoteAdapter(
            QWEN_LOCAL_MANIFEST,
            _Gateway(_valid_response),
            OpenAIProtocol(),
        )


@pytest.mark.asyncio
async def test_remote_probe_rejects_oversized_provider_body_before_parsing() -> None:
    def oversized(request: ProviderGatewayRequest, call: int) -> ProviderGatewayResponse:
        del request, call
        return ProviderGatewayResponse(
            status_code=200,
            body=b"x" * (8 * 1024 * 1024 + 1),
            model_revision="revision-1",
            revision_fingerprint=FINGERPRINT,
            endpoint_fingerprint=ENDPOINT_FINGERPRINT,
            cancellation_verified=True,
        )

    gateway = _Gateway(oversized)
    adapter = OpenAIProviderAdapter(gateway)
    with pytest.raises(ProviderAdapterError) as captured:
        await adapter.probe(_profile(adapter, ProviderOperation.EMBEDDING))
    assert captured.value.code is ProviderErrorCode.MALFORMED_RESPONSE
