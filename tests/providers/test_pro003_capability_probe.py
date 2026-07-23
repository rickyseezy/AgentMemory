"""PRO-003 adversarial live capability-probe acceptance tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from agentmemory.providers.domain.capability_probe import (
    EmbeddingProbeBatch,
    ProviderProbeSuite,
    RerankingProbeBatch,
    VectorValidator,
    probe_canaries,
)
from agentmemory.providers.domain.errors import ProviderProfileValidationError
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderOperation,
    ProviderProbeBinding,
    ProviderProbeEvidence,
    VectorDtype,
    VectorNormalization,
)
from tests.core.support import NOW, digest
from tests.providers.test_pro001_profiles_domain_application import (
    PROFILE_ID,
    manifest,
    probe_result,
    remote_configuration,
)


def _embedding_batch(
    *,
    content_ids: tuple[str, ...] | None = None,
    vectors: tuple[tuple[float, ...], ...] = ((0.6, 0.8), (0.8, 0.6)),
    dtype: VectorDtype = VectorDtype.FLOAT32,
    normalization: VectorNormalization = VectorNormalization.L2,
) -> EmbeddingProbeBatch:
    canaries = probe_canaries()
    return EmbeddingProbeBatch(
        content_ids=content_ids or tuple(item.content_id for item in canaries),
        vectors=vectors,
        dtype=dtype,
        normalization=normalization,
    )


def _binding(
    *,
    configuration_digest: str | None = None,
) -> ProviderProbeBinding:
    provider_manifest = manifest()
    return ProviderProbeBinding(
        profile_id=PROFILE_ID,
        manifest_digest=provider_manifest.digest,
        adapter_digest=provider_manifest.implementation_digest,
        configuration_digest=configuration_digest or remote_configuration().digest,
    )


@pytest.mark.parametrize(
    "batch",
    [
        _embedding_batch(vectors=((0.6, 0.8),)),
        _embedding_batch(vectors=((0.6,), (0.8, 0.6))),
        _embedding_batch(vectors=((float("nan"), 0.0), (0.8, 0.6))),
        _embedding_batch(vectors=((float("inf"), 0.0), (0.8, 0.6))),
        _embedding_batch(vectors=((0.0, 0.0), (0.8, 0.6))),
        _embedding_batch(vectors=((1_000_001.0, 0.0), (0.8, 0.6))),
        _embedding_batch(vectors=(tuple(0.1 for _ in range(65_537)), (0.8, 0.6))),
    ],
)
def test_vector_validator_rejects_wrong_count_dimension_non_finite_zero_and_huge_vectors(
    batch: EmbeddingProbeBatch,
) -> None:
    with pytest.raises(ProviderProfileValidationError, match="capability probe"):
        VectorValidator().validate_embedding(
            ProviderOperation.EMBEDDING,
            CanonicalPurpose.RETRIEVAL_QUERY,
            probe_canaries(),
            batch,
        )


def test_vector_validator_rejects_invalid_dtype_norm_and_content_id_order() -> None:
    canaries = probe_canaries()
    reversed_ids = tuple(item.content_id for item in reversed(canaries))
    with pytest.raises(ProviderProfileValidationError):
        VectorValidator().validate_embedding(
            ProviderOperation.EMBEDDING,
            CanonicalPurpose.RETRIEVAL_QUERY,
            canaries,
            _embedding_batch(content_ids=reversed_ids),
        )
    with pytest.raises(ProviderProfileValidationError):
        VectorValidator().validate_embedding(
            ProviderOperation.EMBEDDING,
            CanonicalPurpose.RETRIEVAL_QUERY,
            canaries,
            _embedding_batch(vectors=((0.1, 0.1), (0.2, 0.2))),
        )


def test_reordered_duplicate_inputs_are_bound_to_distinct_content_ids() -> None:
    canaries = probe_canaries(duplicate_content=True)
    assert canaries[0].content == canaries[1].content
    assert canaries[0].content_id != canaries[1].content_id
    with pytest.raises(ProviderProfileValidationError):
        VectorValidator().validate_embedding(
            ProviderOperation.EMBEDDING,
            CanonicalPurpose.RETRIEVAL_DOCUMENT,
            canaries,
            EmbeddingProbeBatch(
                content_ids=(canaries[1].content_id, canaries[0].content_id),
                vectors=((0.6, 0.8), (0.8, 0.6)),
                dtype=VectorDtype.FLOAT32,
                normalization=VectorNormalization.L2,
            ),
        )


def test_reranking_validator_requires_exact_unique_ids_and_finite_bounded_scores() -> None:
    canaries = probe_canaries()
    validator = VectorValidator()
    valid = validator.validate_reranking(
        CanonicalPurpose.RETRIEVAL_QUERY,
        canaries,
        RerankingProbeBatch(
            content_ids=(canaries[1].content_id, canaries[0].content_id),
            scores=(0.9, -0.2),
        ),
    )
    assert valid.item_count == len(canaries)
    for batch in (
        RerankingProbeBatch((canaries[0].content_id,), (0.2,)),
        RerankingProbeBatch(
            (canaries[0].content_id, canaries[0].content_id),
            (0.2, 0.1),
        ),
        RerankingProbeBatch(
            (canaries[0].content_id, canaries[1].content_id),
            (float("nan"), 0.1),
        ),
        RerankingProbeBatch(
            (canaries[0].content_id, canaries[1].content_id),
            (1_000_001.0, 0.1),
        ),
    ):
        with pytest.raises(ProviderProfileValidationError):
            validator.validate_reranking(CanonicalPurpose.RETRIEVAL_QUERY, canaries, batch)


def test_probe_suite_rejects_false_purpose_support_and_missing_cancellation() -> None:
    suite = ProviderProbeSuite()
    canaries = probe_canaries()
    validated = VectorValidator().validate_embedding(
        ProviderOperation.EMBEDDING,
        CanonicalPurpose.RETRIEVAL_QUERY,
        canaries,
        _embedding_batch(),
    )
    with pytest.raises(ProviderProfileValidationError):
        suite.finalize(
            ProviderOperation.EMBEDDING,
            (
                CanonicalPurpose.RETRIEVAL_DOCUMENT,
                CanonicalPurpose.RETRIEVAL_QUERY,
            ),
            (validated,),
            cancellation_verified=True,
        )
    with pytest.raises(ProviderProfileValidationError):
        suite.finalize(
            ProviderOperation.EMBEDDING,
            (CanonicalPurpose.RETRIEVAL_QUERY,),
            (validated,),
            cancellation_verified=False,
        )


def test_capability_attestation_binds_adapter_endpoint_configuration_and_suite() -> None:
    configuration = remote_configuration()
    provider_manifest = manifest()
    result = probe_result()
    evidence = ProviderProbeEvidence.create(
        _binding(configuration_digest=configuration.digest),
        result,
        NOW,
    )
    assert evidence.adapter_digest == provider_manifest.implementation_digest
    assert evidence.endpoint_fingerprint == result.endpoint_fingerprint
    assert evidence.configuration_digest == configuration.digest
    assert evidence.suite_digest == result.suite_digest
    assert evidence.evidence_id == evidence.expected_id
    with pytest.raises(ProviderProfileValidationError):
        replace(evidence, adapter_digest=digest("other-adapter").value)
    with pytest.raises(ProviderProfileValidationError):
        replace(evidence, endpoint_fingerprint=digest("other-endpoint").value)
    with pytest.raises(ProviderProfileValidationError):
        replace(evidence, configuration_digest=digest("other-configuration").value)
    with pytest.raises(ProviderProfileValidationError):
        replace(evidence, suite_digest=digest("other-suite").value)


def test_configuration_or_probe_time_change_invalidates_attestation_identity() -> None:
    configuration = remote_configuration()
    evidence = ProviderProbeEvidence.create(
        _binding(configuration_digest=configuration.digest),
        probe_result(),
        NOW,
    )
    changed = remote_configuration(model_id="text-embedding-3-small")
    changed_evidence = ProviderProbeEvidence.create(
        _binding(configuration_digest=changed.digest),
        probe_result(model_id="text-embedding-3-small"),
        NOW,
    )
    later = ProviderProbeEvidence.create(
        _binding(configuration_digest=configuration.digest),
        probe_result(),
        NOW + timedelta(microseconds=1),
    )
    assert changed_evidence.evidence_id != evidence.evidence_id
    assert later.evidence_id != evidence.evidence_id
