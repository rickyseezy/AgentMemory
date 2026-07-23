"""PRO-004 immutable embedding-space and vector-batch domain acceptance tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta, timezone
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentmemory.providers.domain.embedding_space_ports import (
    EmbeddingGenerationReservation,
    VectorWriteReceipt,
)
from agentmemory.providers.domain.embedding_spaces import (
    EmbeddingSpace,
    EmbeddingSpaceDescriptor,
    IndexGeneration,
    IndexGenerationState,
    VectorRecord,
    VectorWriteBatch,
    generation_names,
)
from agentmemory.providers.domain.errors import EmbeddingSpaceValidationError
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    VectorDtype,
    VectorNormalization,
)
from tests.core.support import BRAIN_ID, GENERATION_ID, NOW, digest

SPACE_ID = "018f0000-0000-7000-8000-000000000101"
PROFILE_ID = "018f0000-0000-7000-8000-000000000102"
SOURCE_ID = "018f0000-0000-7000-8000-000000000103"
RECORD_ID = "018f0000-0000-7000-8000-000000000104"
PROJECT_ID = "018f0000-0000-7000-8000-000000000105"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000106"


def descriptor(**changes: object) -> EmbeddingSpaceDescriptor:
    """Build one complete semantic descriptor with no implicit defaults."""
    values: dict[str, object] = {
        "adapter_id": "openai",
        "adapter_digest": digest("adapter").value,
        "adapter_version": "1.2.3",
        "endpoint_class": "approved-openai-global",
        "model_id": "text-embedding-3-large",
        "model_revision": "2026-07-01",
        "model_weight_digest": None,
        "tokenizer_id": "cl100k_base",
        "tokenizer_revision": "2026-01",
        "tokenizer_digest": digest("tokenizer").value,
        "pooling": "provider_native",
        "preprocessing_version": "agentmemory-preprocess-v1",
        "unicode_normalization": "NFC",
        "line_normalization": "LF",
        "chunking_contract": "semantic-code-v1",
        "truncation_policy": "reject",
        "dimension": 2,
        "dtype": VectorDtype.FLOAT32,
        "vector_encoding": "float32-list",
        "normalization": VectorNormalization.L2,
        "similarity": "cosine",
        "quantization": "none",
        "inference_settings_digest": digest("inference").value,
        "purpose": CanonicalPurpose.RETRIEVAL_DOCUMENT,
        "asymmetry_mapping": "document-v1",
        "instruction_template_digest": digest("instruction").value,
        "runtime_image_digest": digest("runtime").value,
        "deterministic_inference": True,
        "execution_class": ProviderExecutionClass.REMOTE,
        "residency_class": "global",
    }
    values.update(changes)
    return EmbeddingSpaceDescriptor(**values)  # type: ignore[arg-type]


def space(space_descriptor: EmbeddingSpaceDescriptor | None = None) -> EmbeddingSpace:
    """Create the deterministic space aggregate used by vector tests."""
    return EmbeddingSpace.create(
        space_id=SPACE_ID,
        profile_id=PROFILE_ID,
        capability_attestation_id=digest("attestation").value,
        descriptor=space_descriptor or descriptor(),
        created_at=NOW,
    )


def generation(
    embedding_space: EmbeddingSpace | None = None,
    *,
    state: IndexGenerationState = IndexGenerationState.POPULATING,
) -> IndexGeneration:
    """Create one exact generation bound to the space and Brain."""
    return IndexGeneration.create(
        generation_id=GENERATION_ID,
        brain_id=BRAIN_ID,
        space=embedding_space or space(),
        state=state,
        created_at=NOW,
    )


def record(
    embedding_space: EmbeddingSpace | None = None,
    index_generation: IndexGeneration | None = None,
    **changes: object,
) -> VectorRecord:
    """Build one valid vector record."""
    resolved_space = embedding_space or space()
    resolved_generation = index_generation or generation(resolved_space)
    values: dict[str, object] = {
        "record_id": RECORD_ID,
        "brain_id": BRAIN_ID,
        "project_id": PROJECT_ID,
        "repository_id": REPOSITORY_ID,
        "checkout_id": None,
        "source_entity_id": SOURCE_ID,
        "source_content_hash": digest("source-content").value,
        "space_id": resolved_space.space_id,
        "space_fingerprint": resolved_space.immutable_fingerprint,
        "generation_id": resolved_generation.generation_id,
        "provider_profile_id": PROFILE_ID,
        "purpose": resolved_space.descriptor.purpose,
        "classification": "internal",
        "vector": (0.6, 0.8),
        "embedded_at": NOW,
    }
    values.update(changes)
    return VectorRecord(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "changed"),
    [
        ("adapter_id", "cohere"),
        ("adapter_digest", digest("other-adapter").value),
        ("adapter_version", "1.2.4"),
        ("endpoint_class", "approved-openai-eu"),
        ("model_id", "text-embedding-3-small"),
        ("model_revision", "2026-07-02"),
        ("model_weight_digest", digest("weights").value),
        ("tokenizer_id", "o200k_base"),
        ("tokenizer_revision", "2026-02"),
        ("tokenizer_digest", digest("other-tokenizer").value),
        ("pooling", "mean"),
        ("preprocessing_version", "agentmemory-preprocess-v2"),
        ("unicode_normalization", "NFKC"),
        ("line_normalization", "preserve"),
        ("chunking_contract", "semantic-code-v2"),
        ("truncation_policy", "tail-8192"),
        ("dimension", 3),
        ("dtype", VectorDtype.FLOAT16),
        ("vector_encoding", "base64-float32"),
        ("normalization", VectorNormalization.NONE),
        ("similarity", "euclidean"),
        ("quantization", "int8-symmetric"),
        ("inference_settings_digest", digest("other-inference").value),
        ("purpose", CanonicalPurpose.RETRIEVAL_QUERY),
        ("asymmetry_mapping", "query-v1"),
        ("instruction_template_digest", digest("other-instruction").value),
        ("runtime_image_digest", digest("other-runtime").value),
        ("deterministic_inference", False),
        ("execution_class", ProviderExecutionClass.LOCAL),
        ("residency_class", "AE"),
    ],
)
def test_every_semantic_metadata_delta_creates_a_new_fingerprint(
    field: str,
    changed: object,
) -> None:
    baseline = descriptor()
    change = cast("dict[str, Any]", {field: changed})
    assert replace(baseline, **change).immutable_fingerprint != (baseline.immutable_fingerprint)


@given(st.permutations(tuple(descriptor().document)))
def test_canonical_fingerprint_does_not_depend_on_mapping_insertion_order(
    key_order: list[str],
) -> None:
    baseline = descriptor()
    reordered = {key: baseline.document[key] for key in key_order}
    assert EmbeddingSpaceDescriptor.fingerprint_document(reordered) == (
        baseline.immutable_fingerprint
    )


def test_space_fingerprint_is_content_addressed_and_immutable() -> None:
    first = space()
    second = EmbeddingSpace.create(
        space_id="018f0000-0000-7000-8000-000000000199",
        profile_id=PROFILE_ID,
        capability_attestation_id=digest("attestation").value,
        descriptor=descriptor(),
        created_at=NOW + timedelta(seconds=1),
    )
    assert first.immutable_fingerprint == first.descriptor.immutable_fingerprint
    assert second.immutable_fingerprint == first.immutable_fingerprint
    assert first.canonical_bytes == second.canonical_bytes


def test_descriptor_contract_rejects_invalid_identity_and_closed_documents() -> None:
    baseline = descriptor()
    with pytest.raises(EmbeddingSpaceValidationError):
        descriptor(adapter_id="")
    with pytest.raises(EmbeddingSpaceValidationError):
        EmbeddingSpaceDescriptor.fingerprint_document({})

    wrong_schema = dict(baseline.document)
    wrong_schema["operation"] = "completion"
    with pytest.raises(EmbeddingSpaceValidationError):
        EmbeddingSpaceDescriptor.from_document(wrong_schema)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("adapter_id", 7),
        ("dimension", True),
        ("deterministic_inference", 1),
    ],
)
def test_descriptor_restore_rejects_wrong_runtime_types(field: str, value: object) -> None:
    document = dict(descriptor().document)
    document[field] = value
    with pytest.raises(EmbeddingSpaceValidationError):
        EmbeddingSpaceDescriptor.from_document(document)


def test_descriptor_fingerprint_rejects_non_json_coordinate() -> None:
    document = dict(descriptor().document)
    document["adapter_id"] = object()
    with pytest.raises(EmbeddingSpaceValidationError):
        EmbeddingSpaceDescriptor.fingerprint_document(document)


def test_space_generation_record_and_reservation_reject_inconsistent_aggregates() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    with pytest.raises(EmbeddingSpaceValidationError):
        replace(embedding_space, immutable_fingerprint=digest("wrong-space").value)
    with pytest.raises(EmbeddingSpaceValidationError):
        replace(index_generation, similarity="dot")
    with pytest.raises(EmbeddingSpaceValidationError):
        record(embedding_space, index_generation, classification="secret")
    with pytest.raises(EmbeddingSpaceValidationError):
        EmbeddingGenerationReservation(
            space=embedding_space,
            generation=replace(
                index_generation,
                space_id="018f0000-0000-7000-8000-000000000199",
            ),
            request_digest=digest("reservation").value,
            created=True,
        )


def test_generation_names_are_derived_only_from_uuid_bytes() -> None:
    names = generation_names(GENERATION_ID)
    assert names.label == "AMVector_018f0000000070008000000000000005"
    assert names.vector_index == "am_vec_018f0000000070008000000000000005"
    assert names.vector_property == "embedding"
    for hostile in (
        "foo`) DELETE n //",
        "AMVector_deadbeef",
        "018f0000-0000-7000-8000-000000000005`",
        "text-embedding-3-large",
    ):
        with pytest.raises(EmbeddingSpaceValidationError):
            generation_names(hostile)


@pytest.mark.parametrize(
    "changes",
    [
        {"vector": (1.0,)},
        {"vector": (0.6, 0.8, 0.0)},
        {"vector": (float("nan"), 0.0)},
        {"vector": (float("inf"), 0.0)},
        {"vector": (1, 0.0)},
        {"vector": (0.0, 0.0)},
        {"space_id": "018f0000-0000-7000-8000-000000000199"},
        {"space_fingerprint": digest("wrong-space").value},
        {"generation_id": "018f0000-0000-7000-8000-000000000199"},
        {"purpose": CanonicalPurpose.RETRIEVAL_QUERY},
        {"brain_id": "018f0000-0000-7000-8000-000000000199"},
    ],
)
def test_vector_batch_rejects_dimension_numeric_and_mixed_space_errors_atomically(
    changes: dict[str, object],
) -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    candidate = record(embedding_space, index_generation, **changes)
    with pytest.raises(EmbeddingSpaceValidationError):
        VectorWriteBatch.create(embedding_space, index_generation, (candidate,))


def test_vector_batch_rejects_non_unit_l2_vector() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    with pytest.raises(EmbeddingSpaceValidationError):
        VectorWriteBatch.create(
            embedding_space,
            index_generation,
            (record(embedding_space, index_generation, vector=(0.5, 0.5)),),
        )


def test_vector_batch_binds_content_hash_and_deterministic_idempotency_key() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    candidate = record(embedding_space, index_generation)
    batch = VectorWriteBatch.create(embedding_space, index_generation, (candidate,))
    assert batch.records == (candidate,)
    assert (
        candidate.idempotency_key
        == digest(
            f"{BRAIN_ID}|{SOURCE_ID}|{digest('source-content').value}|"
            f"{embedding_space.immutable_fingerprint}|"
            f"{CanonicalPurpose.RETRIEVAL_DOCUMENT.value}"
        ).value
    )


def test_vector_batch_rejects_duplicate_record_and_idempotency_coordinates() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    first = record(embedding_space, index_generation)
    with pytest.raises(EmbeddingSpaceValidationError):
        VectorWriteBatch.create(embedding_space, index_generation, (first, first))
    same_content = replace(
        first,
        record_id="018f0000-0000-7000-8000-000000000199",
    )
    with pytest.raises(EmbeddingSpaceValidationError):
        VectorWriteBatch.create(
            embedding_space,
            index_generation,
            (first, same_content),
        )


@pytest.mark.parametrize(
    "committed_at",
    [
        NOW.replace(tzinfo=None),
        NOW.astimezone(timezone(timedelta(hours=4))),
    ],
)
def test_vector_write_receipt_requires_an_exact_utc_commit_instant(
    committed_at: object,
) -> None:
    with pytest.raises(EmbeddingSpaceValidationError):
        VectorWriteReceipt(
            generation_id=GENERATION_ID,
            space_fingerprint=digest("space").value,
            record_count=1,
            batch_digest=digest("batch").value,
            committed_at=cast("Any", committed_at),
        )


@pytest.mark.parametrize(
    "state",
    [
        IndexGenerationState.CREATING,
        IndexGenerationState.FAILED,
        IndexGenerationState.RETIRED,
    ],
)
def test_vector_batch_rejects_non_writable_generation_state(
    state: IndexGenerationState,
) -> None:
    embedding_space = space()
    index_generation = generation(embedding_space, state=state)
    with pytest.raises(EmbeddingSpaceValidationError):
        VectorWriteBatch.create(
            embedding_space,
            index_generation,
            (record(embedding_space, index_generation),),
        )
