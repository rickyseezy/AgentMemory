"""PRO-004 immutable embedding-space, index-generation, and vector contracts."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING
from uuid import UUID

from agentmemory.providers.domain.errors import EmbeddingSpaceValidationError
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderExecutionClass,
    ProviderOperation,
    VectorDtype,
    VectorNormalization,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from datetime import datetime

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")
_ENDPOINT_CLASS = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_RESIDENCY = re.compile(r"^(?:global|[A-Z]{2}(?:-[A-Z0-9]{1,8})*)$")
_CLASSIFICATION = frozenset({"public", "internal", "confidential", "restricted", "local_only"})
_UUID_VERSION = 7
_MIN_DIMENSION = 1
_MAX_NEO4J_DIMENSION = 4096
_MAX_VECTOR_ABS = 1_000_000.0
_L2_TOLERANCE = 1e-4
_MAX_BATCH = 1000
_ERR_INPUT = "embedding space input is invalid"
_ERR_VECTOR = "vector batch disagrees with its immutable embedding space"


class IndexGenerationState(StrEnum):
    """ADR-007 generation states required by creation and safe writes."""

    CREATING = "creating"
    POPULATING = "populating"
    VALIDATING = "validating"
    SHADOW_READY = "shadow_ready"
    ACTIVE = "active"
    ROLLBACK_READY = "rollback_ready"
    RETIRED = "retired"
    FAILED = "failed"


_WRITABLE_GENERATION_STATES = frozenset(
    {
        IndexGenerationState.POPULATING,
        IndexGenerationState.SHADOW_READY,
        IndexGenerationState.ACTIVE,
    }
)


@dataclass(frozen=True, slots=True, kw_only=True)
class EmbeddingSpaceDescriptor:
    """Complete V1 semantic identity for comparable embedding vectors."""

    adapter_id: str
    adapter_digest: str
    adapter_version: str
    endpoint_class: str
    model_id: str
    model_revision: str | None
    model_weight_digest: str | None
    tokenizer_id: str
    tokenizer_revision: str
    tokenizer_digest: str
    pooling: str
    preprocessing_version: str
    unicode_normalization: str
    line_normalization: str
    chunking_contract: str
    truncation_policy: str
    dimension: int
    dtype: VectorDtype
    vector_encoding: str
    normalization: VectorNormalization
    similarity: str
    quantization: str
    inference_settings_digest: str
    purpose: CanonicalPurpose
    asymmetry_mapping: str
    instruction_template_digest: str
    runtime_image_digest: str
    deterministic_inference: bool
    execution_class: ProviderExecutionClass
    residency_class: str

    def __post_init__(self) -> None:
        """Reject implicit, mutable, or unsupported semantic coordinates."""
        tokens = (
            self.adapter_id,
            self.adapter_version,
            self.model_id,
            self.tokenizer_id,
            self.tokenizer_revision,
            self.pooling,
            self.preprocessing_version,
            self.unicode_normalization,
            self.line_normalization,
            self.chunking_contract,
            self.truncation_policy,
            self.vector_encoding,
            self.quantization,
            self.asymmetry_mapping,
        )
        if (
            any(_TOKEN.fullmatch(value) is None for value in tokens)
            or _ENDPOINT_CLASS.fullmatch(self.endpoint_class) is None
            or _RESIDENCY.fullmatch(self.residency_class) is None
            or not _is_digest(self.adapter_digest)
            or not _is_digest(self.tokenizer_digest)
            or not _is_digest(self.inference_settings_digest)
            or not _is_digest(self.instruction_template_digest)
            or not _is_digest(self.runtime_image_digest)
            or (self.model_weight_digest is not None and not _is_digest(self.model_weight_digest))
            or (self.model_revision is not None and _TOKEN.fullmatch(self.model_revision) is None)
            or (self.model_revision is None and self.model_weight_digest is None)
            or not _MIN_DIMENSION <= self.dimension <= _MAX_NEO4J_DIMENSION
            or self.similarity not in {"cosine", "euclidean"}
            or type(self.deterministic_inference) is not bool
        ):
            _invalid()

    @property
    def document(self) -> Mapping[str, object]:
        """Return every explicit V1 semantic coordinate in a read-only mapping."""
        return MappingProxyType(
            {
                "adapter_digest": self.adapter_digest,
                "adapter_id": self.adapter_id,
                "adapter_version": self.adapter_version,
                "asymmetry_mapping": self.asymmetry_mapping,
                "chunking_contract": self.chunking_contract,
                "descriptor_version": "EmbeddingSpaceDescriptorV1",
                "deterministic_inference": self.deterministic_inference,
                "dimension": self.dimension,
                "dtype": self.dtype.value,
                "endpoint_class": self.endpoint_class,
                "execution_class": self.execution_class.value,
                "inference_settings_digest": self.inference_settings_digest,
                "instruction_template_digest": self.instruction_template_digest,
                "line_normalization": self.line_normalization,
                "model_id": self.model_id,
                "model_revision": self.model_revision,
                "model_weight_digest": self.model_weight_digest,
                "normalization": self.normalization.value,
                "operation": ProviderOperation.EMBEDDING.value,
                "pooling": self.pooling,
                "preprocessing_version": self.preprocessing_version,
                "purpose": self.purpose.value,
                "quantization": self.quantization,
                "residency_class": self.residency_class,
                "runtime_image_digest": self.runtime_image_digest,
                "similarity": self.similarity,
                "tokenizer_digest": self.tokenizer_digest,
                "tokenizer_id": self.tokenizer_id,
                "tokenizer_revision": self.tokenizer_revision,
                "truncation_policy": self.truncation_policy,
                "unicode_normalization": self.unicode_normalization,
                "vector_encoding": self.vector_encoding,
            }
        )

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize the descriptor using the RFC-8785-compatible closed JSON subset."""
        return _canonical_document(self.document)

    @property
    def immutable_fingerprint(self) -> str:
        """Return the lowercase content address for this exact semantic space."""
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @classmethod
    def fingerprint_document(cls, document: Mapping[str, object]) -> str:
        """Fingerprint a complete descriptor document independent of mapping order."""
        if frozenset(document) != _DESCRIPTOR_KEYS:
            _invalid()
        return hashlib.sha256(_canonical_document(document)).hexdigest()

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> EmbeddingSpaceDescriptor:
        """Restore a descriptor only from its exact closed V1 schema."""
        if (
            frozenset(document) != _DESCRIPTOR_KEYS
            or document.get("descriptor_version") != "EmbeddingSpaceDescriptorV1"
            or document.get("operation") != ProviderOperation.EMBEDDING.value
        ):
            _invalid()
        try:
            return cls(
                adapter_id=_string(document["adapter_id"]),
                adapter_digest=_string(document["adapter_digest"]),
                adapter_version=_string(document["adapter_version"]),
                endpoint_class=_string(document["endpoint_class"]),
                model_id=_string(document["model_id"]),
                model_revision=_optional_string(document["model_revision"]),
                model_weight_digest=_optional_string(document["model_weight_digest"]),
                tokenizer_id=_string(document["tokenizer_id"]),
                tokenizer_revision=_string(document["tokenizer_revision"]),
                tokenizer_digest=_string(document["tokenizer_digest"]),
                pooling=_string(document["pooling"]),
                preprocessing_version=_string(document["preprocessing_version"]),
                unicode_normalization=_string(document["unicode_normalization"]),
                line_normalization=_string(document["line_normalization"]),
                chunking_contract=_string(document["chunking_contract"]),
                truncation_policy=_string(document["truncation_policy"]),
                dimension=_integer(document["dimension"]),
                dtype=VectorDtype(_string(document["dtype"])),
                vector_encoding=_string(document["vector_encoding"]),
                normalization=VectorNormalization(_string(document["normalization"])),
                similarity=_string(document["similarity"]),
                quantization=_string(document["quantization"]),
                inference_settings_digest=_string(document["inference_settings_digest"]),
                purpose=CanonicalPurpose(_string(document["purpose"])),
                asymmetry_mapping=_string(document["asymmetry_mapping"]),
                instruction_template_digest=_string(document["instruction_template_digest"]),
                runtime_image_digest=_string(document["runtime_image_digest"]),
                deterministic_inference=_boolean(document["deterministic_inference"]),
                execution_class=ProviderExecutionClass(_string(document["execution_class"])),
                residency_class=_string(document["residency_class"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise EmbeddingSpaceValidationError(_ERR_INPUT) from error


_DESCRIPTOR_KEYS = frozenset(EmbeddingSpaceDescriptor.__dataclass_fields__) | frozenset(
    {"descriptor_version", "operation"}
)


@dataclass(frozen=True, slots=True)
class EmbeddingSpace:
    """Immutable content-addressed embedding space bound to live probe evidence."""

    space_id: str
    profile_id: str
    capability_attestation_id: str
    descriptor: EmbeddingSpaceDescriptor
    immutable_fingerprint: str
    created_at: datetime

    def __post_init__(self) -> None:
        """Protect identity, evidence, fingerprint, and UTC persistence invariants."""
        if (
            not _is_uuid7(self.space_id)
            or not _is_uuid7(self.profile_id)
            or not _is_digest(self.capability_attestation_id)
            or self.immutable_fingerprint != self.descriptor.immutable_fingerprint
            or not _is_utc(self.created_at)
        ):
            _invalid()

    @classmethod
    def create(
        cls,
        *,
        space_id: str,
        profile_id: str,
        capability_attestation_id: str,
        descriptor: EmbeddingSpaceDescriptor,
        created_at: datetime,
    ) -> EmbeddingSpace:
        """Create one immutable aggregate from the descriptor content address."""
        return cls(
            space_id=space_id,
            profile_id=profile_id,
            capability_attestation_id=capability_attestation_id,
            descriptor=descriptor,
            immutable_fingerprint=descriptor.immutable_fingerprint,
            created_at=created_at,
        )

    @property
    def canonical_bytes(self) -> bytes:
        """Return canonical semantic bytes; database identities do not alter the space."""
        return self.descriptor.canonical_bytes


@dataclass(frozen=True, slots=True)
class GenerationNames:
    """Closed Neo4j identifiers derived solely from generation UUID bytes."""

    label: str
    vector_index: str
    vector_property: str = "embedding"


def generation_names(generation_id: str) -> GenerationNames:
    """Derive injection-proof physical names from one canonical UUIDv7."""
    if not _is_uuid7(generation_id):
        _invalid()
    compact = UUID(generation_id).hex
    return GenerationNames(
        label=f"AMVector_{compact}",
        vector_index=f"am_vec_{compact}",
    )


@dataclass(frozen=True, slots=True)
class IndexGeneration:
    """One Brain-bound physical vector index for exactly one embedding space."""

    generation_id: str
    brain_id: str
    space_id: str
    space_fingerprint: str
    names: GenerationNames
    dimension: int
    similarity: str
    state: IndexGenerationState
    created_at: datetime

    def __post_init__(self) -> None:
        """Require a self-consistent immutable physical-index contract."""
        if (
            not _is_uuid7(self.generation_id)
            or not _is_uuid7(self.brain_id)
            or not _is_uuid7(self.space_id)
            or not _is_digest(self.space_fingerprint)
            or self.names != generation_names(self.generation_id)
            or not _MIN_DIMENSION <= self.dimension <= _MAX_NEO4J_DIMENSION
            or self.similarity not in {"cosine", "euclidean"}
            or not _is_utc(self.created_at)
        ):
            _invalid()

    @classmethod
    def create(
        cls,
        *,
        generation_id: str,
        brain_id: str,
        space: EmbeddingSpace,
        state: IndexGenerationState,
        created_at: datetime,
    ) -> IndexGeneration:
        """Bind a generated label/index to one immutable space."""
        return cls(
            generation_id=generation_id,
            brain_id=brain_id,
            space_id=space.space_id,
            space_fingerprint=space.immutable_fingerprint,
            names=generation_names(generation_id),
            dimension=space.descriptor.dimension,
            similarity=space.descriptor.similarity,
            state=state,
            created_at=created_at,
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class VectorRecord:
    """One source-content-addressed vector prepared for an atomic graph batch."""

    record_id: str
    brain_id: str
    project_id: str
    repository_id: str
    checkout_id: str | None
    source_entity_id: str
    source_content_hash: str
    space_id: str
    space_fingerprint: str
    generation_id: str
    provider_profile_id: str
    purpose: CanonicalPurpose
    classification: str
    vector: tuple[float, ...]
    embedded_at: datetime

    def __post_init__(self) -> None:
        """Validate structural coordinates without changing numeric results."""
        identities = (
            self.record_id,
            self.brain_id,
            self.project_id,
            self.repository_id,
            self.source_entity_id,
            self.space_id,
            self.generation_id,
            self.provider_profile_id,
        )
        if (
            any(not _is_uuid7(value) for value in identities)
            or (self.checkout_id is not None and not _is_uuid7(self.checkout_id))
            or not _is_digest(self.source_content_hash)
            or not _is_digest(self.space_fingerprint)
            or self.classification not in _CLASSIFICATION
            or not self.vector
            or not _is_utc(self.embedded_at)
        ):
            _invalid()

    @property
    def idempotency_key(self) -> str:
        """Bind source content and semantic space without vector transformation."""
        authority = (
            f"{self.brain_id}|{self.source_entity_id}|{self.source_content_hash}|"
            f"{self.space_fingerprint}|{self.purpose.value}"
        )
        return hashlib.sha256(authority.encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class VectorWriteBatch:
    """Prevalidated all-or-nothing vector write for one physical generation."""

    space: EmbeddingSpace
    generation: IndexGeneration
    records: tuple[VectorRecord, ...]

    @classmethod
    def create(
        cls,
        space: EmbeddingSpace,
        generation: IndexGeneration,
        records: Sequence[VectorRecord],
    ) -> VectorWriteBatch:
        """Reject the complete batch before any repository transaction begins."""
        resolved = tuple(records)
        if (
            not resolved
            or len(resolved) > _MAX_BATCH
            or generation.space_id != space.space_id
            or generation.space_fingerprint != space.immutable_fingerprint
            or generation.dimension != space.descriptor.dimension
            or generation.similarity != space.descriptor.similarity
            or generation.state not in _WRITABLE_GENERATION_STATES
        ):
            _invalid_vector()
        record_ids: set[str] = set()
        idempotency_keys: set[str] = set()
        for record in resolved:
            _validate_record(space, generation, record)
            if record.record_id in record_ids or record.idempotency_key in idempotency_keys:
                _invalid_vector()
            record_ids.add(record.record_id)
            idempotency_keys.add(record.idempotency_key)
        return cls(space=space, generation=generation, records=resolved)

    @property
    def batch_digest(self) -> str:
        """Bind order, source content, semantics, and exact float results."""
        document = {
            "generation_id": self.generation.generation_id,
            "records": [
                {
                    "idempotency_key": record.idempotency_key,
                    "record_id": record.record_id,
                    "source_content_hash": record.source_content_hash,
                    "vector": [value.hex() for value in record.vector],
                }
                for record in self.records
            ],
            "space_fingerprint": self.space.immutable_fingerprint,
        }
        return hashlib.sha256(_canonical_document(document)).hexdigest()


def _validate_record(
    space: EmbeddingSpace,
    generation: IndexGeneration,
    record: VectorRecord,
) -> None:
    if (
        record.brain_id != generation.brain_id
        or record.space_id != space.space_id
        or record.space_fingerprint != space.immutable_fingerprint
        or record.generation_id != generation.generation_id
        or record.provider_profile_id != space.profile_id
        or record.purpose is not space.descriptor.purpose
        or len(record.vector) != space.descriptor.dimension
    ):
        _invalid_vector()
    squared_norm = 0.0
    for value in record.vector:
        if type(value) is not float or not math.isfinite(value) or abs(value) > _MAX_VECTOR_ABS:
            _invalid_vector()
        squared_norm += value * value
    norm = math.sqrt(squared_norm)
    if norm == 0.0:
        _invalid_vector()
    if space.descriptor.normalization is VectorNormalization.L2 and abs(norm - 1.0) > _L2_TOLERANCE:
        _invalid_vector()


def _canonical_document(document: Mapping[str, object]) -> bytes:
    try:
        return json.dumps(
            dict(document),
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise EmbeddingSpaceValidationError(_ERR_INPUT) from error


def _is_uuid7(value: str) -> bool:
    try:
        parsed = UUID(value)
    except AttributeError, ValueError:
        return False
    return str(parsed) == value and parsed.version == _UUID_VERSION


def _is_digest(value: str) -> bool:
    return _DIGEST.fullmatch(value) is not None and set(value) != {"0"}


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _string(value)


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError
    return value


def _boolean(value: object) -> bool:
    if not isinstance(value, bool):
        raise TypeError
    return value


def _invalid() -> None:
    raise EmbeddingSpaceValidationError(_ERR_INPUT)


def _invalid_vector() -> None:
    raise EmbeddingSpaceValidationError(_ERR_VECTOR)
