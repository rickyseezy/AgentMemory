"""PRO-003 provider-neutral live probe suite and strict vector validation."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Never, cast

from agentmemory.providers.domain.errors import ProviderProfileValidationError
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderOperation,
    VectorDtype,
    VectorNormalization,
)

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_ABSOLUTE_VALUE = 1_000_000.0
_MAX_DIMENSION = 65_536
_MAX_CANARY_CONTENT_LENGTH = 4_096
_MAX_PROBE_ITEMS = 1_000
_L2_TOLERANCE = 1e-4
_MIN_NONZERO_NORM = 1e-12
_ERR_PROBE = "provider capability probe is invalid"
_SUITE_CONTRACT = {
    "allowed_dtype": VectorDtype.FLOAT32.value,
    "l2_tolerance": _L2_TOLERANCE,
    "max_absolute_value": _MAX_ABSOLUTE_VALUE,
    "max_dimension": _MAX_DIMENSION,
    "ordered_content_ids": True,
    "require_cancellation": True,
    "suite": "agentmemory.provider-capability-probe.v1",
}


@dataclass(frozen=True, slots=True)
class ProbeCanary:
    """One fixed non-sensitive probe input with an order-independent identity."""

    content_id: str
    content: str

    def __post_init__(self) -> None:
        """Reject mutable, empty, oversized, or non-content-addressed canaries."""
        if (
            _DIGEST.fullmatch(self.content_id) is None
            or not 1 <= len(self.content) <= _MAX_CANARY_CONTENT_LENGTH
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class EmbeddingProbeBatch:
    """Untrusted provider embedding output awaiting validation."""

    content_ids: tuple[str, ...]
    vectors: tuple[object, ...]
    dtype: VectorDtype
    normalization: VectorNormalization


@dataclass(frozen=True, slots=True)
class RerankingProbeBatch:
    """Untrusted provider reranking output awaiting validation."""

    content_ids: tuple[str, ...]
    scores: tuple[float, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidatedProbeBatch:
    """Content-free digest evidence for one purpose-specific canary batch."""

    operation: ProviderOperation
    purpose: CanonicalPurpose
    item_count: int
    dimension: int | None
    batch_digest: str

    def __post_init__(self) -> None:
        """Reject evidence that cannot describe one bounded validated batch."""
        embedding = self.operation is ProviderOperation.EMBEDDING
        if (
            not 1 <= self.item_count <= _MAX_PROBE_ITEMS
            or _DIGEST.fullmatch(self.batch_digest) is None
            or (embedding and (self.dimension is None or not 1 <= self.dimension <= _MAX_DIMENSION))
            or (not embedding and self.dimension is not None)
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class ProbeSuiteResult:
    """Aggregate evidence that every requested purpose passed the same suite."""

    suite_digest: str
    canary_digest: str
    validation_digest: str
    validated_batches: int
    dimension: int | None

    def __post_init__(self) -> None:
        """Reject incomplete suite identities or impossible aggregate facts."""
        if (
            any(
                _DIGEST.fullmatch(value) is None
                for value in (self.suite_digest, self.canary_digest, self.validation_digest)
            )
            or not 1 <= self.validated_batches <= len(CanonicalPurpose)
            or (self.dimension is not None and not 1 <= self.dimension <= _MAX_DIMENSION)
        ):
            _invalid()


class VectorValidator:
    """Validate exact IDs, count, dtype, shape, finite range, and norm policy."""

    def validate_embedding(
        self,
        operation: ProviderOperation,
        purpose: CanonicalPurpose,
        expected: tuple[ProbeCanary, ...],
        batch: EmbeddingProbeBatch,
        *,
        expected_dimension: int | None = None,
    ) -> ValidatedProbeBatch:
        """Reject any embedding response that changes the ordered batch contract."""
        _validate_embedding_contract(operation, expected, batch)
        dimension: int | None = None
        canonical_vectors: list[list[str]] = []
        for untrusted_vector in batch.vectors:
            if not isinstance(untrusted_vector, tuple):
                _invalid()
            vector = cast("tuple[object, ...]", untrusted_vector)
            if not 1 <= len(vector) <= _MAX_DIMENSION:
                _invalid()
            if dimension is None:
                dimension = len(vector)
            if len(vector) != dimension:
                _invalid()
            canonical_vectors.append(_canonicalize_vector(vector, batch.normalization))
        if dimension is None or (
            expected_dimension is not None and dimension != expected_dimension
        ):
            _invalid()
        digest = _digest(
            {
                "content_ids": list(batch.content_ids),
                "dimension": dimension,
                "dtype": batch.dtype.value,
                "normalization": batch.normalization.value,
                "operation": operation.value,
                "purpose": purpose.value,
                "vectors": canonical_vectors,
            }
        )
        return ValidatedProbeBatch(
            operation=operation,
            purpose=purpose,
            item_count=len(expected),
            dimension=dimension,
            batch_digest=digest,
        )

    def validate_reranking(
        self,
        purpose: CanonicalPurpose,
        expected: tuple[ProbeCanary, ...],
        batch: RerankingProbeBatch,
    ) -> ValidatedProbeBatch:
        """Require a complete one-to-one content-ID permutation and finite scores."""
        expected_ids = tuple(item.content_id for item in expected)
        if (
            not expected
            or len(batch.content_ids) != len(expected_ids)
            or len(batch.scores) != len(expected_ids)
            or len(set(batch.content_ids)) != len(batch.content_ids)
            or set(batch.content_ids) != set(expected_ids)
        ):
            _invalid()
        canonical_scores: list[str] = []
        for score in batch.scores:
            if (
                type(score) is not float
                or not math.isfinite(score)
                or abs(score) > _MAX_ABSOLUTE_VALUE
            ):
                _invalid()
            canonical_scores.append(score.hex())
        return ValidatedProbeBatch(
            operation=ProviderOperation.RERANKING,
            purpose=purpose,
            item_count=len(expected),
            dimension=None,
            batch_digest=_digest(
                {
                    "content_ids": list(batch.content_ids),
                    "operation": ProviderOperation.RERANKING.value,
                    "purpose": purpose.value,
                    "scores": canonical_scores,
                }
            ),
        )


class ProviderProbeSuite:
    """Aggregate purpose-specific runtime evidence into one immutable suite result."""

    @property
    def suite_digest(self) -> str:
        """Return the release-stable validator contract identity."""
        return _digest(_SUITE_CONTRACT)

    @property
    def canary_digest(self) -> str:
        """Return the stable identity of the normal ordered canary corpus."""
        return _canary_digest(probe_canaries())

    def finalize(
        self,
        operation: ProviderOperation,
        purposes: tuple[CanonicalPurpose, ...],
        batches: tuple[ValidatedProbeBatch, ...],
        *,
        cancellation_verified: bool,
    ) -> ProbeSuiteResult:
        """Require one successful batch for every claimed purpose and one dimension."""
        if (
            not cancellation_verified
            or not purposes
            or tuple(sorted(set(purposes), key=str)) != purposes
            or len(batches) != len(purposes)
            or tuple(sorted((item.purpose for item in batches), key=str)) != purposes
            or any(item.operation is not operation for item in batches)
        ):
            _invalid()
        dimensions = {item.dimension for item in batches}
        if operation is ProviderOperation.EMBEDDING:
            if len(dimensions) != 1 or None in dimensions:
                _invalid()
            dimension = dimensions.pop()
        else:
            if dimensions != {None}:
                _invalid()
            dimension = None
        validation_digest = _digest(
            {
                "batch_digests": [item.batch_digest for item in batches],
                "canary_digest": self.canary_digest,
                "operation": operation.value,
                "purposes": [purpose.value for purpose in purposes],
                "suite_digest": self.suite_digest,
            }
        )
        return ProbeSuiteResult(
            suite_digest=self.suite_digest,
            canary_digest=self.canary_digest,
            validation_digest=validation_digest,
            validated_batches=len(batches),
            dimension=dimension,
        )


def probe_canaries(*, duplicate_content: bool = False) -> tuple[ProbeCanary, ...]:
    """Return fixed ordered, non-sensitive canaries with distinct content identities."""
    contents = (
        "AgentMemory provider probe alpha",
        "AgentMemory provider probe alpha"
        if duplicate_content
        else "AgentMemory provider probe beta",
    )
    return tuple(
        ProbeCanary(
            hashlib.sha256(
                f"agentmemory.provider-capability-probe.v1\0{index}\0{content}".encode()
            ).hexdigest(),
            content,
        )
        for index, content in enumerate(contents)
    )


def _canary_digest(canaries: tuple[ProbeCanary, ...]) -> str:
    return _digest([{"content": item.content, "content_id": item.content_id} for item in canaries])


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def _validate_embedding_contract(
    operation: ProviderOperation,
    expected: tuple[ProbeCanary, ...],
    batch: EmbeddingProbeBatch,
) -> None:
    expected_ids = tuple(item.content_id for item in expected)
    if (
        operation is not ProviderOperation.EMBEDDING
        or not expected
        or batch.content_ids != expected_ids
        or len(set(batch.content_ids)) != len(batch.content_ids)
        or len(batch.vectors) != len(expected)
        or batch.dtype is not VectorDtype.FLOAT32
    ):
        _invalid()


def _canonicalize_vector(
    vector: tuple[object, ...],
    normalization: VectorNormalization,
) -> list[str]:
    values: list[float] = []
    for value in vector:
        if type(value) is not float or not math.isfinite(value) or abs(value) > _MAX_ABSOLUTE_VALUE:
            _invalid()
        values.append(value)
    norm = math.sqrt(math.fsum(value * value for value in values))
    if not math.isfinite(norm) or norm <= _MIN_NONZERO_NORM:
        _invalid()
    if normalization is VectorNormalization.L2 and not math.isclose(
        norm,
        1.0,
        rel_tol=_L2_TOLERANCE,
        abs_tol=_L2_TOLERANCE,
    ):
        _invalid()
    return [value.hex() for value in values]


def _invalid() -> Never:
    raise ProviderProfileValidationError(_ERR_PROBE)
