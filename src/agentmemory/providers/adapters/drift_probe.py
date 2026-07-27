"""Privacy-safe PRO-010 reduction of fixed canary vectors to drift evidence."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Never, Protocol

from agentmemory.providers.domain.capability_probe import ProviderProbeSuite, probe_canaries
from agentmemory.providers.domain.errors import ProviderObservabilityDependencyError
from agentmemory.providers.domain.observability import DriftCanary, DriftObservation
from agentmemory.providers.domain.profiles import ProviderOperation, ProviderProfileStatus

if TYPE_CHECKING:
    from collections.abc import Callable

    from agentmemory.providers.domain.profiles import CanonicalPurpose, ProviderProfile

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_DIMENSION = 65_536
_MAX_ABSOLUTE_VALUE = 1_000_000.0
_QUANTIZATION_UNITS = 1_000_000
_NORM_UNITS = 1_000_000
_ERR_PROBE = "Provider drift probe returned invalid safe evidence"


@dataclass(slots=True, kw_only=True)
class MutableDriftVectorBatch:
    """Untrusted ephemeral canary output whose vectors are always overwritten."""

    canary_set_digest: str
    content_ids: tuple[str, ...]
    vectors: list[list[float]] = field(repr=False)
    revision_fingerprint: str
    observed_at_microseconds: int


class DriftVectorGateway(Protocol):
    """Execute only the fixed public canary corpus for one exact profile revision."""

    async def execute(self, canary: DriftCanary) -> MutableDriftVectorBatch:
        """Return mutable vectors so the reduction boundary can zero them."""
        ...


@dataclass(slots=True, kw_only=True)
class MutableAdapterVectorResult:
    """Ephemeral validated adapter output retained only until drift reduction."""

    content_ids: tuple[str, ...]
    vectors: list[list[float]] = field(repr=False)
    revision_fingerprint: str


class ProviderDriftVectorAdapter(Protocol):
    """Execute the certified fixed canary corpus for one profile purpose."""

    async def observe_drift_vectors(
        self,
        profile: ProviderProfile,
        purpose: CanonicalPurpose,
    ) -> MutableAdapterVectorResult:
        """Return validated mutable vectors and immutable revision evidence."""
        ...


class ProviderDriftProfileSource(Protocol):
    """Load one exact active profile bound to its capability attestation."""

    async def get_drift_profile(
        self,
        canary: DriftCanary,
    ) -> tuple[ProviderProfile, CanonicalPurpose] | None:
        """Return the exact active semantic profile and purpose or ``None``."""
        ...


class ProviderDriftAdapterRegistry(Protocol):
    """Resolve one installed certified adapter by immutable adapter identity."""

    def get_drift(self, adapter_id: str) -> ProviderDriftVectorAdapter:
        """Return the exact drift-capable adapter."""
        ...


@dataclass(frozen=True, slots=True)
class ConfiguredDriftVectorGateway:
    """Resolve and execute only the shipped public canary against exact authority."""

    profiles: ProviderDriftProfileSource
    adapters: ProviderDriftAdapterRegistry
    now_microseconds: Callable[[], int]

    async def execute(self, canary: DriftCanary) -> MutableDriftVectorBatch:
        """Fail closed unless corpus, profile, purpose, and attestation still match."""
        expected = probe_canaries()
        if (
            canary.canary_set_digest != ProviderProbeSuite().canary_digest
            or canary.canary_item_ids != tuple(item.content_id for item in expected)
        ):
            _invalid()
        authority = await self.profiles.get_drift_profile(canary)
        if authority is None:
            _invalid()
        profile, purpose = authority
        if (
            profile.status is not ProviderProfileStatus.ACTIVE
            or profile.configuration.operation is not ProviderOperation.EMBEDDING
            or purpose not in profile.configuration.purposes
        ):
            _invalid()
        result = await self.adapters.get_drift(
            profile.configuration.adapter_id
        ).observe_drift_vectors(profile, purpose)
        return MutableDriftVectorBatch(
            canary_set_digest=canary.canary_set_digest,
            content_ids=result.content_ids,
            vectors=result.vectors,
            revision_fingerprint=result.revision_fingerprint,
            observed_at_microseconds=self.now_microseconds(),
        )


@dataclass(frozen=True, slots=True)
class ProviderVectorDriftProbe:
    """Validate, reduce, and zero drift vectors before canonical persistence."""

    gateway: DriftVectorGateway

    async def observe(self, canary: DriftCanary) -> DriftObservation:
        """Return fingerprints/norms/order only; vector buffers never escape."""
        batch = await self.gateway.execute(canary)
        try:
            return _reduce(canary, batch)
        except ProviderObservabilityDependencyError:
            raise
        except Exception as error:
            raise ProviderObservabilityDependencyError(_ERR_PROBE) from error
        finally:
            _zero(batch.vectors)


def _reduce(
    canary: DriftCanary,
    batch: MutableDriftVectorBatch,
) -> DriftObservation:
    if (
        batch.canary_set_digest != canary.canary_set_digest
        or batch.content_ids != canary.canary_item_ids
        or len(batch.vectors) != len(canary.canary_item_ids)
        or _DIGEST.fullmatch(batch.revision_fingerprint) is None
        or batch.observed_at_microseconds < canary.created_at_microseconds
    ):
        _invalid()
    dimension: int | None = None
    norms: list[int] = []
    quantized: list[list[int]] = []
    validated: list[tuple[float, ...]] = []
    for vector in batch.vectors:
        if (
            not _mutable_list(vector)
            or not vector
            or len(vector) > _MAX_DIMENSION
            or any(
                type(value) is not float
                or not math.isfinite(value)
                or abs(value) > _MAX_ABSOLUTE_VALUE
                for value in vector
            )
        ):
            _invalid()
        if dimension is None:
            dimension = len(vector)
        if len(vector) != dimension:
            _invalid()
        norm = math.sqrt(math.fsum(value * value for value in vector))
        if not math.isfinite(norm) or norm <= 0:
            _invalid()
        norms.append(round(norm * _NORM_UNITS))
        quantized.append([round(value * _QUANTIZATION_UNITS) for value in vector])
        validated.append(tuple(vector))
    fingerprint = hashlib.sha256(
        json.dumps(
            {
                "canary_item_ids": list(batch.content_ids),
                "quantization_units": _QUANTIZATION_UNITS,
                "vectors": quantized,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    ordering = _distance_order(batch.content_ids, tuple(validated), tuple(norms))
    return DriftObservation.create(
        canary=canary,
        revision_fingerprint=batch.revision_fingerprint,
        vector_fingerprint=fingerprint,
        canary_item_ids=batch.content_ids,
        norms_micros=tuple(norms),
        distance_order=ordering,
        observed_at_microseconds=batch.observed_at_microseconds,
    )


def _distance_order(
    content_ids: tuple[str, ...],
    vectors: tuple[tuple[float, ...], ...],
    norms_micros: tuple[int, ...],
) -> tuple[str, ...]:
    scores: list[tuple[float, str]] = []
    for left, vector in enumerate(vectors):
        distances = [
            1.0
            - math.fsum(a * b for a, b in zip(vector, other, strict=True))
            / ((norms_micros[left] / _NORM_UNITS) * (norms_micros[right] / _NORM_UNITS))
            for right, other in enumerate(vectors)
            if right != left
        ]
        score = math.fsum(distances) / len(distances)
        if not math.isfinite(score):
            _invalid()
        scores.append((score, content_ids[left]))
    return tuple(content_id for _, content_id in sorted(scores))


def _zero(vectors: list[list[float]]) -> None:
    for vector in vectors:
        vector[:] = [0.0] * len(vector)


def _mutable_list(value: object) -> bool:
    return isinstance(value, list)


def _invalid() -> Never:
    raise ProviderObservabilityDependencyError(_ERR_PROBE)
