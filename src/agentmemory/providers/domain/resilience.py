"""PRO-007 pure provider retry, equivalence, and circuit-breaker contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Never
from uuid import UUID

from agentmemory.providers.domain.errors import (
    ProviderErrorCode,
    ProviderResilienceValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderOperation,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+@-]{0,255}$")
_SAFE_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_UUID_VERSION = 7
_MAX_ATTEMPTS = 100
_MAX_DELAY_MICROSECONDS = 3_600_000_000
_MAX_FAILURE_THRESHOLD = 100
_MAX_CIRCUIT_WINDOW_MICROSECONDS = 3_600_000_000
_MAX_VECTOR_DIMENSION = 65_536
_MAX_OPERATION_KEY_LENGTH = 512
_MAX_EQUIVALENT_ENDPOINTS = 100
_ERR_INPUT = "provider resilience input is invalid"
_ERR_EQUIVALENCE = "provider endpoints are not proven equivalent"


class ProviderRetryAction(StrEnum):
    """Closed action returned by the canonical provider error policy."""

    FAIL = "fail"
    RETRY = "retry"
    EXHAUSTED = "exhausted"


class ProviderCircuitState(StrEnum):
    """Durable provider-endpoint circuit states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderErrorTraits:
    """Reviewed behavior for one canonical provider error code."""

    retryable: bool
    fallback_safe: bool
    counts_toward_circuit: bool


_ERROR_TRAITS: Mapping[ProviderErrorCode, ProviderErrorTraits] = MappingProxyType(
    {
        ProviderErrorCode.AUTHENTICATION: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.PERMISSION: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.INVALID_CONFIGURATION: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.UNSUPPORTED_CAPABILITY: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.MISSING_MODEL: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.OVERSIZED_INPUT: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.RATE_LIMIT: ProviderErrorTraits(
            retryable=True,
            fallback_safe=True,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.QUOTA: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.TIMEOUT: ProviderErrorTraits(
            retryable=True,
            fallback_safe=True,
            counts_toward_circuit=True,
        ),
        ProviderErrorCode.CANCELLATION: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.TRANSIENT_UPSTREAM: ProviderErrorTraits(
            retryable=True,
            fallback_safe=True,
            counts_toward_circuit=True,
        ),
        ProviderErrorCode.MALFORMED_RESPONSE: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=True,
        ),
        ProviderErrorCode.DIMENSION_MISMATCH: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=True,
        ),
        ProviderErrorCode.MODEL_DRIFT: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=True,
        ),
        ProviderErrorCode.PRIVACY_DENIAL: ProviderErrorTraits(
            retryable=False,
            fallback_safe=False,
            counts_toward_circuit=False,
        ),
        ProviderErrorCode.ADAPTER_CRASH: ProviderErrorTraits(
            retryable=True,
            fallback_safe=True,
            counts_toward_circuit=True,
        ),
    }
)


class ProviderErrorPolicy:
    """Exhaustive canonical classification shared by retries and circuits."""

    @staticmethod
    def traits(code: ProviderErrorCode) -> ProviderErrorTraits:
        """Return the reviewed behavior for every closed error code."""
        return _ERROR_TRAITS[code]

    @staticmethod
    def verify_complete() -> None:
        """Fail composition if an added provider error lacks reviewed behavior."""
        if set(_ERROR_TRAITS) != set(ProviderErrorCode):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderRetryDecision:
    """One pure bounded retry decision."""

    action: ProviderRetryAction
    retry_at_microseconds: int | None

    def __post_init__(self) -> None:
        """Require an absolute time only for a retry decision."""
        retrying = self.action is ProviderRetryAction.RETRY
        if retrying != (self.retry_at_microseconds is not None) or (
            self.retry_at_microseconds is not None and self.retry_at_microseconds < 0
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderRetryContext:
    """Caller and provider timing evidence for one retry decision."""

    attempt: int
    now_microseconds: int
    deadline_at_microseconds: int
    jitter_seed: str
    retry_after_microseconds: int | None = None

    def __post_init__(self) -> None:
        """Require a live deadline and a standards-normalized absolute hint."""
        if (
            not 1 <= self.attempt <= _MAX_ATTEMPTS
            or self.now_microseconds < 0
            or self.deadline_at_microseconds <= self.now_microseconds
            or _DIGEST.fullmatch(self.jitter_seed) is None
            or (
                self.retry_after_microseconds is not None
                and self.retry_after_microseconds < self.now_microseconds
            )
        ):
            _invalid()


@dataclass(frozen=True, slots=True)
class ProviderRetryPolicy:
    """Bounded exponential backoff with deterministic full jitter."""

    max_attempts: int
    transient_base_delay_microseconds: int
    throttle_base_delay_microseconds: int
    max_delay_microseconds: int

    @classmethod
    def production(cls) -> ProviderRetryPolicy:
        """Return the reviewed single-layer production retry policy."""
        return cls(
            max_attempts=3,
            transient_base_delay_microseconds=100_000,
            throttle_base_delay_microseconds=1_000_000,
            max_delay_microseconds=20_000_000,
        )

    def __post_init__(self) -> None:
        """Reject unbounded attempts, zero-delay loops, and invalid caps."""
        if (
            not 1 <= self.max_attempts <= _MAX_ATTEMPTS
            or not 1 <= self.transient_base_delay_microseconds <= _MAX_DELAY_MICROSECONDS
            or not 1 <= self.throttle_base_delay_microseconds <= _MAX_DELAY_MICROSECONDS
            or not max(
                self.transient_base_delay_microseconds,
                self.throttle_base_delay_microseconds,
            )
            <= self.max_delay_microseconds
            <= _MAX_DELAY_MICROSECONDS
        ):
            _invalid()

    def decide(
        self,
        code: ProviderErrorCode,
        context: ProviderRetryContext,
    ) -> ProviderRetryDecision:
        """Apply error class, attempt budget, jitter, hint, and caller deadline."""
        if not ProviderErrorPolicy.traits(code).retryable:
            return ProviderRetryDecision(ProviderRetryAction.FAIL, None)
        if context.attempt >= self.max_attempts:
            return ProviderRetryDecision(ProviderRetryAction.EXHAUSTED, None)
        base = (
            self.throttle_base_delay_microseconds
            if code is ProviderErrorCode.RATE_LIMIT
            else self.transient_base_delay_microseconds
        )
        exponent = min(context.attempt - 1, 30)
        window = min(self.max_delay_microseconds, base * (2**exponent))
        entropy = int(context.jitter_seed[:16], 16)
        delay = 1 + entropy % window
        retry_at = context.now_microseconds + delay
        if context.retry_after_microseconds is not None:
            retry_at = max(retry_at, context.retry_after_microseconds)
        if retry_at >= context.deadline_at_microseconds:
            return ProviderRetryDecision(ProviderRetryAction.EXHAUSTED, None)
        return ProviderRetryDecision(ProviderRetryAction.RETRY, retry_at)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderOutputContract:
    """Immutable semantic output identity required for safe endpoint fallback."""

    space_id: str
    space_fingerprint: str
    model_revision: str
    revision_fingerprint: str
    operation: ProviderOperation
    purpose: CanonicalPurpose
    preprocessing_digest: str
    dimension: int | None
    dtype: VectorDtype | None
    normalization: VectorNormalization | None
    similarity: SimilarityMetric | None
    suite_digest: str
    canary_digest: str
    validation_digest: str

    def __post_init__(self) -> None:
        """Require a complete live-probed output contract."""
        _uuid7(self.space_id)
        embedding = self.operation is ProviderOperation.EMBEDDING
        if (
            _DIGEST.fullmatch(self.space_fingerprint) is None
            or _REVISION.fullmatch(self.model_revision) is None
            or any(
                _DIGEST.fullmatch(value) is None
                for value in (
                    self.revision_fingerprint,
                    self.preprocessing_digest,
                    self.suite_digest,
                    self.canary_digest,
                    self.validation_digest,
                )
            )
            or (
                embedding
                and (
                    self.dimension is None
                    or not 1 <= self.dimension <= _MAX_VECTOR_DIMENSION
                    or self.dtype is None
                    or self.normalization is None
                    or self.similarity is None
                )
            )
            or (
                not embedding
                and any(
                    value is not None
                    for value in (
                        self.dimension,
                        self.dtype,
                        self.normalization,
                        self.similarity,
                    )
                )
            )
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return the complete canonical semantic identity."""
        return {
            "canary_digest": self.canary_digest,
            "dimension": self.dimension,
            "dtype": None if self.dtype is None else self.dtype.value,
            "model_revision": self.model_revision,
            "normalization": (None if self.normalization is None else self.normalization.value),
            "operation": self.operation.value,
            "preprocessing_digest": self.preprocessing_digest,
            "purpose": self.purpose.value,
            "revision_fingerprint": self.revision_fingerprint,
            "similarity": None if self.similarity is None else self.similarity.value,
            "space_fingerprint": self.space_fingerprint,
            "space_id": self.space_id,
            "suite_digest": self.suite_digest,
            "validation_digest": self.validation_digest,
        }

    @property
    def digest(self) -> str:
        """Return the exact output contract fingerprint."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderEndpointAttestation:
    """One live-probed endpoint bound to an immutable profile revision."""

    profile_id: str
    profile_version: int
    capability_attestation_id: str
    endpoint_fingerprint: str
    configuration_digest: str
    adapter_digest: str
    output_contract: ProviderOutputContract

    def __post_init__(self) -> None:
        """Reject mutable or unprobed endpoint evidence."""
        _uuid7(self.profile_id)
        if not 1 <= self.profile_version <= 2**31 - 1 or any(
            _DIGEST.fullmatch(value) is None
            for value in (
                self.capability_attestation_id,
                self.endpoint_fingerprint,
                self.configuration_digest,
                self.adapter_digest,
            )
        ):
            _invalid()

    @property
    def document(self) -> dict[str, object]:
        """Return content-free endpoint evidence."""
        return {
            "adapter_digest": self.adapter_digest,
            "capability_attestation_id": self.capability_attestation_id,
            "configuration_digest": self.configuration_digest,
            "endpoint_fingerprint": self.endpoint_fingerprint,
            "output_contract_digest": self.output_contract.digest,
            "profile_id": self.profile_id,
            "profile_version": self.profile_version,
        }

    @property
    def digest(self) -> str:
        """Return a content-addressed endpoint-attestation identity."""
        return _digest(self.document)


@dataclass(frozen=True, slots=True)
class EquivalentEndpointSet:
    """Ordered endpoints proven to emit one identical immutable output contract."""

    primary: ProviderEndpointAttestation
    fallbacks: tuple[ProviderEndpointAttestation, ...]

    def __post_init__(self) -> None:
        """Reject duplicate or semantically different fallback endpoints."""
        endpoints = self.endpoints
        if (
            not 1 <= len(endpoints) <= _MAX_EQUIVALENT_ENDPOINTS
            or any(item.output_contract != self.primary.output_contract for item in endpoints)
            or len({item.profile_id for item in endpoints}) != len(endpoints)
            or len({item.endpoint_fingerprint for item in endpoints}) != len(endpoints)
        ):
            raise ProviderResilienceValidationError(_ERR_EQUIVALENCE)

    @property
    def endpoints(self) -> tuple[ProviderEndpointAttestation, ...]:
        """Return primary then administrator-ranked equivalent fallbacks."""
        return (self.primary, *self.fallbacks)

    @property
    def set_id(self) -> str:
        """Return the immutable ordered equivalence-attestation identity."""
        return _digest(
            {
                "endpoints": [item.digest for item in self.endpoints],
                "output_contract_digest": self.primary.output_contract.digest,
            }
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderDispatchFact:
    """One content-free immutable endpoint-attempt fact."""

    operation_key_sha256: str
    endpoint: ProviderEndpointAttestation
    attempt: int
    fallback_ordinal: int
    outcome_code: str
    occurred_at_microseconds: int

    def __post_init__(self) -> None:
        """Reject content, ambiguous ordinals, or unbounded codes."""
        if (
            _DIGEST.fullmatch(self.operation_key_sha256) is None
            or not 1 <= self.attempt <= _MAX_ATTEMPTS
            or not 0 <= self.fallback_ordinal <= _MAX_ATTEMPTS
            or _SAFE_CODE.fullmatch(self.outcome_code) is None
            or self.occurred_at_microseconds < 0
        ):
            _invalid()

    @property
    def fact_id(self) -> str:
        """Return an idempotent evidence identity for one exact attempt outcome."""
        return _digest(
            {
                "attempt": self.attempt,
                "endpoint_attestation_digest": self.endpoint.digest,
                "fallback_ordinal": self.fallback_ordinal,
                "occurred_at_microseconds": self.occurred_at_microseconds,
                "operation_key_sha256": self.operation_key_sha256,
                "outcome_code": self.outcome_code,
            }
        )


@dataclass(frozen=True, slots=True)
class ProviderCircuitSnapshot:
    """Versioned circuit state for one exact endpoint attestation."""

    endpoint_fingerprint: str
    state: ProviderCircuitState
    consecutive_failures: int
    window_started_at_microseconds: int | None
    open_until_microseconds: int | None
    probe_in_flight: bool
    version: int

    @classmethod
    def initial(cls, endpoint_fingerprint: str) -> ProviderCircuitSnapshot:
        """Create one closed endpoint circuit."""
        return cls(
            endpoint_fingerprint=endpoint_fingerprint,
            state=ProviderCircuitState.CLOSED,
            consecutive_failures=0,
            window_started_at_microseconds=None,
            open_until_microseconds=None,
            probe_in_flight=False,
            version=0,
        )

    def __post_init__(self) -> None:
        """Require a coherent persisted circuit state."""
        if (
            _DIGEST.fullmatch(self.endpoint_fingerprint) is None
            or self.consecutive_failures < 0
            or self.version < 0
            or (
                self.window_started_at_microseconds is not None
                and self.window_started_at_microseconds < 0
            )
            or (self.open_until_microseconds is not None and self.open_until_microseconds < 0)
            or (
                self.state is ProviderCircuitState.CLOSED
                and (self.open_until_microseconds is not None or self.probe_in_flight)
            )
            or (
                self.state is ProviderCircuitState.OPEN
                and (self.open_until_microseconds is None or self.probe_in_flight)
            )
            or (
                self.state is ProviderCircuitState.HALF_OPEN
                and (self.open_until_microseconds is None or not self.probe_in_flight)
            )
        ):
            _invalid()


@dataclass(frozen=True, slots=True, kw_only=True)
class ProviderCircuitPermit:
    """Atomic before-call decision and its compare-and-swap state."""

    allowed: bool
    snapshot: ProviderCircuitSnapshot


@dataclass(frozen=True, slots=True)
class ProviderCircuitPolicy:
    """Pure provider circuit transitions driven by canonical error traits."""

    failure_threshold: int
    failure_window_microseconds: int
    open_microseconds: int

    @classmethod
    def production(cls) -> ProviderCircuitPolicy:
        """Return reviewed local production circuit thresholds."""
        return cls(
            failure_threshold=5,
            failure_window_microseconds=30_000_000,
            open_microseconds=30_000_000,
        )

    def __post_init__(self) -> None:
        """Reject zero, unbounded, or unusable circuit policy."""
        if (
            not 1 <= self.failure_threshold <= _MAX_FAILURE_THRESHOLD
            or not 1 <= self.failure_window_microseconds <= _MAX_CIRCUIT_WINDOW_MICROSECONDS
            or not 1 <= self.open_microseconds <= _MAX_CIRCUIT_WINDOW_MICROSECONDS
        ):
            _invalid()

    def acquire(
        self,
        snapshot: ProviderCircuitSnapshot,
        now_microseconds: int,
    ) -> ProviderCircuitPermit:
        """Allow a closed call or reserve the sole due half-open probe."""
        if now_microseconds < 0:
            _invalid()
        if snapshot.state is ProviderCircuitState.CLOSED:
            return ProviderCircuitPermit(allowed=True, snapshot=snapshot)
        if snapshot.state is ProviderCircuitState.HALF_OPEN:
            return ProviderCircuitPermit(allowed=False, snapshot=snapshot)
        if (
            snapshot.open_until_microseconds is None
            or now_microseconds < snapshot.open_until_microseconds
        ):
            return ProviderCircuitPermit(allowed=False, snapshot=snapshot)
        return ProviderCircuitPermit(
            allowed=True,
            snapshot=ProviderCircuitSnapshot(
                endpoint_fingerprint=snapshot.endpoint_fingerprint,
                state=ProviderCircuitState.HALF_OPEN,
                consecutive_failures=snapshot.consecutive_failures,
                window_started_at_microseconds=snapshot.window_started_at_microseconds,
                open_until_microseconds=snapshot.open_until_microseconds,
                probe_in_flight=True,
                version=snapshot.version + 1,
            ),
        )

    def after_failure(
        self,
        snapshot: ProviderCircuitSnapshot,
        code: ProviderErrorCode,
        now_microseconds: int,
    ) -> ProviderCircuitSnapshot:
        """Count only reviewed dependency/integrity failures and open at threshold."""
        if now_microseconds < 0:
            _invalid()
        traits = ProviderErrorPolicy.traits(code)
        if not traits.counts_toward_circuit:
            return self.after_abandon(snapshot, now_microseconds)
        started = snapshot.window_started_at_microseconds
        outside = started is None or now_microseconds - started > self.failure_window_microseconds
        failures = 1 if outside else snapshot.consecutive_failures + 1
        window_started = now_microseconds if outside else started
        should_open = (
            snapshot.state is ProviderCircuitState.HALF_OPEN or failures >= self.failure_threshold
        )
        return ProviderCircuitSnapshot(
            endpoint_fingerprint=snapshot.endpoint_fingerprint,
            state=ProviderCircuitState.OPEN if should_open else ProviderCircuitState.CLOSED,
            consecutive_failures=failures,
            window_started_at_microseconds=window_started,
            open_until_microseconds=(
                now_microseconds + self.open_microseconds if should_open else None
            ),
            probe_in_flight=False,
            version=snapshot.version + 1,
        )

    def after_success(
        self,
        snapshot: ProviderCircuitSnapshot,
        now_microseconds: int,
    ) -> ProviderCircuitSnapshot:
        """Close and reset a successful endpoint circuit."""
        if now_microseconds < 0:
            _invalid()
        return ProviderCircuitSnapshot(
            endpoint_fingerprint=snapshot.endpoint_fingerprint,
            state=ProviderCircuitState.CLOSED,
            consecutive_failures=0,
            window_started_at_microseconds=None,
            open_until_microseconds=None,
            probe_in_flight=False,
            version=snapshot.version + 1,
        )

    def after_abandon(
        self,
        snapshot: ProviderCircuitSnapshot,
        now_microseconds: int,
    ) -> ProviderCircuitSnapshot:
        """Release a half-open permit without fabricating failure or success."""
        if now_microseconds < 0:
            _invalid()
        if snapshot.state is not ProviderCircuitState.HALF_OPEN:
            return snapshot
        return ProviderCircuitSnapshot(
            endpoint_fingerprint=snapshot.endpoint_fingerprint,
            state=ProviderCircuitState.OPEN,
            consecutive_failures=snapshot.consecutive_failures,
            window_started_at_microseconds=snapshot.window_started_at_microseconds,
            open_until_microseconds=now_microseconds + self.open_microseconds,
            probe_in_flight=False,
            version=snapshot.version + 1,
        )


def retry_jitter_seed(operation_key: str, endpoint_fingerprint: str, attempt: int) -> str:
    """Bind deterministic jitter to one operation, endpoint, and attempt."""
    if (
        not operation_key
        or len(operation_key) > _MAX_OPERATION_KEY_LENGTH
        or _DIGEST.fullmatch(endpoint_fingerprint) is None
        or not 1 <= attempt <= _MAX_ATTEMPTS
    ):
        _invalid()
    return hashlib.sha256(
        f"agentmemory.provider-retry.v1\0{operation_key}\0"
        f"{endpoint_fingerprint}\0{attempt}".encode()
    ).hexdigest()


def _digest(value: object) -> str:
    try:
        payload = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    except (TypeError, ValueError) as error:
        raise ProviderResilienceValidationError(_ERR_INPUT) from error
    return hashlib.sha256(payload).hexdigest()


def _uuid7(value: str) -> None:
    try:
        parsed = UUID(value)
    except (TypeError, ValueError, AttributeError) as error:
        raise ProviderResilienceValidationError(_ERR_INPUT) from error
    if parsed.version != _UUID_VERSION or str(parsed) != value:
        _invalid()


def _invalid() -> Never:
    raise ProviderResilienceValidationError(_ERR_INPUT)
