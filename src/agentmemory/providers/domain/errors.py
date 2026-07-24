"""Typed provider-operation failures safe to expose across application boundaries."""

from enum import StrEnum


class ProviderErrorCode(StrEnum):
    """Canonical provider failure codes shared by every built-in adapter."""

    AUTHENTICATION = "authentication"
    PERMISSION = "permission"
    INVALID_CONFIGURATION = "invalid_configuration"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    MISSING_MODEL = "missing_model"
    OVERSIZED_INPUT = "oversized_input"
    RATE_LIMIT = "rate_limit"
    QUOTA = "quota"
    TIMEOUT = "timeout"
    CANCELLATION = "cancellation"
    TRANSIENT_UPSTREAM = "transient_upstream"
    MALFORMED_RESPONSE = "malformed_response"
    DIMENSION_MISMATCH = "dimension_mismatch"
    MODEL_DRIFT = "model_drift"
    PRIVACY_DENIAL = "privacy_denial"
    ADAPTER_CRASH = "adapter_crash"


class ProviderAdapterError(RuntimeError):
    """Safe adapter exception carrying no upstream body, credential, or URL."""

    def __init__(
        self,
        code: ProviderErrorCode,
        *,
        retry_after_microseconds: int | None = None,
    ) -> None:
        """Store only canonical retry evidence and one generated content-free message."""
        if retry_after_microseconds is not None and retry_after_microseconds < 0:
            msg = "provider retry hint is invalid"
            raise ValueError(msg)
        self.code = code
        self.retry_after_microseconds = retry_after_microseconds
        super().__init__(f"provider adapter failed: {code.value}")


class ProviderOperationConflictError(RuntimeError):
    """Reject reuse of an immutable provider idempotency identity with different input."""


class ProviderOperationDependencyError(RuntimeError):
    """Report retryable cache or provider dependency failure without leaking internals."""


class ProviderOperationIntegrityError(RuntimeError):
    """Fail closed when persisted provider operation evidence diverges."""


class ProviderProfileValidationError(ValueError):
    """Reject malformed or unsupported provider-profile input."""


class ProviderProfileAuthorizationError(PermissionError):
    """Reject a provider-profile action without current Brain-wide authority."""


class ProviderProfileConflictError(RuntimeError):
    """Reject an idempotency, manifest, version, or immutable-history conflict."""


class ProviderProfileDependencyError(RuntimeError):
    """Expose one content-free provider, gateway, or storage dependency failure."""


class ProviderModelDriftError(ProviderProfileConflictError):
    """Prevent a mutable provider alias from changing an active model generation."""


class EmbeddingSpaceValidationError(ValueError):
    """Reject malformed or semantically incompatible embedding-space data."""


class EmbeddingSpaceAuthorizationError(PermissionError):
    """Reject an embedding-space action without current Brain-wide authority."""


class EmbeddingSpaceConflictError(RuntimeError):
    """Reject immutable-space, generation, or idempotency conflicts."""


class EmbeddingSpaceDependencyError(RuntimeError):
    """Expose a content-free canonical or graph storage dependency failure."""


class EmbeddingMigrationValidationError(ValueError):
    """Reject malformed generation migration state, progress, or evidence."""


class EmbeddingMigrationAuthorizationError(PermissionError):
    """Reject generation migration without current Brain-wide authority."""


class EmbeddingMigrationConflictError(RuntimeError):
    """Reject stale, divergent, or unsafe generation migration state."""


class EmbeddingMigrationDependencyError(RuntimeError):
    """Expose content-free migration source, target, or storage failure."""


class ProviderRoutingValidationError(ValueError):
    """Reject malformed, ambiguous, or policy-broadening routing input."""


class ProviderRoutingAuthorizationError(PermissionError):
    """Reject routing publication or resolution without current Brain authority."""


class ProviderRoutingConflictError(RuntimeError):
    """Reject stale versions, idempotency conflicts, or corrupt routing history."""


class ProviderRoutingDependencyError(RuntimeError):
    """Expose a content-free routing storage dependency failure."""


class ProviderRoutingDeniedError(PermissionError):
    """Fail closed when the selected route violates privacy or residency policy."""


class ProviderRoutingCapabilityError(RuntimeError):
    """Fail closed when the selected profile cannot serve the requested operation."""


class ProviderSchedulingValidationError(ValueError):
    """Reject malformed, mixed, oversized, or inconsistent provider work."""


class ProviderSchedulingAuthorizationError(PermissionError):
    """Reject scheduling or final dispatch without current exact authority."""


class ProviderSchedulingConflictError(RuntimeError):
    """Reject idempotency, cancellation, lease, or immutable-result conflicts."""


class ProviderSchedulingDependencyError(RuntimeError):
    """Expose a content-free scheduler, payload, or provider dependency failure."""


class ProviderSchedulingCapacityError(RuntimeError):
    """Report a bounded rate, concurrency, quota, or cost-budget denial."""


class ProviderResilienceValidationError(ValueError):
    """Reject malformed retry, circuit, endpoint, or output-contract evidence."""


class ProviderResilienceAuthorizationError(PermissionError):
    """Reject resilience publication or lookup without current Brain authority."""


class ProviderResilienceConflictError(RuntimeError):
    """Reject divergent equivalence, circuit, or operation evidence."""


class ProviderResilienceDependencyError(RuntimeError):
    """Expose one content-free circuit or operation-store dependency failure."""


class ProviderRetryScheduledError(RuntimeError):
    """Return one durable retry time without exposing an upstream response."""

    def __init__(self, code: ProviderErrorCode, retry_at_microseconds: int) -> None:
        """Bind a canonical retryable code to its absolute due time."""
        if retry_at_microseconds < 0:
            msg = "provider retry schedule is invalid"
            raise ValueError(msg)
        self.code = code
        self.retry_at_microseconds = retry_at_microseconds
        super().__init__(f"provider retry scheduled: {code.value}")


class ProviderPermanentFailureError(RuntimeError):
    """Fail immediately for a canonical nonretryable provider error."""

    def __init__(self, code: ProviderErrorCode) -> None:
        """Store only the safe closed error code."""
        self.code = code
        super().__init__(f"provider operation failed permanently: {code.value}")
