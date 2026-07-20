"""Typed provider-operation failures safe to expose across application boundaries."""


class ProviderOperationConflictError(RuntimeError):
    """Reject reuse of an immutable provider idempotency identity with different input."""


class ProviderOperationDependencyError(RuntimeError):
    """Report retryable cache or provider dependency failure without leaking internals."""


class ProviderOperationIntegrityError(RuntimeError):
    """Fail closed when persisted provider operation evidence diverges."""
