"""Closed PF-003 external-adapter error taxonomy."""

from __future__ import annotations


class AdapterExtensionError(ValueError):
    """Base class for privacy-safe adapter extension failures."""


class AdapterValidationError(AdapterExtensionError):
    """A manifest, protocol, probe, or command violated the public contract."""


class AdapterAuthorizationError(AdapterExtensionError):
    """Current authority or requested permissions did not permit registration."""


class AdapterTrustError(AdapterExtensionError):
    """The package digest, signature, or publisher trust could not be proven."""


class AdapterProbeError(AdapterExtensionError):
    """The external implementation failed or substituted live conformance evidence."""


class AdapterConflictError(AdapterExtensionError):
    """An operation or immutable adapter version was reused inconsistently."""


class AdapterStorageError(AdapterExtensionError):
    """Atomic registry, audit, or outbox persistence failed closed."""
