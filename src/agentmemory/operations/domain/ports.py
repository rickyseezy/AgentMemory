"""Capability-specific ports owned by the Core operations context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, Self

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.operations.domain.active_release import ActiveReleasePointer
    from agentmemory.operations.domain.bootstrap import BootstrapDisposition, BootstrapRequest
    from agentmemory.operations.domain.readiness import (
        ProbeEvidence,
        ReadinessBinding,
        ReadinessProbe,
        ReadinessReceipt,
    )
    from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest


class ReadinessProbePort(Protocol):
    """Execute exactly one independently evidenced readiness capability."""

    @property
    def probe(self) -> ReadinessProbe:
        """Return the one closed probe implemented by this capability."""
        ...

    async def execute(self, binding: ReadinessBinding) -> ProbeEvidence:
        """Return a bound positive or negative observation."""
        ...


class ReadinessReceiptRepository(Protocol):
    """Persist complete readiness receipts idempotently within one UoW."""

    async def add(self, receipt: ReadinessReceipt) -> None:
        """Add a new receipt or accept the exact previously stored receipt."""
        ...

    async def latest(self) -> ReadinessReceipt | None:
        """Return the latest verified receipt without mutating state."""
        ...


class ReadinessStatusPort(Protocol):
    """Read-only optimized readiness receipt query."""

    async def latest(self) -> ReadinessReceipt | None:
        """Return the latest verified receipt without mutating state."""
        ...


class RuntimeReadinessPort(Protocol):
    """Bound full-gate cadence while proving cheap dependencies live on every check."""

    async def verify(self, anchor: ReadinessReceipt) -> ReadinessReceipt | None:
        """Return a current trusted certificate only while runtime dependencies pass."""
        ...


class BootstrapRepository(Protocol):
    """Own the atomic first-install identity aggregate creation."""

    async def ensure(self, request: BootstrapRequest) -> BootstrapDisposition:
        """Create exact bootstrap state or return an exact idempotent match."""
        ...


class AuditRepository(Protocol):
    """Append governed non-content Core bootstrap facts."""

    async def append_bootstrap(
        self,
        request: BootstrapRequest,
        disposition: BootstrapDisposition,
    ) -> None:
        """Append one hash-chained audit fact inside the owning UoW."""
        ...


class ActiveReleaseRepository(Protocol):
    """Own the staged intent and exact active pointer mirror in one transaction."""

    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> tuple[Sha256Digest, bool]:
        """Persist or verify an exact readiness-authorized stage."""
        ...

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        """Mirror the exact staged pointer under anti-rollback policy."""
        ...

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        """Return equality only after authenticating every durable mirror."""
        ...


class ActiveReleaseUnitOfWork(Protocol):
    """Own one canonical transaction containing active-release persistence."""

    @property
    def active_releases(self) -> ActiveReleaseRepository:
        """Return transaction-scoped active-release persistence."""
        ...

    async def __aenter__(self) -> Self:
        """Open the active-release transaction scope."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unless the handler explicitly committed."""
        ...

    async def commit(self) -> None:
        """Commit the active-release mutation atomically."""
        ...


class ActiveReleaseUnitOfWorkFactory(Protocol):
    """Construct one fresh active-release transaction scope."""

    def __call__(self) -> ActiveReleaseUnitOfWork:
        """Return an unopened active-release Unit of Work."""
        ...


class CoreUnitOfWork(Protocol):
    """Own one canonical SQLite transaction and aggregate repositories."""

    @property
    def receipts(self) -> ReadinessReceiptRepository:
        """Return transaction-scoped readiness receipt persistence."""
        ...

    @property
    def bootstrap(self) -> BootstrapRepository:
        """Return transaction-scoped bootstrap aggregate persistence."""
        ...

    @property
    def audit(self) -> AuditRepository:
        """Return transaction-scoped governed audit persistence."""
        ...

    async def __aenter__(self) -> Self:
        """Open one transaction-scoped repository set."""
        ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        """Roll back unless the handler explicitly committed."""
        ...

    async def commit(self) -> None:
        """Commit all canonical mutations atomically."""
        ...


class CoreUnitOfWorkFactory(Protocol):
    """Construct one fresh explicit Core transaction scope."""

    def __call__(self) -> CoreUnitOfWork:
        """Return an unopened Unit of Work."""
        ...
