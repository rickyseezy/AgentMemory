"""PRO-010 pricing, budget, telemetry, drift, and status ports."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.observability import (
        BudgetAdmission,
        DriftCanary,
        DriftEvaluation,
        DriftObservation,
        PricingSnapshot,
        ProviderBudgetPolicy,
        ProviderBudgetReservationRequest,
        ProviderDriftProbeLease,
        ProviderOperationFact,
        ProviderStatusSnapshot,
    )


class ProviderObservabilityAdministrationRepository(Protocol):
    """Persist immutable pricing, budget, and canary administration authority."""

    async def publish_pricing(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        snapshot: PricingSnapshot,
    ) -> PricingSnapshot:
        """Publish or exactly replay one pricing version."""
        ...

    async def publish_budget(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        policy: ProviderBudgetPolicy,
    ) -> ProviderBudgetPolicy:
        """Publish or exactly replay one budget policy version."""
        ...

    async def register_canary(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        canary: DriftCanary,
    ) -> DriftCanary:
        """Register or replay one pinned generation canary."""
        ...


class ProviderBudgetRepository(Protocol):
    """Serialize cost reservations and actual-usage reconciliation."""

    async def reserve_budget(
        self,
        request: ProviderBudgetReservationRequest,
    ) -> BudgetAdmission:
        """Reserve estimated cost or return the configured queue/degrade behavior."""
        ...

    async def record_and_reconcile(self, fact: ProviderOperationFact) -> None:
        """Append one operation fact and reconcile its reservation atomically."""
        ...


class ProviderPricingQuery(Protocol):
    """Resolve one exact immutable pricing snapshot."""

    async def get_pricing(self, snapshot_id: str) -> PricingSnapshot | None:
        """Return one catalog version or ``None``."""
        ...

    async def get_active_pricing(
        self,
        brain_id: str,
        profile_id: str,
        profile_version: int,
        at_microseconds: int,
    ) -> PricingSnapshot | None:
        """Return the effective exact catalog version for pre-dispatch admission."""
        ...


class ProviderDriftRepository(Protocol):
    """Read canaries and atomically record observations/write suspension."""

    async def get_canary(
        self,
        scope: AuthorizedScope,
        canary_id: str,
    ) -> DriftCanary | None:
        """Return one Brain-scoped canary or hide its existence."""
        ...

    async def record_drift(
        self,
        observation: DriftObservation,
        evaluation: DriftEvaluation,
    ) -> None:
        """Append evidence and suspend the exact generation on mismatch."""
        ...


class ProviderDriftProbe(Protocol):
    """Execute fixed non-sensitive canaries through one exact provider revision."""

    async def observe(self, canary: DriftCanary) -> DriftObservation:
        """Return only safe fingerprints, norms, ordering, and revision evidence."""
        ...


class ProviderDriftScheduleRepository(Protocol):
    """Lease, complete, and safely retry scheduled canary work."""

    async def claim_due(
        self,
        owner: str,
        now_microseconds: int,
        lease_until_microseconds: int,
    ) -> ProviderDriftProbeLease | None:
        """Claim at most one due non-suspended canary."""
        ...

    async def complete_probe(
        self,
        lease: ProviderDriftProbeLease,
        observation: DriftObservation,
        evaluation: DriftEvaluation,
    ) -> None:
        """Record one owner-bound observation and close its lease."""
        ...

    async def release_probe(
        self,
        lease: ProviderDriftProbeLease,
        retry_at_microseconds: int,
        released_at_microseconds: int,
    ) -> None:
        """Release one failed/cancelled lease with a bounded safe retry."""
        ...


class ProviderStatusRepository(Protocol):
    """Assemble one complete Brain-scoped provider status snapshot."""

    async def status(
        self,
        scope: AuthorizedScope,
        observed_at_microseconds: int,
    ) -> ProviderStatusSnapshot:
        """Aggregate canonical provider state without content or high-cardinality labels."""
        ...
