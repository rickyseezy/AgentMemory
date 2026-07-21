"""GRA-003 bounded durable assertion-edge projection worker."""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.graph.application.materialized_edges import (
    MaterializeAssertionEdgeCommand,
    ValidateAssertionEdgesCommand,
)
from agentmemory.graph.domain.errors import (
    GraphAuthorizationError,
    GraphConflictError,
    GraphIntegrityError,
    GraphUnavailableError,
)
from agentmemory.graph.domain.materialized_edges import ProjectionJobFailureCode

if TYPE_CHECKING:
    from agentmemory.graph.application.materialized_edges import (
        MaterializeAssertionEdgeHandler,
        ValidateAssertionEdgesHandler,
    )
    from agentmemory.graph.domain.materialized_edge_ports import (
        MaterializedEdgeGenerationResolver,
        MaterializedEdgeIntegrityScopeSource,
        MaterializedEdgeProjectionAuthorization,
        MaterializedEdgeProjectionWorkRepository,
    )
    from agentmemory.graph.domain.materialized_edges import MaterializedEdgeProjectionJob
    from agentmemory.shared.clock import Clock

_OWNER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_DEFAULT_LEASE_SECONDS = 30
_DEFAULT_POLL_SECONDS = 0.5
_MAX_ATTEMPTS = 12
_MAX_LEASE_SECONDS = 300
_MAX_POLL_SECONDS = 10.0
_MAX_RETRY_SECONDS = 300
_DEFAULT_INTEGRITY_INTERVAL_SECONDS = 60.0
_MAX_INTEGRITY_INTERVAL_SECONDS = 3_600.0
_MAX_INTEGRITY_SCOPES = 100
_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class MaterializedEdgeProjectionWorker:
    """Drain canonical assertion events into the current graph generation safely."""

    owner: str
    repository: MaterializedEdgeProjectionWorkRepository
    authorization: MaterializedEdgeProjectionAuthorization
    generations: MaterializedEdgeGenerationResolver
    handler: MaterializeAssertionEdgeHandler
    clock: Clock
    lease_seconds: int = _DEFAULT_LEASE_SECONDS
    poll_seconds: float = _DEFAULT_POLL_SECONDS

    def __post_init__(self) -> None:
        """Bound worker identity, lease duration, polling, and shutdown latency."""
        if (
            _OWNER.fullmatch(self.owner) is None
            or not 1 <= self.lease_seconds <= _MAX_LEASE_SECONDS
            or not 0 < self.poll_seconds <= _MAX_POLL_SECONDS
        ):
            msg = "materialized edge worker configuration is invalid"
            raise ValueError(msg)

    async def run(self, stop: asyncio.Event) -> None:
        """Process durable work until graceful shutdown is requested."""
        while not stop.is_set():
            processed = await self.execute_once()
            if processed:
                continue
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.poll_seconds)
            except TimeoutError:
                continue

    async def execute_once(self) -> bool:
        """Claim and contain exactly one durable work item."""
        now = self.clock.now()
        job = await self.repository.claim_next(
            self.owner,
            now,
            now + timedelta(seconds=self.lease_seconds),
        )
        if job is None:
            return False
        try:
            generation_id = await self.generations.active_generation(job.brain_id)
            if generation_id is None:
                await self._retry(job, ProjectionJobFailureCode.GENERATION_UNAVAILABLE)
                return True
            scope = await self.authorization.authorize(
                job,
                "graph.assertion.materialize",
                self.clock.now(),
            )
            edge = await self.handler.execute(
                MaterializeAssertionEdgeCommand(
                    job.source_event_id,
                    job.assertion_id,
                    generation_id,
                    scope,
                )
            )
            await self.repository.complete(
                job,
                generation_id,
                edge.projection_digest,
                edge.projection_status,
                self.clock.now(),
            )
        except GraphUnavailableError:
            await self._retry(job, ProjectionJobFailureCode.DEPENDENCY_UNAVAILABLE)
        except GraphAuthorizationError:
            await self.repository.quarantine(
                job,
                ProjectionJobFailureCode.AUTHORIZATION_REVOKED,
                self.clock.now(),
            )
        except GraphConflictError:
            await self.repository.quarantine(
                job,
                ProjectionJobFailureCode.CONCURRENT_CONFLICT,
                self.clock.now(),
            )
        except GraphIntegrityError:
            await self.repository.quarantine(
                job,
                ProjectionJobFailureCode.INTEGRITY_VIOLATION,
                self.clock.now(),
            )
        except Exception:  # noqa: BLE001 -- Unknown job failure is contained and bounded.
            await self._retry(job, ProjectionJobFailureCode.INTERNAL_ERROR)
        return True

    async def _retry(
        self,
        job: MaterializedEdgeProjectionJob,
        code: ProjectionJobFailureCode,
    ) -> None:
        if job.attempts >= _MAX_ATTEMPTS:
            await self.repository.quarantine(
                job,
                code,
                self.clock.now(),
            )
            return
        delay = min(_MAX_RETRY_SECONDS, 2 ** min(job.attempts, 8))
        attempted_at = self.clock.now()
        await self.repository.retry(
            job,
            code,
            attempted_at + timedelta(seconds=delay),
            attempted_at,
        )


@dataclass(frozen=True, slots=True)
class MaterializedEdgeIntegrityWorker:
    """Periodically reverse-check every bounded active Brain graph projection."""

    scopes: MaterializedEdgeIntegrityScopeSource
    handler: ValidateAssertionEdgesHandler
    clock: Clock
    interval_seconds: float = _DEFAULT_INTEGRITY_INTERVAL_SECONDS
    scope_limit: int = _MAX_INTEGRITY_SCOPES

    def __post_init__(self) -> None:
        """Bound scan fan-out, cadence, and shutdown latency."""
        if (
            not 0 < self.interval_seconds <= _MAX_INTEGRITY_INTERVAL_SECONDS
            or not 1 <= self.scope_limit <= _MAX_INTEGRITY_SCOPES
        ):
            msg = "materialized edge integrity worker configuration is invalid"
            raise ValueError(msg)

    async def run(self, stop: asyncio.Event) -> None:
        """Scan immediately and at a bounded cadence until shutdown."""
        while not stop.is_set():
            await self.execute_once()
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval_seconds)
            except TimeoutError:
                continue

    async def execute_once(self) -> tuple[int, int]:
        """Contain dependency/scope failures while returning observable safe counts."""
        checked_at = self.clock.now()
        values = await self.scopes.integrity_scopes(checked_at, self.scope_limit)
        checked = 0
        failed = 0
        for scope, generation_id in values:
            try:
                await self.handler.execute(
                    ValidateAssertionEdgesCommand(generation_id, checked_at, scope)
                )
                checked += 1
            except (
                GraphAuthorizationError,
                GraphConflictError,
                GraphIntegrityError,
                GraphUnavailableError,
            ) as error:
                failed += 1
                _LOGGER.warning(
                    "materialized edge integrity scope failed: %s",
                    type(error).__name__,
                )
        return checked, failed
