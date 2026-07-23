"""PRO-006 authorized enqueue, query, cancellation, and provider worker."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.providers.domain.errors import (
    ProviderSchedulingAuthorizationError,
    ProviderSchedulingDependencyError,
    ProviderSchedulingValidationError,
)
from agentmemory.providers.domain.scheduling import ProviderWorkItem

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.scheduling import ProviderBatchKey
    from agentmemory.providers.domain.scheduling_ports import (
        ProviderBatchGateway,
        ProviderDispatchAuthorizationPort,
        ProviderPayloadMaterializer,
        ProviderSchedulingIdentityGenerator,
        ProviderSchedulingRepository,
    )
    from agentmemory.shared.clock import Clock

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_WORKER = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_WRITE_ROLES = frozenset(
    {
        RetrievalRole.OWNER,
        RetrievalRole.ADMIN,
        RetrievalRole.EDITOR,
        RetrievalRole.ADAPTER,
        RetrievalRole.WORKER,
    }
)
_READ_ROLES = _WRITE_ROLES | frozenset({RetrievalRole.READER, RetrievalRole.AUDITOR})
_LEASE_MICROSECONDS = 60_000_000
_DEPENDENCY_RETRY_MICROSECONDS = 1_000_000
_MAX_POLL_SECONDS = 1.0
_ERR_INPUT = "provider scheduling request is invalid"
_ERR_ACTION = "provider scheduling action is not authorized"


@dataclass(frozen=True, slots=True, kw_only=True)
class EnqueueProviderWorkCommand:
    """Queue one immutable child under complete semantic/privacy coordinates."""

    operation_id: str
    scope: AuthorizedScope
    batch_key: ProviderBatchKey
    ordinal: int
    payload_ref: str
    content_digest: str
    token_count: int
    byte_count: int
    estimated_cost_micros: int
    deadline_at_microseconds: int
    enqueued_at: datetime

    def __post_init__(self) -> None:
        """Require stable idempotency, matching Brain/scope, and UTC enqueue time."""
        if (
            _OPERATION.fullmatch(self.operation_id) is None
            or self.batch_key.brain_id != self.scope.brain_id.value
            or not _is_utc(self.enqueued_at)
            or self.deadline_at_microseconds <= _microseconds_at(self.enqueued_at)
        ):
            raise ProviderSchedulingValidationError(_ERR_INPUT)

    @property
    def request_digest(self) -> str:
        """Bind idempotency to all caller-authored metadata, never payload content."""
        return _digest(
            {
                "batch_key": self.batch_key.document,
                "byte_count": self.byte_count,
                "content_digest": self.content_digest,
                "deadline_at_microseconds": self.deadline_at_microseconds,
                "estimated_cost_micros": self.estimated_cost_micros,
                "ordinal": self.ordinal,
                "payload_ref": self.payload_ref,
                "token_count": self.token_count,
            }
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class GetProviderWorkQuery:
    """Read one content-free provider item under current authority."""

    scope: AuthorizedScope
    item_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class CancelProviderWorkCommand:
    """Cancel one queued/retry item idempotently."""

    operation_id: str
    scope: AuthorizedScope
    item_id: str
    cancelled_at: datetime

    def __post_init__(self) -> None:
        """Require one stable operation and UTC cancellation time."""
        if _OPERATION.fullmatch(self.operation_id) is None or not _is_utc(self.cancelled_at):
            raise ProviderSchedulingValidationError(_ERR_INPUT)


@dataclass(frozen=True, slots=True)
class EnqueueProviderWorkHandler:
    """Authorize and persist one content-free work identity."""

    repository: ProviderSchedulingRepository
    identities: ProviderSchedulingIdentityGenerator

    async def execute(self, command: EnqueueProviderWorkCommand) -> ProviderWorkItem:
        """Queue one item without reading or materializing its payload."""
        _authorize(command.scope, "provider.schedule.enqueue", _WRITE_ROLES)
        _authorize_coordinates(command.scope, command.batch_key)
        work = ProviderWorkItem(
            item_id=self.identities.new(),
            operation_id=command.operation_id,
            batch_key=command.batch_key,
            ordinal=command.ordinal,
            payload_ref=command.payload_ref,
            content_digest=command.content_digest,
            token_count=command.token_count,
            byte_count=command.byte_count,
            estimated_cost_micros=command.estimated_cost_micros,
            enqueued_at_microseconds=_microseconds_at(command.enqueued_at),
            deadline_at_microseconds=command.deadline_at_microseconds,
        )
        return await self.repository.enqueue(
            command.scope,
            command.operation_id,
            command.request_digest,
            work,
        )


@dataclass(frozen=True, slots=True)
class GetProviderWorkHandler:
    """Read one exact Brain-scoped work item."""

    repository: ProviderSchedulingRepository

    async def execute(self, query: GetProviderWorkQuery) -> ProviderWorkItem | None:
        """Return content-free queue progress under current authority."""
        _authorize(query.scope, "provider.schedule.read", _READ_ROLES)
        return await self.repository.get(query.scope, query.item_id)


@dataclass(frozen=True, slots=True)
class CancelProviderWorkHandler:
    """Cancel queued or retry-scheduled provider work."""

    repository: ProviderSchedulingRepository

    async def execute(self, command: CancelProviderWorkCommand) -> ProviderWorkItem:
        """Persist one idempotent cancellation transition."""
        _authorize(command.scope, "provider.schedule.cancel", _WRITE_ROLES)
        return await self.repository.cancel(
            command.scope,
            command.operation_id,
            command.item_id,
            _microseconds_at(command.cancelled_at),
        )


@dataclass(frozen=True, slots=True)
class ProviderSchedulerWorker:
    """Claim, reauthorize, materialize, execute, zero, and complete one batch."""

    repository: ProviderSchedulingRepository
    authorizer: ProviderDispatchAuthorizationPort
    materializer: ProviderPayloadMaterializer
    gateway: ProviderBatchGateway
    clock: Clock
    owner: str
    poll_seconds: float = 0.05

    def __post_init__(self) -> None:
        """Bound worker identity and idle wait."""
        if _WORKER.fullmatch(self.owner) is None or not 0 <= self.poll_seconds <= _MAX_POLL_SECONDS:
            raise ProviderSchedulingValidationError(_ERR_INPUT)

    async def run(self, stop: asyncio.Event) -> None:
        """Recover expired leases once, then isolate every batch failure."""
        recovered = False
        while not stop.is_set():
            try:
                if not recovered:
                    await self.repository.recover_expired(_microseconds(self.clock))
                    recovered = True
                claimed = await self.run_once()
            except Exception:  # noqa: BLE001 -- One provider job cannot kill scheduling.
                await _wait_or_stop(stop, self.poll_seconds)
                continue
            if not claimed:
                await _wait_or_stop(stop, self.poll_seconds)

    async def run_once(self) -> bool:
        """Execute at most one due batch and report whether a lease was claimed."""
        now = _microseconds(self.clock)
        lease = await self.repository.claim_next(
            self.owner,
            now,
            now + _LEASE_MICROSECONDS,
        )
        if lease is None:
            return False
        payloads: list[bytearray] = []
        try:
            for work in lease.batch.items:
                await self.authorizer.authorize(work, _microseconds(self.clock))
                payloads.append(await self.materializer.materialize(work))
            outcome = await self.gateway.execute(lease.batch, payloads)
            outcome.validate_for(lease.batch)
            await self.repository.complete(lease, outcome, _microseconds(self.clock))
        except asyncio.CancelledError:
            await self.repository.release(
                lease,
                "worker_cancelled",
                _microseconds(self.clock) + _DEPENDENCY_RETRY_MICROSECONDS,
                _microseconds(self.clock),
            )
            raise
        except ProviderSchedulingAuthorizationError:
            await self.repository.release(
                lease,
                "authorization_denied",
                None,
                _microseconds(self.clock),
            )
        except ProviderSchedulingDependencyError:
            now = _microseconds(self.clock)
            await self.repository.release(
                lease,
                "dependency_unavailable",
                now + _DEPENDENCY_RETRY_MICROSECONDS,
                now,
            )
        except ProviderSchedulingValidationError:
            await self.repository.release(
                lease,
                "malformed_provider_response",
                None,
                _microseconds(self.clock),
            )
        finally:
            _zero(payloads)
        return True


def _authorize(
    scope: AuthorizedScope,
    action: str,
    roles: frozenset[RetrievalRole],
) -> None:
    if scope.action != action or scope.role not in roles:
        raise ProviderSchedulingAuthorizationError(_ERR_ACTION)


def _authorize_coordinates(scope: AuthorizedScope, key: ProviderBatchKey) -> None:
    if (
        key.project_id is not None
        and key.project_id not in {value.value for value in scope.project_ids}
    ) or (
        key.repository_id is not None
        and key.repository_id not in {value.value for value in scope.repository_ids}
    ):
        raise ProviderSchedulingAuthorizationError(_ERR_ACTION)


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
        raise ProviderSchedulingValidationError(_ERR_INPUT) from error
    result = hashlib.sha256(payload).hexdigest()
    if _DIGEST.fullmatch(result) is None:
        raise ProviderSchedulingValidationError(_ERR_INPUT)
    return result


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)


def _microseconds(clock: Clock) -> int:
    return _microseconds_at(clock.now())


def _microseconds_at(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _zero(payloads: list[bytearray]) -> None:
    for payload in payloads:
        payload[:] = b"\x00" * len(payload)


async def _wait_or_stop(stop: asyncio.Event, seconds: float) -> None:
    if seconds == 0:
        await asyncio.sleep(0)
        return
    try:
        await asyncio.wait_for(stop.wait(), timeout=seconds)
    except TimeoutError:
        return
