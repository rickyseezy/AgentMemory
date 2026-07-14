"""Stage, commit, and reconcile the Core active-release pointer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from agentmemory.operations.domain.active_release import ActiveReleasePointer
    from agentmemory.operations.domain.ports import ActiveReleaseUnitOfWorkFactory
    from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest


@dataclass(frozen=True, slots=True)
class ActiveReleaseStageResult:
    """Return Core's independently derived durable stage receipt."""

    stage_digest: Sha256Digest
    already_staged: bool


class ActiveReleaseTransactionHandler:
    """Authorize every pointer transition through one canonical SQLite UoW."""

    def __init__(self, unit_of_work: ActiveReleaseUnitOfWorkFactory) -> None:
        """Bind the use case to the injected transaction factory."""
        self._unit_of_work = unit_of_work

    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> ActiveReleaseStageResult:
        """Persist an idempotent intent only after restoring the 11-probe receipt."""
        try:
            async with self._unit_of_work() as unit_of_work:
                stage_digest, already_staged = await unit_of_work.active_releases.stage(
                    operation_id,
                    pointer,
                )
                await unit_of_work.commit()
        except OperationError:
            raise
        except Exception as error:
            raise OperationError(
                ErrorCode.INTERNAL,
                "active-release stage did not commit",
                retryable=False,
            ) from error
        return ActiveReleaseStageResult(stage_digest, already_staged)

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        """Atomically mirror only the exact host-approved staged pointer."""
        try:
            async with self._unit_of_work() as unit_of_work:
                pointer_digest = await unit_of_work.active_releases.commit(
                    operation_id,
                    stage_digest,
                    pointer,
                )
                await unit_of_work.commit()
        except OperationError:
            raise
        except Exception as error:
            raise OperationError(
                ErrorCode.INTERNAL,
                "active-release commit did not complete",
                retryable=False,
            ) from error
        return pointer_digest

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        """Re-authenticate the durable Core mirror and compare every pointer field."""
        try:
            async with self._unit_of_work() as unit_of_work:
                result = await unit_of_work.active_releases.matches(pointer)
                await unit_of_work.commit()
        except OperationError:
            raise
        except Exception as error:
            raise OperationError(
                ErrorCode.INTERNAL,
                "active-release reconciliation did not complete",
                retryable=False,
            ) from error
        return result
