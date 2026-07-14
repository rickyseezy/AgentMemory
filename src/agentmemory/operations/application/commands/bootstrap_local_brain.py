"""Idempotently create the first local installation owner and Brain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from agentmemory.operations.domain.bootstrap import BootstrapDisposition, BootstrapRequest
    from agentmemory.operations.domain.ports import CoreUnitOfWorkFactory


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    """Return the exact idempotent local-Brain bootstrap outcome."""

    installation_id: str
    brain_id: str
    disposition: BootstrapDisposition


class BootstrapLocalBrainHandler:
    """Authorize persistence through one constructor-injected canonical UoW."""

    def __init__(self, unit_of_work: CoreUnitOfWorkFactory) -> None:
        """Bind the handler to the canonical transaction boundary."""
        self._unit_of_work = unit_of_work

    async def execute(self, request: BootstrapRequest) -> BootstrapResult:
        """Create exact bootstrap records and one audit fact atomically."""
        try:
            async with self._unit_of_work() as unit_of_work:
                disposition = await unit_of_work.bootstrap.ensure(request)
                await unit_of_work.audit.append_bootstrap(request, disposition)
                await unit_of_work.commit()
        except OperationError:
            raise
        except Exception as error:
            raise OperationError(
                ErrorCode.INTERNAL,
                "local Brain bootstrap did not commit",
                retryable=False,
            ) from error
        return BootstrapResult(
            installation_id=request.installation_id.value,
            brain_id=request.brain_id.value,
            disposition=disposition,
        )
