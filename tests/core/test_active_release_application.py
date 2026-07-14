"""Active-release application transaction boundary tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

import pytest

from agentmemory.operations.application.commands.active_release import (
    ActiveReleaseTransactionHandler,
)
from agentmemory.operations.domain.errors import ErrorCode, OperationError
from tests.core.support import active_pointer, binding, digest

if TYPE_CHECKING:
    from types import TracebackType

    from agentmemory.operations.domain.active_release import ActiveReleasePointer
    from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest


@dataclass(slots=True)
class _ActiveRepository:
    failure: Exception | None = None

    def _raise(self) -> None:
        if self.failure is not None:
            raise self.failure

    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> tuple[Sha256Digest, bool]:
        del operation_id, pointer
        self._raise()
        return digest("stage"), False

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        del operation_id, stage_digest
        self._raise()
        return pointer.pointer_digest

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        del pointer
        self._raise()
        return True


@dataclass(slots=True)
class _ActiveUnitOfWork:
    active_releases: _ActiveRepository
    committed: bool = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None

    async def commit(self) -> None:
        self.committed = True


@dataclass(frozen=True, slots=True)
class _ActiveFactory:
    unit_of_work: _ActiveUnitOfWork

    def __call__(self) -> _ActiveUnitOfWork:
        return self.unit_of_work


@pytest.mark.asyncio
async def test_active_release_handler_commits_each_exact_repository_result() -> None:
    unit_of_work = _ActiveUnitOfWork(_ActiveRepository())
    handler = ActiveReleaseTransactionHandler(_ActiveFactory(unit_of_work))
    operation_id = binding().operation_id
    pointer = active_pointer()
    staged = await handler.stage(operation_id, pointer)
    assert staged.stage_digest == digest("stage")
    assert (
        await handler.commit(operation_id, staged.stage_digest, pointer) == pointer.pointer_digest
    )
    assert await handler.matches(pointer)
    assert unit_of_work.committed


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["stage", "commit", "matches"])
async def test_active_release_handler_maps_untyped_failures(method: str) -> None:
    repository = _ActiveRepository(failure=RuntimeError("raw database detail"))
    handler = ActiveReleaseTransactionHandler(_ActiveFactory(_ActiveUnitOfWork(repository)))
    with pytest.raises(OperationError) as raised:
        await _invoke(handler, method)
    assert raised.value.code is ErrorCode.INTERNAL
    assert "raw database detail" not in str(raised.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["stage", "commit", "matches"])
async def test_active_release_handler_preserves_typed_failures(method: str) -> None:
    expected = OperationError(ErrorCode.CONFLICT, "safe conflict")
    repository = _ActiveRepository(failure=expected)
    handler = ActiveReleaseTransactionHandler(_ActiveFactory(_ActiveUnitOfWork(repository)))
    with pytest.raises(OperationError) as raised:
        await _invoke(handler, method)
    assert raised.value is expected


async def _invoke(handler: ActiveReleaseTransactionHandler, method: str) -> object:
    operation_id = binding().operation_id
    pointer = active_pointer()
    if method == "stage":
        return await handler.stage(operation_id, pointer)
    if method == "commit":
        return await handler.commit(operation_id, digest("stage"), pointer)
    return await handler.matches(pointer)
