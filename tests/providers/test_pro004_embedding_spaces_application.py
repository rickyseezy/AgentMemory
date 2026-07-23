"""PRO-004 application orchestration tests for generation creation and vector writes."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.identity.domain.retrieval_scope import AuthorizedScope, RetrievalRole
from agentmemory.providers.application.embedding_spaces import (
    EnsureIndexGenerationCommand,
    EnsureIndexGenerationHandler,
    WriteVectorBatchCommand,
    WriteVectorBatchHandler,
)
from agentmemory.providers.domain.embedding_space_ports import (
    EmbeddingGenerationReservation,
    VectorWriteReceipt,
)
from agentmemory.providers.domain.embedding_spaces import (
    EmbeddingSpace,
    IndexGeneration,
    IndexGenerationState,
    VectorWriteBatch,
)
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
)
from tests.core.support import GENERATION_ID, NOW, digest
from tests.providers.test_pro001_profiles_domain_application import scope
from tests.providers.test_pro004_embedding_spaces_domain import (
    PROFILE_ID,
    SPACE_ID,
    descriptor,
    generation,
    record,
    space,
)

if TYPE_CHECKING:
    from datetime import datetime


def _reservations() -> list[tuple[str, str, EmbeddingSpace, IndexGeneration]]:
    return []


def _completions() -> list[tuple[str, str, datetime]]:
    return []


def _generation_calls() -> list[tuple[EmbeddingSpace, IndexGeneration]]:
    return []


def _vector_calls() -> list[VectorWriteBatch]:
    return []


@dataclass(slots=True)
class _Identities:
    values: list[str] = field(
        default_factory=lambda: [
            SPACE_ID,
            GENERATION_ID,
        ]
    )

    def new(self) -> str:
        return self.values.pop(0)


@dataclass(slots=True)
class _Repository:
    reservations: list[tuple[str, str, EmbeddingSpace, IndexGeneration]] = field(
        default_factory=_reservations
    )
    completions: list[tuple[str, str, datetime]] = field(default_factory=_completions)

    async def reserve(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        candidate_space: EmbeddingSpace,
        candidate_generation: IndexGeneration,
    ) -> EmbeddingGenerationReservation:
        del scope
        self.reservations.append(
            (operation_id, request_digest, candidate_space, candidate_generation)
        )
        return EmbeddingGenerationReservation(
            space=candidate_space,
            generation=candidate_generation,
            request_digest=request_digest,
            created=True,
        )

    async def complete(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        generation_id: str,
        completed_at: datetime,
    ) -> IndexGeneration:
        del scope
        self.completions.append((operation_id, generation_id, completed_at))
        reservation = self.reservations[-1]
        return replace(reservation[3], state=IndexGenerationState.POPULATING)


@dataclass(slots=True)
class _Provisioner:
    calls: list[tuple[EmbeddingSpace, IndexGeneration]] = field(default_factory=_generation_calls)
    fail: bool = False

    async def ensure(self, space: EmbeddingSpace, generation: IndexGeneration) -> None:
        self.calls.append((space, generation))
        if self.fail:
            message = "index generation provisioning failed"
            raise EmbeddingSpaceDependencyError(message)


@dataclass(slots=True)
class _VectorRepository:
    calls: list[VectorWriteBatch] = field(default_factory=_vector_calls)

    async def write(self, batch: VectorWriteBatch) -> VectorWriteReceipt:
        self.calls.append(batch)
        return VectorWriteReceipt(
            generation_id=batch.generation.generation_id,
            space_fingerprint=batch.space.immutable_fingerprint,
            record_count=len(batch.records),
            batch_digest=batch.batch_digest,
            committed_at=NOW,
        )


def ensure_command(
    *,
    action: str = "provider.embedding_space.ensure",
    authorized_scope: AuthorizedScope | None = None,
) -> EnsureIndexGenerationCommand:
    return EnsureIndexGenerationCommand(
        operation_id="ensure-space-0001",
        scope=authorized_scope or scope(action),
        profile_id=PROFILE_ID,
        capability_attestation_id=digest("attestation").value,
        descriptor=descriptor(),
        requested_at=NOW,
    )


@pytest.mark.asyncio
async def test_ensure_generation_reserves_provisions_and_completes_exact_contract() -> None:
    repository = _Repository()
    provisioner = _Provisioner()
    handler = EnsureIndexGenerationHandler(repository, provisioner, _Identities())
    result = await handler.execute(ensure_command())
    assert result.state is IndexGenerationState.POPULATING
    assert len(repository.reservations) == 1
    _, request_digest, embedding_space, reserved = repository.reservations[0]
    assert request_digest == ensure_command().request_digest
    assert embedding_space.immutable_fingerprint == descriptor().immutable_fingerprint
    assert reserved.state is IndexGenerationState.CREATING
    assert provisioner.calls == [(embedding_space, reserved)]
    assert repository.completions == [
        ("ensure-space-0001", GENERATION_ID, NOW),
    ]


@pytest.mark.asyncio
async def test_generation_provision_failure_leaves_recoverable_creating_reservation() -> None:
    repository = _Repository()
    provisioner = _Provisioner(fail=True)
    handler = EnsureIndexGenerationHandler(repository, provisioner, _Identities())
    with pytest.raises(EmbeddingSpaceDependencyError):
        await handler.execute(ensure_command())
    assert len(repository.reservations) == 1
    assert repository.reservations[0][3].state is IndexGenerationState.CREATING
    assert repository.completions == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "authorized_scope",
    [
        scope("provider.embedding_space.ensure", role=RetrievalRole.READER),
        scope("provider.profile.read"),
    ],
)
async def test_generation_creation_rejects_wrong_role_or_action_before_storage(
    authorized_scope: AuthorizedScope,
) -> None:
    repository = _Repository()
    handler = EnsureIndexGenerationHandler(repository, _Provisioner(), _Identities())
    with pytest.raises(EmbeddingSpaceAuthorizationError):
        await handler.execute(ensure_command(authorized_scope=authorized_scope))
    assert repository.reservations == []


def test_commands_reject_invalid_boundary_coordinates() -> None:
    with pytest.raises(EmbeddingSpaceValidationError):
        replace(ensure_command(), operation_id="contains spaces")
    embedding_space = space()
    index_generation = generation(embedding_space)
    with pytest.raises(EmbeddingSpaceValidationError):
        WriteVectorBatchCommand(
            operation_id="write-vectors-0001",
            scope=scope("provider.vector.write"),
            space=embedding_space,
            generation=index_generation,
            records=(record(embedding_space, index_generation),),
            requested_at=NOW.replace(tzinfo=None),
        )


@pytest.mark.asyncio
async def test_vector_handler_validates_complete_batch_before_repository_write() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    repository = _VectorRepository()
    handler = WriteVectorBatchHandler(repository)
    command = WriteVectorBatchCommand(
        operation_id="write-vectors-0001",
        scope=scope("provider.vector.write"),
        space=embedding_space,
        generation=index_generation,
        records=(record(embedding_space, index_generation),),
        requested_at=NOW,
    )
    receipt = await handler.execute(command)
    assert receipt.record_count == 1
    assert len(repository.calls) == 1

    wrong_space = replace(command.records[0], space_fingerprint=digest("other-space").value)
    with pytest.raises(EmbeddingSpaceValidationError):
        await handler.execute(replace(command, records=(wrong_space,)))
    assert len(repository.calls) == 1


@pytest.mark.asyncio
async def test_vector_handler_rejects_generation_from_another_brain() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    repository = _VectorRepository()
    command = WriteVectorBatchCommand(
        operation_id="write-vectors-0001",
        scope=scope("provider.vector.write"),
        space=embedding_space,
        generation=replace(
            index_generation,
            brain_id="018f0000-0000-7000-8000-000000000199",
        ),
        records=(record(embedding_space, index_generation),),
        requested_at=NOW,
    )
    with pytest.raises(EmbeddingSpaceValidationError):
        await WriteVectorBatchHandler(repository).execute(command)
    assert repository.calls == []


@pytest.mark.asyncio
async def test_vector_handler_rejects_non_worker_authority_before_validation() -> None:
    embedding_space = space()
    index_generation = generation(embedding_space)
    repository = _VectorRepository()
    handler = WriteVectorBatchHandler(repository)
    command = WriteVectorBatchCommand(
        operation_id="write-vectors-0001",
        scope=scope("provider.vector.write", role=RetrievalRole.READER),
        space=embedding_space,
        generation=index_generation,
        records=(record(embedding_space, index_generation),),
        requested_at=NOW,
    )
    with pytest.raises(EmbeddingSpaceAuthorizationError):
        await handler.execute(command)
    assert repository.calls == []
