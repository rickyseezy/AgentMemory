# pyright: reportPrivateUsage=false
"""MEM-004 domain, application, persistence, and transport fail-closed boundaries."""

from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest
from sqlalchemy import text

from agentmemory.memory.adapters.outbound import sqlite_correction as sqlite_memory
from agentmemory.memory.adapters.outbound.sqlite_correction import (
    SqliteMemoryCorrectionRepository,
    SqliteMemoryCorrectionUnitOfWorkFactory,
)
from agentmemory.memory.application.correct_memory import CorrectMemoryHandler
from agentmemory.memory.application.query_memory_corrections import (
    GetMemoryCorrectionHistoryHandler,
    MemoryCorrectionHistoryQuery,
    MemoryCorrectionHistoryView,
)
from agentmemory.memory.domain.consolidation import MemoryScope, MemoryStatus
from agentmemory.memory.domain.correction import (
    CorrectionEvidence,
    CorrectionTarget,
    MemoryAssertionSelection,
    MemoryCorrectionAssertion,
    MemoryCorrectionCommit,
    MemoryCorrectionHistory,
    MemoryCorrectionPlan,
    MemoryCorrectionResult,
    MemoryPrecedencePolicy,
    correction_idempotency_key,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
    MemoryIntegrityError,
    MemoryValidationError,
)
from tests.core.support import migrated_store, write_secret
from tests.memory.test_mem002_sqlite_repository import _persist_memory
from tests.memory.test_mem004_correction_application import (
    _Clock,
    _command,
    _Repository,
    _UnitOfWork,
)
from tests.memory.test_mem004_correction_domain import (
    ACTOR_ID,
    BRAIN_ID,
    CORRECTION_ID,
    EVIDENCE_ID,
    GRANT_ID,
    MEMORY_ID,
    NOW,
    PROJECT_ID,
    REPOSITORY_ID,
    _target,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from sqlalchemy.engine import RowMapping


OTHER_ID = "018f0000-0000-7000-8000-000000000599"

_TARGET_MUTATIONS: tuple[Callable[[CorrectionTarget], CorrectionTarget], ...] = (
    lambda item: replace(item, content_sha256="f" * 64),
    lambda item: replace(item, classification="secret"),
    lambda item: replace(item, evidence_ids=(EVIDENCE_ID, EVIDENCE_ID)),
    lambda item: replace(item, aggregate_version=0),
    lambda item: replace(item, statement=" invalid"),
    lambda item: replace(item, valid_to=item.valid_from),
    lambda item: replace(item, assertion_id="invalid"),
)

_ASSERTION_MUTATIONS: tuple[
    Callable[[MemoryCorrectionAssertion], MemoryCorrectionAssertion], ...
] = (
    lambda item: replace(item, assertion_id=item.root_memory_id),
    lambda item: replace(item, content_sha256="f" * 64),
    lambda item: replace(item, evidence=(CorrectionEvidence(EVIDENCE_ID, "e" * 64),) * 2),
    lambda item: replace(item, status=MemoryStatus.MERGED),
    lambda item: replace(item, classification="secret"),
    lambda item: replace(item, policy_version="memory-precedence.v2"),
    lambda item: replace(item, aggregate_version=0),
    lambda item: replace(item, reason="INVALID"),
)

_RESULT_MUTATIONS: tuple[Callable[[MemoryCorrectionResult], MemoryCorrectionResult], ...] = (
    lambda item: replace(item, source_status=MemoryStatus.ACTIVE),
    lambda item: replace(item, source_version=1),
    lambda item: replace(item, policy_version="memory-precedence.v2"),
    lambda item: replace(item, result_sha256="f" * 64),
)


def _plan() -> MemoryCorrectionPlan:
    target = _target("Use PostgreSQL")
    return MemoryCorrectionPlan.create(
        correction_id=CORRECTION_ID,
        target=target,
        expected_version=1,
        statement="Use SQLite",
        scope=target.scope,
        valid_from=NOW,
        valid_to=None,
        reason="user_correction",
        evidence=(),
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        recorded_at=NOW + timedelta(minutes=1),
        policy=MemoryPrecedencePolicy(),
    )


def _result(
    plan: MemoryCorrectionPlan | None = None, request: str = "e" * 64
) -> MemoryCorrectionResult:
    value = plan or _plan()
    return MemoryCorrectionResult.create(
        correction_idempotency_key(CORRECTION_ID, MEMORY_ID, BRAIN_ID),
        request,
        value,
    )


def _commit() -> MemoryCorrectionCommit:
    plan = _plan()
    return MemoryCorrectionCommit(
        CORRECTION_ID,
        ACTOR_ID,
        GRANT_ID,
        BRAIN_ID,
        "018f0000-0000-7000-8000-000000000511",
        "018f0000-0000-7000-8000-000000000512",
        plan.target,
        plan,
        _result(plan),
        NOW,
        NOW + timedelta(minutes=1),
    )


def _different_result(commit: MemoryCorrectionCommit) -> MemoryCorrectionResult:
    target = commit.target
    different = MemoryCorrectionPlan.create(
        correction_id=CORRECTION_ID,
        target=target,
        expected_version=target.aggregate_version,
        statement="Use MariaDB",
        scope=target.scope,
        valid_from=NOW,
        valid_to=None,
        reason="user_correction",
        evidence=(),
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        recorded_at=NOW + timedelta(minutes=1),
        policy=MemoryPrecedencePolicy(),
    )
    return MemoryCorrectionResult.create(
        commit.result.idempotency_key,
        commit.result.request_sha256,
        different,
    )


def _commit_with_early_completion(item: MemoryCorrectionCommit) -> MemoryCorrectionCommit:
    return replace(item, completed_at=NOW - timedelta(seconds=1))


def _commit_with_wrong_brain(item: MemoryCorrectionCommit) -> MemoryCorrectionCommit:
    return replace(item, brain_id=OTHER_ID)


def _commit_with_changed_target(item: MemoryCorrectionCommit) -> MemoryCorrectionCommit:
    return replace(item, target=replace(item.target, aggregate_version=2))


def _commit_with_wrong_operation(item: MemoryCorrectionCommit) -> MemoryCorrectionCommit:
    return replace(item, operation_id=OTHER_ID)


def _commit_with_different_result(item: MemoryCorrectionCommit) -> MemoryCorrectionCommit:
    return replace(item, result=_different_result(item))


@pytest.mark.parametrize("mutation", _TARGET_MUTATIONS)
def test_target_rejects_tampered_content_scope_time_identity_and_version(
    mutation: Callable[[CorrectionTarget], CorrectionTarget],
) -> None:
    with pytest.raises(MemoryValidationError):
        mutation(_target("Use PostgreSQL"))


@pytest.mark.parametrize("mutation", _ASSERTION_MUTATIONS)
def test_assertion_rejects_lineage_content_evidence_lifecycle_and_policy_tampering(
    mutation: Callable[[MemoryCorrectionAssertion], MemoryCorrectionAssertion],
) -> None:
    with pytest.raises(MemoryValidationError):
        mutation(_plan().assertion)


def test_history_policy_and_plan_reject_disconnected_or_ineffective_state() -> None:
    plan = _plan()
    target = plan.target
    with pytest.raises(MemoryValidationError):
        MemoryCorrectionHistory(replace(target, assertion_id=CORRECTION_ID), ())
    with pytest.raises(MemoryValidationError):
        MemoryCorrectionHistory(
            target,
            (replace(plan.assertion, source_assertion_id=OTHER_ID),),
        )
    with pytest.raises(MemoryValidationError):
        MemoryPrecedencePolicy("memory-precedence.v2")
    with pytest.raises(MemoryValidationError):
        MemoryPrecedencePolicy().resolve(
            target,
            (),
            MemoryScope(BRAIN_ID, PROJECT_ID, OTHER_ID, None),
            valid_at=NOW,
            recorded_at=NOW,
        )
    with pytest.raises(MemoryValidationError):
        MemoryPrecedencePolicy().resolve(
            replace(target, valid_to=NOW + timedelta(seconds=1)),
            (),
            target.scope,
            valid_at=NOW + timedelta(minutes=2),
            recorded_at=NOW + timedelta(minutes=2),
        )
    with pytest.raises(MemoryConflictError):
        MemoryCorrectionPlan.create(
            correction_id=OTHER_ID,
            target=replace(
                target,
                status=MemoryStatus.SUPERSEDED,
                recorded_to=NOW + timedelta(minutes=1),
            ),
            expected_version=1,
            statement="Use SQLite",
            scope=target.scope,
            valid_from=NOW,
            valid_to=None,
            reason="user_correction",
            evidence=(),
            actor_id=ACTOR_ID,
            grant_id=GRANT_ID,
            recorded_at=NOW + timedelta(minutes=2),
            policy=MemoryPrecedencePolicy(),
        )
    with pytest.raises(MemoryValidationError):
        replace(plan, source_version=99)
    with pytest.raises(MemoryValidationError):
        replace(plan, source_status=MemoryStatus.DISPUTED)
    with pytest.raises(MemoryValidationError):
        replace(plan, policy_version="memory-precedence.v2")


@pytest.mark.parametrize("mutation", _RESULT_MUTATIONS)
def test_receipt_rejects_lifecycle_policy_and_digest_tampering(
    mutation: Callable[[MemoryCorrectionResult], MemoryCorrectionResult],
) -> None:
    with pytest.raises(MemoryValidationError):
        mutation(_result())


@pytest.mark.parametrize(
    "mutation",
    [
        _commit_with_early_completion,
        _commit_with_wrong_brain,
        _commit_with_changed_target,
        _commit_with_wrong_operation,
        _commit_with_different_result,
    ],
)
def test_commit_rejects_time_scope_target_authority_and_result_drift(
    mutation: Callable[[MemoryCorrectionCommit], MemoryCorrectionCommit],
) -> None:
    with pytest.raises(MemoryValidationError):
        mutation(_commit())


@pytest.mark.asyncio
async def test_application_rechecks_deadline_target_and_evidence_inside_transaction() -> None:
    target = _target("Use PostgreSQL")
    command = _command()
    for invalid in (
        replace(command, requested_at=NOW + timedelta(minutes=2)),
        replace(command, deadline=NOW + timedelta(seconds=30)),
    ):
        repository = _Repository(target=target)
        with pytest.raises(MemoryValidationError):
            await CorrectMemoryHandler(
                repository,
                lambda repository=repository: _UnitOfWork(repository),
                MemoryPrecedencePolicy(),
                _Clock(),
            ).execute(invalid)

    missing_target = _Repository(target=target, transaction_target=None)
    missing_target.in_transaction = True
    # Explicitly model revocation at the transaction boundary.
    missing_target.target = None
    with pytest.raises(MemoryEvidenceNotFoundError):
        await CorrectMemoryHandler(
            _Repository(target=target),
            lambda: _UnitOfWork(missing_target),
            MemoryPrecedencePolicy(),
            _Clock(),
        ).execute(command)

    initial = CorrectionEvidence(EVIDENCE_ID, "e" * 64)
    changed = CorrectionEvidence(EVIDENCE_ID, "d" * 64)
    outer = _Repository(target=target, evidence=(initial,))
    inner = _Repository(target=target, evidence=(changed,))
    with pytest.raises(MemoryConflictError):
        await CorrectMemoryHandler(
            outer,
            lambda: _UnitOfWork(inner),
            MemoryPrecedencePolicy(),
            _Clock(),
        ).execute(_command(evidence_ids=(EVIDENCE_ID,)))


def test_history_query_rejects_invalid_identity_scope_time_and_selection() -> None:
    target = _target("Use PostgreSQL")
    base = MemoryCorrectionHistoryQuery(
        MEMORY_ID,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        target.scope,
        NOW,
        NOW,
        NOW,
    )
    invalid_queries: tuple[Callable[[], MemoryCorrectionHistoryQuery], ...] = (
        lambda: replace(base, root_memory_id="invalid"),
        lambda: replace(base, query_scope=replace(target.scope, brain_id=OTHER_ID)),
        lambda: replace(base, valid_at=NOW.replace(tzinfo=None)),
    )
    for invalid in invalid_queries:
        with pytest.raises(MemoryValidationError):
            invalid()
    with pytest.raises(MemoryValidationError):
        MemoryCorrectionHistoryView(
            MemoryCorrectionHistory(target, ()),
            MemoryAssertionSelection(
                MEMORY_ID,
                OTHER_ID,
                target.statement,
                target.scope,
                None,
                "memory-precedence.v1",
            ),
        )


@pytest.mark.asyncio
async def test_history_handler_rejects_future_query_and_missing_authority() -> None:
    target = _target("Use PostgreSQL")
    query = MemoryCorrectionHistoryQuery(
        MEMORY_ID,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        target.scope,
        NOW,
        NOW,
        NOW + timedelta(minutes=2),
    )
    repository = _Repository(target=target)
    handler = GetMemoryCorrectionHistoryHandler(repository, MemoryPrecedencePolicy(), _Clock())
    with pytest.raises(MemoryValidationError):
        await handler.execute(query)
    with pytest.raises(MemoryEvidenceNotFoundError):
        await handler.execute(replace(query, requested_at=NOW))


def test_sqlite_mapping_helpers_reject_ambiguous_or_tampered_values() -> None:
    assert sqlite_memory._bytes(bytearray(b"a")) == b"a"
    assert sqlite_memory._bytes(memoryview(b"b")) == b"b"
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._bytes("bad")
    confused_integer = True
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._integer(confused_integer)
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._string({"field": 1}, "field")
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._strict_object(b'{"a":1,"a":2}')
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._strict_object(b"[]")
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._strict_object(b'{"value":NaN}')
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._strict_object(b'{ "a":1}')
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._canonical_json({1, 2})
    with pytest.raises(MemoryValidationError):
        sqlite_memory._digest("invalid", "digest")
    with pytest.raises(MemoryValidationError):
        sqlite_memory._digest("0" * 64, "digest")
    with pytest.raises(MemoryValidationError):
        sqlite_memory._micros(NOW.replace(tzinfo=None))
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._time(10**30)
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._statement("{}")
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._statement('{"statement":" invalid"}')
    row = cast(
        "RowMapping",
        {
            "brain_id": BRAIN_ID,
            "project_id": PROJECT_ID,
            "repository_id": REPOSITORY_ID,
            "checkout_id": None,
            "scope_json": "{}",
        },
    )
    with pytest.raises(MemoryIntegrityError):
        sqlite_memory._scope(row)


@pytest.mark.asyncio
@pytest.mark.integration
@pytest.mark.security
async def test_sqlite_rejects_read_only_role_tampered_receipt_and_history(tmp_path: Path) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        memory_id = commit.memories[0].memory_id
        repository = SqliteMemoryCorrectionRepository(store)
        async with store.write_lock, store.engine.begin() as connection:
            await connection.execute(
                text("UPDATE scope_grants SET role='reader' WHERE id=:grant"),
                {"grant": commit.grant_id},
            )
        assert (
            await repository.load_authorized(
                memory_id,
                commit.scope.brain_id,
                commit.actor_id,
                commit.grant_id,
                NOW + timedelta(seconds=10),
            )
            is None
        )
        assert (
            await repository.load_evidence_authorized(
                (EVIDENCE_ID,),
                commit.scope.brain_id,
                commit.actor_id,
                commit.grant_id,
                NOW + timedelta(seconds=10),
            )
            is None
        )
        with pytest.raises(MemoryIntegrityError):
            await repository.add(_commit())
    finally:
        await store.close()


@pytest.mark.asyncio
@pytest.mark.integration
async def test_sqlite_uow_rejects_double_commit_and_receipt_tampering(tmp_path: Path) -> None:
    key_file = tmp_path / "installation.key"
    write_secret(key_file, bytes(range(32)))
    store = migrated_store(tmp_path)
    try:
        commit = await _persist_memory(store, key_file)
        repository = SqliteMemoryCorrectionRepository(store)
        handler = CorrectMemoryHandler(
            repository,
            SqliteMemoryCorrectionUnitOfWorkFactory(store),
            MemoryPrecedencePolicy(),
            _Clock(),
        )
        result = await handler.execute(
            replace(
                _command(),
                actor_id=commit.actor_id,
                grant_id=commit.grant_id,
                brain_id=commit.scope.brain_id,
                assertion_id=commit.memories[0].memory_id,
                scope=commit.scope,
            )
        )
        unit = SqliteMemoryCorrectionUnitOfWorkFactory(store)()
        async with unit:
            await unit.commit()
            with pytest.raises(MemoryIntegrityError):
                await unit.commit()
        async with store.write_lock, store.engine.begin() as connection:
            await connection.exec_driver_sql("DROP TRIGGER memory_correction_operation_immutable")
            await connection.execute(
                text(
                    "UPDATE memory_correction_operations SET result_json='{}' "
                    "WHERE idempotency_key=:key"
                ),
                {"key": bytes.fromhex(result.idempotency_key)},
            )
        with pytest.raises(MemoryIntegrityError):
            await repository.get_result(result.idempotency_key)
    finally:
        await store.close()
