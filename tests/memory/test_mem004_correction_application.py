"""MEM-004 authorization-first correction command TDD tests."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.memory.application.correct_memory import CorrectMemoryCommand, CorrectMemoryHandler
from agentmemory.memory.application.query_memory_corrections import (
    GetMemoryCorrectionHistoryHandler,
    MemoryCorrectionHistoryQuery,
)
from agentmemory.memory.domain.consolidation import MemoryScope
from agentmemory.memory.domain.correction import (
    CorrectionEvidence,
    CorrectionTarget,
    MemoryCorrectionCommit,
    MemoryCorrectionHistory,
    MemoryCorrectionPlan,
    MemoryCorrectionResult,
    MemoryPrecedencePolicy,
)
from agentmemory.memory.domain.errors import (
    MemoryConflictError,
    MemoryEvidenceNotFoundError,
    MemoryValidationError,
)
from tests.memory.test_mem004_correction_domain import (
    ACTOR_ID,
    BRAIN_ID,
    CHECKOUT_ID,
    CORRECTION_ID,
    EVIDENCE_ID,
    GRANT_ID,
    MEMORY_ID,
    NOW,
    PROJECT_ID,
    REPOSITORY_ID,
    _target,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType
    from typing import Self

CORRELATION_ID = "018f0000-0000-7000-8000-000000000511"
CAUSATION_ID = "018f0000-0000-7000-8000-000000000512"


@pytest.mark.asyncio
async def test_explicit_authorized_correction_commits_scope_bound_plan() -> None:
    target = _target("Use PostgreSQL")
    evidence = CorrectionEvidence(EVIDENCE_ID, "e" * 64)
    repository = _Repository(target=target, evidence=(evidence,))
    unit = _UnitOfWork(repository)
    handler = CorrectMemoryHandler(
        repository,
        lambda: unit,
        MemoryPrecedencePolicy(),
        _Clock(),
    )

    result = await handler.execute(_command(evidence_ids=(EVIDENCE_ID,)))

    assert result.correction_id == CORRECTION_ID
    assert result.source_assertion_id == MEMORY_ID
    assert result.root_memory_id == MEMORY_ID
    assert result.relation.value == "contradicts"
    assert repository.commit is not None
    assert repository.commit.plan.assertion.evidence == (evidence,)
    assert repository.commit.plan.assertion.scope.checkout_id == CHECKOUT_ID
    assert unit.committed


@pytest.mark.asyncio
async def test_absent_target_or_optional_evidence_is_scope_neutral_not_found() -> None:
    missing = _Repository(target=None)
    handler = CorrectMemoryHandler(
        missing,
        lambda: _UnitOfWork(missing),
        MemoryPrecedencePolicy(),
        _Clock(),
    )
    with pytest.raises(MemoryEvidenceNotFoundError):
        await handler.execute(_command())

    target = _target("Use PostgreSQL")
    missing_evidence = _Repository(target=target, evidence=None)
    handler = replace(
        handler,
        reads=missing_evidence,
        unit_of_work=lambda: _UnitOfWork(missing_evidence),
    )
    with pytest.raises(MemoryEvidenceNotFoundError):
        await handler.execute(_command(evidence_ids=(EVIDENCE_ID,)))


@pytest.mark.asyncio
async def test_replay_is_request_bound_and_transaction_rechecks_target_version() -> None:
    target = _target("Use PostgreSQL")
    base = _Repository(target=target)
    handler = CorrectMemoryHandler(
        base,
        lambda: _UnitOfWork(base),
        MemoryPrecedencePolicy(),
        _Clock(),
    )
    first = await handler.execute(_command())

    replay = _Repository(target=target, existing=first)
    handler = replace(handler, reads=replay, unit_of_work=lambda: _UnitOfWork(replay))
    assert await handler.execute(_command()) == first
    with pytest.raises(MemoryConflictError):
        await handler.execute(replace(_command(), reason="different_reason"))

    changed = _Repository(target=target, transaction_target=replace(target, aggregate_version=2))
    handler = replace(handler, reads=changed, unit_of_work=lambda: _UnitOfWork(changed))
    with pytest.raises(MemoryConflictError):
        await handler.execute(_command())


def test_command_rejects_noncanonical_evidence_versions_and_time_windows() -> None:
    with pytest.raises(MemoryValidationError):
        replace(_command(), expected_version=0)
    with pytest.raises(MemoryValidationError):
        replace(_command(), evidence_ids=(EVIDENCE_ID, EVIDENCE_ID))
    with pytest.raises(MemoryValidationError):
        replace(_command(), deadline=NOW - timedelta(minutes=1))


def test_command_request_digest_is_stable_and_binds_microsecond_utc_times() -> None:
    assert _command().request_sha256 == (
        "76b863e408a4eb8ae091a0b692e11c6b28c5ee8b3059ad2eef8596bae4dfc1c9"
    )
    changed = replace(_command(), requested_at=NOW + timedelta(microseconds=1))
    assert changed.request_sha256 != _command().request_sha256


@pytest.mark.parametrize(
    ("invalid_command", "failure"),
    [
        (lambda: replace(_command(), actor_id="invalid"), "actor_id: invalid_uuid7"),
        (lambda: replace(_command(), grant_id="invalid"), "grant_id: invalid_uuid7"),
        (
            lambda: replace(_command(), correlation_id="invalid"),
            "correlation_id: invalid_uuid7",
        ),
        (
            lambda: replace(_command(), causation_id="invalid"),
            "causation_id: invalid_uuid7",
        ),
    ],
)
def test_command_authority_coordinates_report_exact_uuid_failure(
    invalid_command: Callable[[], CorrectMemoryCommand],
    failure: str,
) -> None:
    with pytest.raises(MemoryValidationError) as error:
        invalid_command()
    assert str(error.value) == failure


@pytest.mark.parametrize(
    ("invalid_command", "failure"),
    [
        (lambda: replace(_command(), statement=" leading"), "statement: invalid"),
        (lambda: replace(_command(), statement="e\u0301"), "statement: invalid"),
        (lambda: replace(_command(), statement="x" * 8_193), "statement: invalid"),
        (lambda: replace(_command(), reason="Invalid Reason"), "reason: invalid_token"),
        (lambda: replace(_command(), expected_version=True), "expected_version: out_of_range"),
        (
            lambda: replace(_command(), valid_from=NOW.replace(tzinfo=None)),
            "valid_from: not_utc",
        ),
        (lambda: replace(_command(), valid_to=NOW), "valid_to: not_after_start"),
        (
            lambda: replace(
                _command(),
                valid_to=(NOW + timedelta(minutes=1)).replace(tzinfo=None),
            ),
            "valid_to: not_utc",
        ),
        (
            lambda: replace(_command(), requested_at=NOW.replace(tzinfo=None)),
            "requested_at: not_utc",
        ),
        (
            lambda: replace(
                _command(),
                deadline=(NOW + timedelta(minutes=1)).replace(tzinfo=None),
            ),
            "deadline: not_utc",
        ),
    ],
)
def test_command_reports_exact_canonical_validation_failure(
    invalid_command: Callable[[], CorrectMemoryCommand],
    failure: str,
) -> None:
    with pytest.raises(MemoryValidationError) as error:
        invalid_command()
    assert str(error.value) == failure


def test_history_query_rejects_invalid_identifiers_and_non_utc_times() -> None:
    valid = MemoryCorrectionHistoryQuery(
        MEMORY_ID,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID),
        NOW,
        NOW,
        NOW,
    )

    with pytest.raises(MemoryValidationError) as invalid_identifier:
        replace(valid, root_memory_id="not-a-uuid7")
    assert invalid_identifier.value.violations[0].field == "root_memory_id"
    assert invalid_identifier.value.violations[0].code == "invalid_uuid7"

    with pytest.raises(MemoryValidationError) as non_utc_time:
        replace(valid, requested_at=NOW.replace(tzinfo=None))
    assert non_utc_time.value.violations[0].field == "requested_at"
    assert non_utc_time.value.violations[0].code == "not_utc"


@pytest.mark.asyncio
async def test_history_query_authorizes_root_and_applies_scope_specific_precedence() -> None:
    target = _target("Use PostgreSQL")
    plan = MemoryCorrectionPlan.create(
        correction_id=CORRECTION_ID,
        target=target,
        expected_version=1,
        statement="Use SQLite",
        scope=replace(target.scope, checkout_id=CHECKOUT_ID),
        valid_from=NOW,
        valid_to=None,
        reason="user_correction",
        evidence=(),
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        recorded_at=NOW + timedelta(minutes=1),
        policy=MemoryPrecedencePolicy(),
    )
    repository = _Repository(
        target=target, history=MemoryCorrectionHistory(target, (plan.assertion,))
    )
    query = MemoryCorrectionHistoryQuery(
        MEMORY_ID,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        replace(target.scope, checkout_id=CHECKOUT_ID),
        NOW + timedelta(minutes=2),
        NOW + timedelta(minutes=2),
        NOW,
    )

    view = await GetMemoryCorrectionHistoryHandler(
        repository,
        MemoryPrecedencePolicy(),
        _Clock(),
    ).execute(query)

    assert view.selected.assertion_id == CORRECTION_ID
    assert view.history.root.statement == "Use PostgreSQL"

    repository.history = None
    with pytest.raises(MemoryEvidenceNotFoundError):
        await GetMemoryCorrectionHistoryHandler(
            repository,
            MemoryPrecedencePolicy(),
            _Clock(),
        ).execute(query)


def _command(*, evidence_ids: tuple[str, ...] = ()) -> CorrectMemoryCommand:
    return CorrectMemoryCommand(
        operation_id=CORRECTION_ID,
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        brain_id=BRAIN_ID,
        correlation_id=CORRELATION_ID,
        causation_id=CAUSATION_ID,
        assertion_id=MEMORY_ID,
        expected_version=1,
        statement="Do not use PostgreSQL",
        scope=MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID),
        valid_from=NOW,
        valid_to=None,
        reason="user_correction",
        evidence_ids=evidence_ids,
        requested_at=NOW,
        deadline=NOW + timedelta(minutes=5),
    )


@dataclass
class _Clock:
    def now(self) -> datetime:
        return NOW + timedelta(minutes=1)


class _Repository:
    def __init__(
        self,
        *,
        target: CorrectionTarget | None,
        evidence: tuple[CorrectionEvidence, ...] | None = (),
        existing: MemoryCorrectionResult | None = None,
        transaction_target: CorrectionTarget | None = None,
        history: MemoryCorrectionHistory | None = None,
    ) -> None:
        self.target = target
        self.evidence = evidence
        self.existing = existing
        self.transaction_target = transaction_target
        self.history = history
        self.in_transaction = False
        self.commit: MemoryCorrectionCommit | None = None

    async def get_result(self, idempotency_key: str) -> MemoryCorrectionResult | None:
        del idempotency_key
        return self.existing

    async def load_authorized(
        self,
        assertion_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> CorrectionTarget | None:
        del assertion_id, brain_id, actor_id, grant_id, at
        if self.in_transaction and self.transaction_target is not None:
            return self.transaction_target
        return self.target

    async def load_evidence_authorized(
        self,
        evidence_ids: tuple[str, ...],
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> tuple[CorrectionEvidence, ...] | None:
        del evidence_ids, brain_id, actor_id, grant_id, at
        return self.evidence

    async def add(self, commit: MemoryCorrectionCommit) -> None:
        self.commit = commit

    async def history_authorized(
        self,
        root_memory_id: str,
        brain_id: str,
        actor_id: str,
        grant_id: str,
        at: datetime,
    ) -> MemoryCorrectionHistory | None:
        del root_memory_id, brain_id, actor_id, grant_id, at
        return self.history


class _UnitOfWork:
    def __init__(self, repository: _Repository) -> None:
        self.repository = repository
        self.committed = False

    async def __aenter__(self) -> Self:
        self.repository.in_transaction = True
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.repository.in_transaction = False

    async def commit(self) -> None:
        self.committed = True
