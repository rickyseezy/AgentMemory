"""MEM-005 lifecycle state-machine and recall-ranking TDD tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from agentmemory.memory.domain.consolidation import MemoryScope
from agentmemory.memory.domain.errors import MemoryConflictError, MemoryValidationError
from agentmemory.memory.domain.lifecycle import (
    MemoryLifecycleAction,
    MemoryLifecyclePlan,
    MemoryLifecycleResult,
    MemoryLifecycleSnapshot,
    MemoryRecallCandidate,
    MemoryRecallState,
    _digest_document,  # pyright: ignore[reportPrivateUsage]
    lifecycle_idempotency_key,
    rank_recallable_memories,
    require_forget_confirmation,
)

NOW = datetime(2026, 7, 21, 15, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000601"
PROJECT_ID = "018f0000-0000-7000-8000-000000000602"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000603"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000604"
OTHER_CHECKOUT_ID = "018f0000-0000-7000-8000-000000000605"
MEMORY_ID = "018f0000-0000-7000-8000-000000000606"
OTHER_MEMORY_ID = "018f0000-0000-7000-8000-000000000607"


def test_pin_changes_only_recall_priority_and_archive_clears_pin() -> None:
    source = _snapshot()
    pinned = MemoryLifecyclePlan.create(
        source,
        MemoryLifecycleAction.PIN,
        expected_version=1,
        occurred_at=NOW + timedelta(minutes=1),
    )
    archived = MemoryLifecyclePlan.create(
        pinned.result,
        MemoryLifecycleAction.ARCHIVE,
        expected_version=2,
        occurred_at=NOW + timedelta(minutes=2),
    )

    assert pinned.result.recall_state is MemoryRecallState.ACTIVE
    assert pinned.result.pinned
    assert pinned.result.expires_at is None
    assert archived.result.recall_state is MemoryRecallState.ARCHIVED
    assert not archived.result.pinned
    assert archived.result.version == 3


def test_expiry_boundary_is_exact_and_scheduler_transition_is_idempotency_safe() -> None:
    expiry = NOW + timedelta(hours=1)
    scheduled = MemoryLifecyclePlan.create(
        _snapshot(),
        MemoryLifecycleAction.SET_EXPIRY,
        expected_version=1,
        occurred_at=NOW + timedelta(minutes=1),
        expires_at=expiry,
    )
    with pytest.raises(MemoryConflictError):
        MemoryLifecyclePlan.create(
            scheduled.result,
            MemoryLifecycleAction.EXPIRE,
            expected_version=2,
            occurred_at=expiry - timedelta(microseconds=1),
        )

    expired = MemoryLifecyclePlan.create(
        scheduled.result,
        MemoryLifecycleAction.EXPIRE,
        expected_version=2,
        occurred_at=expiry,
    )
    assert expired.result.recall_state is MemoryRecallState.EXPIRED
    assert expired.result.expires_at == expiry
    assert not expired.result.pinned


@pytest.mark.parametrize(
    "state",
    [MemoryRecallState.ACTIVE, MemoryRecallState.ARCHIVED, MemoryRecallState.EXPIRED],
)
def test_forget_is_terminal_and_requires_a_tombstone(state: MemoryRecallState) -> None:
    source = replace(
        _snapshot(),
        recall_state=state,
        pinned=False,
        expires_at=NOW if state is MemoryRecallState.EXPIRED else None,
    )
    forgotten = MemoryLifecyclePlan.create(
        source,
        MemoryLifecycleAction.FORGET,
        expected_version=1,
        occurred_at=NOW + timedelta(minutes=1),
    )

    assert forgotten.result.recall_state is MemoryRecallState.FORGOTTEN
    assert forgotten.requires_deletion_tombstone
    with pytest.raises(MemoryConflictError):
        MemoryLifecyclePlan.create(
            forgotten.result,
            MemoryLifecycleAction.PIN,
            expected_version=2,
            occurred_at=NOW + timedelta(minutes=2),
        )


def test_state_machine_rejects_stale_versions_and_invalid_transitions() -> None:
    with pytest.raises(MemoryConflictError):
        MemoryLifecyclePlan.create(
            _snapshot(),
            MemoryLifecycleAction.PIN,
            expected_version=2,
            occurred_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(MemoryConflictError):
        MemoryLifecyclePlan.create(
            replace(_snapshot(), pinned=True),
            MemoryLifecycleAction.PIN,
            expected_version=1,
            occurred_at=NOW + timedelta(minutes=1),
        )
    with pytest.raises(MemoryValidationError):
        MemoryLifecyclePlan.create(
            _snapshot(),
            MemoryLifecycleAction.SET_EXPIRY,
            expected_version=1,
            occurred_at=NOW + timedelta(minutes=1),
            expires_at=NOW,
        )


def test_plan_and_receipt_reject_forged_transition_or_authenticated_fields() -> None:
    plan = MemoryLifecyclePlan.create(
        _snapshot(),
        MemoryLifecycleAction.PIN,
        expected_version=1,
        occurred_at=NOW + timedelta(minutes=1),
    )
    with pytest.raises(MemoryValidationError):
        replace(
            plan,
            result=replace(
                plan.result,
                recall_state=MemoryRecallState.ARCHIVED,
                pinned=False,
            ),
        )
    result = MemoryLifecycleResult.create(
        lifecycle_idempotency_key(OTHER_MEMORY_ID, MEMORY_ID, "pin"),
        "e" * 64,
        OTHER_MEMORY_ID,
        plan,
    )
    with pytest.raises(MemoryValidationError):
        replace(result, pinned=False)


def test_lifecycle_digests_are_a_stable_canonical_contract() -> None:
    plan = MemoryLifecyclePlan.create(
        _snapshot(),
        MemoryLifecycleAction.PIN,
        expected_version=1,
        occurred_at=NOW + timedelta(minutes=1),
    )
    key = lifecycle_idempotency_key(OTHER_MEMORY_ID, MEMORY_ID, "pin")
    result = MemoryLifecycleResult.create(key, "e" * 64, OTHER_MEMORY_ID, plan)

    assert key == "3d14320f12b0dd214ac2cceede5cb82ccde3961e67c9356900838495aa1a58b7"
    assert plan.result_sha256 == (
        "2b4bfff7aed3da6f36719e1f2d934d5721fe5208894648b25ac407df1c4dd73b"
    )
    assert result.result_sha256 == (
        "ef6700de91776bc899ad9de2063ca2a85f31e0fcf42878eb3aa7ae854666f7e4"
    )
    assert _digest_document({"z": "Mémoire", "a": 1}) == (
        "c2d7850577d48fa92c589f0330eda385789d2e5787ad20c76e53aef3ecee17a4"
    )
    with pytest.raises(ValueError, match="Out of range float values"):
        _digest_document({"score": float("nan")})


@pytest.mark.parametrize(
    ("changes", "field", "code"),
    [
        ({"memory_id": "not-a-uuid"}, "memory_id", "invalid_uuid7"),
        ({"version": True}, "version", "out_of_range"),
        ({"version": 0}, "version", "out_of_range"),
        (
            {"updated_at": NOW.replace(tzinfo=None)},
            "updated_at",
            "not_utc",
        ),
        (
            {"expires_at": NOW.replace(tzinfo=None)},
            "expires_at",
            "not_utc",
        ),
        (
            {"recall_state": MemoryRecallState.ARCHIVED, "pinned": True},
            "pinned",
            "inactive_memory",
        ),
        (
            {"recall_state": MemoryRecallState.EXPIRED},
            "expires_at",
            "required_for_expired",
        ),
        (
            {"recall_state": MemoryRecallState.FORGOTTEN, "expires_at": NOW},
            "expires_at",
            "forbidden_for_forgotten",
        ),
    ],
)
def test_snapshot_validation_reports_exact_closed_violation(
    changes: dict[str, object],
    field: str,
    code: str,
) -> None:
    values: dict[str, Any] = {
        "memory_id": MEMORY_ID,
        "scope": MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
        "recall_state": MemoryRecallState.ACTIVE,
        "pinned": False,
        "expires_at": None,
        "version": 1,
        "updated_at": NOW,
    }
    values.update(changes)
    with pytest.raises(MemoryValidationError) as caught:
        MemoryLifecycleSnapshot(
            memory_id=values["memory_id"],
            scope=values["scope"],
            recall_state=values["recall_state"],
            pinned=values["pinned"],
            expires_at=values["expires_at"],
            version=values["version"],
            updated_at=values["updated_at"],
        )
    assert caught.value.code_for(field) == code


@pytest.mark.parametrize("value", ["", "FORGET-MEMORY", "forget-memory ", "pin"])
def test_forget_confirmation_is_exact_and_content_free(value: str) -> None:
    with pytest.raises(MemoryValidationError) as caught:
        require_forget_confirmation(value)
    assert caught.value.code_for("confirmation") == "mismatch"


@pytest.mark.parametrize("action", list(MemoryLifecycleAction))
def test_every_lifecycle_action_has_a_stable_event_and_tombstone_policy(
    action: MemoryLifecycleAction,
) -> None:
    source = _snapshot()
    if action is MemoryLifecycleAction.EXPIRE:
        source = replace(source, expires_at=NOW + timedelta(minutes=1))
    plan = MemoryLifecyclePlan.create(
        source,
        action,
        expected_version=1,
        occurred_at=NOW + timedelta(minutes=1),
        expires_at=(
            NOW + timedelta(minutes=2) if action is MemoryLifecycleAction.SET_EXPIRY else None
        ),
    )
    expected_events = {
        MemoryLifecycleAction.PIN: "MemoryPinned",
        MemoryLifecycleAction.ARCHIVE: "MemoryArchived",
        MemoryLifecycleAction.SET_EXPIRY: "MemoryExpirySet",
        MemoryLifecycleAction.EXPIRE: "MemoryExpired",
        MemoryLifecycleAction.FORGET: "MemoryForgotten",
    }
    assert plan.event_type == expected_events[action]
    assert plan.requires_deletion_tombstone is (action is MemoryLifecycleAction.FORGET)


def test_pinned_candidate_cannot_bypass_scope_time_or_lifecycle_filters() -> None:
    scope = MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID)
    active = MemoryRecallCandidate(
        replace(_snapshot(), scope=scope),
        semantic_score=0.4,
        valid_from=NOW,
        valid_to=None,
        recorded_from=NOW,
        recorded_to=None,
    )
    pinned = replace(
        active,
        lifecycle=replace(active.lifecycle, memory_id=OTHER_MEMORY_ID, pinned=True),
        semantic_score=0.1,
    )
    wrong_scope = replace(
        pinned,
        lifecycle=replace(
            pinned.lifecycle,
            memory_id="018f0000-0000-7000-8000-000000000608",
            scope=replace(scope, checkout_id=OTHER_CHECKOUT_ID),
        ),
    )
    expired_time = replace(
        pinned,
        lifecycle=replace(
            pinned.lifecycle,
            memory_id="018f0000-0000-7000-8000-000000000609",
        ),
        valid_to=NOW + timedelta(minutes=1),
    )
    archived = replace(
        pinned,
        lifecycle=replace(
            pinned.lifecycle,
            memory_id="018f0000-0000-7000-8000-000000000610",
            recall_state=MemoryRecallState.ARCHIVED,
            pinned=False,
        ),
    )

    ranked = rank_recallable_memories(
        (active, pinned, wrong_scope, expired_time, archived),
        scope,
        valid_at=NOW + timedelta(minutes=2),
        recorded_at=NOW + timedelta(minutes=2),
        now=NOW + timedelta(minutes=2),
    )

    assert tuple(item.lifecycle.memory_id for item in ranked) == (OTHER_MEMORY_ID, MEMORY_ID)


def _snapshot() -> MemoryLifecycleSnapshot:
    return MemoryLifecycleSnapshot(
        memory_id=MEMORY_ID,
        scope=MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None),
        recall_state=MemoryRecallState.ACTIVE,
        pinned=False,
        expires_at=None,
        version=1,
        updated_at=NOW,
    )
