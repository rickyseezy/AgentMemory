"""MEM-004 correction, dispute, supersession, and precedence acceptance tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from agentmemory.memory.domain.consolidation import MemoryClass, MemoryScope, MemoryStatus
from agentmemory.memory.domain.correction import (
    CorrectionEvidence,
    CorrectionRelation,
    CorrectionTarget,
    MemoryCorrectionPlan,
    MemoryCorrectionResult,
    MemoryPrecedencePolicy,
    correction_idempotency_key,
)
from agentmemory.memory.domain.errors import MemoryConflictError, MemoryValidationError

if TYPE_CHECKING:
    from collections.abc import Callable

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000501"
PROJECT_ID = "018f0000-0000-7000-8000-000000000502"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000503"
CHECKOUT_ID = "018f0000-0000-7000-8000-000000000504"
OTHER_CHECKOUT_ID = "018f0000-0000-7000-8000-000000000505"
MEMORY_ID = "018f0000-0000-7000-8000-000000000506"
CORRECTION_ID = "018f0000-0000-7000-8000-000000000507"
ACTOR_ID = "018f0000-0000-7000-8000-000000000508"
GRANT_ID = "018f0000-0000-7000-8000-000000000509"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000510"


def test_equal_scope_explicit_correction_supersedes_without_overwriting_history() -> None:
    target = _target("Use PostgreSQL for persistence")
    plan = MemoryCorrectionPlan.create(
        correction_id=CORRECTION_ID,
        target=target,
        expected_version=1,
        statement="Use SQLite for persistence",
        scope=target.scope,
        valid_from=NOW,
        valid_to=None,
        reason="architecture_changed",
        evidence=(),
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        recorded_at=NOW + timedelta(minutes=1),
        policy=MemoryPrecedencePolicy(),
    )

    assert plan.relation is CorrectionRelation.SUPERSEDES
    assert plan.source_status is MemoryStatus.SUPERSEDED
    assert plan.source_recorded_to == NOW + timedelta(minutes=1)
    assert plan.assertion.source_assertion_id == MEMORY_ID
    assert plan.assertion.root_memory_id == MEMORY_ID
    assert plan.assertion.statement == "Use SQLite for persistence"
    assert plan.assertion.version == 1
    assert target.statement == "Use PostgreSQL for persistence"
    assert target.aggregate_version == 1


def test_opposite_polarity_creates_visible_contradiction_and_dispute() -> None:
    target = _target("Use PostgreSQL")
    plan = _plan(target, "Do not use PostgreSQL", target.scope)

    assert plan.relation is CorrectionRelation.CONTRADICTS
    assert plan.source_status is MemoryStatus.DISPUTED
    assert plan.assertion.relation is CorrectionRelation.CONTRADICTS


def test_narrower_scope_correction_wins_only_inside_declared_checkout() -> None:
    target = _target("Use PostgreSQL")
    correction_scope = replace(target.scope, checkout_id=CHECKOUT_ID)
    plan = _plan(target, "Use SQLite", correction_scope)
    policy = MemoryPrecedencePolicy()

    inside = policy.resolve(
        target,
        (plan.assertion,),
        correction_scope,
        valid_at=NOW + timedelta(minutes=2),
        recorded_at=NOW + timedelta(minutes=2),
    )
    outside = policy.resolve(
        target,
        (plan.assertion,),
        replace(target.scope, checkout_id=OTHER_CHECKOUT_ID),
        valid_at=NOW + timedelta(minutes=2),
        recorded_at=NOW + timedelta(minutes=2),
    )

    assert plan.source_recorded_to is None
    assert inside.assertion_id == CORRECTION_ID
    assert inside.statement == "Use SQLite"
    assert outside.assertion_id == MEMORY_ID
    assert outside.statement == "Use PostgreSQL"


def test_broader_or_sibling_scope_and_stale_version_fail_closed() -> None:
    checkout_target = _target(
        "Use PostgreSQL",
        scope=MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, CHECKOUT_ID),
    )
    for invalid_scope in (
        replace(checkout_target.scope, checkout_id=None),
        replace(checkout_target.scope, checkout_id=OTHER_CHECKOUT_ID),
        MemoryScope(BRAIN_ID, PROJECT_ID, OTHER_CHECKOUT_ID, CHECKOUT_ID),
    ):
        with pytest.raises(MemoryValidationError):
            _plan(checkout_target, "Use SQLite", invalid_scope)

    with pytest.raises(MemoryConflictError):
        MemoryCorrectionPlan.create(
            correction_id=CORRECTION_ID,
            target=checkout_target,
            expected_version=2,
            statement="Use SQLite",
            scope=checkout_target.scope,
            valid_from=NOW,
            valid_to=None,
            reason="architecture_changed",
            evidence=(),
            actor_id=ACTOR_ID,
            grant_id=GRANT_ID,
            recorded_at=NOW + timedelta(minutes=1),
            policy=MemoryPrecedencePolicy(),
        )


def test_optional_evidence_is_canonical_hash_bound_and_retained() -> None:
    target = _target("Use PostgreSQL")
    evidence = CorrectionEvidence(EVIDENCE_ID, "e" * 64)
    plan = MemoryCorrectionPlan.create(
        correction_id=CORRECTION_ID,
        target=target,
        expected_version=1,
        statement="Use SQLite",
        scope=target.scope,
        valid_from=NOW,
        valid_to=None,
        reason="benchmark_result",
        evidence=(evidence,),
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        recorded_at=NOW + timedelta(minutes=1),
        policy=MemoryPrecedencePolicy(),
    )

    assert plan.assertion.evidence == (evidence,)
    assert len(plan.result_sha256) == 64
    with pytest.raises(MemoryValidationError):
        replace(plan.assertion, evidence=(evidence, evidence))


def test_correction_receipts_and_idempotency_have_stable_canonical_digests() -> None:
    target = _target("Use PostgreSQL")
    plan = _plan(target, "Use SQLite", target.scope)
    key = correction_idempotency_key(CORRECTION_ID, MEMORY_ID, BRAIN_ID)
    result = MemoryCorrectionResult.create(key, "a" * 64, plan)

    assert key == "6982d064730d9b712d0645d4932cb5669650a5f9e13c20908de9eb4f0d5c1be8"
    assert plan.result_sha256 == (
        "33bf6ea4abcb7af053ac4b2dec92881c13017448dd3e60e99b526ad30d06d328"
    )
    assert result.result_sha256 == (
        "2ec135b17d48916bd979f258fc7376c4d0c29c0d1a513652db3b4b680ed89ce3"
    )


@pytest.mark.parametrize(
    ("coordinate", "field"),
    [
        (("invalid", MEMORY_ID, BRAIN_ID), "operation_id"),
        ((CORRECTION_ID, "invalid", BRAIN_ID), "assertion_id"),
        ((CORRECTION_ID, MEMORY_ID, "invalid"), "brain_id"),
    ],
)
def test_idempotency_coordinates_report_exact_validation_failure(
    coordinate: tuple[str, str, str],
    field: str,
) -> None:
    with pytest.raises(MemoryValidationError) as error:
        correction_idempotency_key(*coordinate)
    assert str(error.value) == f"{field}: invalid_uuid7"


@pytest.mark.parametrize(
    "statement",
    ["", " leading", "trailing ", "e\u0301", "bad\x00value", "bad\x7fvalue", "x" * 8_193],
)
def test_target_statement_validation_rejects_every_noncanonical_form(statement: str) -> None:
    with pytest.raises(MemoryValidationError) as error:
        replace(_target("Use PostgreSQL"), statement=statement)
    assert str(error.value) == "statement: invalid"


@pytest.mark.parametrize(
    ("invalid_target", "failure"),
    [
        (
            lambda: replace(_target("Use PostgreSQL"), valid_from=NOW.replace(tzinfo=None)),
            "valid_from: not_utc",
        ),
        (
            lambda: replace(_target("Use PostgreSQL"), valid_to=NOW),
            "valid_to: not_after_start",
        ),
        (
            lambda: replace(
                _target("Use PostgreSQL"),
                valid_to=(NOW + timedelta(minutes=1)).replace(tzinfo=None),
            ),
            "valid_to: not_utc",
        ),
        (
            lambda: replace(_target("Use PostgreSQL"), recorded_from=NOW.replace(tzinfo=None)),
            "recorded_from: not_utc",
        ),
        (
            lambda: replace(_target("Use PostgreSQL"), recorded_to=NOW),
            "recorded_to: not_after_start",
        ),
        (
            lambda: replace(
                _target("Use PostgreSQL"),
                recorded_to=(NOW + timedelta(minutes=1)).replace(tzinfo=None),
            ),
            "recorded_to: not_utc",
        ),
    ],
)
def test_target_ranges_report_exact_temporal_failure(
    invalid_target: Callable[[], CorrectionTarget],
    failure: str,
) -> None:
    with pytest.raises(MemoryValidationError) as error:
        invalid_target()
    assert str(error.value) == failure


@pytest.mark.parametrize(
    ("event_id", "digest", "failure"),
    [
        ("invalid", "e" * 64, "evidence.event_id: invalid_uuid7"),
        (EVIDENCE_ID, "0" * 64, "evidence.canonical_event_sha256: invalid_digest"),
        (EVIDENCE_ID, "E" * 64, "evidence.canonical_event_sha256: invalid_digest"),
    ],
)
def test_correction_evidence_reports_exact_identity_and_digest_failures(
    event_id: str,
    digest: str,
    failure: str,
) -> None:
    with pytest.raises(MemoryValidationError) as error:
        CorrectionEvidence(event_id, digest)
    assert str(error.value) == failure


def test_precedence_time_ranges_are_start_inclusive_and_end_exclusive() -> None:
    target = _target(
        "Use PostgreSQL",
        valid_from=NOW,
        valid_to=NOW + timedelta(minutes=10),
    )
    policy = MemoryPrecedencePolicy()

    at_start = policy.resolve(target, (), target.scope, valid_at=NOW, recorded_at=NOW)
    assert at_start.assertion_id == MEMORY_ID

    for invalid_time in (NOW - timedelta(microseconds=1), NOW + timedelta(minutes=10)):
        with pytest.raises(MemoryValidationError) as error:
            policy.resolve(target, (), target.scope, valid_at=invalid_time, recorded_at=NOW)
        assert str(error.value) == "query_time: no_effective_assertion"


def _target(
    statement: str,
    *,
    scope: MemoryScope | None = None,
    valid_from: datetime = NOW,
    valid_to: datetime | None = None,
) -> CorrectionTarget:
    target_scope = scope or MemoryScope(BRAIN_ID, PROJECT_ID, REPOSITORY_ID, None)
    content = hashlib.sha256(
        json.dumps(
            {
                "memory_class": MemoryClass.DECISION.value,
                "scope": dict(target_scope.canonical),
                "statement": statement,
                "valid_from": valid_from.isoformat(timespec="microseconds").replace("+00:00", "Z"),
                "valid_to": (
                    None
                    if valid_to is None
                    else valid_to.isoformat(timespec="microseconds").replace("+00:00", "Z")
                ),
            },
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return CorrectionTarget(
        assertion_id=MEMORY_ID,
        root_memory_id=MEMORY_ID,
        memory_class=MemoryClass.DECISION,
        statement=statement,
        content_sha256=content,
        scope=target_scope,
        status=MemoryStatus.ACTIVE,
        valid_from=valid_from,
        valid_to=valid_to,
        recorded_from=NOW,
        recorded_to=None,
        classification="internal",
        retention_policy_id="default",
        evidence_ids=(EVIDENCE_ID,),
        aggregate_version=1,
    )


def _plan(
    target: CorrectionTarget,
    statement: str,
    scope: MemoryScope,
) -> MemoryCorrectionPlan:
    return MemoryCorrectionPlan.create(
        correction_id=CORRECTION_ID,
        target=target,
        expected_version=target.aggregate_version,
        statement=statement,
        scope=scope,
        valid_from=NOW,
        valid_to=None,
        reason="user_correction",
        evidence=(),
        actor_id=ACTOR_ID,
        grant_id=GRANT_ID,
        recorded_at=NOW + timedelta(minutes=1),
        policy=MemoryPrecedencePolicy(),
    )
