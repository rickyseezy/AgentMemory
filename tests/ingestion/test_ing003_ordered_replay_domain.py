"""ING-003 causal ordering and deterministic replay domain tests."""

from __future__ import annotations

from dataclasses import replace
from itertools import permutations
from typing import Any, cast

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentmemory.ingestion.domain.errors import FieldViolation, IngestionValidationError
from agentmemory.ingestion.domain.ordered_replay import (
    OrderClaimDisposition,
    OrderedEventClaim,
    OrderedProjectionState,
    OrderedReductionInput,
    OrderedReplayRun,
    RecordedOperationEvidence,
    ReplayRunRequest,
    ReplayRunState,
    ReplaySourcePage,
    ReplaySourceRecord,
    generation_digest,
    reduce_projection,
)
from tests.core.support import BRAIN_ID, digest
from tests.ingestion.adp002_support import EVENT_ID, ORDERING_KEY, PRINCIPAL_ID

OTHER_EVENT_ID = "018f0000-0000-7000-8000-000000000121"
OTHER_ORDERING_KEY = "018f0000-0000-7000-8000-000000000122"
OPERATION_ID = "018f0000-0000-7000-8000-000000000123"
PROFILE_ID = "018f0000-0000-7000-8000-000000000124"
GRANT_ID = "018f0000-0000-7000-8000-000000000125"
GENERATION_ID = "018f0000-0000-7000-8000-000000000126"
ZERO_DIGEST = "0" * 64
CODE_FINGERPRINT = "a" * 40


def evidence(**changes: object) -> RecordedOperationEvidence:
    value = RecordedOperationEvidence(
        operation_id=OPERATION_ID,
        profile_id=PROFILE_ID,
        model_revision="b" * 40,
        purpose="extract",
        result_sha256=digest("recorded-provider-result").value,
    )
    return replace(value, **cast("Any", changes))


def reduction(sequence: int = 1, **changes: object) -> OrderedReductionInput:
    value = OrderedReductionInput(
        event_id=EVENT_ID,
        ordering_key=ORDERING_KEY,
        event_sequence=sequence,
        event_schema_version=1,
        canonical_sha256=digest(f"canonical-{sequence}").value,
        projection_sha256=digest(f"projection-{sequence}").value,
        requires_recorded_operation=False,
        recorded_operation=None,
    )
    return replace(value, **cast("Any", changes))


def ready_claim(**changes: object) -> OrderedEventClaim:
    value = OrderedEventClaim(
        ordering_key=ORDERING_KEY,
        event_sequence=1,
        prior_sequence=0,
        prior_state_sha256=ZERO_DIGEST,
        disposition=OrderClaimDisposition.READY,
        owner="worker-1",
        lease_until_microseconds=42,
        gap_from_sequence=None,
        gap_to_sequence=None,
    )
    return replace(value, **cast("Any", changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"ordering_key": "bad"},
        {"event_sequence": 0},
        {"prior_sequence": -1},
        {"prior_state_sha256": "bad"},
        {"owner": None},
        {
            "disposition": OrderClaimDisposition.WAIT,
            "owner": None,
            "lease_until_microseconds": None,
        },
        {
            "disposition": OrderClaimDisposition.READY_AFTER_GAP,
            "event_sequence": 3,
            "owner": "worker-1",
            "lease_until_microseconds": 42,
            "gap_from_sequence": 1,
            "gap_to_sequence": 1,
        },
    ],
)
def test_order_claim_rejects_ambiguous_lease_sequence_and_gap_shapes(
    changes: dict[str, object],
) -> None:
    with pytest.raises(IngestionValidationError):
        ready_claim(**changes)


@pytest.mark.parametrize(
    "claim",
    [
        OrderedEventClaim(
            ORDERING_KEY,
            None,
            None,
            ZERO_DIGEST,
            OrderClaimDisposition.UNORDERED,
            None,
            None,
            None,
            None,
        ),
        OrderedEventClaim(
            ORDERING_KEY,
            3,
            0,
            ZERO_DIGEST,
            OrderClaimDisposition.WAIT,
            None,
            None,
            1,
            2,
        ),
        OrderedEventClaim(
            ORDERING_KEY,
            3,
            0,
            ZERO_DIGEST,
            OrderClaimDisposition.READY_AFTER_GAP,
            "worker-1",
            42,
            1,
            2,
        ),
        OrderedEventClaim(
            ORDERING_KEY,
            2,
            0,
            ZERO_DIGEST,
            OrderClaimDisposition.BUSY,
            None,
            None,
            None,
            None,
        ),
        OrderedEventClaim(
            ORDERING_KEY,
            1,
            2,
            digest("late-prior").value,
            OrderClaimDisposition.LATE_REPLAY_REQUIRED,
            None,
            None,
            None,
            None,
        ),
    ],
)
def test_order_claim_accepts_each_exact_closed_variant(claim: OrderedEventClaim) -> None:
    assert claim.disposition in OrderClaimDisposition


@pytest.mark.parametrize(
    "changes",
    [
        {"owner": "bad owner"},
        {"lease_until_microseconds": -1},
        {
            "disposition": OrderClaimDisposition.UNORDERED,
            "owner": None,
            "lease_until_microseconds": None,
        },
        {
            "disposition": OrderClaimDisposition.READY,
            "event_sequence": 2,
        },
        {
            "disposition": OrderClaimDisposition.BUSY,
            "owner": None,
            "lease_until_microseconds": None,
            "event_sequence": 0,
        },
        {
            "disposition": OrderClaimDisposition.BUSY,
            "owner": None,
            "lease_until_microseconds": None,
            "event_sequence": 2,
            "gap_from_sequence": 1,
        },
        {
            "disposition": OrderClaimDisposition.LATE_REPLAY_REQUIRED,
            "owner": None,
            "lease_until_microseconds": None,
            "event_sequence": 2,
            "prior_sequence": 1,
        },
    ],
)
def test_order_claim_rejects_each_malformed_closed_variant(changes: dict[str, object]) -> None:
    with pytest.raises(IngestionValidationError):
        ready_claim(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"operation_id": "bad"},
        {"profile_id": "bad"},
        {"model_revision": "mutable"},
        {"purpose": "bad purpose"},
        {"result_sha256": "bad"},
    ],
)
def test_recorded_operation_rejects_mutable_or_incomplete_evidence(
    changes: dict[str, object],
) -> None:
    with pytest.raises(IngestionValidationError):
        evidence(**changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"event_id": "bad"},
        {"ordering_key": "bad"},
        {"event_sequence": 0},
        {"event_schema_version": 0},
        {"canonical_sha256": "bad"},
        {"projection_sha256": "bad"},
        {"recorded_operation": evidence()},
    ],
)
def test_reduction_input_rejects_invalid_or_unexpected_evidence(
    changes: dict[str, object],
) -> None:
    with pytest.raises(IngestionValidationError):
        reduction(**cast("Any", changes))


@pytest.mark.parametrize(
    "changes",
    [
        {"ordering_key": "bad"},
        {"applied_sequence": -1},
        {"state_sha256": "bad"},
    ],
)
def test_projection_state_rejects_invalid_identity_sequence_or_digest(
    changes: dict[str, object],
) -> None:
    with pytest.raises(IngestionValidationError):
        replace(
            OrderedProjectionState(ORDERING_KEY, 1, digest("state").value),
            **cast("Any", changes),
        )


def test_pure_reducer_is_deterministic_order_sensitive_and_code_pinned() -> None:
    first = reduction(1)
    second = reduction(2, event_id=OTHER_EVENT_ID)
    after_first = reduce_projection(ZERO_DIGEST, first, CODE_FINGERPRINT)
    live = reduce_projection(after_first, second, CODE_FINGERPRINT)
    replay = reduce_projection(
        reduce_projection(ZERO_DIGEST, first, CODE_FINGERPRINT),
        second,
        CODE_FINGERPRINT,
    )
    reversed_result = reduce_projection(
        reduce_projection(ZERO_DIGEST, second, CODE_FINGERPRINT),
        first,
        CODE_FINGERPRINT,
    )

    assert live == replay
    assert live != reversed_result
    assert live != reduce_projection(after_first, second, "c" * 40)


def test_reducer_and_generation_canonical_documents_match_golden_digests() -> None:
    recorded = reduction(
        2,
        event_id=OTHER_EVENT_ID,
        requires_recorded_operation=True,
        recorded_operation=evidence(),
    )
    assert (
        reduce_projection(digest("prior").value, recorded, CODE_FINGERPRINT)
        == "cf8b2154d381574784b4fa980a4283c67b97ac08142e42b660649b8a694b5429"
    )
    states = (
        OrderedProjectionState(ORDERING_KEY, 2, digest("state-a").value),
        OrderedProjectionState(OTHER_ORDERING_KEY, 7, digest("state-b").value),
    )
    assert (
        generation_digest(states, CODE_FINGERPRINT)
        == "a2e15cb35d077bebdcbd80a2fe4aa0e48aaab9f0234e789a8724f6ab9d85cbf3"
    )
    assert replay_request().request_sha256 == (
        "a484a0c5af4f58f2920d628f5fd991bc4e4db156ede99aa6b5cedb4dfb99b0bd"
    )


@given(st.lists(st.integers(min_value=1, max_value=50), min_size=1, max_size=20, unique=True))
def test_reordered_property_sequences_replay_to_one_canonical_digest(
    arrival_sequences: list[int],
) -> None:
    reductions = {
        sequence: reduction(
            sequence,
            event_id=f"018f0000-0000-7000-8000-{sequence:012x}",
            canonical_sha256=digest(f"canonical-{sequence}").value,
            projection_sha256=digest(f"projection-{sequence}").value,
        )
        for sequence in arrival_sequences
    }

    def replay(sequences: list[int]) -> str:
        state = ZERO_DIGEST
        for sequence in sorted(sequences):
            state = reduce_projection(state, reductions[sequence], CODE_FINGERPRINT)
        return state

    assert replay(arrival_sequences) == replay(list(reversed(arrival_sequences)))


def test_nondeterministic_reduction_requires_complete_recorded_operation_evidence() -> None:
    with pytest.raises(IngestionValidationError, match="recorded"):
        reduction(requires_recorded_operation=True)
    recorded = reduction(
        requires_recorded_operation=True,
        recorded_operation=evidence(),
    )
    assert reduce_projection(ZERO_DIGEST, recorded, CODE_FINGERPRINT) != reduce_projection(
        ZERO_DIGEST,
        replace(recorded, recorded_operation=evidence(result_sha256="d" * 64)),
        CODE_FINGERPRINT,
    )


def test_generation_digest_is_independent_of_concurrent_ordering_key_arrival() -> None:
    states = (
        OrderedProjectionState(ORDERING_KEY, 2, digest("state-a").value),
        OrderedProjectionState(OTHER_ORDERING_KEY, 7, digest("state-b").value),
    )
    expected = generation_digest(states, CODE_FINGERPRINT)
    assert {
        generation_digest(tuple(order), CODE_FINGERPRINT) for order in permutations(states)
    } == {expected}

    with pytest.raises(IngestionValidationError, match="duplicate"):
        generation_digest((states[0], states[0]), CODE_FINGERPRINT)
    with pytest.raises(IngestionValidationError, match="fingerprint"):
        generation_digest(states, "mutable")


@pytest.mark.parametrize(
    ("prior", "fingerprint"),
    [("bad", CODE_FINGERPRINT), (ZERO_DIGEST, "mutable")],
)
def test_reducer_rejects_unpinned_or_invalid_digest_input(prior: str, fingerprint: str) -> None:
    with pytest.raises(IngestionValidationError) as caught:
        reduce_projection(prior, reduction(), fingerprint)
    expected = (
        FieldViolation("prior_state_sha256", "invalid_digest")
        if prior == "bad"
        else FieldViolation("code_fingerprint", "invalid_fingerprint")
    )
    assert caught.value.violations == (expected,)


def test_uuid7_and_generation_validation_expose_exact_safe_field_codes() -> None:
    with pytest.raises(IngestionValidationError) as invalid_id:
        reduction(event_id="bad")
    assert invalid_id.value.violations == (FieldViolation("event_id", "invalid_id"),)

    states = (OrderedProjectionState(ORDERING_KEY, 1, digest("state").value),)
    with pytest.raises(IngestionValidationError) as invalid_fingerprint:
        generation_digest(states, "mutable")
    assert invalid_fingerprint.value.violations == (
        FieldViolation("code_fingerprint", "invalid_fingerprint"),
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"operation_id": "bad"},
        {"brain_id": "bad"},
        {"projection_name": "bad name"},
        {"projection_generation": "bad"},
        {"code_fingerprint": "mutable-tag"},
        {"from_ingested_at_microseconds": -1},
        {"from_ingested_at_microseconds": 10, "to_ingested_at_microseconds": 9},
        {"from_event_id": "bad"},
        {"from_event_id": OTHER_EVENT_ID, "to_event_id": EVENT_ID},
    ],
)
def test_replay_run_request_rejects_ambiguous_scope_range_and_mutable_code(
    changes: dict[str, object],
) -> None:
    request = ReplayRunRequest(
        operation_id=OPERATION_ID,
        brain_id=BRAIN_ID,
        actor_id=PRINCIPAL_ID,
        grant_id=GRANT_ID,
        projection_name="canonical-event-projection-v1",
        projection_generation=GENERATION_ID,
        code_fingerprint=CODE_FINGERPRINT,
        from_ingested_at_microseconds=1,
        to_ingested_at_microseconds=10,
        from_event_id=EVENT_ID,
        to_event_id=OTHER_EVENT_ID,
    )
    with pytest.raises(IngestionValidationError):
        replace(request, **cast("Any", changes))


def replay_request() -> ReplayRunRequest:
    return ReplayRunRequest(
        OPERATION_ID,
        BRAIN_ID,
        PRINCIPAL_ID,
        GRANT_ID,
        "canonical-event-projection-v1",
        GENERATION_ID,
        CODE_FINGERPRINT,
    )


def replay_run(**changes: object) -> OrderedReplayRun:
    value = OrderedReplayRun(
        replay_request(),
        ReplayRunState.QUEUED,
        10,
        OTHER_EVENT_ID,
        2,
        0,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        1,
        1,
        None,
    )
    return replace(value, **cast("Any", changes))


def test_replay_request_digest_is_operation_independent_but_range_bound() -> None:
    selected = replay_request()
    other_operation = replace(
        selected,
        operation_id="018f0000-0000-7000-8000-000000000127",
    )
    assert selected.request_sha256 == other_operation.request_sha256
    assert (
        selected.request_sha256 != replace(selected, from_ingested_at_microseconds=1).request_sha256
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"source_count": -1},
        {"processed_count": 3},
        {"processed_count": 1},
        {"shadow_digest": "bad"},
        {"cursor_ingested_at_microseconds": 1},
        {"cursor_event_id": OTHER_EVENT_ID},
        {
            "state": ReplayRunState.BUILDING,
            "lease_owner": None,
            "lease_until_microseconds": None,
        },
        {"state": ReplayRunState.PARTIAL, "failure_code": None},
        {"failure_code": "unexpected"},
        {"created_at_microseconds": -1},
        {
            "state": ReplayRunState.READY,
            "processed_count": 2,
            "cursor_ingested_at_microseconds": 2,
            "cursor_event_id": OTHER_EVENT_ID,
            "shadow_digest": "a" * 64,
            "live_digest": "b" * 64,
            "completed_at_microseconds": 3,
        },
    ],
)
def test_replay_run_rejects_ambiguous_lifecycle_evidence(changes: dict[str, object]) -> None:
    with pytest.raises(IngestionValidationError):
        replay_run(**changes)


def test_replay_source_page_requires_strictly_ascending_unique_ordinals() -> None:
    first = ReplaySourceRecord(1, 1, reduction())
    second = ReplaySourceRecord(2, 2, reduction(2, event_id=OTHER_EVENT_ID))
    assert ReplaySourcePage((first, second), complete=True).complete
    with pytest.raises(IngestionValidationError):
        ReplaySourcePage((second, first), complete=False)
    with pytest.raises(IngestionValidationError):
        ReplaySourceRecord(0, 1, reduction())
    with pytest.raises(IngestionValidationError):
        ReplaySourceRecord(1, -1, reduction())
