"""Cross-language active-release domain and transaction tests."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime

import pytest

from agentmemory.operations.domain.active_release import (
    ActiveReleasePointer,
    ActiveReleasePointerInput,
    active_release_stage_digest,
    permits_replacement,
)
from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.value_objects import (
    OperationId,
    ReleaseId,
    Sha256Digest,
    Uuid7Id,
)


def _digest(value: str) -> Sha256Digest:
    return Sha256Digest(hashlib.sha256(value.encode()).hexdigest())


def _input() -> ActiveReleasePointerInput:
    return ActiveReleasePointerInput(
        installation_id=Uuid7Id("019f5f20-1234-7abc-8123-0123456789ab"),
        release_id=ReleaseId("release-v1"),
        generation_id=Uuid7Id("019f5f21-5678-7def-9123-abcdef012345"),
        manifest_digest=_digest("manifest"),
        compose_digest=_digest("compose"),
        readiness_receipt_digest=_digest("ready"),
        runtime_endpoint="unix:///var/run/docker.sock",
        release_sequence=7,
        resource_inventory_version=9,
        resource_inventory_digest=_digest("inventory"),
        security_epoch=3,
        activated_at=datetime(2026, 7, 13, 6, 11, 12, 123456, tzinfo=UTC),
    )


def test_pointer_and_stage_digest_match_go_golden_contract() -> None:
    pointer = ActiveReleasePointer.create(_input())
    operation_id = OperationId("019f5f23-5678-7def-9123-abcdef012347")
    assert pointer.pointer_digest.value == (
        "5096de10e5cbbf8ddc2cfae38b2283beff89fa1354272913d87fceb484fcbd7b"
    )
    assert active_release_stage_digest(operation_id, pointer).value == (
        "3eecdea699b3fc251c76079c92ac88e29b24d3f496255347b08928a9ae13b2c5"
    )
    assert ActiveReleasePointer.restore(pointer.record()) == pointer


def test_pointer_restore_rejects_tamper_unknown_fields_and_noncanonical_time() -> None:
    pointer = ActiveReleasePointer.create(_input())
    record = pointer.record()
    record["pointer_digest"] = _digest("tampered").value
    with pytest.raises(DomainValidationError):
        ActiveReleasePointer.restore(record)
    record = pointer.record()
    record["unknown"] = True
    with pytest.raises(DomainValidationError):
        ActiveReleasePointer.restore(record)
    record = pointer.record()
    record["activated_at"] = "2026-07-13T06:11:12.1234560Z"
    with pytest.raises(DomainValidationError):
        ActiveReleasePointer.restore(record)


def test_pointer_replacement_policy_matches_launcher_anti_rollback_rules() -> None:
    current = ActiveReleasePointer.create(_input())
    upgraded_input = _input()
    upgraded = ActiveReleasePointer.create(
        ActiveReleasePointerInput(
            installation_id=upgraded_input.installation_id,
            release_id=ReleaseId("release-v2"),
            generation_id=upgraded_input.generation_id,
            manifest_digest=_digest("manifest-v2"),
            compose_digest=_digest("compose-v2"),
            readiness_receipt_digest=_digest("ready-v2"),
            runtime_endpoint=upgraded_input.runtime_endpoint,
            release_sequence=8,
            resource_inventory_version=10,
            resource_inventory_digest=_digest("inventory-v2"),
            security_epoch=4,
            activated_at=upgraded_input.activated_at,
        )
    )
    rollback = ActiveReleasePointer.create(
        ActiveReleasePointerInput(
            installation_id=upgraded.installation_id,
            release_id=upgraded.release_id,
            generation_id=upgraded.generation_id,
            manifest_digest=upgraded.manifest_digest,
            compose_digest=upgraded.compose_digest,
            readiness_receipt_digest=upgraded.readiness_receipt_digest,
            runtime_endpoint=upgraded.runtime_endpoint,
            release_sequence=6,
            resource_inventory_version=upgraded.resource_inventory_version,
            resource_inventory_digest=upgraded.resource_inventory_digest,
            security_epoch=upgraded.security_epoch,
            activated_at=upgraded.activated_at,
        )
    )
    assert permits_replacement(None, current)
    assert permits_replacement(current, current)
    assert permits_replacement(current, upgraded)
    assert not permits_replacement(current, rollback)


@pytest.mark.parametrize(
    "candidate",
    [
        replace(_input(), release_sequence=0),
        replace(_input(), resource_inventory_version=True),
        replace(_input(), security_epoch=(1 << 64)),
        replace(_input(), runtime_endpoint="tcp://127.0.0.1:2375"),
        replace(_input(), runtime_endpoint="unix:///run/../docker.sock"),
        replace(_input(), runtime_endpoint="npipe:////./pipe/a/b"),
    ],
)
def test_pointer_rejects_invalid_monotonic_values_and_runtime_endpoints(
    candidate: ActiveReleasePointerInput,
) -> None:
    with pytest.raises(DomainValidationError):
        ActiveReleasePointer.create(candidate)
    assert (
        ActiveReleasePointer.create(
            replace(_input(), runtime_endpoint="npipe:////./pipe/docker_engine")
        ).runtime_endpoint
        == "npipe:////./pipe/docker_engine"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("installation_id", 1),
        ("release_sequence", "7"),
        ("release_sequence", False),
        ("activated_at", "not-a-timeZ"),
        ("activated_at", "2026-07-13T06:11:12+01:00"),
    ],
)
def test_pointer_restore_rejects_wrong_types_and_invalid_times(field: str, value: object) -> None:
    record = ActiveReleasePointer.create(_input()).record()
    record[field] = value
    with pytest.raises(DomainValidationError):
        ActiveReleasePointer.restore(record)


def test_replacement_rejects_cross_install_inventory_security_and_equivocation() -> None:
    current = ActiveReleasePointer.create(_input())
    candidates = (
        replace(_input(), installation_id=Uuid7Id("019f5f20-1234-7abc-9123-0123456789ac")),
        replace(_input(), resource_inventory_version=8),
        replace(_input(), security_epoch=2),
        replace(_input(), release_id=ReleaseId("release-other")),
    )
    for candidate in candidates:
        assert not permits_replacement(current, ActiveReleasePointer.create(candidate))
