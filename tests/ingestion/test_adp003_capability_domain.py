"""ADP-003 immutable manifests, evidence availability, and compatibility tests."""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime

import pytest

from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    AdapterCapabilityObservation,
    CapabilityCompatibilityImpact,
    EvidenceAvailability,
    RegisteredAdapterCapabilities,
    compare_capability_availability,
)
from agentmemory.ingestion.domain.agent_event import (
    CaptureCapability,
    CaptureMethod,
    EventFamily,
)
from agentmemory.ingestion.domain.errors import IngestionValidationError

DIGEST = "a" * 64
OBSERVATION_ID = "018f0000-0000-7000-8000-000000000301"
NOW = datetime(2026, 7, 20, 12, 0, tzinfo=UTC)


def availability(
    overrides: dict[CaptureCapability, CaptureMethod] | None = None,
) -> tuple[EvidenceAvailability, ...]:
    selected = overrides or {}
    return tuple(
        EvidenceAvailability(
            capability,
            selected.get(capability, CaptureMethod.UNSUPPORTED),
        )
        for capability in CaptureCapability
    )


def manifest(
    *,
    version: str = "1.0.0",
    overrides: dict[CaptureCapability, CaptureMethod] | None = None,
    families: tuple[EventFamily, ...] = (EventFamily.SESSION_STARTED,),
) -> AdapterCapabilityManifest:
    methods = {
        CaptureCapability.SESSION_LIFECYCLE: CaptureMethod.NATIVE,
        **(overrides or {}),
    }
    return AdapterCapabilityManifest.create(
        adapter_id="agentmemory.codex",
        adapter_version=version,
        adapter_digest=DIGEST,
        schema_major=1,
        supported_families=families,
        evidence_availability=availability(methods),
    )


def observation(
    configured: AdapterCapabilityManifest,
    *,
    revision: int = 1,
    overrides: dict[CaptureCapability, CaptureMethod] | None = None,
) -> AdapterCapabilityObservation:
    effective = {item.capability: item.status for item in configured.evidence_availability}
    effective.update(overrides or {})
    return AdapterCapabilityObservation.create(
        observation_id=OBSERVATION_ID,
        operation_id=f"observe-{revision}",
        adapter_id=configured.adapter_id,
        adapter_version=configured.adapter_version,
        adapter_digest=configured.adapter_digest,
        capability_manifest_digest=configured.manifest_sha256,
        revision=revision,
        evidence_availability=availability(effective),
        observed_at=NOW,
    )


def test_partial_host_matrix_preserves_every_explicit_status() -> None:
    configured = manifest(
        overrides={
            CaptureCapability.PROMPT_CONTENT: CaptureMethod.PERMISSION_DENIED,
            CaptureCapability.TURN_LIFECYCLE: CaptureMethod.INFERRED,
            CaptureCapability.TASK_LIFECYCLE: CaptureMethod.EXPLICIT_TOOL_ONLY,
        }
    )
    statuses = {item.status for item in configured.evidence_availability}
    assert statuses == {
        CaptureMethod.NATIVE,
        CaptureMethod.INFERRED,
        CaptureMethod.EXPLICIT_TOOL_ONLY,
        CaptureMethod.UNSUPPORTED,
        CaptureMethod.PERMISSION_DENIED,
    }
    assert configured.availability_for(CaptureCapability.SESSION_LIFECYCLE).observable
    assert not configured.availability_for(CaptureCapability.PROMPT_CONTENT).observable
    assert not configured.availability_for(CaptureCapability.FILE_OBSERVATION).observable


def test_manifest_requires_one_canonical_status_for_every_capability() -> None:
    complete = manifest()
    with pytest.raises(IngestionValidationError, match="complete"):
        replace(complete, evidence_availability=complete.evidence_availability[:-1])
    with pytest.raises(IngestionValidationError, match="canonical"):
        replace(
            complete,
            evidence_availability=(
                complete.evidence_availability[1],
                complete.evidence_availability[0],
                *complete.evidence_availability[2:],
            ),
        )
    with pytest.raises(IngestionValidationError, match="complete"):
        replace(
            complete,
            evidence_availability=(
                complete.evidence_availability[0],
                *complete.evidence_availability[:-1],
            ),
        )


def test_supported_family_requires_observable_evidence() -> None:
    with pytest.raises(IngestionValidationError, match="observable"):
        AdapterCapabilityManifest.create(
            adapter_id="agentmemory.codex",
            adapter_version="1.0.0",
            adapter_digest=DIGEST,
            schema_major=1,
            supported_families=(EventFamily.TOOL_STARTED,),
            evidence_availability=availability(),
        )
    with pytest.raises(IngestionValidationError, match="canonical"):
        manifest(
            families=(
                EventFamily.SESSION_STARTED,
                EventFamily.SESSION_STARTED,
            )
        )


def test_manifest_is_immutable_canonical_and_digest_bound() -> None:
    configured = manifest()
    reordered = AdapterCapabilityManifest.create(
        adapter_id=configured.adapter_id,
        adapter_version=configured.adapter_version,
        adapter_digest=configured.adapter_digest,
        schema_major=1,
        supported_families=tuple(reversed(configured.supported_families)),
        evidence_availability=tuple(reversed(configured.evidence_availability)),
    )
    assert reordered == configured
    assert reordered.manifest_sha256 == (
        "1c73ec3399ec584d25b9ceb94b314352b83a39f1026c4375ca711607908edd4c"
    )
    with pytest.raises(FrozenInstanceError):
        configured.adapter_version = "2.0.0"  # type: ignore[misc]


def test_effective_observation_only_allows_permission_loss_or_restoration() -> None:
    configured = manifest()
    denied = observation(
        configured,
        overrides={CaptureCapability.SESSION_LIFECYCLE: CaptureMethod.PERMISSION_DENIED},
    )
    registered = RegisteredAdapterCapabilities(configured, denied)
    assert not registered.availability_for(CaptureCapability.SESSION_LIFECYCLE).observable
    assert not registered.authorizes(EventFamily.SESSION_STARTED, CaptureMethod.NATIVE)

    fabricated = observation(
        configured,
        overrides={CaptureCapability.FILE_OBSERVATION: CaptureMethod.NATIVE},
    )
    with pytest.raises(IngestionValidationError, match="exceeds"):
        RegisteredAdapterCapabilities(configured, fabricated)


def test_permission_loss_and_version_change_create_typed_warnings() -> None:
    before = manifest().evidence_availability
    permission_lost = availability(
        {CaptureCapability.SESSION_LIFECYCLE: CaptureMethod.PERMISSION_DENIED}
    )
    warnings = compare_capability_availability(before, permission_lost)
    assert len(warnings) == 1
    assert warnings[0].code == "permission_lost"
    assert warnings[0].impact is CapabilityCompatibilityImpact.BREAKING
    assert warnings[0].capability is CaptureCapability.SESSION_LIFECYCLE
    assert warnings[0].previous_status is CaptureMethod.NATIVE
    assert warnings[0].current_status is CaptureMethod.PERMISSION_DENIED

    upgraded = manifest(
        version="2.0.0",
        overrides={CaptureCapability.SESSION_LIFECYCLE: CaptureMethod.INFERRED},
    )
    warnings = compare_capability_availability(before, upgraded.evidence_availability)
    assert warnings[0].code == "capture_method_changed"
    assert warnings[0].impact is CapabilityCompatibilityImpact.DEGRADED


def test_every_availability_transition_has_explicit_semantics_and_stable_order() -> None:
    unavailable = availability()
    added = availability(
        {
            CaptureCapability.SESSION_LIFECYCLE: CaptureMethod.EXPLICIT_TOOL_ONLY,
            CaptureCapability.PROMPT_CONTENT: CaptureMethod.INFERRED,
        }
    )
    warnings = compare_capability_availability(unavailable, added)
    assert [item.capability for item in warnings] == [
        CaptureCapability.PROMPT_CONTENT,
        CaptureCapability.SESSION_LIFECYCLE,
    ]
    assert all(item.code == "signal_added" for item in warnings)
    assert all(
        item.impact is CapabilityCompatibilityImpact.INFORMATIONAL
        for item in warnings
    )

    removed = compare_capability_availability(added, unavailable)
    assert all(item.code == "signal_removed" for item in removed)
    assert all(
        item.impact is CapabilityCompatibilityImpact.BREAKING for item in removed
    )

    denied = availability(
        {CaptureCapability.SESSION_LIFECYCLE: CaptureMethod.PERMISSION_DENIED}
    )
    restored = compare_capability_availability(denied, manifest().evidence_availability)
    assert restored[0].code == "permission_restored"
    assert restored[0].impact is CapabilityCompatibilityImpact.INFORMATIONAL


def test_registered_evidence_rejects_wrong_identity_digest_and_revision() -> None:
    configured = manifest()
    current = observation(configured)
    with pytest.raises(IngestionValidationError, match="identity"):
        RegisteredAdapterCapabilities(
            configured,
            replace(current, capability_manifest_digest="b" * 64),
        )
    with pytest.raises(IngestionValidationError, match="revision"):
        replace(current, revision=0)
    with pytest.raises(IngestionValidationError, match="uuid7"):
        replace(current, observation_id="not-a-uuid")
    with pytest.raises(IngestionValidationError, match="uuid7"):
        replace(current, observation_id="018f0000-0000-4000-8000-000000000301")
    with pytest.raises(IngestionValidationError, match="uuid7"):
        replace(current, observation_id=OBSERVATION_ID.upper())
