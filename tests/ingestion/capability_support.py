"""Shared complete ADP-003 capability fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    AdapterCapabilityObservation,
    EvidenceAvailability,
    RegisteredAdapterCapabilities,
)
from agentmemory.ingestion.domain.agent_event import CaptureCapability, CaptureMethod

if TYPE_CHECKING:
    from datetime import datetime

OBSERVATION_ID = "018f0000-0000-7000-8000-000000000301"


def complete_availability(
    default: CaptureMethod = CaptureMethod.UNSUPPORTED,
    **overrides: CaptureMethod,
) -> tuple[EvidenceAvailability, ...]:
    """Build one explicit status for every closed capability."""
    return tuple(
        EvidenceAvailability(
            capability,
            overrides.get(capability.value, default),
        )
        for capability in CaptureCapability
    )


def registered(
    manifest: AdapterCapabilityManifest,
    *,
    observed_at: datetime,
    revision: int = 1,
    **overrides: CaptureMethod,
) -> RegisteredAdapterCapabilities:
    """Pair a manifest with a canonical effective observation fixture."""
    declared = {item.capability.value: item.status for item in manifest.evidence_availability}
    declared.update(overrides)
    observation = AdapterCapabilityObservation.create(
        observation_id=OBSERVATION_ID,
        operation_id=f"fixture-{revision}",
        adapter_id=manifest.adapter_id,
        adapter_version=manifest.adapter_version,
        adapter_digest=manifest.adapter_digest,
        capability_manifest_digest=manifest.manifest_sha256,
        revision=revision,
        evidence_availability=complete_availability(**declared),
        observed_at=observed_at,
    )
    return RegisteredAdapterCapabilities(manifest, observation)
