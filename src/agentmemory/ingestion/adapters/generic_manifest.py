"""Immutable capability declaration for the vendor-neutral generic adapter."""

from __future__ import annotations

from agentmemory.ingestion.domain.adapter_capability import (
    AdapterCapabilityManifest,
    EvidenceAvailability,
)
from agentmemory.ingestion.domain.agent_event import (
    CaptureCapability,
    CaptureMethod,
    EventFamily,
)


def build_generic_adapter_manifest(
    *,
    adapter_version: str,
    adapter_digest: str,
) -> AdapterCapabilityManifest:
    """Build the complete honest matrix for a hookless host integration."""
    statuses = {
        CaptureCapability.ARTIFACT_OBSERVATION: CaptureMethod.INFERRED,
        CaptureCapability.COMMAND_OBSERVATION: CaptureMethod.INFERRED,
        CaptureCapability.FILE_OBSERVATION: CaptureMethod.INFERRED,
        CaptureCapability.SESSION_LIFECYCLE: CaptureMethod.INFERRED,
        CaptureCapability.TASK_LIFECYCLE: CaptureMethod.EXPLICIT_TOOL_ONLY,
        CaptureCapability.VCS_OBSERVATION: CaptureMethod.INFERRED,
    }
    availability = tuple(
        EvidenceAvailability(
            capability,
            statuses.get(capability, CaptureMethod.UNSUPPORTED),
        )
        for capability in sorted(CaptureCapability, key=str)
    )
    return AdapterCapabilityManifest.create(
        adapter_id="agentmemory.generic",
        adapter_version=adapter_version,
        adapter_digest=adapter_digest,
        schema_major=1,
        supported_families=tuple(
            sorted(
                (
                    EventFamily.SESSION_STARTED,
                    EventFamily.SESSION_COMPLETED,
                    EventFamily.TASK_CHECKPOINTED,
                    EventFamily.FILE_CHANGED,
                    EventFamily.FILE_DELETED,
                    EventFamily.FILE_RENAMED,
                    EventFamily.TRANSCRIPT_CHUNK_OBSERVED,
                    EventFamily.COMMAND_COMPLETED,
                    EventFamily.GIT_COMMIT_OBSERVED,
                    EventFamily.CHECKOUT_CHANGED,
                    EventFamily.BRANCH_CHANGED,
                ),
                key=str,
            )
        ),
        evidence_availability=availability,
    )
