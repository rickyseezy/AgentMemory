"""ADP-001 translator, capability, trust-boundary, and skew tests."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta

import pytest

from agentmemory.ingestion.adapters.native_event_translator import (
    CanonicalNativeEventTranslator,
    NativeEventObservation,
)
from agentmemory.ingestion.application.admit_agent_event import AgentEventAdmissionHandler
from agentmemory.ingestion.domain.agent_event import (
    AdapterCapabilityDescriptor,
    AgentEvent,
    AgentEventData,
    AgentEventIdentity,
    AgentEventProvenance,
    CaptureCapability,
    CaptureMethod,
    Classification,
    EventFamily,
    PayloadReference,
    ResolvedAgentEventIdentity,
)
from agentmemory.ingestion.domain.errors import (
    IngestionAuthorizationError,
    IngestionValidationError,
)

EVENT_ID = "018f0000-0000-7000-8000-000000000101"
BRAIN_ID = "018f0000-0000-7000-8000-000000000001"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
SESSION_ID = "018f0000-0000-7000-8000-000000000111"
CORRELATION_ID = "018f0000-0000-7000-8000-000000000121"
ORDERING_KEY = "018f0000-0000-7000-8000-000000000131"
NOW = datetime(2026, 7, 20, 10, 12, tzinfo=UTC)
DIGEST = "a" * 64


def _descriptor(adapter_id: str = "agentmemory.codex") -> AdapterCapabilityDescriptor:
    return AdapterCapabilityDescriptor.create(
        adapter_id=adapter_id,
        adapter_version="1.0.0",
        adapter_digest=DIGEST,
        schema_major=1,
        supported_families=tuple(EventFamily),
        capture_capabilities=tuple(CaptureCapability),
    )


def _observation(
    descriptor: AdapterCapabilityDescriptor,
    *,
    occurred_at: datetime = NOW,
) -> NativeEventObservation:
    data = b'{"status":"observed"}'
    return NativeEventObservation(
        event_id=EVENT_ID,
        event_type=EventFamily.SESSION_STARTED,
        subject=f"session/{SESSION_ID}",
        occurred_at=occurred_at,
        claimed_identity=AgentEventIdentity(
            brain_id=BRAIN_ID,
            principal_id="018f0000-0000-7000-8000-000000000002",
            project_id=PROJECT_ID,
            repository_id=REPOSITORY_ID,
            checkout_id=None,
            branch_name=None,
            commit_sha=None,
        ),
        agent_host="codex",
        model_id="unknown",
        session_id=SESSION_ID,
        task_id=None,
        turn_id=None,
        subagent_id=None,
        correlation_id=CORRELATION_ID,
        causation_id=None,
        ordering_key=ORDERING_KEY,
        sequence=1,
        classification=Classification.INTERNAL,
        retention_policy_id="default",
        capture_method=CaptureMethod.NATIVE,
        source_sha256=DIGEST,
        payload=AgentEventData(data, hashlib.sha256(data).hexdigest()),
        payload_reference=None,
        capture_capabilities=(CaptureCapability.SESSION_LIFECYCLE,),
    )


@dataclass(frozen=True)
class _Clock:
    value: datetime = NOW

    def now(self) -> datetime:
        return self.value


class _ScopeResolver:
    def __init__(self) -> None:
        self.claim: AgentEventIdentity | None = None

    async def resolve(
        self,
        claim: AgentEventIdentity,
        provenance: AgentEventProvenance,
    ) -> ResolvedAgentEventIdentity:
        del provenance
        self.claim = claim
        return ResolvedAgentEventIdentity(
            brain_id="018f0000-0000-7000-8000-000000000901",
            principal_id="018f0000-0000-7000-8000-000000000902",
            project_id="018f0000-0000-7000-8000-000000000910",
            repository_id="018f0000-0000-7000-8000-000000000920",
            checkout_id=None,
        )


class _PayloadReader:
    def __init__(self, value: bytes = b'{"status":"observed"}') -> None:
        self.value = value

    async def read(self, reference: PayloadReference) -> bytes:
        del reference
        return self.value


def _translate(
    descriptor: AdapterCapabilityDescriptor,
    *,
    occurred_at: datetime = NOW,
) -> AgentEvent:
    translator = CanonicalNativeEventTranslator(descriptor)
    return translator.translate(_observation(descriptor, occurred_at=occurred_at))


def test_adapter_generated_uuidv7_and_exact_bytes_are_stable_across_retries() -> None:
    descriptor = _descriptor()
    translator = CanonicalNativeEventTranslator(descriptor)
    observation = _observation(descriptor)
    first = translator.translate(observation)
    second = translator.translate(observation)
    assert first == second
    assert first.event_id == EVENT_ID
    assert first.content_sha256 == second.content_sha256


def test_cross_adapter_equivalent_observations_have_same_semantic_digest() -> None:
    codex = _descriptor("agentmemory.codex")
    claude = _descriptor("agentmemory.claude")
    codex_event = _translate(codex)
    claude_event = _translate(claude)
    assert codex_event.provenance.adapter_id != claude_event.provenance.adapter_id
    assert codex_event.semantic_digest == claude_event.semantic_digest


def test_translator_rejects_observation_outside_descriptor() -> None:
    descriptor = AdapterCapabilityDescriptor.create(
        adapter_id="agentmemory.codex",
        adapter_version="1.0.0",
        adapter_digest=DIGEST,
        schema_major=1,
        supported_families=(EventFamily.TOOL_STARTED,),
        capture_capabilities=(CaptureCapability.TOOL_LIFECYCLE,),
    )
    with pytest.raises(IngestionAuthorizationError):
        CanonicalNativeEventTranslator(descriptor).translate(_observation(_descriptor()))


@pytest.mark.asyncio
async def test_daemon_recalculates_hash_and_resolves_scope_before_admission() -> None:
    descriptor = _descriptor()
    resolver = _ScopeResolver()
    admitted = await AgentEventAdmissionHandler(
        descriptor=descriptor,
        scope_resolver=resolver,
        payload_reader=_PayloadReader(),
        clock=_Clock(),
    ).execute(_translate(descriptor))
    assert resolver.claim is not None
    assert resolver.claim.brain_id == BRAIN_ID
    assert admitted.identity.brain_id != BRAIN_ID
    assert admitted.ingested_at == NOW
    assert admitted.clock_skew_microseconds == 0


@pytest.mark.asyncio
async def test_admission_rejects_transit_hash_tampering() -> None:
    descriptor = _descriptor()
    event = _translate(descriptor)
    assert event.payload is not None
    object.__setattr__(event.payload, "value", b'{"tampered":true}')
    with pytest.raises(IngestionValidationError) as raised:
        await AgentEventAdmissionHandler(
            descriptor, _ScopeResolver(), _PayloadReader(), _Clock()
        ).execute(event)
    assert raised.value.code_for("content_sha256") == "hash_mismatch"


@pytest.mark.asyncio
async def test_dataref_content_is_rehashed_at_daemon_boundary() -> None:
    descriptor = _descriptor()
    value = b'{"status":"observed"}'
    digest = hashlib.sha256(value).hexdigest()
    event = replace(
        _translate(descriptor),
        payload=None,
        payload_reference=PayloadReference(f"cas://sha256/{digest}", digest, len(value)),
    )
    with pytest.raises(IngestionValidationError) as raised:
        await AgentEventAdmissionHandler(
            descriptor, _ScopeResolver(), _PayloadReader(b"different"), _Clock()
        ).execute(event)
    assert raised.value.code_for("content_sha256") == "hash_mismatch"


@pytest.mark.asyncio
async def test_delayed_event_keeps_occurrence_time_and_records_skew() -> None:
    descriptor = _descriptor()
    occurred_at = NOW - timedelta(days=2)
    admitted = await AgentEventAdmissionHandler(
        descriptor, _ScopeResolver(), _PayloadReader(), _Clock()
    ).execute(_translate(descriptor, occurred_at=occurred_at))
    assert admitted.event.occurred_at == occurred_at
    assert admitted.clock_skew_microseconds == 172_800_000_000


@pytest.mark.asyncio
async def test_unbounded_future_timestamp_is_rejected() -> None:
    descriptor = _descriptor()
    with pytest.raises(IngestionValidationError) as raised:
        await AgentEventAdmissionHandler(
            descriptor, _ScopeResolver(), _PayloadReader(), _Clock()
        ).execute(_translate(descriptor, occurred_at=NOW + timedelta(minutes=5, microseconds=1)))
    assert raised.value.code_for("time") == "future_clock_skew"


@pytest.mark.asyncio
async def test_daemon_clock_must_be_aware_utc() -> None:
    descriptor = _descriptor()
    naive = NOW.replace(tzinfo=None)
    with pytest.raises(IngestionValidationError) as raised:
        await AgentEventAdmissionHandler(
            descriptor, _ScopeResolver(), _PayloadReader(), _Clock(naive)
        ).execute(_translate(descriptor))
    assert raised.value.code_for("ingested_at") == "clock_not_utc"


@pytest.mark.asyncio
async def test_dataref_size_is_verified_after_a_matching_hash() -> None:
    descriptor = _descriptor()
    value = b'{"status":"observed"}'
    digest = hashlib.sha256(value).hexdigest()
    event = replace(
        _translate(descriptor),
        payload=None,
        payload_reference=PayloadReference(f"cas://sha256/{digest}", digest, len(value) + 1),
    )
    with pytest.raises(IngestionValidationError) as raised:
        await AgentEventAdmissionHandler(
            descriptor, _ScopeResolver(), _PayloadReader(value), _Clock()
        ).execute(event)
    assert raised.value.code_for("dataref") == "size_mismatch"


@pytest.mark.asyncio
async def test_missing_descriptor_capability_is_rejected_before_scope_resolution() -> None:
    full = _descriptor()
    limited = AdapterCapabilityDescriptor.create(
        adapter_id=full.adapter_id,
        adapter_version=full.adapter_version,
        adapter_digest=full.adapter_digest,
        schema_major=1,
        supported_families=(EventFamily.TOOL_STARTED,),
        capture_capabilities=(CaptureCapability.TOOL_LIFECYCLE,),
    )
    resolver = _ScopeResolver()
    with pytest.raises(IngestionAuthorizationError):
        await AgentEventAdmissionHandler(limited, resolver, _PayloadReader(), _Clock()).execute(
            _translate(full)
        )
    assert resolver.claim is None
