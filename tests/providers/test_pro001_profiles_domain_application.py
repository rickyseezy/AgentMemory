"""PRO-001 provider-profile domain and application acceptance tests."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import timedelta
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.providers.application.profiles import (
    CreateProviderProfileCommand,
    CreateProviderProfileHandler,
    GetProviderProfileHandler,
    GetProviderProfileQuery,
    ProbeProviderCommand,
    ProbeProviderHandler,
)
from agentmemory.providers.domain.errors import (
    ProviderModelDriftError,
    ProviderProfileAuthorizationError,
    ProviderProfileConflictError,
    ProviderProfileValidationError,
)
from agentmemory.providers.domain.profiles import (
    CanonicalPurpose,
    ProviderBudget,
    ProviderDataPolicy,
    ProviderExecutionClass,
    ProviderLimits,
    ProviderManifest,
    ProviderOperation,
    ProviderProbeEvidence,
    ProviderProbeResult,
    ProviderProfile,
    ProviderProfileConfiguration,
    ProviderProfileStatus,
    ProviderQuota,
    SimilarityMetric,
    VectorDtype,
    VectorNormalization,
    finite_vector,
)
from tests.core.support import BRAIN_ID, NOW, OWNER_ID, digest

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime
    from typing import Any

    from agentmemory.providers.domain.profile_ports import ProviderAdapterPort

PROFILE_ID = "018f0000-0000-7000-8000-000000000701"
PROJECT_ID = "018f0000-0000-7000-8000-000000000702"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000703"
MANIFEST_IMPLEMENTATION = digest("pro001-manifest").value
REVISION_FINGERPRINT = digest("pro001-model-revision").value
PURPOSES = (
    CanonicalPurpose.RETRIEVAL_DOCUMENT,
    CanonicalPurpose.RETRIEVAL_QUERY,
)


def limits(max_items: int = 16) -> ProviderLimits:
    """Build one bounded profile limit set."""
    return ProviderLimits(max_items, 64_000, 4096, 65_536, 30_000)


def remote_configuration(**changes: object) -> ProviderProfileConfiguration:
    """Build a complete governed remote profile configuration."""
    value = ProviderProfileConfiguration(
        brain_id=BRAIN_ID,
        adapter_id="openai",
        operation=ProviderOperation.EMBEDDING,
        model_id="text-embedding-3-large",
        purposes=PURPOSES,
        limits=limits(),
        execution_class=ProviderExecutionClass.REMOTE,
        endpoint_policy_ref="policy://providers/openai-production",
        secret_ref="secret://providers/openai-production",  # noqa: S106 -- Opaque reference.
        egress_approval_ref="approval://providers/openai-production",
        data_policy=ProviderDataPolicy(
            declaration_version="2026-07-01",
            retention_days=30,
            training_allowed=False,
            residency="US",
        ),
        quota=ProviderQuota(60, 250_000, 25_000_000),
        budget=ProviderBudget("USD", 50_000_000),
    )
    return replace(value, **cast("Any", changes))


def local_configuration(**changes: object) -> ProviderProfileConfiguration:
    """Build a no-egress local profile configuration."""
    value = ProviderProfileConfiguration(
        brain_id=BRAIN_ID,
        adapter_id="qwen-local",
        operation=ProviderOperation.EMBEDDING,
        model_id="Qwen3-Embedding-0.6B-GGUF-Q8_0",
        purposes=PURPOSES,
        limits=limits(),
        execution_class=ProviderExecutionClass.LOCAL,
    )
    return replace(value, **cast("Any", changes))


def manifest(
    *,
    adapter_id: str = "openai",
    execution_class: ProviderExecutionClass = ProviderExecutionClass.REMOTE,
    implementation_digest: str = MANIFEST_IMPLEMENTATION,
) -> ProviderManifest:
    """Build a certified manifest matching the profile helpers."""
    return ProviderManifest(
        adapter_id=adapter_id,
        implementation_version="1.0.0",
        implementation_digest=implementation_digest,
        protocol_version="1.0",
        execution_class=execution_class,
        operations=(ProviderOperation.EMBEDDING,),
        purposes=PURPOSES,
        limits=limits(32),
        revision_evidence=True,
        cancellation=True,
        vendor=adapter_id,
    )


def probe_result(
    *,
    adapter_id: str = "openai",
    model_id: str = "text-embedding-3-large",
    fingerprint: str = REVISION_FINGERPRINT,
) -> ProviderProbeResult:
    """Build complete content-free live probe evidence."""
    return ProviderProbeResult(
        adapter_id=adapter_id,
        model_id=model_id,
        model_revision="text-embedding-3-large-2026-01-15",
        revision_fingerprint=fingerprint,
        operation=ProviderOperation.EMBEDDING,
        purposes=PURPOSES,
        dimension=3072,
        dtype=VectorDtype.FLOAT32,
        normalization=VectorNormalization.PROVIDER_DEFINED,
        similarity=SimilarityMetric.COSINE,
        max_items=32,
        cancellation_verified=True,
    )


def profile(
    configuration: ProviderProfileConfiguration | None = None,
    provider_manifest: ProviderManifest | None = None,
) -> ProviderProfile:
    """Build one immutable draft profile."""
    resolved_configuration = configuration or remote_configuration()
    resolved_manifest = provider_manifest or manifest()
    return ProviderProfile(
        profile_id=PROFILE_ID,
        configuration=resolved_configuration,
        manifest_digest=resolved_manifest.digest,
        status=ProviderProfileStatus.DRAFT,
        version=1,
        created_at=NOW,
        updated_at=NOW,
    )


def scope(
    action: str,
    *,
    role: RetrievalRole = RetrievalRole.OWNER,
) -> AuthorizedScope:
    """Build current Brain-scoped provider administration authority."""
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(OWNER_ID),
        role=role,
        mode=RetrievalScopeMode.CURRENT,
        members=(
            ScopeMember(
                StableId(PROJECT_ID),
                (StableId(REPOSITORY_ID),),
                (),
            ),
        ),
        classification_ceiling=Classification.LOCAL_ONLY,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action=action,
        purpose="provider_administration",
    )


@pytest.mark.parametrize(
    "field_name",
    [
        "endpoint_policy_ref",
        "secret_ref",
        "egress_approval_ref",
        "data_policy",
        "quota",
        "budget",
    ],
)
def test_remote_profile_requires_every_governance_authority(field_name: str) -> None:
    """A remote profile cannot exist with a partially configured authority set."""
    with pytest.raises(ProviderProfileValidationError, match="profile input"):
        remote_configuration(**{field_name: None})


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("endpoint_policy_ref", "policy://providers/local"),
        ("secret_ref", "secret://providers/local"),
        ("egress_approval_ref", "approval://providers/local"),
        (
            "data_policy",
            ProviderDataPolicy(
                declaration_version="1",
                retention_days=0,
                training_allowed=False,
                residency="global",
            ),
        ),
        ("quota", ProviderQuota(1, 1, 1)),
        ("budget", ProviderBudget("USD", 1)),
    ],
)
def test_local_profile_forbids_remote_authorities(field_name: str, value: object) -> None:
    """Local inference cannot accidentally acquire a remote egress configuration."""
    with pytest.raises(ProviderProfileValidationError, match="profile input"):
        local_configuration(**{field_name: value})


def test_configuration_serializes_only_opaque_secret_reference() -> None:
    """Credential values are not accepted by or serialized through the domain contract."""
    configuration = remote_configuration()
    raw_credential = b"sk-pro001-this-value-must-never-persist"
    assert raw_credential not in configuration.canonical_bytes
    assert b"secret://providers/openai-production" in configuration.canonical_bytes
    with pytest.raises(ProviderProfileValidationError):
        remote_configuration(secret_ref=raw_credential.decode())


def test_manifest_validation_is_vendor_neutral_and_limit_narrowing_is_exact() -> None:
    """Every adapter uses the same operation, purpose, execution, and limit rules."""
    provider_manifest = manifest()
    provider_manifest.validate_configuration(remote_configuration())
    for changed in (
        remote_configuration(adapter_id="cohere"),
        remote_configuration(operation=ProviderOperation.RERANKING),
        remote_configuration(purposes=(CanonicalPurpose.CLASSIFICATION,)),
        remote_configuration(limits=limits(33)),
        local_configuration(adapter_id="openai"),
    ):
        with pytest.raises(ProviderProfileValidationError):
            provider_manifest.validate_configuration(changed)


def _invalid_limits() -> object:
    return ProviderLimits(0, 1, 1, 1, 100)


def _invalid_quota() -> object:
    return ProviderQuota(0, 1, 1)


def _invalid_budget() -> object:
    return ProviderBudget("usd", 1)


def _invalid_data_policy() -> object:
    return ProviderDataPolicy(
        declaration_version="bad value",
        retention_days=0,
        training_allowed=False,
        residency="global",
    )


def _invalid_manifest() -> object:
    return replace(manifest(), revision_evidence=False)


def _invalid_brain() -> object:
    return remote_configuration(brain_id="not-a-brain")


def _invalid_purposes() -> object:
    return remote_configuration(purposes=(PURPOSES[0], PURPOSES[0]))


@pytest.mark.parametrize(
    "factory",
    [
        _invalid_limits,
        _invalid_quota,
        _invalid_budget,
        _invalid_data_policy,
        _invalid_manifest,
        _invalid_brain,
        _invalid_purposes,
    ],
)
def test_bounded_profile_value_objects_reject_invalid_authority(
    factory: Callable[[], object],
) -> None:
    with pytest.raises(ProviderProfileValidationError):
        factory()


@pytest.mark.parametrize(
    "values",
    [(), (float("nan"),), (float("inf"),), (float("-inf"),)],
)
def test_vector_finiteness_predicate_rejects_empty_and_non_finite(
    values: tuple[float, ...],
) -> None:
    assert not finite_vector(values)
    assert finite_vector((0.0, -1.5, 2.5))


def test_probe_evidence_is_content_addressed_and_tamper_evident() -> None:
    """Live capability facts are immutable and self-authenticating."""
    evidence = ProviderProbeEvidence.create(PROFILE_ID, manifest().digest, probe_result(), NOW)
    assert evidence.evidence_id == evidence.expected_id
    with pytest.raises(ProviderProfileValidationError):
        replace(evidence, evidence_id="0" * 64)
    with pytest.raises(ProviderProfileValidationError):
        replace(evidence, profile_id="not-a-profile")


def test_profile_snapshot_rejects_invalid_identity_and_status_evidence_shape() -> None:
    draft = profile()
    with pytest.raises(ProviderProfileValidationError):
        replace(draft, profile_id="not-a-profile")
    with pytest.raises(ProviderProfileValidationError):
        replace(draft, status=ProviderProfileStatus.ACTIVE)


def test_activation_pins_revision_and_rejects_alias_drift_or_time_regression() -> None:
    """An active model alias cannot silently move to another model generation."""
    draft = profile()
    first = ProviderProbeEvidence.create(PROFILE_ID, manifest().digest, probe_result(), NOW)
    active = draft.activate(first)
    assert active.status is ProviderProfileStatus.ACTIVE
    assert active.version == 2

    drifted = ProviderProbeEvidence.create(
        PROFILE_ID,
        manifest().digest,
        probe_result(fingerprint=digest("different-revision").value),
        NOW + timedelta(seconds=1),
    )
    with pytest.raises(ProviderModelDriftError, match="revision drifted"):
        active.activate(drifted)

    older = ProviderProbeEvidence.create(
        PROFILE_ID,
        manifest().digest,
        probe_result(),
        NOW - timedelta(microseconds=1),
    )
    with pytest.raises(ProviderProfileValidationError):
        active.activate(older)


@pytest.mark.parametrize(
    "result",
    [
        lambda: replace(probe_result(), cancellation_verified=False),
        lambda: replace(probe_result(), dimension=None),
        lambda: replace(probe_result(), revision_fingerprint="bad"),
        lambda: replace(
            probe_result(),
            operation=ProviderOperation.RERANKING,
            dimension=1,
            dtype=VectorDtype.FLOAT32,
            normalization=VectorNormalization.L2,
            similarity=SimilarityMetric.COSINE,
        ),
    ],
)
def test_probe_result_rejects_incomplete_or_incompatible_capability(
    result: Callable[[], ProviderProbeResult],
) -> None:
    with pytest.raises(ProviderProfileValidationError):
        result()


def _create_with_time(value: datetime) -> object:
    return CreateProviderProfileCommand(
        "create-1", scope("provider.profile.create"), remote_configuration(), value
    )


def _probe_with_time(value: datetime) -> object:
    current = profile()
    return ProbeProviderCommand(
        "probe-1",
        scope("provider.profile.probe"),
        PROFILE_ID,
        current.version,
        current.snapshot_digest,
        value,
    )


@pytest.mark.parametrize(
    ("version", "snapshot_digest"),
    [(0, digest("snapshot").value), (1, "not-a-digest")],
)
def test_probe_command_requires_a_valid_snapshot_precondition(
    version: int, snapshot_digest: str
) -> None:
    with pytest.raises(ProviderProfileValidationError):
        ProbeProviderCommand(
            "probe-1",
            scope("provider.profile.probe"),
            PROFILE_ID,
            version,
            snapshot_digest,
            NOW,
        )


def _query_with_time(value: datetime) -> object:
    return GetProviderProfileQuery(scope("provider.profile.read"), PROFILE_ID, value)


@pytest.mark.parametrize("factory", [_create_with_time, _probe_with_time, _query_with_time])
def test_application_contracts_reject_non_utc_times(factory: Callable[[datetime], object]) -> None:
    naive = NOW.replace(tzinfo=None)
    with pytest.raises(ProviderProfileValidationError):
        factory(naive)


@dataclass(slots=True)
class _Repository:
    """Deterministic in-memory handler port fake."""

    current: ProviderProfile | None = None
    operations: dict[str, ProviderProfile] = field(default_factory=dict[str, ProviderProfile])

    async def create(  # noqa: PLR0913 -- Fake mirrors the production port.
        self,
        scope: AuthorizedScope,
        operation_id: str,
        profile_id: str,
        configuration: ProviderProfileConfiguration,
        manifest_digest: str,
        created_at: datetime,
    ) -> ProviderProfile:
        del scope
        value = ProviderProfile(
            profile_id=profile_id,
            configuration=configuration,
            manifest_digest=manifest_digest,
            status=ProviderProfileStatus.DRAFT,
            version=1,
            created_at=created_at,
            updated_at=created_at,
        )
        self.current = value
        self.operations[operation_id] = value
        return value

    async def get(
        self,
        scope: AuthorizedScope,
        profile_id: str,
        requested_at: datetime,
    ) -> ProviderProfile | None:
        del scope, requested_at
        return (
            self.current
            if self.current is not None and self.current.profile_id == profile_id
            else None
        )

    async def find_operation(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        operation_kind: str,
        profile_id: str | None,
        requested_at: datetime,
    ) -> ProviderProfile | None:
        del scope, operation_kind, profile_id, requested_at
        return self.operations.get(operation_id)

    async def activate(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        expected_version: int,
        evidence: ProviderProbeEvidence,
    ) -> ProviderProfile:
        del scope
        assert self.current is not None
        assert self.current.version == expected_version
        self.current = self.current.activate(evidence)
        self.operations[operation_id] = self.current
        return self.current


@dataclass(slots=True)
class _Adapter:
    manifest: ProviderManifest
    result: ProviderProbeResult = field(default_factory=probe_result)
    calls: int = 0

    async def probe(self, profile: ProviderProfile) -> ProviderProbeResult:
        del profile
        self.calls += 1
        return self.result


@dataclass(frozen=True, slots=True)
class _Registry:
    adapter: _Adapter

    def get(self, adapter_id: str) -> ProviderAdapterPort:
        assert adapter_id == self.adapter.manifest.adapter_id
        return self.adapter


@dataclass(frozen=True, slots=True)
class _Identity:
    value: str = PROFILE_ID

    def new(self) -> str:
        return self.value


@pytest.mark.asyncio
async def test_create_probe_query_lifecycle_is_manifest_bound_and_idempotent() -> None:
    """Create is offline; activation requires exactly one live probe and exact replay."""
    repository = _Repository()
    adapter = _Adapter(manifest())
    registry = _Registry(adapter)
    create_handler = CreateProviderProfileHandler(repository, registry, _Identity())
    create_command = CreateProviderProfileCommand(
        "create-1",
        scope("provider.profile.create"),
        remote_configuration(),
        NOW,
    )
    draft = await create_handler.execute(create_command)
    assert draft.status is ProviderProfileStatus.DRAFT
    assert adapter.calls == 0
    assert await create_handler.execute(create_command) == draft

    with pytest.raises(ProviderProfileConflictError):
        await create_handler.execute(
            replace(
                create_command,
                configuration=remote_configuration(model_id="text-embedding-3-small"),
            )
        )

    probe_handler = ProbeProviderHandler(repository, registry)
    probe_command = ProbeProviderCommand(
        "probe-1",
        scope("provider.profile.probe"),
        PROFILE_ID,
        draft.version,
        draft.snapshot_digest,
        NOW + timedelta(seconds=1),
    )
    active = await probe_handler.execute(probe_command)
    assert active.status is ProviderProfileStatus.ACTIVE
    assert active.active_probe is not None
    assert adapter.calls == 1
    assert await probe_handler.execute(probe_command) == active
    assert adapter.calls == 1

    result = await GetProviderProfileHandler(repository).execute(
        GetProviderProfileQuery(scope("provider.profile.read"), PROFILE_ID, NOW)
    )
    assert result == active


@pytest.mark.asyncio
async def test_handlers_fail_closed_for_role_action_brain_manifest_and_missing_profile() -> None:
    """Application authorization and manifest revalidation precede external work."""
    repository = _Repository(profile())
    adapter = _Adapter(manifest())
    registry = _Registry(adapter)
    create_handler = CreateProviderProfileHandler(repository, registry, _Identity())
    with pytest.raises(ProviderProfileAuthorizationError):
        await create_handler.execute(
            CreateProviderProfileCommand(
                "create-denied",
                scope("provider.profile.create", role=RetrievalRole.READER),
                remote_configuration(),
                NOW,
            )
        )
    with pytest.raises(ProviderProfileAuthorizationError):
        await create_handler.execute(
            CreateProviderProfileCommand(
                "create-wrong-action",
                scope("provider.profile.read"),
                remote_configuration(),
                NOW,
            )
        )
    with pytest.raises(ProviderProfileValidationError):
        await create_handler.execute(
            CreateProviderProfileCommand(
                "create-wrong-brain",
                scope("provider.profile.create"),
                remote_configuration(brain_id="018f0000-0000-7000-8000-000000000799"),
                NOW,
            )
        )

    with pytest.raises(ProviderProfileConflictError, match="precondition failed"):
        await ProbeProviderHandler(repository, registry).execute(
            ProbeProviderCommand(
                "probe-stale",
                scope("provider.profile.probe"),
                PROFILE_ID,
                profile().version + 1,
                profile().snapshot_digest,
                NOW,
            )
        )
    assert adapter.calls == 0

    repository.current = replace(
        profile(),
        manifest_digest=manifest(implementation_digest=digest("changed").value).digest,
    )
    with pytest.raises(ProviderProfileConflictError, match="manifest changed"):
        await ProbeProviderHandler(repository, registry).execute(
            ProbeProviderCommand(
                "probe-drift",
                scope("provider.profile.probe"),
                PROFILE_ID,
                repository.current.version,
                repository.current.snapshot_digest,
                NOW,
            )
        )
    assert adapter.calls == 0

    repository.current = None
    with pytest.raises(ProviderProfileValidationError, match="not found"):
        await ProbeProviderHandler(repository, registry).execute(
            ProbeProviderCommand(
                "probe-missing",
                scope("provider.profile.probe"),
                PROFILE_ID,
                profile().version,
                profile().snapshot_digest,
                NOW,
            )
        )
    with pytest.raises(ProviderProfileValidationError, match="not found"):
        await GetProviderProfileHandler(repository).execute(
            GetProviderProfileQuery(scope("provider.profile.read"), PROFILE_ID, NOW)
        )
