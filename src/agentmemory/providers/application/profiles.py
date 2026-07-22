"""PRO-001 provider-profile creation, live probe, activation, and query use cases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING

from agentmemory.identity.domain.retrieval_scope import RetrievalRole
from agentmemory.providers.domain.errors import (
    ProviderProfileAuthorizationError,
    ProviderProfileConflictError,
    ProviderProfileValidationError,
)
from agentmemory.providers.domain.profiles import ProviderProbeEvidence

if TYPE_CHECKING:
    from datetime import datetime

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.providers.domain.profile_ports import (
        ProviderAdapterRegistry,
        ProviderProfileIdentityGenerator,
        ProviderProfileRepository,
    )
    from agentmemory.providers.domain.profiles import ProviderProfile, ProviderProfileConfiguration

_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_PROFILE_ID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_WRITE_ROLES = frozenset({RetrievalRole.OWNER, RetrievalRole.ADMIN})
_ERR_REQUEST = "provider profile request is invalid"
_ERR_ACTION = "provider profile action is not authorized"
_ERR_NOT_FOUND = "provider profile was not found"
_ERR_MANIFEST = "provider adapter manifest changed"
_ERR_PRECONDITION = "provider profile precondition failed"


@dataclass(frozen=True, slots=True)
class CreateProviderProfileCommand:
    """Create one manifest-bound draft without receiving credential values."""

    operation_id: str
    scope: AuthorizedScope
    configuration: ProviderProfileConfiguration
    created_at: datetime

    def __post_init__(self) -> None:
        """Require one stable idempotency coordinate."""
        if _OPERATION.fullmatch(self.operation_id) is None or not _is_utc(self.created_at):
            raise ProviderProfileValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class ProbeProviderCommand:
    """Run one live probe and activate the exact current profile revision."""

    operation_id: str
    scope: AuthorizedScope
    profile_id: str
    expected_version: int
    expected_snapshot_digest: str
    probed_at: datetime

    def __post_init__(self) -> None:
        """Require stable operation and profile identities."""
        _validate_operation_profile(self.operation_id, self.profile_id)
        if (
            not 1 <= self.expected_version <= 2**31 - 1
            or _DIGEST.fullmatch(self.expected_snapshot_digest) is None
            or not _is_utc(self.probed_at)
        ):
            raise ProviderProfileValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class GetProviderProfileQuery:
    """Read one content-free profile snapshot under current authorization."""

    scope: AuthorizedScope
    profile_id: str
    requested_at: datetime

    def __post_init__(self) -> None:
        """Require one canonical UUIDv7 profile identity."""
        if _PROFILE_ID.fullmatch(self.profile_id) is None or not _is_utc(self.requested_at):
            raise ProviderProfileValidationError(_ERR_REQUEST)


@dataclass(frozen=True, slots=True)
class CreateProviderProfileHandler:
    """Validate one configuration against its certified manifest before storage."""

    repository: ProviderProfileRepository
    adapters: ProviderAdapterRegistry
    identities: ProviderProfileIdentityGenerator

    async def execute(self, command: CreateProviderProfileCommand) -> ProviderProfile:
        """Create or replay one draft with no network or secret resolution."""
        _authorize(command.scope, "provider.profile.create")
        if command.configuration.brain_id != command.scope.brain_id.value:
            raise ProviderProfileValidationError(_ERR_REQUEST)
        replay = await self.repository.find_operation(
            command.scope,
            command.operation_id,
            "create",
            None,
            command.created_at,
        )
        if replay is not None:
            if replay.configuration.digest != command.configuration.digest:
                raise ProviderProfileConflictError(_ERR_REQUEST)
            return replay
        adapter = self.adapters.get(command.configuration.adapter_id)
        manifest = adapter.manifest
        manifest.validate_configuration(command.configuration)
        return await self.repository.create(
            command.scope,
            command.operation_id,
            self.identities.new(),
            command.configuration,
            manifest.digest,
            command.created_at,
        )


@dataclass(frozen=True, slots=True)
class ProbeProviderHandler:
    """Revalidate manifest, run live conformance, and activate atomically."""

    repository: ProviderProfileRepository
    adapters: ProviderAdapterRegistry

    async def execute(self, command: ProbeProviderCommand) -> ProviderProfile:
        """Never activate on a claim-only manifest or drifted model result."""
        _authorize(command.scope, "provider.profile.probe")
        replay = await self.repository.find_operation(
            command.scope,
            command.operation_id,
            "probe",
            command.profile_id,
            command.probed_at,
        )
        if replay is not None:
            return replay
        profile = await self.repository.get(command.scope, command.profile_id, command.probed_at)
        if profile is None:
            raise ProviderProfileValidationError(_ERR_NOT_FOUND)
        if (
            profile.version != command.expected_version
            or profile.snapshot_digest != command.expected_snapshot_digest
        ):
            raise ProviderProfileConflictError(_ERR_PRECONDITION)
        adapter = self.adapters.get(profile.configuration.adapter_id)
        manifest = adapter.manifest
        if manifest.digest != profile.manifest_digest:
            raise ProviderProfileConflictError(_ERR_MANIFEST)
        manifest.validate_configuration(profile.configuration)
        result = await adapter.probe(profile)
        evidence = ProviderProbeEvidence.create(
            profile.profile_id,
            profile.manifest_digest,
            result,
            command.probed_at,
        )
        # Domain activation validates exact model, purpose, and revision behavior before a write.
        profile.activate(evidence)
        return await self.repository.activate(
            command.scope,
            command.operation_id,
            profile.version,
            evidence,
        )


@dataclass(frozen=True, slots=True)
class GetProviderProfileHandler:
    """Load one profile only after exact read authorization."""

    repository: ProviderProfileRepository

    async def execute(self, query: GetProviderProfileQuery) -> ProviderProfile:
        """Return one currently authorized content-free profile snapshot."""
        _authorize(query.scope, "provider.profile.read")
        profile = await self.repository.get(query.scope, query.profile_id, query.requested_at)
        if profile is None:
            raise ProviderProfileValidationError(_ERR_NOT_FOUND)
        return profile


def _authorize(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action or scope.role not in _WRITE_ROLES:
        raise ProviderProfileAuthorizationError(_ERR_ACTION)


def _validate_operation_profile(operation_id: str, profile_id: str) -> None:
    if _OPERATION.fullmatch(operation_id) is None or _PROFILE_ID.fullmatch(profile_id) is None:
        raise ProviderProfileValidationError(_ERR_REQUEST)


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timedelta(0)
