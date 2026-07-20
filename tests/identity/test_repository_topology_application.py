"""ID-003 topology discovery and link confirmation application tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Self

import pytest

if TYPE_CHECKING:
    from types import TracebackType

from agentmemory.identity.application.commands.confirm_repository_link import (
    ConfirmRepositoryLinkCommand,
    ConfirmRepositoryLinkHandler,
)
from agentmemory.identity.application.queries.discover_repository_topology import (
    DiscoverRepositoryTopologyHandler,
    DiscoverRepositoryTopologyQuery,
)
from agentmemory.identity.domain.errors import (
    IdentityAuthorizationError,
    IdentityConflictError,
    IdentityValidationError,
)
from agentmemory.identity.domain.topology import (
    ProjectRepositoryLink,
    RepositoryRelationType,
    RepositoryTopologyCandidate,
    TopologyConfirmationSource,
    TopologyEndpointType,
    TopologyEvidence,
    TopologyEvidenceKind,
    TopologyEvidenceStrength,
)
from agentmemory.identity.domain.value_objects import Fingerprint, StableId

BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000004")
OTHER_BRAIN_ID = StableId("018f0000-0000-7000-8000-000000000005")
ACTOR_ID = StableId("018f0000-0000-7000-8000-000000000002")
GRANT_ID = StableId("018f0000-0000-7000-8000-000000000003")
PROJECT_ID = StableId("018f0000-0000-7000-8000-000000000010")
REPOSITORY_ID = StableId("018f0000-0000-7000-8000-000000000020")
CHILD_ID = StableId("018f0000-0000-7000-8000-000000000021")
LINK_ID = StableId("018f0000-0000-7000-8000-000000000040")
EVENT_ID = StableId("018f0000-0000-7000-8000-000000000041")


def _string_list() -> list[str]:
    return []


def _candidate(
    *,
    brain_id: StableId = BRAIN_ID,
    relation: RepositoryRelationType = RepositoryRelationType.CONTAINS_REPOSITORY,
    evidence_seed: bytes = b"nested",
) -> RepositoryTopologyCandidate:
    evidence = TopologyEvidence(
        Fingerprint.from_bytes(evidence_seed),
        TopologyEvidenceKind.NESTED_GIT_MARKER,
        TopologyEvidenceStrength.DETERMINISTIC_VCS,
    )
    return RepositoryTopologyCandidate(
        brain_id,
        TopologyEndpointType.REPOSITORY,
        REPOSITORY_ID,
        relation,
        TopologyEndpointType.REPOSITORY,
        CHILD_ID,
        None,
        (evidence,),
    )


@dataclass(slots=True)
class _Authorization:
    allowed: bool = True
    calls: list[str] = field(default_factory=_string_list)

    async def authorize_resolution(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        self.calls.append(f"auth:{brain_id.value}:{actor_id.value}:{grant_id.value}")
        if not self.allowed:
            raise IdentityAuthorizationError

    async def authorize(
        self,
        brain_id: StableId,
        actor_id: StableId,
        grant_id: StableId,
    ) -> None:
        await self.authorize_resolution(brain_id, actor_id, grant_id)


@dataclass(slots=True)
class _TopologyReader:
    calls: list[str] = field(default_factory=_string_list)

    async def require_candidate(self, candidate: RepositoryTopologyCandidate) -> None:
        self.calls.append(f"candidate:{candidate.relation_type.value}")


@dataclass(slots=True)
class _IdentityGenerator:
    values: list[StableId] = field(default_factory=lambda: [LINK_ID, EVENT_ID])

    def new(self) -> StableId:
        return self.values.pop(0)


@dataclass(slots=True)
class _Clock:
    instant: datetime = datetime(2026, 7, 20, 12, tzinfo=UTC)

    def now(self) -> datetime:
        return self.instant


@dataclass(slots=True)
class _LinkRepository:
    operation: tuple[str, ProjectRepositoryLink] | None = None
    active: ProjectRepositoryLink | None = None
    appended: ProjectRepositoryLink | None = None
    calls: list[str] = field(default_factory=_string_list)

    async def require_candidate(self, candidate: RepositoryTopologyCandidate) -> None:
        del candidate
        self.calls.append("require")

    async def find_operation(
        self,
        brain_id: StableId,
        operation_id: str,
    ) -> tuple[str, ProjectRepositoryLink] | None:
        del brain_id, operation_id
        self.calls.append("operation")
        return self.operation

    async def find_link(
        self,
        brain_id: StableId,
        link_id: StableId,
    ) -> ProjectRepositoryLink | None:
        del brain_id
        self.calls.append("link")
        return self.active if self.active is not None and self.active.link_id == link_id else None

    async def find_active(
        self,
        candidate: RepositoryTopologyCandidate,
    ) -> ProjectRepositoryLink | None:
        del candidate
        self.calls.append("active")
        return self.active

    async def append(
        self,
        request_digest: str,
        event_id: StableId,
        aggregate: ProjectRepositoryLink,
        *,
        expected_previous_version: int | None,
    ) -> None:
        del request_digest, event_id, expected_previous_version
        self.calls.append("append")
        self.appended = aggregate


@dataclass(slots=True)
class _UnitOfWork:
    authorization: _Authorization
    links: _LinkRepository
    committed: bool = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        del exc_type, exc, traceback
        return None

    async def commit(self) -> None:
        self.committed = True


@dataclass(slots=True)
class _UnitOfWorkFactory:
    value: _UnitOfWork

    def __call__(self) -> _UnitOfWork:
        return self.value


@pytest.mark.asyncio
async def test_discovery_authorizes_then_validates_and_deduplicates_candidates() -> None:
    authorization = _Authorization()
    reader = _TopologyReader()
    handler = DiscoverRepositoryTopologyHandler(authorization, reader)
    first = _candidate(evidence_seed=b"one")
    duplicate = _candidate(evidence_seed=b"two")
    result = await handler.execute(
        DiscoverRepositoryTopologyQuery(
            "discover-1",
            BRAIN_ID,
            ACTOR_ID,
            GRANT_ID,
            (duplicate, first),
        )
    )
    assert len(result.candidates) == 1
    assert len(result.candidates[0].evidence) == 2
    assert result.explanation == ("candidate:contains_repository",)
    assert authorization.calls
    assert len(reader.calls) == 2


@pytest.mark.asyncio
async def test_discovery_denies_before_candidate_repository_access() -> None:
    reader = _TopologyReader()
    handler = DiscoverRepositoryTopologyHandler(_Authorization(allowed=False), reader)
    with pytest.raises(IdentityAuthorizationError):
        await handler.execute(
            DiscoverRepositoryTopologyQuery(
                "discover-1",
                BRAIN_ID,
                ACTOR_ID,
                GRANT_ID,
                (_candidate(),),
            )
        )
    assert reader.calls == []


@pytest.mark.asyncio
async def test_discovery_rejects_cross_brain_observation_before_authorization() -> None:
    authorization = _Authorization()
    with pytest.raises(IdentityConflictError):
        await DiscoverRepositoryTopologyHandler(authorization, _TopologyReader()).execute(
            DiscoverRepositoryTopologyQuery(
                "discover-1",
                BRAIN_ID,
                ACTOR_ID,
                GRANT_ID,
                (_candidate(brain_id=OTHER_BRAIN_ID),),
            )
        )
    assert authorization.calls == []


def _command(
    *,
    operation_id: str = "confirm-1",
    link_id: StableId | None = None,
    expected_version: int | None = None,
    reason: str | None = None,
) -> ConfirmRepositoryLinkCommand:
    return ConfirmRepositoryLinkCommand(
        operation_id,
        BRAIN_ID,
        ACTOR_ID,
        GRANT_ID,
        _candidate(),
        TopologyConfirmationSource.USER,
        link_id,
        expected_version,
        reason,
    )


@pytest.mark.asyncio
async def test_confirm_link_is_authorized_transactional_and_idempotent() -> None:
    authorization = _Authorization()
    links = _LinkRepository()
    unit_of_work = _UnitOfWork(authorization, links)
    handler = ConfirmRepositoryLinkHandler(
        _UnitOfWorkFactory(unit_of_work),
        _IdentityGenerator(),
        _Clock(),
    )
    result = await handler.execute(_command())
    assert result.link_id == LINK_ID
    assert result.subject_id == REPOSITORY_ID
    assert result.target_id == CHILD_ID
    assert result.version == 1
    assert links.calls == ["require", "operation", "active", "append"]
    assert unit_of_work.committed

    links.operation = (_command().request_digest(), result)
    replay = await ConfirmRepositoryLinkHandler(
        _UnitOfWorkFactory(_UnitOfWork(authorization, links)),
        _IdentityGenerator([]),
        _Clock(),
    ).execute(_command())
    assert replay == result


@pytest.mark.asyncio
async def test_idempotency_conflict_and_duplicate_effective_link_fail_closed() -> None:
    existing, _ = ProjectRepositoryLink.confirm(
        LINK_ID,
        _candidate(),
        _command().confirmation(1),
    )
    links = _LinkRepository(operation=("0" * 64, existing))
    handler = ConfirmRepositoryLinkHandler(
        _UnitOfWorkFactory(_UnitOfWork(_Authorization(), links)),
        _IdentityGenerator(),
        _Clock(),
    )
    with pytest.raises(IdentityConflictError):
        await handler.execute(_command())

    links.operation = None
    links.active = existing
    with pytest.raises(IdentityConflictError):
        await handler.execute(_command(operation_id="confirm-2"))


@pytest.mark.asyncio
async def test_confirm_command_appends_user_correction_with_optimistic_version() -> None:
    original, _ = ProjectRepositoryLink.confirm(
        LINK_ID,
        _candidate(),
        _command().confirmation(1),
    )
    links = _LinkRepository(active=original)
    unit_of_work = _UnitOfWork(_Authorization(), links)
    handler = ConfirmRepositoryLinkHandler(
        _UnitOfWorkFactory(unit_of_work),
        _IdentityGenerator([EVENT_ID]),
        _Clock(),
    )
    result = await handler.execute(
        _command(
            operation_id="correct-1",
            link_id=LINK_ID,
            expected_version=1,
            reason="user_verified_relationship",
        )
    )
    assert result.version == 2
    assert len(result.history) == 2
    assert result.history[-1].correction_reason == "user_verified_relationship"
    assert unit_of_work.committed


@pytest.mark.asyncio
async def test_correction_requires_link_version_and_reason() -> None:
    with pytest.raises(IdentityConflictError):
        await ConfirmRepositoryLinkHandler(
            _UnitOfWorkFactory(_UnitOfWork(_Authorization(), _LinkRepository())),
            _IdentityGenerator(),
            _Clock(),
        ).execute(_command(link_id=LINK_ID))


def test_query_and_command_validate_bounds_before_access() -> None:
    with pytest.raises(IdentityValidationError, match="operation ID"):
        DiscoverRepositoryTopologyQuery(
            "bad operation",
            BRAIN_ID,
            ACTOR_ID,
            GRANT_ID,
            (),
        )
    with pytest.raises(IdentityValidationError, match="observation bound"):
        DiscoverRepositoryTopologyQuery(
            "discover-many",
            BRAIN_ID,
            ACTOR_ID,
            GRANT_ID,
            (_candidate(),) * 513,
        )
    with pytest.raises(IdentityValidationError, match="operation ID"):
        _command(operation_id="bad operation")
    with pytest.raises(IdentityConflictError):
        ConfirmRepositoryLinkCommand(
            "confirm-cross-brain",
            OTHER_BRAIN_ID,
            ACTOR_ID,
            GRANT_ID,
            _candidate(),
            TopologyConfirmationSource.USER,
        )
    with pytest.raises(IdentityValidationError, match="expected version"):
        ConfirmRepositoryLinkCommand(
            "correct-invalid-version",
            BRAIN_ID,
            ACTOR_ID,
            GRANT_ID,
            _candidate(),
            TopologyConfirmationSource.USER,
            LINK_ID,
            0,
            "invalid_version",
        )


@pytest.mark.asyncio
async def test_correction_of_missing_link_fails_before_identity_generation() -> None:
    handler = ConfirmRepositoryLinkHandler(
        _UnitOfWorkFactory(_UnitOfWork(_Authorization(), _LinkRepository())),
        _IdentityGenerator([]),
        _Clock(),
    )
    with pytest.raises(IdentityConflictError):
        await handler.execute(
            _command(
                operation_id="correct-missing",
                link_id=LINK_ID,
                expected_version=1,
                reason="missing_link",
            )
        )
