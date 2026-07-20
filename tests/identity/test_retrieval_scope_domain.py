"""ID-004 immutable authorized retrieval-scope domain tests."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable

from agentmemory.identity.domain.errors import IdentityValidationError
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizationSnapshot,
    AuthorizedScope,
    Classification,
    ProjectBinding,
    RelatedProject,
    RetrievalGrant,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId

BRAIN = StableId("018f0000-0000-7000-8000-000000000001")
ACTOR = StableId("018f0000-0000-7000-8000-000000000002")
PROJECT = StableId("018f0000-0000-7000-8000-000000000010")
REPOSITORY = StableId("018f0000-0000-7000-8000-000000000020")
CHECKOUT = StableId("018f0000-0000-7000-8000-000000000030")


def _scope(*, grant_version: int = 7) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=BRAIN,
        principal_id=ACTOR,
        role=RetrievalRole.READER,
        mode=RetrievalScopeMode.CURRENT,
        members=(ScopeMember(PROJECT, (REPOSITORY,), (CHECKOUT,), 1_000_000),),
        classification_ceiling=Classification.CONFIDENTIAL,
        temporal_scope=TemporalScope(10, 20),
        grant_version=grant_version,
        policy_version=3,
        security_epoch=5,
        action="memory.recall",
        purpose="interactive_recall",
    )


def test_authorized_scope_is_canonical_immutable_and_cache_versioned() -> None:
    scope = _scope()
    same = _scope()
    revoked = _scope(grant_version=8)

    assert scope == same
    assert scope.scope_fingerprint == same.scope_fingerprint
    assert scope.cache_key == same.cache_key
    assert revoked.scope_fingerprint != scope.scope_fingerprint
    assert revoked.cache_key != scope.cache_key
    assert "current" in scope.cache_key
    with pytest.raises(AttributeError):
        scope.members = ()  # type: ignore[misc]


@pytest.mark.parametrize("value", [0, -1])
def test_scope_rejects_non_positive_security_versions(value: int) -> None:
    with pytest.raises(IdentityValidationError):
        AuthorizedScope.create(
            brain_id=BRAIN,
            principal_id=ACTOR,
            role=RetrievalRole.OWNER,
            mode=RetrievalScopeMode.CURRENT,
            members=(ScopeMember(PROJECT, (REPOSITORY,), (), 1_000_000),),
            classification_ceiling=Classification.LOCAL_ONLY,
            temporal_scope=TemporalScope(None, None),
            grant_version=value,
            policy_version=1,
            security_epoch=1,
            action="memory.recall",
            purpose="interactive_recall",
        )


def test_scope_member_requires_repository_and_checkout_consistency() -> None:
    with pytest.raises(IdentityValidationError):
        ScopeMember(PROJECT, (), (CHECKOUT,), 0)


@pytest.mark.parametrize(
    "temporal",
    [TemporalScope(0, None), TemporalScope(None, 1)],
)
def test_temporal_scope_accepts_valid_open_intervals(temporal: TemporalScope) -> None:
    assert temporal.valid_from is not None or temporal.valid_to is not None


@pytest.mark.parametrize("values", [(-1, None), (None, 0), (20, 20), (21, 20)])
def test_temporal_scope_rejects_invalid_intervals(
    values: tuple[int | None, int | None],
) -> None:
    with pytest.raises(IdentityValidationError):
        TemporalScope(*values)


@pytest.mark.parametrize(
    "member",
    [
        lambda: ScopeMember(PROJECT, (REPOSITORY,), (), -1),
        lambda: ScopeMember(PROJECT, (REPOSITORY,), (), 1_000_001),
        lambda: ScopeMember(PROJECT, (REPOSITORY, REPOSITORY), (), 0),
        lambda: ScopeMember(PROJECT, (REPOSITORY,), (CHECKOUT, CHECKOUT), 0),
    ],
)
def test_scope_member_rejects_noncanonical_values(
    member: Callable[[], ScopeMember],
) -> None:
    with pytest.raises(IdentityValidationError):
        member()


def test_grant_binding_snapshot_and_related_project_invariants() -> None:
    with pytest.raises(IdentityValidationError):
        RetrievalGrant(
            StableId("018f0000-0000-7000-8000-000000000003"),
            RetrievalRole.READER,
            None,
            REPOSITORY,
            1,
        )
    with pytest.raises(IdentityValidationError):
        RetrievalGrant(
            StableId("018f0000-0000-7000-8000-000000000003"),
            RetrievalRole.READER,
            PROJECT,
            REPOSITORY,
            0,
        )
    with pytest.raises(IdentityValidationError):
        ProjectBinding(BRAIN, PROJECT, (), ())
    grant = RetrievalGrant(
        StableId("018f0000-0000-7000-8000-000000000003"),
        RetrievalRole.READER,
        None,
        None,
        1,
    )
    with pytest.raises(IdentityValidationError):
        AuthorizationSnapshot(BRAIN, ACTOR, (), (), Classification.LOCAL_ONLY, 1, 1)
    with pytest.raises(IdentityValidationError):
        AuthorizationSnapshot(
            BRAIN,
            ACTOR,
            (grant,),
            (
                ProjectBinding(
                    StableId("018f0000-0000-7000-8000-000000000099"),
                    PROJECT,
                    (REPOSITORY,),
                    (),
                ),
            ),
            Classification.LOCAL_ONLY,
            1,
            1,
        )
    with pytest.raises(IdentityValidationError):
        RelatedProject(PROJECT, 0, 1, "repository_topology")


def test_authorized_scope_rejects_empty_duplicate_and_invalid_policy_tokens() -> None:
    with pytest.raises(IdentityValidationError):
        AuthorizedScope.create(
            brain_id=BRAIN,
            principal_id=ACTOR,
            role=RetrievalRole.READER,
            mode=RetrievalScopeMode.SELECTED,
            members=(),
            classification_ceiling=Classification.LOCAL_ONLY,
            temporal_scope=TemporalScope(None, None),
            grant_version=1,
            policy_version=1,
            security_epoch=1,
            action="memory.recall",
            purpose="interactive_recall",
        )
    member = ScopeMember(PROJECT, (REPOSITORY,), ())
    with pytest.raises(IdentityValidationError):
        AuthorizedScope.create(
            brain_id=BRAIN,
            principal_id=ACTOR,
            role=RetrievalRole.READER,
            mode=RetrievalScopeMode.SELECTED,
            members=(member, member),
            classification_ceiling=Classification.LOCAL_ONLY,
            temporal_scope=TemporalScope(None, None),
            grant_version=1,
            policy_version=1,
            security_epoch=1,
            action="memory.recall",
            purpose="interactive_recall",
        )
    with pytest.raises(IdentityValidationError):
        AuthorizedScope.create(
            brain_id=BRAIN,
            principal_id=ACTOR,
            role=RetrievalRole.READER,
            mode=RetrievalScopeMode.SELECTED,
            members=(member,),
            classification_ceiling=Classification.LOCAL_ONLY,
            temporal_scope=TemporalScope(None, None),
            grant_version=1,
            policy_version=1,
            security_epoch=1,
            action="NOT VALID",
            purpose="interactive_recall",
        )
