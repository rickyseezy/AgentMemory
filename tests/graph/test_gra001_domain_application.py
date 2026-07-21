"""GRA-001 graph schema, identity, scope, and application TDD tests."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta, timezone
from typing import TYPE_CHECKING, cast

import pytest

from agentmemory.graph.application.project_entity import (
    GetGraphEntityHandler,
    GetGraphEntityQuery,
    ProjectGraphEntityCommand,
    ProjectGraphEntityHandler,
)
from agentmemory.graph.domain.errors import GraphAuthorizationError, GraphValidationError
from agentmemory.graph.domain.models import (
    GraphClassification,
    GraphEntity,
    GraphEntityType,
    GraphRelationship,
    GraphRelationshipType,
    GraphWriteResult,
    derive_revision_id,
    stable_graph_id,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId

if TYPE_CHECKING:
    from agentmemory.graph.domain.ports import AuthorizedGraphQuery, GraphProjectionWriter

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN_ID = "018f0000-0000-7000-8000-000000000004"
OTHER_BRAIN_ID = "018f0000-0000-7000-8000-000000000005"
PRINCIPAL_ID = "018f0000-0000-7000-8000-000000000002"
PROJECT_ID = "018f0000-0000-7000-8000-000000000010"
OTHER_PROJECT_ID = "018f0000-0000-7000-8000-000000000011"
REPOSITORY_ID = "018f0000-0000-7000-8000-000000000020"
ENTITY_ID = "018f0000-0000-7000-8000-000000000030"
FINGERPRINT = "a" * 64


def test_stable_and_revision_ids_are_canonical_and_deterministic() -> None:
    assert stable_graph_id(ENTITY_ID) == ENTITY_ID
    first = derive_revision_id(ENTITY_ID, FINGERPRINT)
    assert first == derive_revision_id(ENTITY_ID, FINGERPRINT)
    assert len(first) == 64
    assert first != derive_revision_id(ENTITY_ID, "b" * 64)
    assert first == "d7b51b7e896100d382b118705c6e57aa1f7c16936a990ee2d649e1a312b5d618"
    for invalid in ("", "not-a-uuid", ENTITY_ID.upper()):
        with pytest.raises(GraphValidationError):
            stable_graph_id(invalid)
    for invalid in ("", "0" * 64, "A" * 64):
        with pytest.raises(GraphValidationError):
            derive_revision_id(ENTITY_ID, invalid)


def test_graph_entity_requires_complete_typed_brain_scoped_schema() -> None:
    entity = _entity()
    assert entity.revision_id == derive_revision_id(ENTITY_ID, FINGERPRINT)
    assert entity.entity_type is GraphEntityType.FILE
    for changes in (
        {"brain_id": "missing"},
        {"id": "missing"},
        {"schema_version": 0},
        {"content_fingerprint": "0" * 64},
        {"revision_id": "b" * 64},
        {"created_at": NOW + timedelta(seconds=1)},
        {"recorded_to": NOW - timedelta(seconds=1)},
        {"project_id": None},
        {"repository_id": None},
        {"classification": cast("GraphClassification", "internal")},
        {"entity_type": cast("GraphEntityType", "File")},
        {"schema_version": True},
        {"schema_version": 2_147_483_648},
        {"created_at": NOW.replace(tzinfo=None)},
        {"recorded_from": NOW.astimezone(timezone(timedelta(hours=4)))},
    ):
        with pytest.raises(GraphValidationError) as raised:
            replace(entity, **changes)
        assert str(raised.value)
    with pytest.raises(GraphValidationError, match="project scope is required"):
        replace(entity, project_id=None)
    with pytest.raises(GraphValidationError, match="recorded time is invalid"):
        replace(entity, created_at=NOW + timedelta(seconds=1))


def test_entity_coordinates_cover_global_project_repository_and_checkout_rules() -> None:
    global_entity = _entity_with_coordinates(GraphEntityType.BRAIN, BRAIN_ID, None, None, None)
    assert global_entity.project_id is None
    with pytest.raises(GraphValidationError, match="global graph entity scope"):
        replace(global_entity, project_id=PROJECT_ID)
    with pytest.raises(GraphValidationError, match="global graph entity scope"):
        replace(global_entity, repository_id=REPOSITORY_ID)
    with pytest.raises(GraphValidationError, match="global graph entity scope"):
        replace(global_entity, checkout_id=ENTITY_ID)

    project = _entity_with_coordinates(GraphEntityType.PROJECT, PROJECT_ID, PROJECT_ID, None, None)
    assert project.project_id == project.id
    with pytest.raises(GraphValidationError, match="Project graph entity scope"):
        replace(project, project_id=OTHER_PROJECT_ID)
    with pytest.raises(GraphValidationError, match="Project graph entity scope"):
        replace(project, repository_id=REPOSITORY_ID)

    repository = _entity_with_coordinates(
        GraphEntityType.REPOSITORY, REPOSITORY_ID, PROJECT_ID, REPOSITORY_ID, None
    )
    assert repository.repository_id == repository.id
    with pytest.raises(GraphValidationError, match="Repository graph entity scope"):
        replace(repository, repository_id=ENTITY_ID)

    checkout_id = "018f0000-0000-7000-8000-000000000021"
    checkout = _entity_with_coordinates(
        GraphEntityType.CHECKOUT,
        checkout_id,
        PROJECT_ID,
        REPOSITORY_ID,
        checkout_id,
    )
    assert checkout.checkout_id == checkout.id
    with pytest.raises(GraphValidationError, match="Checkout graph entity scope"):
        replace(checkout, checkout_id=None)


def test_entity_document_round_trip_rejects_every_malformed_field_family() -> None:
    document = _entity().document()
    assert GraphEntity.from_document(document) == _entity()
    malformed_documents = (
        {key: value for key, value in document.items() if key != "id"},
        {**document, "id": 7},
        {**document, "entity_type": "Unknown"},
        {**document, "project_id": 7},
        {**document, "repository_id": 7},
        {**document, "checkout_id": 7},
        {**document, "schema_version": "1"},
        {**document, "created_at": "now"},
        {**document, "recorded_from": "now"},
        {**document, "recorded_to": "later"},
        {**document, "classification": "unknown"},
        {**document, "content_fingerprint": 7},
        {**document, "revision_id": 7},
    )
    for malformed in malformed_documents:
        with pytest.raises(GraphValidationError, match="document is invalid"):
            GraphEntity.from_document(malformed)


def test_graph_relationship_requires_stable_endpoints_and_complete_schema() -> None:
    relationship = GraphRelationship.create(
        relationship_id="018f0000-0000-7000-8000-000000000040",
        brain_id=BRAIN_ID,
        relationship_type=GraphRelationshipType.IMPORTS,
        subject_id=ENTITY_ID,
        object_id="018f0000-0000-7000-8000-000000000031",
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        schema_version=1,
        created_at=NOW,
        recorded_from=NOW,
        recorded_to=None,
        classification=GraphClassification.INTERNAL,
        content_fingerprint="c" * 64,
    )
    assert relationship.relationship_type is GraphRelationshipType.IMPORTS
    for changes in (
        {"subject_id": "missing"},
        {"object_id": relationship.subject_id},
        {"brain_id": "missing"},
        {"schema_version": 0},
        {"revision_id": "0" * 64},
        {"relationship_type": cast("GraphRelationshipType", "IMPORTS")},
        {"classification": cast("GraphClassification", "internal")},
        {"recorded_to": NOW},
    ):
        with pytest.raises(GraphValidationError) as raised:
            replace(relationship, **changes)
        assert str(raised.value)
    assert relationship.document()["relationship_type"] == "IMPORTS"


@pytest.mark.asyncio
async def test_application_opens_one_operation_scoped_repository() -> None:
    factory = _Factory()
    projected = await ProjectGraphEntityHandler(factory).execute(
        ProjectGraphEntityCommand(_scope("graph.project"), _entity())
    )
    loaded = await GetGraphEntityHandler(factory).execute(
        GetGraphEntityQuery(_scope("graph.read"), GraphEntityType.FILE, ENTITY_ID)
    )
    assert projected == GraphWriteResult(
        stable_id=ENTITY_ID,
        revision_id=_entity().revision_id,
        created=False,
    )
    assert loaded == _entity()
    assert factory.actions == ["graph.project", "graph.read"]


@pytest.mark.asyncio
async def test_application_rejects_cross_brain_project_and_wrong_action_before_adapter() -> None:
    factory = _Factory()
    handler = ProjectGraphEntityHandler(factory)
    for scope, entity in (
        (_scope("graph.project"), replace(_entity(), brain_id=OTHER_BRAIN_ID)),
        (_scope("graph.project"), replace(_entity(), project_id=OTHER_PROJECT_ID)),
        (_scope("graph.read"), _entity()),
    ):
        with pytest.raises(GraphAuthorizationError, match="outside authorized scope"):
            await handler.execute(ProjectGraphEntityCommand(scope, entity))
    assert factory.actions == []


def _entity() -> GraphEntity:
    return GraphEntity.create(
        entity_id=ENTITY_ID,
        brain_id=BRAIN_ID,
        entity_type=GraphEntityType.FILE,
        project_id=PROJECT_ID,
        repository_id=REPOSITORY_ID,
        checkout_id=None,
        schema_version=1,
        created_at=NOW,
        recorded_from=NOW,
        recorded_to=None,
        classification=GraphClassification.INTERNAL,
        content_fingerprint=FINGERPRINT,
    )


def _entity_with_coordinates(
    entity_type: GraphEntityType,
    entity_id: str,
    project_id: str | None,
    repository_id: str | None,
    checkout_id: str | None,
) -> GraphEntity:
    return GraphEntity.create(
        entity_id=entity_id,
        brain_id=BRAIN_ID,
        entity_type=entity_type,
        project_id=project_id,
        repository_id=repository_id,
        checkout_id=checkout_id,
        schema_version=1,
        created_at=NOW,
        recorded_from=NOW,
        recorded_to=None,
        classification=GraphClassification.INTERNAL,
        content_fingerprint=FINGERPRINT,
    )


def _scope(action: str) -> AuthorizedScope:
    return AuthorizedScope.create(
        brain_id=StableId(BRAIN_ID),
        principal_id=StableId(PRINCIPAL_ID),
        role=RetrievalRole.WORKER if action == "graph.project" else RetrievalRole.READER,
        mode=RetrievalScopeMode.SELECTED,
        members=(
            ScopeMember(
                StableId(PROJECT_ID),
                (StableId(REPOSITORY_ID),),
                (),
            ),
        ),
        classification_ceiling=Classification.INTERNAL,
        temporal_scope=TemporalScope(None, None),
        grant_version=1,
        policy_version=1,
        security_epoch=1,
        action=action,
        purpose="graph_projection" if action == "graph.project" else "graph_query",
    )


@dataclass
class _Repository:
    async def merge_entity(self, entity: GraphEntity) -> GraphWriteResult:
        return GraphWriteResult(
            stable_id=entity.id,
            revision_id=entity.revision_id,
            created=False,
        )

    async def get_entity(self, query: object) -> GraphEntity | None:
        del query
        return _entity()

    async def merge_relationship(self, relationship: GraphRelationship) -> GraphWriteResult:
        return GraphWriteResult(
            stable_id=relationship.id,
            revision_id=relationship.revision_id,
            created=False,
        )


@dataclass
class _Factory:
    actions: list[str] | None = None

    def __post_init__(self) -> None:
        if self.actions is None:
            self.actions = []

    def writer(self, scope: AuthorizedScope) -> GraphProjectionWriter:
        assert self.actions is not None
        self.actions.append(scope.action)
        return _Repository()

    def query(self, scope: AuthorizedScope) -> AuthorizedGraphQuery:
        assert self.actions is not None
        self.actions.append(scope.action)
        return _Repository()
