"""IDX-005 common topology schema and temporal invariant tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest

from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyBatch,
    ArtifactTopologyEvidence,
    ArtifactTopologyPluginKind,
    ArtifactTopologySnapshot,
    ArtifactTopologySourceArtifact,
    ReferenceSensitivity,
    TopologyCandidate,
    TopologyEntityKind,
    TopologyRelationCandidate,
    TopologyRelationKind,
    UnknownConstructReason,
    UnknownTopologyEvidence,
    normalize_environment_reference,
    safe_external_reference,
    stable_topology_entity_id,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN = "018f0000-0000-7000-8000-000000000001"
PROJECT = "018f0000-0000-7000-8000-000000000002"
REPOSITORY = "018f0000-0000-7000-8000-000000000003"
EVIDENCE_ID = "018f0000-0000-7000-8000-000000000004"


def test_common_candidate_and_relation_identities_bind_all_temporal_observations() -> None:
    evidence = _evidence()
    package = _candidate(evidence, "fastapi", version="0.116.0")
    relation = TopologyRelationCandidate(
        evidence,
        REPOSITORY,
        TopologyRelationKind.DEPENDS_ON,
        package.entity_id,
        "PRODUCTION",
        NOW,
        NOW + timedelta(days=1),
    )

    assert package.id != replace(package, version="0.117.0").id
    assert relation.id != replace(relation, environment_reference="STAGING").id
    assert relation.id != replace(relation, valid_from=NOW + timedelta(seconds=1)).id
    assert stable_topology_entity_id(TopologyEntityKind.PACKAGE, "fastapi@0.116.0") == (
        package.entity_id
    )
    assert package.entity_id == "b97b9e5f-c4b2-79b4-adec-9ec2308918f1"


def test_environment_references_are_normalized_names_and_never_values() -> None:
    reference = normalize_environment_reference(" user-api.token ")
    candidate = TopologyCandidate(
        _evidence(),
        stable_topology_entity_id(TopologyEntityKind.ENVIRONMENT_REFERENCE, reference),
        TopologyEntityKind.ENVIRONMENT_REFERENCE,
        reference,
        environment_reference=reference,
        sensitivity=ReferenceSensitivity.SECRET_REFERENCE,
    )

    assert reference == "USER_API_TOKEN"
    assert normalize_environment_reference("---User API---") == "USER_API"
    assert normalize_environment_reference("Mixed.Case") == "MIXED_CASE"
    assert candidate.name == candidate.environment_reference
    with pytest.raises(IndexingValidationError):
        replace(candidate, name="plaintext-secret")
    with pytest.raises(IndexingValidationError):
        replace(candidate, environment_reference="TOKEN=plaintext")
    with pytest.raises(IndexingValidationError):
        replace(candidate, sensitivity=None)


@pytest.mark.parametrize(
    "unsafe",
    [
        "https://user:password@example.invalid/image",
        "image:tag?token=secret",
        "image:tag#secret",
        "${SECRET_IMAGE}",
        "{{ values.image }}",
        "contains whitespace",
    ],
)
def test_external_references_reject_credentials_values_and_templates(unsafe: str) -> None:
    with pytest.raises(IndexingValidationError):
        safe_external_reference(unsafe)


def test_batch_requires_canonical_scope_coordinates_and_known_relation_endpoints() -> None:
    evidence = _evidence()
    package = _candidate(evidence, "fastapi", version="0.116.0")
    relation = TopologyRelationCandidate(
        evidence,
        REPOSITORY,
        TopologyRelationKind.DEPENDS_ON,
        package.entity_id,
        None,
        NOW,
    )
    batch = _batch(package, relation)

    assert batch.digest == replace(batch).digest
    with pytest.raises(IndexingValidationError):
        replace(batch, candidates=(package, package))
    with pytest.raises(IndexingValidationError):
        replace(batch, source_file_id="f" * 64)
    with pytest.raises(IndexingValidationError):
        replace(
            batch,
            relations=(
                replace(
                    relation,
                    object_entity_id="018f0000-0000-7000-8000-000000000099",
                ),
            ),
        )


def test_conflicting_environment_observations_remain_separate_temporal_relations() -> None:
    evidence = _evidence()
    image_a = _candidate(evidence, "app:1")
    image_b = _candidate(evidence, "app:2")
    production = TopologyRelationCandidate(
        evidence,
        REPOSITORY,
        TopologyRelationKind.DEPLOYED_AS,
        image_a.entity_id,
        "PRODUCTION",
        NOW,
    )
    staging = replace(
        production,
        object_entity_id=image_b.entity_id,
        environment_reference="STAGING",
    )
    snapshot = ArtifactTopologySnapshot(
        tuple(sorted((image_a, image_b), key=lambda item: item.id)),
        tuple(sorted((production, staging), key=lambda item: item.id)),
        (),
        NOW,
    )

    assert len(snapshot.relations) == 2
    assert {item.environment_reference for item in snapshot.relations} == {
        "PRODUCTION",
        "STAGING",
    }
    with pytest.raises(IndexingValidationError):
        ArtifactTopologySnapshot(snapshot.candidates, (production, production), (), NOW)


def test_unknown_evidence_is_digest_only_bounded_and_source_artifact_is_ephemeral() -> None:
    evidence = _evidence()
    unknown = UnknownTopologyEvidence(
        evidence,
        UnknownConstructReason.UNRESOLVED_TEMPLATE,
        "a" * 64,
        2,
        3,
    )
    artifact = ArtifactTopologySourceArtifact(evidence, "1" * 40, b"secret source")

    assert unknown.fragment_digest == "a" * 64
    assert not hasattr(unknown, "content")
    assert artifact.content == b"secret source"
    with pytest.raises(IndexingValidationError):
        replace(unknown, start_line=0)
    with pytest.raises(IndexingValidationError):
        replace(artifact, content=b"")
    with pytest.raises(IndexingValidationError):
        replace(artifact, commit_sha="mutable")


def test_models_reject_invalid_enum_boolean_time_path_and_identity_types() -> None:
    evidence = _evidence()
    package = _candidate(evidence, "fastapi")
    with pytest.raises(IndexingValidationError):
        replace(evidence, relative_path="../escape")
    with pytest.raises(IndexingValidationError):
        replace(evidence, relative_path="deploy\\escape.yaml")
    with pytest.raises(IndexingValidationError):
        replace(evidence, relative_path="deploy/escape\x00.yaml")
    with pytest.raises(IndexingValidationError):
        replace(evidence, observed_at=NOW.replace(tzinfo=None))
    with pytest.raises(IndexingValidationError):
        replace(evidence, observed_at=NOW.astimezone(timezone(timedelta(hours=4))))
    with pytest.raises(IndexingValidationError):
        replace(package, kind=cast("TopologyEntityKind", "package"))
    with pytest.raises(IndexingValidationError):
        replace(package, entity_id="018f0000-0000-4000-8000-000000000099")


def _evidence() -> ArtifactTopologyEvidence:
    return ArtifactTopologyEvidence(
        BRAIN,
        PROJECT,
        REPOSITORY,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        EVIDENCE_ID,
        "deploy/topology.yaml",
        "internal",
        NOW,
    )


def _candidate(
    evidence: ArtifactTopologyEvidence,
    name: str,
    *,
    version: str | None = None,
) -> TopologyCandidate:
    canonical = name if version is None else f"{name}@{version}"
    return TopologyCandidate(
        evidence,
        stable_topology_entity_id(TopologyEntityKind.PACKAGE, canonical),
        TopologyEntityKind.PACKAGE,
        name,
        version,
    )


def _batch(
    candidate: TopologyCandidate,
    relation: TopologyRelationCandidate,
) -> ArtifactTopologyBatch:
    return ArtifactTopologyBatch(
        ArtifactTopologyPluginKind.DEPENDENCY_MANIFEST,
        "v1.0.0",
        candidate.evidence.source_revision_context_id,
        candidate.evidence.source_file_id,
        "1" * 40,
        (candidate,),
        (relation,),
    )
