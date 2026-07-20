"""PF-002 deterministic projection-rebuild domain acceptance tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from agentmemory.operations.domain.errors import DomainValidationError
from agentmemory.operations.domain.projection_rebuild import (
    ProjectionRebuild,
    ProjectionRecord,
    ProjectionType,
    RebuildManifest,
    RebuildState,
    SourcePage,
    SourceRecord,
    StartProjectionRebuildCommand,
    canonical_json,
    derive_generation_id,
    derive_rebuild_key,
    projection_digest,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id
from tests.core.support import BRAIN_ID, GRANT_ID, NOW, OWNER_ID, digest


def _manifest() -> RebuildManifest:
    return RebuildManifest(
        application_build="1.2.3+abc",
        relational_schema="0002_pf002_projection_rebuild",
        graph_schema="0002_pf002_projection_schema",
        parser_version="tree-sitter-0.25.0",
        extractor_version="qwen-3.0@sha256:abc",
        provider_versions=("local:qwen-3.0@sha256:abc",),
        embedding_space="qwen3:4096:cosine:normalized:v1",
        implementation_fingerprint=digest("implementation"),
    )


def _record(stable_id: str, seed: str) -> ProjectionRecord:
    payload = canonical_json({"stable_id": stable_id, "text": seed})
    return ProjectionRecord(
        stable_id=stable_id,
        source_event_id=f"event-{stable_id}",
        source_sequence=1,
        source_digest=digest(f"source-{seed}"),
        content_digest=Sha256Digest.from_bytes(payload.encode()),
        payload_json=payload,
    )


def test_manifest_and_generation_identity_are_canonical_and_stable() -> None:
    manifest = _manifest()
    key = derive_rebuild_key(
        ProjectionType.GRAPH,
        Uuid7Id(BRAIN_ID),
        91,
        manifest.implementation_fingerprint,
    )
    assert key == derive_rebuild_key(
        ProjectionType.GRAPH,
        Uuid7Id(BRAIN_ID),
        91,
        manifest.implementation_fingerprint,
    )
    assert derive_generation_id(key, manifest.digest) == derive_generation_id(key, manifest.digest)
    assert key.value == "548285696ae3b90a077d7a3d75b79d35a1aba0e24e9622ae481a033f52861369"
    assert (
        derive_generation_id(key, manifest.digest).value
        == "6bf0276a8166656ffd27653b6b1d8427078c3e22c39205fdad54befc0bd31634"
    )
    assert manifest.digest.value == Sha256Digest.from_bytes(manifest.canonical_bytes()).value


def test_zero_watermark_has_a_stable_valid_identity() -> None:
    manifest = _manifest()
    key = derive_rebuild_key(
        ProjectionType.GRAPH,
        Uuid7Id(BRAIN_ID),
        0,
        manifest.implementation_fingerprint,
    )
    assert key.value == "462da08fc2fe9478ce649d7b9ffc7468d47f58069ec48587aa2bb976ff26a979"


def test_projection_digest_is_order_independent_and_duplicate_safe() -> None:
    first = _record("assertion-a", "one")
    second = _record("assertion-b", "two")
    assert projection_digest((first, second)) == projection_digest((second, first))
    assert (
        projection_digest((first, second)).value
        == "9a0597b55e39fb40de935ef721c87d3f992f60e2d675bda7bf970bd1087332ce"
    )
    with pytest.raises(DomainValidationError) as duplicate:
        projection_digest((first, first))
    assert str(duplicate.value) == "duplicate stable projection ID"


def test_canonical_json_rejects_noncanonical_and_nonobject_payloads() -> None:
    canonical = canonical_json({"z": 1, "a": [True, None]})
    assert canonical == '{"a":[true,null],"z":1}'
    assert json.loads(canonical) == {"a": [True, None], "z": 1}
    assert canonical_json({"text": "mémoire"}) == '{"text":"mémoire"}'
    with pytest.raises(DomainValidationError) as root_error:
        canonical_json(["not", "an", "object"])
    assert str(root_error.value) == "canonical JSON root must be an object"
    with pytest.raises(DomainValidationError, match="finite"):
        canonical_json({"value": float("nan")})


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (RebuildState.QUEUED, RebuildState.BUILDING),
        (RebuildState.BUILDING, RebuildState.PARTIAL),
        (RebuildState.PARTIAL, RebuildState.BUILDING),
        (RebuildState.BUILDING, RebuildState.VALIDATING),
        (RebuildState.VALIDATING, RebuildState.READY),
        (RebuildState.READY, RebuildState.ACTIVE),
    ],
)
def test_rebuild_state_machine_allows_governed_path(
    current: RebuildState,
    target: RebuildState,
) -> None:
    current.require_transition(target)


def test_rebuild_state_machine_forbids_activation_before_validation() -> None:
    with pytest.raises(DomainValidationError, match="transition"):
        RebuildState.BUILDING.require_transition(RebuildState.ACTIVE)


def test_manifest_rejects_ambiguous_or_unbounded_pins() -> None:
    manifest = _manifest()
    with pytest.raises(DomainValidationError):
        replace(manifest, application_build="")
    with pytest.raises(DomainValidationError):
        replace(manifest, application_build="x" * 257)
    with pytest.raises(DomainValidationError):
        replace(manifest, provider_versions=())
    with pytest.raises(DomainValidationError):
        replace(manifest, provider_versions=("z", "a"))
    with pytest.raises(DomainValidationError):
        replace(manifest, provider_versions=("a", "a"))
    with pytest.raises(DomainValidationError):
        replace(manifest, provider_versions=("",))


def test_projection_record_rejects_each_invalid_identity_and_content_form() -> None:
    valid = _record("assertion-a", "one")
    with pytest.raises(DomainValidationError):
        replace(valid, stable_id="")
    with pytest.raises(DomainValidationError):
        replace(valid, source_event_id="")
    with pytest.raises(DomainValidationError):
        replace(valid, source_sequence=0)
    with pytest.raises(DomainValidationError):
        replace(valid, payload_json="{")
    with pytest.raises(DomainValidationError):
        replace(valid, payload_json='{"text": "one"}')
    with pytest.raises(DomainValidationError):
        replace(valid, content_digest=digest("wrong"))


def test_source_page_command_and_rebuild_reject_invalid_progress() -> None:
    record = _record("assertion-a", "one")
    source = SourceRecord(record, "event", digest("target"))
    with pytest.raises(DomainValidationError, match="target type"):
        replace(source, target_type="")
    with pytest.raises(DomainValidationError, match="dependency"):
        replace(source, missing_dependency="")
    with pytest.raises(DomainValidationError, match="cursor"):
        SourcePage((), -1, complete=False)

    command = StartProjectionRebuildCommand(
        "operation-1",
        Uuid7Id(BRAIN_ID),
        Uuid7Id(OWNER_ID),
        Uuid7Id(GRANT_ID),
        ProjectionType.GRAPH,
        _manifest(),
    )
    with pytest.raises(DomainValidationError, match="operation ID"):
        replace(command, operation_id="")
    with pytest.raises(DomainValidationError, match="watermark"):
        replace(command, requested_watermark=-1)

    rebuild = ProjectionRebuild(
        command.operation_id,
        command.brain_id,
        command.actor_id,
        command.grant_id,
        command.projection_type,
        1,
        0,
        digest("rebuild-key"),
        digest("generation"),
        command.manifest,
        RebuildState.QUEUED,
        None,
        0,
        0,
        None,
        None,
        NOW,
        NOW,
    )
    with pytest.raises(DomainValidationError, match="progress"):
        replace(rebuild, cursor=2)
    with pytest.raises(DomainValidationError, match="counters"):
        replace(rebuild, record_count=-1)


def test_canonical_json_rejects_invalid_keys_values_and_negative_watermarks() -> None:
    with pytest.raises(DomainValidationError, match="keys"):
        canonical_json({1: "invalid"})
    with pytest.raises(DomainValidationError, match="represented"):
        canonical_json({"invalid": object()})
    with pytest.raises(DomainValidationError, match="watermark"):
        derive_rebuild_key(
            ProjectionType.GRAPH,
            Uuid7Id(BRAIN_ID),
            -1,
            digest("implementation"),
        )
