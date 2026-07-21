"""IDX-005 deterministic artifact parser fixture and adversarial tests."""

from __future__ import annotations

import json
from dataclasses import replace
from typing import TYPE_CHECKING

import pytest

from agentmemory.indexing.adapters.outbound.artifact_topology_plugins import (
    CiArtifactParser,
    ContainerArtifactParser,
    DependencyLockParser,
    DependencyManifestParser,
    EnvironmentTemplateParser,
    KubernetesArtifactParser,
    MessagingSchemaParser,
    TerraformArtifactParser,
    production_artifact_topology_parsers,
)
from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologySourceArtifact,
    ReferenceSensitivity,
    TopologyEntityKind,
    TopologyRelationKind,
    UnknownConstructReason,
)
from agentmemory.indexing.domain.errors import IndexingValidationError
from tests.indexing.test_idx005_artifact_topology_domain import (
    _evidence,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from agentmemory.indexing.domain.artifact_topology_ports import ArtifactParserPort


@pytest.mark.parametrize(
    ("path", "content", "expected_name", "expected_version"),
    [
        ("package.json", '{"dependencies":{"fastify":"^5.0.0"}}', "fastify", "^5.0.0"),
        (
            "pyproject.toml",
            '[project]\ndependencies=["fastapi>=0.116"]\n',
            "fastapi",
            ">=0.116",
        ),
        ("requirements.txt", "httpx==0.28.1\n", "httpx", "==0.28.1"),
        (
            "go.mod",
            "module example.test/app\nrequire example.test/lib v1.2.3\n",
            "example.test/lib",
            "v1.2.3",
        ),
        ("Cargo.toml", '[dependencies]\nserde="1.0.0"\n', "serde", "1.0.0"),
    ],
)
def test_dependency_manifest_fixture_matrix(
    path: str, content: str, expected_name: str, expected_version: str
) -> None:
    batch = DependencyManifestParser().parse(_artifact(path, content))

    assert [(item.name, item.version) for item in batch.candidates] == [
        (expected_name, expected_version)
    ]
    assert batch.relations[0].relation is TopologyRelationKind.DEPENDS_ON


@pytest.mark.parametrize(
    ("path", "content", "expected"),
    [
        (
            "package-lock.json",
            '{"lockfileVersion":3,"packages":{"node_modules/react":{"version":"19.1.0"}}}',
            ("react", "19.1.0"),
        ),
        (
            "pnpm-lock.yaml",
            "lockfileVersion: '9.0'\npackages:\n  react@19.1.0: {}\n",
            ("react", "19.1.0"),
        ),
        (
            "uv.lock",
            'version = 1\n[[package]]\nname = "httpx"\nversion = "0.28.1"\n',
            ("httpx", "0.28.1"),
        ),
        (
            "poetry.lock",
            '[[package]]\nname = "pydantic"\nversion = "2.11.7"\n',
            ("pydantic", "2.11.7"),
        ),
        (
            "Cargo.lock",
            '[[package]]\nname = "serde"\nversion = "1.0.0"\n',
            ("serde", "1.0.0"),
        ),
        (
            "go.sum",
            "example.test/lib v1.2.3 h1:checksum\nexample.test/lib v1.2.3/go.mod h1:other\n",
            ("example.test/lib", "v1.2.3"),
        ),
    ],
)
def test_lockfile_versions_resolve_exact_packages(
    path: str, content: str, expected: tuple[str, str]
) -> None:
    batch = DependencyLockParser().parse(_artifact(path, content))
    assert (batch.candidates[0].name, batch.candidates[0].version) == expected


def test_dockerfile_and_compose_parse_images_services_and_value_free_environment_names() -> None:
    dockerfile = ContainerArtifactParser().parse(
        _artifact(
            "Dockerfile",
            "FROM python:3.14-slim\nARG BUILD_TOKEN\nENV APP_MODE=production\n",
        )
    )
    compose = ContainerArtifactParser().parse(
        _artifact(
            "compose.yaml",
            "services:\n  api:\n    image: ghcr.io/acme/api:1.2.3\n"
            "    environment:\n      DATABASE_URL: postgresql://secret-host/db\n"
            "      API_TOKEN: plaintext-must-disappear\n    secrets:\n      - signing_key\n",
        )
    )
    serialized = json.dumps(
        [
            {
                "name": item.name,
                "version": item.version,
                "environment_reference": item.environment_reference,
            }
            for item in compose.candidates
        ]
    )

    assert any(item.name == "python:3.14-slim" for item in dockerfile.candidates)
    assert {
        item.environment_reference for item in dockerfile.candidates if item.environment_reference
    } == {
        "APP_MODE",
        "BUILD_TOKEN",
    }
    assert "postgresql://secret-host/db" not in serialized
    assert "plaintext-must-disappear" not in serialized
    assert any(item.name == "SIGNING_KEY" for item in compose.candidates)


def test_kubernetes_templates_overlays_secret_refs_and_raw_values_are_safe() -> None:
    deployment = KubernetesArtifactParser().parse(
        _artifact(
            "k8s/deployment.yaml",
            "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: user-api\n"
            "spec:\n  template:\n    spec:\n      containers:\n        - name: api\n"
            "          image: ghcr.io/acme/user-api:2\n          env:\n"
            "            - name: DATABASE_PASSWORD\n              value: raw-password\n"
            "            - name: SIGNING_KEY\n              valueFrom:\n"
            "                secretKeyRef:\n                  name: auth-secret\n"
            "                  key: signing\n",
        )
    )
    overlay = KubernetesArtifactParser().parse(
        _artifact(
            "k8s/overlays/prod/kustomization.yaml",
            "kind: Kustomization\nresources: [../../base]\n"
            "images:\n  - name: app\n    newName: ghcr.io/acme/app\n    newTag: '2'\n"
            "patches:\n  - target: {kind: Deployment}\n    patch: '{{ values.patch }}'\n",
        )
    )
    serialized = repr((deployment.candidates, deployment.relations))

    assert "raw-password" not in serialized
    assert any(
        item.sensitivity is ReferenceSensitivity.SECRET_REFERENCE
        for item in deployment.candidates
        if item.environment_reference
    )
    assert any(item.name == "ghcr.io/acme/app:2" for item in overlay.candidates)
    assert {item.reason for item in overlay.unknown_evidence} == {
        UnknownConstructReason.UNRESOLVED_TEMPLATE,
        UnknownConstructReason.UNRESOLVED_OVERLAY,
    }


def test_terraform_hcl_and_json_retain_resources_and_variable_names_only() -> None:
    hcl = TerraformArtifactParser().parse(
        _artifact(
            "infra/main.tf",
            'variable "db_password" { sensitive = true }\n'
            'resource "aws_db_instance" "main" { password = var.db_password }\n',
        )
    )
    json_batch = TerraformArtifactParser().parse(
        _artifact(
            "infra/main.tf.json",
            '{"resource":{"aws_s3_bucket":{"assets":{"bucket":"private-name"}}},'
            '"variable":{"region":{"default":"eu-west-1"}}}',
        )
    )

    assert any(item.name == "resource/aws_db_instance/main" for item in hcl.candidates)
    assert any(item.name == "DB_PASSWORD" for item in hcl.candidates)
    assert "private-name" not in repr(json_batch.candidates)
    assert "eu-west-1" not in repr(json_batch.candidates)


def test_ci_actions_images_and_secret_expressions_are_value_free() -> None:
    batch = CiArtifactParser().parse(
        _artifact(
            ".github/workflows/test.yml",
            "name: test\non: [push]\njobs:\n  build:\n    container:\n"
            "      image: python:3.14\n    env:\n      API_URL: https://private.invalid\n"
            "      RELEASE_TOKEN: ${{ secrets.RELEASE_TOKEN }}\n    steps:\n"
            "      - uses: actions/checkout@v4\n      - run: echo never-persist-command\n",
        )
    )

    assert any(item.name == "actions/checkout@v4" for item in batch.candidates)
    assert any(item.name == "RELEASE_TOKEN" for item in batch.candidates)
    assert "https://private.invalid" not in repr(batch.candidates)
    assert "never-persist-command" not in repr(batch.candidates)


def test_environment_template_discards_values_and_classifies_secret_names() -> None:
    batch = EnvironmentTemplateParser().parse(
        _artifact(
            ".env.example",
            "PUBLIC_URL=https://internal.invalid\nAPI_TOKEN=plaintext\nEMPTY=\n",
        )
    )

    assert {item.name for item in batch.candidates} == {"API_TOKEN", "EMPTY", "PUBLIC_URL"}
    assert "internal.invalid" not in repr(batch.candidates)
    assert "plaintext" not in repr(batch.candidates)
    token = next(item for item in batch.candidates if item.name == "API_TOKEN")
    assert token.sensitivity is ReferenceSensitivity.SECRET_REFERENCE


def test_asyncapi_versions_and_avro_produce_channels_schemas_and_direction() -> None:
    asyncapi = MessagingSchemaParser().parse(
        _artifact(
            "asyncapi.yaml",
            "asyncapi: 2.6.0\nchannels:\n  users.created:\n    publish:\n"
            "      message:\n        name: UserCreated\n    subscribe:\n"
            "      message:\n        $ref: '#/components/messages/UserCreated'\n",
        )
    )
    avro = MessagingSchemaParser().parse(
        _artifact("events/user-created.avsc", '{"type":"record","name":"UserCreated"}')
    )

    assert {item.relation for item in asyncapi.relations} >= {
        TopologyRelationKind.PRODUCES,
        TopologyRelationKind.CONSUMES,
        TopologyRelationKind.DEPENDS_ON,
    }
    assert any(item.kind is TopologyEntityKind.MESSAGE_CHANNEL for item in asyncapi.candidates)
    assert avro.candidates[0].kind is TopologyEntityKind.EVENT_SCHEMA


def test_parser_registry_has_exactly_one_owner_for_every_supported_fixture() -> None:
    paths = (
        "package.json",
        "package-lock.json",
        "Dockerfile",
        "compose.yaml",
        "k8s/deployment.yaml",
        "infra/main.tf",
        ".github/workflows/test.yml",
        ".env.example",
        "asyncapi.yaml",
        "events/user.avsc",
    )
    parsers = production_artifact_topology_parsers()
    assert all(sum(parser.supports(path) for parser in parsers) == 1 for path in paths)


@pytest.mark.parametrize(
    ("parser", "path", "content"),
    [
        (DependencyManifestParser(), "package.json", "{"),
        (DependencyLockParser(), "package-lock.json", '{"lockfileVersion":99}'),
        (ContainerArtifactParser(), "compose.yaml", "services: []"),
        (KubernetesArtifactParser(), "k8s/deploy.yaml", "kind: [broken"),
        (TerraformArtifactParser(), "main.tf.json", "[]"),
        (CiArtifactParser(), ".github/workflows/test.yml", "jobs: []"),
        (MessagingSchemaParser(), "asyncapi.yaml", "asyncapi: 1.0.0\nchannels: {}"),
    ],
)
def test_malformed_or_unsupported_artifacts_fail_closed(
    parser: ArtifactParserPort, path: str, content: str
) -> None:
    with pytest.raises(IndexingValidationError, match="artifact topology"):
        parser.parse(_artifact(path, content))


def test_unsupported_environment_template_line_is_retained_as_digest_only_evidence() -> None:
    batch = EnvironmentTemplateParser().parse(_artifact(".env.example", "not an assignment"))
    assert batch.candidates == ()
    assert len(batch.unknown_evidence) == 1
    assert not hasattr(batch.unknown_evidence[0], "content")


def test_yaml_alias_bomb_and_credential_bearing_image_are_rejected() -> None:
    with pytest.raises(IndexingValidationError):
        ContainerArtifactParser().parse(_artifact("compose.yaml", "services: &all\n  api: *all\n"))
    with pytest.raises(IndexingValidationError):
        ContainerArtifactParser().parse(
            _artifact(
                "compose.yaml",
                "services:\n  api:\n    image: https://user:secret@example.invalid/image\n",
            )
        )


def _artifact(path: str, content: str) -> ArtifactTopologySourceArtifact:
    evidence = replace(_evidence(), relative_path=path)
    return ArtifactTopologySourceArtifact(evidence, "1" * 40, content.encode())
