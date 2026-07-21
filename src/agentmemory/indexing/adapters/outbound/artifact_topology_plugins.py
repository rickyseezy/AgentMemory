"""IDX-005 deterministic parsers for local build and runtime topology artifacts."""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, cast

import yaml

from agentmemory.indexing.domain.artifact_topology import (
    ArtifactTopologyBatch,
    ArtifactTopologyPluginKind,
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

if TYPE_CHECKING:
    from collections.abc import Iterable

    from agentmemory.indexing.domain.artifact_topology import ArtifactTopologyEvidence

_VERSION = "idx005-parsers-1.0.0"
_ERR_PARSE = "artifact topology parser rejected malformed or unsafe input"
_MAX_DOCUMENT_NODES = 100_000
_MAX_DOCUMENT_DEPTH = 64
_MAX_LINE_LENGTH = 64 * 1024
_MIN_GO_REQUIRE_PARTS = 2
_PNPM_SCOPED_PARTS = 3
_GO_SUM_PARTS = 3
_ENV_INTERPOLATION = re.compile(
    r"(?:\$\{([A-Za-z_][A-Za-z0-9_]*)[^}]*\}|\$\{\{\s*(?:secrets|vars|env)\.([A-Za-z_][A-Za-z0-9_]*)[^}]*\}\})"
)
_TERRAFORM_VARIABLE = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_]*)\b")
_TERRAFORM_RESOURCE = re.compile(
    r'(?m)^\s*(resource|data|module|provider)\s+"([A-Za-z0-9_-]+)"(?:\s+"([A-Za-z0-9_-]+)")?\s*\{'
)
_TERRAFORM_REFERENCE = re.compile(
    r"\b((?:data\.)?[A-Za-z][A-Za-z0-9_-]*\.[A-Za-z][A-Za-z0-9_-]*)\b"
)
_SECRET_NAME = re.compile(
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY|CREDENTIAL|AUTH)", re.IGNORECASE
)
_YAML_ANCHOR = re.compile(r"(?:^|[\s\[{,])(?:&|\*)[A-Za-z0-9_-]+", re.MULTILINE)


def _candidate_map() -> dict[str, TopologyCandidate]:
    return {}


def _relation_map() -> dict[str, TopologyRelationCandidate]:
    return {}


def _unknown_map() -> dict[str, UnknownTopologyEvidence]:
    return {}


@dataclass(slots=True)
class _Builder:
    artifact: ArtifactTopologySourceArtifact
    kind: ArtifactTopologyPluginKind
    candidates: dict[str, TopologyCandidate] = field(default_factory=_candidate_map)
    relations: dict[str, TopologyRelationCandidate] = field(default_factory=_relation_map)
    unknown: dict[str, UnknownTopologyEvidence] = field(default_factory=_unknown_map)

    @property
    def evidence(self) -> ArtifactTopologyEvidence:
        return self.artifact.evidence

    def entity(  # noqa: PLR0913 -- Common schema requires each closed candidate field.
        self,
        kind: TopologyEntityKind,
        name: str,
        *,
        version: str | None = None,
        environment_reference: str | None = None,
        sensitivity: ReferenceSensitivity | None = None,
        qualifiers: Iterable[str] = (),
    ) -> str:
        canonical_name = safe_external_reference(name)
        canonical_version = None if version is None else safe_external_reference(version)
        identity = (
            canonical_name if canonical_version is None else f"{canonical_name}@{canonical_version}"
        )
        entity_id = stable_topology_entity_id(kind, identity)
        candidate = TopologyCandidate(
            self.evidence,
            entity_id,
            kind,
            canonical_name,
            canonical_version,
            environment_reference,
            sensitivity,
            tuple(sorted(set(qualifiers))),
        )
        self.candidates[candidate.id] = candidate
        return entity_id

    def environment(self, name: str, sensitivity: ReferenceSensitivity | None = None) -> str:
        reference = normalize_environment_reference(name)
        classification = sensitivity or _sensitivity(reference)
        return self.entity(
            TopologyEntityKind.ENVIRONMENT_REFERENCE,
            reference,
            environment_reference=reference,
            sensitivity=classification,
        )

    def relation(
        self,
        subject: str,
        relation: TopologyRelationKind,
        object_id: str,
        *,
        environment_reference: str | None = None,
    ) -> None:
        candidate = TopologyRelationCandidate(
            self.evidence,
            subject,
            relation,
            object_id,
            environment_reference,
            self.evidence.observed_at,
        )
        self.relations[candidate.id] = candidate

    def unresolved(
        self,
        value: str | bytes,
        reason: UnknownConstructReason,
        *,
        start_line: int = 1,
        end_line: int = 1,
    ) -> None:
        raw = value if isinstance(value, bytes) else value.encode()
        item = UnknownTopologyEvidence(
            self.evidence,
            reason,
            hashlib.sha256(raw).hexdigest(),
            start_line,
            end_line,
        )
        self.unknown[item.id] = item

    def finish(self) -> ArtifactTopologyBatch:
        return ArtifactTopologyBatch(
            self.kind,
            _VERSION,
            self.evidence.source_revision_context_id,
            self.evidence.source_file_id,
            self.artifact.commit_sha,
            tuple(sorted(self.candidates.values(), key=lambda item: item.id)),
            tuple(sorted(self.relations.values(), key=lambda item: item.id)),
            tuple(sorted(self.unknown.values(), key=lambda item: item.id)),
        )


@dataclass(frozen=True, slots=True)
class DependencyManifestParser:
    """Parse direct dependency declarations without guessing lock resolution."""

    def supports(self, relative_path: str) -> bool:
        """Own supported direct dependency manifest paths."""
        name = PurePosixPath(relative_path).name
        return name in {"package.json", "pyproject.toml", "go.mod", "Cargo.toml"} or (
            name.startswith("requirements") and name.endswith(".txt")
        )

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse a complete direct dependency artifact deterministically."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.DEPENDENCY_MANIFEST)
        name = PurePosixPath(artifact.evidence.relative_path).name
        text = _text(artifact.content)
        try:
            if name == "package.json":
                _package_manifest(builder, _json_mapping(text))
            elif name == "pyproject.toml":
                _python_manifest(builder, _toml_mapping(text))
            elif name == "go.mod":
                _go_manifest(builder, text)
            elif name == "Cargo.toml":
                _cargo_manifest(builder, _toml_mapping(text))
            else:
                _requirements_manifest(builder, text)
        except IndexingValidationError, UnicodeError:
            raise
        except (KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
            raise IndexingValidationError(_ERR_PARSE) from error
        return builder.finish()


@dataclass(frozen=True, slots=True)
class DependencyLockParser:
    """Parse exact resolved versions from common lockfile generations."""

    def supports(self, relative_path: str) -> bool:
        """Own supported dependency lock paths."""
        return PurePosixPath(relative_path).name in {
            "package-lock.json",
            "pnpm-lock.yaml",
            "pnpm-lock.yml",
            "uv.lock",
            "poetry.lock",
            "Cargo.lock",
            "go.sum",
        }

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse exact resolved dependency versions."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.DEPENDENCY_LOCK)
        name = PurePosixPath(artifact.evidence.relative_path).name
        text = _text(artifact.content)
        try:
            if name == "package-lock.json":
                _package_lock(builder, _json_mapping(text))
            elif name.startswith("pnpm-lock"):
                _pnpm_lock(builder, _yaml_documents(text)[0])
            elif name in {"uv.lock", "poetry.lock", "Cargo.lock"}:
                ecosystem = {"uv.lock": "python", "poetry.lock": "python", "Cargo.lock": "cargo"}[
                    name
                ]
                _toml_lock(builder, _toml_mapping(text), ecosystem)
            else:
                _go_sum(builder, text)
        except IndexingValidationError, UnicodeError:
            raise
        except (KeyError, TypeError, ValueError, tomllib.TOMLDecodeError) as error:
            raise IndexingValidationError(_ERR_PARSE) from error
        return builder.finish()


@dataclass(frozen=True, slots=True)
class ContainerArtifactParser:
    """Parse Dockerfiles and Compose files while retaining only environment names."""

    def supports(self, relative_path: str) -> bool:
        """Own Dockerfile and Compose paths."""
        name = PurePosixPath(relative_path).name.lower()
        return (
            name == "dockerfile"
            or name.endswith(".dockerfile")
            or (name.startswith(("compose", "docker-compose")) and name.endswith((".yaml", ".yml")))
        )

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse container build and service topology without values."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.CONTAINER)
        name = PurePosixPath(artifact.evidence.relative_path).name.lower()
        text = _text(artifact.content)
        if name == "dockerfile" or name.endswith(".dockerfile"):
            _dockerfile(builder, text)
        else:
            _compose(builder, _yaml_documents(text)[0])
        return builder.finish()


@dataclass(frozen=True, slots=True)
class KubernetesArtifactParser:
    """Parse Kubernetes resources, Kustomize overlays, templates, and secret references."""

    def supports(self, relative_path: str) -> bool:
        """Own Kubernetes and Kustomize paths without overlapping other YAML parsers."""
        path = PurePosixPath(relative_path)
        lowered = relative_path.lower()
        name = path.name.lower()
        return name in {"kustomization.yaml", "kustomization.yml"} or (
            name.endswith((".yaml", ".yml"))
            and (
                "/k8s/" in f"/{lowered}"
                or "/kubernetes/" in f"/{lowered}"
                or "/manifests/" in f"/{lowered}"
                or name.endswith((".k8s.yaml", ".k8s.yml"))
            )
        )

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse Kubernetes resources and retain unresolved templates as digest-only evidence."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.KUBERNETES)
        text = _text(artifact.content)
        name = PurePosixPath(artifact.evidence.relative_path).name.lower()
        if "{{" in text or "}}" in text:
            for line, value in enumerate(text.splitlines(), start=1):
                if "{{" in value or "}}" in value:
                    builder.unresolved(
                        value,
                        UnknownConstructReason.UNRESOLVED_TEMPLATE,
                        start_line=line,
                        end_line=line,
                    )
            text = re.sub(r"\{\{[^{}]*\}\}", "AGENTMEMORY_TEMPLATE", text)
        documents = _yaml_documents(text)
        if name.startswith("kustomization"):
            _kustomization(builder, documents[0])
        else:
            for document in documents:
                _kubernetes_document(builder, document)
        return builder.finish()


@dataclass(frozen=True, slots=True)
class TerraformArtifactParser:
    """Parse Terraform/HCL resource identities and normalized variable references."""

    def supports(self, relative_path: str) -> bool:
        """Own Terraform HCL and JSON syntax paths."""
        return relative_path.endswith((".tf", ".tf.json"))

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse Terraform resources and variable references."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.TERRAFORM)
        text = _text(artifact.content)
        if artifact.evidence.relative_path.endswith(".tf.json"):
            _terraform_json(builder, _json_mapping(text))
        else:
            _terraform_hcl(builder, text)
        return builder.finish()


@dataclass(frozen=True, slots=True)
class CiArtifactParser:
    """Parse supported local CI formats without retaining commands or environment values."""

    def supports(self, relative_path: str) -> bool:
        """Own supported CI pipeline paths."""
        lowered = relative_path.lower()
        name = PurePosixPath(relative_path).name.lower()
        return (
            lowered.startswith(".github/workflows/")
            or name in {".gitlab-ci.yml", ".gitlab-ci.yaml", "azure-pipelines.yml"}
            or lowered == ".circleci/config.yml"
            or name == "jenkinsfile"
        )

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse pipeline dependencies, images, actions, and configuration names."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.CI)
        text = _text(artifact.content)
        if PurePosixPath(artifact.evidence.relative_path).name.lower() == "jenkinsfile":
            _jenkins(builder, text)
        else:
            _ci_yaml(builder, _yaml_documents(text)[0], text)
        return builder.finish()


@dataclass(frozen=True, slots=True)
class EnvironmentTemplateParser:
    """Parse only environment templates/schemas and discard every supplied value."""

    def supports(self, relative_path: str) -> bool:
        """Own example, sample, template, and schema environment files only."""
        name = PurePosixPath(relative_path).name.lower()
        return name.endswith(
            (".env.example", ".env.sample", ".env.template", ".env.schema")
        ) or name in {
            ".env.example",
            ".env.sample",
            ".env.template",
            ".env.schema",
        }

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse environment names while discarding every value."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.ENVIRONMENT)
        _environment_template(builder, _text(artifact.content))
        return builder.finish()


@dataclass(frozen=True, slots=True)
class MessagingSchemaParser:
    """Parse AsyncAPI, Avro, and event JSON schema identities and channel direction."""

    def supports(self, relative_path: str) -> bool:
        """Own AsyncAPI and explicitly named event schemas."""
        name = PurePosixPath(relative_path).name.lower()
        lowered = relative_path.lower()
        return (name.startswith("asyncapi.") and name.endswith((".json", ".yaml", ".yml"))) or (
            name.endswith((".avsc", ".event-schema.json"))
            or ("/events/" in f"/{lowered}" and name.endswith(".json"))
        )

    def parse(self, artifact: ArtifactTopologySourceArtifact) -> ArtifactTopologyBatch:
        """Parse channel direction and schema identities."""
        builder = _Builder(artifact, ArtifactTopologyPluginKind.MESSAGING_SCHEMA)
        name = PurePosixPath(artifact.evidence.relative_path).name.lower()
        text = _text(artifact.content)
        if name.startswith("asyncapi."):
            document = _json_mapping(text) if name.endswith(".json") else _yaml_documents(text)[0]
            _asyncapi(builder, document)
        else:
            _event_schema(
                builder, _json_mapping(text), "avro" if name.endswith(".avsc") else "json"
            )
        return builder.finish()


def production_artifact_topology_parsers() -> tuple[
    DependencyManifestParser,
    DependencyLockParser,
    ContainerArtifactParser,
    KubernetesArtifactParser,
    TerraformArtifactParser,
    CiArtifactParser,
    EnvironmentTemplateParser,
    MessagingSchemaParser,
]:
    """Return the pinned non-overlapping deterministic parser registry."""
    return (
        DependencyManifestParser(),
        DependencyLockParser(),
        ContainerArtifactParser(),
        KubernetesArtifactParser(),
        TerraformArtifactParser(),
        CiArtifactParser(),
        EnvironmentTemplateParser(),
        MessagingSchemaParser(),
    )


def _package_manifest(builder: _Builder, document: Mapping[str, object]) -> None:
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        values = document.get(section, {})
        if not isinstance(values, Mapping):
            raise IndexingValidationError(_ERR_PARSE)
        dependency_values = cast("Mapping[str, object]", values)
        for name, version in sorted(dependency_values.items()):
            _dependency(builder, str(name), str(version), "npm", section)


def _python_manifest(builder: _Builder, document: Mapping[str, object]) -> None:
    project = _mapping(document.get("project", {}))
    dependencies = project.get("dependencies", [])
    if not isinstance(dependencies, Sequence) or isinstance(dependencies, str):
        raise IndexingValidationError(_ERR_PARSE)
    for value in cast("Sequence[object]", dependencies):
        name, version = _python_requirement(str(value))
        _dependency(builder, name, version, "python", "runtime")
    optional = _mapping(project.get("optional-dependencies", {}))
    for group, values in sorted(optional.items(), key=lambda item: str(item[0])):
        if not isinstance(values, Sequence) or isinstance(values, str):
            raise IndexingValidationError(_ERR_PARSE)
        for value in cast("Sequence[object]", values):
            name, version = _python_requirement(str(value))
            _dependency(builder, name, version, "python", f"optional-{group}")
    poetry = _mapping(_mapping(document.get("tool", {})).get("poetry", {}))
    for name, value in sorted(_mapping(poetry.get("dependencies", {})).items()):
        if name.lower() != "python":
            version = (
                str(value) if isinstance(value, str) else str(_mapping(value).get("version", "*"))
            )
            _dependency(builder, name, version, "python", "poetry")


def _go_manifest(builder: _Builder, text: str) -> None:
    in_require = False
    for line in text.splitlines():
        value = line.split("//", 1)[0].strip()
        if value == "require (":
            in_require = True
            continue
        if in_require and value == ")":
            in_require = False
            continue
        if value.startswith("require "):
            value = value.removeprefix("require ").strip()
        elif not in_require:
            continue
        parts = value.split()
        if len(parts) >= _MIN_GO_REQUIRE_PARTS:
            _dependency(builder, parts[0], parts[1], "go", "runtime")


def _cargo_manifest(builder: _Builder, document: Mapping[str, object]) -> None:
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, value in sorted(_mapping(document.get(section, {})).items()):
            version = (
                str(value) if isinstance(value, str) else str(_mapping(value).get("version", "*"))
            )
            _dependency(builder, name, version, "cargo", section)


def _requirements_manifest(builder: _Builder, text: str) -> None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        value = line.split("#", 1)[0].strip()
        if not value:
            continue
        if value.startswith(("-r", "--requirement", "-c", "--constraint")):
            builder.unresolved(
                value,
                UnknownConstructReason.UNSUPPORTED_CONSTRUCT,
                start_line=line_number,
                end_line=line_number,
            )
            continue
        name, version = _python_requirement(value)
        _dependency(builder, name, version, "python", "requirements")


def _package_lock(builder: _Builder, document: Mapping[str, object]) -> None:
    lock_version = document.get("lockfileVersion")
    if not isinstance(lock_version, int) or lock_version not in {1, 2, 3}:
        raise IndexingValidationError(_ERR_PARSE)
    packages = document.get("packages")
    if isinstance(packages, Mapping):
        package_values = cast("Mapping[str, object]", packages)
        for path, raw in sorted(package_values.items()):
            if not path or not isinstance(raw, Mapping):
                continue
            package = cast("Mapping[str, object]", raw)
            name = package.get("name") or str(path).rsplit("node_modules/", 1)[-1]
            version = package.get("version")
            if isinstance(name, str) and isinstance(version, str):
                _dependency(builder, name, version, "npm", f"lock-v{lock_version}")
    else:
        _walk_npm_dependencies(builder, _mapping(document.get("dependencies", {})), lock_version)


def _walk_npm_dependencies(
    builder: _Builder, values: Mapping[str, object], lock_version: int
) -> None:
    for name, raw in sorted(values.items()):
        item = _mapping(raw)
        version = item.get("version")
        if isinstance(version, str):
            _dependency(builder, name, version, "npm", f"lock-v{lock_version}")
        nested = item.get("dependencies", {})
        if isinstance(nested, Mapping):
            _walk_npm_dependencies(builder, cast("Mapping[str, object]", nested), lock_version)


def _pnpm_lock(builder: _Builder, document: Mapping[str, object]) -> None:
    lock_version = str(document.get("lockfileVersion", ""))
    if not lock_version or lock_version.split(".", 1)[0] not in {"5", "6", "7", "8", "9"}:
        raise IndexingValidationError(_ERR_PARSE)
    packages = _mapping(document.get("packages", document.get("snapshots", {})))
    for key, raw in sorted(packages.items()):
        name, version = _pnpm_key(str(key), _mapping(raw))
        if name and version:
            _dependency(builder, name, version, "pnpm", f"lock-v{lock_version}")


def _pnpm_key(key: str, item: Mapping[str, object]) -> tuple[str, str]:
    normalized = key.strip("/")
    if normalized.startswith("@"):
        parts = normalized.split("/")
        if len(parts) >= _PNPM_SCOPED_PARTS:
            return f"{parts[0]}/{parts[1]}", str(item.get("version", parts[2])).split("(", 1)[0]
    if "@" in normalized:
        name, version = normalized.rsplit("@", 1)
        return name, version.split("(", 1)[0]
    return normalized, str(item.get("version", ""))


def _toml_lock(builder: _Builder, document: Mapping[str, object], ecosystem: str) -> None:
    packages = document.get("package", [])
    if not isinstance(packages, Sequence) or isinstance(packages, str):
        raise IndexingValidationError(_ERR_PARSE)
    for raw in cast("Sequence[object]", packages):
        item = _mapping(raw)
        name, version = item.get("name"), item.get("version")
        if isinstance(name, str) and isinstance(version, str):
            _dependency(builder, name, version, ecosystem, "lock")


def _go_sum(builder: _Builder, text: str) -> None:
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != _GO_SUM_PARTS:
            if line.strip():
                raise IndexingValidationError(_ERR_PARSE)
            continue
        name, version = parts[0], parts[1].removesuffix("/go.mod")
        if (name, version) not in seen:
            _dependency(builder, name, version, "go", "sum")
            seen.add((name, version))


def _dependency(builder: _Builder, name: str, version: str, ecosystem: str, scope: str) -> None:
    try:
        dependency_id = builder.entity(
            TopologyEntityKind.PACKAGE,
            name,
            version=version or "*",
            qualifiers=(ecosystem, _qualifier(scope)),
        )
    except IndexingValidationError:
        builder.unresolved(f"{name}\0{version}", UnknownConstructReason.UNSUPPORTED_CONSTRUCT)
        return
    builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, dependency_id)


def _dockerfile(builder: _Builder, text: str) -> None:
    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        instruction, _, argument = stripped.partition(" ")
        if instruction.upper() == "FROM":
            image = argument.split(" AS ", 1)[0].split(" as ", 1)[0].strip()
            if "$" in image or "{{" in image:
                _environment_references(builder, image)
                builder.unresolved(
                    line,
                    UnknownConstructReason.UNRESOLVED_TEMPLATE,
                    start_line=line_number,
                    end_line=line_number,
                )
            else:
                image_id = builder.entity(TopologyEntityKind.CONTAINER_IMAGE, image)
                builder.relation(
                    builder.evidence.repository_id, TopologyRelationKind.DEPLOYED_AS, image_id
                )
        elif instruction.upper() in {"ARG", "ENV"}:
            for token in argument.split():
                key = token.split("=", 1)[0]
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                    env_id = builder.environment(key)
                    builder.relation(
                        builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, env_id
                    )


def _compose(builder: _Builder, document: Mapping[str, object]) -> None:
    services = _mapping(document.get("services", {}))
    if not services:
        raise IndexingValidationError(_ERR_PARSE)
    for service_name, raw in sorted(services.items()):
        service = _mapping(raw)
        service_id = builder.entity(TopologyEntityKind.SERVICE, f"compose/{service_name}")
        builder.relation(
            builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, service_id
        )
        image = service.get("image")
        if isinstance(image, str):
            if _environment_references(builder, image):
                builder.unresolved(image, UnknownConstructReason.UNRESOLVED_TEMPLATE)
            else:
                image_id = builder.entity(TopologyEntityKind.CONTAINER_IMAGE, image)
                builder.relation(service_id, TopologyRelationKind.DEPLOYED_AS, image_id)
        _environment_block(builder, service_id, service.get("environment", {}))
        for secret in _sequence(service.get("secrets", [])):
            name = str(secret if isinstance(secret, str) else _mapping(secret).get("source", ""))
            if name:
                env_id = builder.environment(name, ReferenceSensitivity.SECRET_REFERENCE)
                builder.relation(service_id, TopologyRelationKind.DEPENDS_ON, env_id)


def _kubernetes_document(  # noqa: C901 -- Closed resource variants share one bounded traversal.
    builder: _Builder, document: Mapping[str, object]
) -> None:
    kind = str(document.get("kind", ""))
    metadata = _mapping(document.get("metadata", {}))
    name = metadata.get("name")
    if not kind or not isinstance(name, str):
        raise IndexingValidationError(_ERR_PARSE)
    workload_id = builder.entity(
        TopologyEntityKind.WORKLOAD,
        f"kubernetes/{kind.lower()}/{name}",
        qualifiers=(kind.lower(),),
    )
    builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, workload_id)
    if kind in {"Secret", "ConfigMap"}:
        sensitivity = (
            ReferenceSensitivity.SECRET_REFERENCE
            if kind == "Secret"
            else ReferenceSensitivity.SENSITIVE_CONFIGURATION
        )
        keys = {*_mapping(document.get("data", {})), *_mapping(document.get("stringData", {}))}
        for key in sorted(keys):
            env_id = builder.environment(str(key), sensitivity)
            builder.relation(workload_id, TopologyRelationKind.DEPENDS_ON, env_id)
        return
    spec = _mapping(document.get("spec", {}))
    template = _mapping(spec.get("template", {}))
    pod_spec = _mapping(
        _mapping(template.get("spec", spec)).get("spec", template.get("spec", spec))
    )
    for container in (
        *_sequence(pod_spec.get("initContainers", [])),
        *_sequence(pod_spec.get("containers", [])),
    ):
        item = _mapping(container)
        image = item.get("image")
        if isinstance(image, str):
            if "AGENTMEMORY_TEMPLATE" in image or _environment_references(builder, image):
                builder.unresolved(image, UnknownConstructReason.UNRESOLVED_TEMPLATE)
            else:
                image_id = builder.entity(TopologyEntityKind.CONTAINER_IMAGE, image)
                builder.relation(workload_id, TopologyRelationKind.DEPLOYED_AS, image_id)
        for env in _sequence(item.get("env", [])):
            _kubernetes_env(builder, workload_id, _mapping(env))
        for source in _sequence(item.get("envFrom", [])):
            source_map = _mapping(source)
            for key, sensitivity in (
                ("secretRef", ReferenceSensitivity.SECRET_REFERENCE),
                ("configMapRef", ReferenceSensitivity.SENSITIVE_CONFIGURATION),
            ):
                reference = _mapping(source_map.get(key, {})).get("name")
                if isinstance(reference, str):
                    env_id = builder.environment(reference, sensitivity)
                    builder.relation(workload_id, TopologyRelationKind.DEPENDS_ON, env_id)


def _kubernetes_env(builder: _Builder, workload_id: str, item: Mapping[str, object]) -> None:
    name = item.get("name")
    if not isinstance(name, str):
        raise IndexingValidationError(_ERR_PARSE)
    source = _mapping(item.get("valueFrom", {}))
    sensitivity = _sensitivity(name)
    if "secretKeyRef" in source:
        sensitivity = ReferenceSensitivity.SECRET_REFERENCE
    elif "configMapKeyRef" in source or "fieldRef" in source:
        sensitivity = ReferenceSensitivity.SENSITIVE_CONFIGURATION
    env_id = builder.environment(name, sensitivity)
    builder.relation(workload_id, TopologyRelationKind.DEPENDS_ON, env_id)


def _kustomization(builder: _Builder, document: Mapping[str, object]) -> None:
    if str(document.get("kind", "")) not in {"Kustomization", ""}:
        raise IndexingValidationError(_ERR_PARSE)
    overlay_id = builder.entity(
        TopologyEntityKind.INFRASTRUCTURE_RESOURCE,
        f"kustomize/{builder.evidence.relative_path}",
        qualifiers=("overlay",),
    )
    builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, overlay_id)
    for resource in _sequence(document.get("resources", [])):
        name = str(resource)
        try:
            resource_id = builder.entity(
                TopologyEntityKind.INFRASTRUCTURE_RESOURCE,
                f"kustomize-resource/{name}",
            )
            builder.relation(overlay_id, TopologyRelationKind.DEPENDS_ON, resource_id)
        except IndexingValidationError:
            builder.unresolved(name, UnknownConstructReason.UNRESOLVED_OVERLAY)
    for image in _sequence(document.get("images", [])):
        item = _mapping(image)
        new_name = item.get("newName", item.get("name"))
        tag = item.get("digest", item.get("newTag"))
        if isinstance(new_name, str):
            image_name = (
                new_name
                if tag is None
                else f"{new_name}@{tag}"
                if str(tag).startswith("sha256:")
                else f"{new_name}:{tag}"
            )
            image_id = builder.entity(TopologyEntityKind.CONTAINER_IMAGE, image_name)
            builder.relation(overlay_id, TopologyRelationKind.DEPLOYED_AS, image_id)
    for patch in (
        *_sequence(document.get("patches", [])),
        *_sequence(document.get("patchesStrategicMerge", [])),
    ):
        builder.unresolved(
            json.dumps(patch, sort_keys=True, default=str),
            UnknownConstructReason.UNRESOLVED_OVERLAY,
        )


def _terraform_hcl(builder: _Builder, text: str) -> None:
    resources: dict[str, str] = {}
    for match in _TERRAFORM_RESOURCE.finditer(text):
        category, first, second = match.groups()
        name = f"{category}/{first}" if second is None else f"{category}/{first}/{second}"
        entity_id = builder.entity(
            TopologyEntityKind.INFRASTRUCTURE_RESOURCE,
            name,
            qualifiers=(category,),
        )
        resources[".".join(value for value in (first, second) if value)] = entity_id
        builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, entity_id)
    for variable in sorted(set(_TERRAFORM_VARIABLE.findall(text))):
        env_id = builder.environment(variable, ReferenceSensitivity.SENSITIVE_CONFIGURATION)
        builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, env_id)
    for reference in sorted(set(_TERRAFORM_REFERENCE.findall(text))):
        normalized = reference.removeprefix("data.")
        if normalized not in resources:
            reference_id = builder.entity(
                TopologyEntityKind.INFRASTRUCTURE_RESOURCE,
                f"terraform-reference/{reference}",
            )
            builder.relation(
                builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, reference_id
            )
    if not resources and not _TERRAFORM_VARIABLE.search(text):
        builder.unresolved(
            text,
            UnknownConstructReason.UNSUPPORTED_CONSTRUCT,
            end_line=max(1, len(text.splitlines())),
        )


def _terraform_json(builder: _Builder, document: Mapping[str, object]) -> None:
    found = False
    for category in ("resource", "data", "module", "provider"):
        for resource_type, raw_instances in sorted(_mapping(document.get(category, {})).items()):
            instances = raw_instances
            if category in {"module", "provider"}:
                instances = {resource_type: instances}
            for name in sorted(_mapping(instances)):
                found = True
                entity_id = builder.entity(
                    TopologyEntityKind.INFRASTRUCTURE_RESOURCE,
                    f"{category}/{resource_type}/{name}",
                    qualifiers=(category,),
                )
                builder.relation(
                    builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, entity_id
                )
    for variable in sorted(_mapping(document.get("variable", {}))):
        env_id = builder.environment(variable, ReferenceSensitivity.SENSITIVE_CONFIGURATION)
        builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, env_id)
    if not found and "variable" not in document:
        builder.unresolved(
            json.dumps(document, sort_keys=True), UnknownConstructReason.UNSUPPORTED_CONSTRUCT
        )


def _ci_yaml(builder: _Builder, document: Mapping[str, object], raw_text: str) -> None:
    pipeline_id = builder.entity(
        TopologyEntityKind.PIPELINE,
        f"ci/{builder.evidence.relative_path}",
    )
    builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, pipeline_id)
    jobs = document.get("jobs", document)
    if not isinstance(jobs, Mapping):
        raise IndexingValidationError(_ERR_PARSE)
    job_values = cast("Mapping[str, object]", jobs)
    for job_name, raw in sorted(job_values.items()):
        if str(job_name) in {"name", "on", "env", "variables", "stages", "include", "default"}:
            continue
        job = _mapping(raw)
        job_id = builder.entity(TopologyEntityKind.PIPELINE, f"ci-job/{job_name}")
        builder.relation(pipeline_id, TopologyRelationKind.DEPENDS_ON, job_id)
        image = job.get("image", _mapping(job.get("container", {})).get("image"))
        if isinstance(image, str):
            if _environment_references(builder, image):
                builder.unresolved(image, UnknownConstructReason.UNRESOLVED_TEMPLATE)
            else:
                image_id = builder.entity(TopologyEntityKind.CONTAINER_IMAGE, image)
                builder.relation(job_id, TopologyRelationKind.DEPLOYED_AS, image_id)
        for step in _sequence(job.get("steps", [])):
            uses = _mapping(step).get("uses")
            if isinstance(uses, str) and not uses.startswith("./"):
                action_id = builder.entity(
                    TopologyEntityKind.PACKAGE,
                    uses,
                    qualifiers=("ci-action",),
                )
                builder.relation(job_id, TopologyRelationKind.DEPENDS_ON, action_id)
        _environment_block(builder, job_id, job.get("env", job.get("variables", {})))
    _environment_references(builder, raw_text, subject=pipeline_id)


def _jenkins(builder: _Builder, text: str) -> None:
    pipeline_id = builder.entity(
        TopologyEntityKind.PIPELINE,
        f"jenkins/{builder.evidence.relative_path}",
    )
    builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, pipeline_id)
    for image in re.findall(r"docker\s*\{\s*image\s+['\"]([^'\"]+)['\"]", text):
        image_id = builder.entity(TopologyEntityKind.CONTAINER_IMAGE, image)
        builder.relation(pipeline_id, TopologyRelationKind.DEPLOYED_AS, image_id)
    for credential in re.findall(r"credentials\(['\"]([A-Za-z0-9_.-]+)['\"]\)", text):
        env_id = builder.environment(credential, ReferenceSensitivity.SECRET_REFERENCE)
        builder.relation(pipeline_id, TopologyRelationKind.DEPENDS_ON, env_id)
    if "pipeline" not in text:
        raise IndexingValidationError(_ERR_PARSE)


def _environment_template(builder: _Builder, text: str) -> None:
    found = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value.startswith("export "):
            value = value.removeprefix("export ").strip()
        name, separator, _discarded_value = value.partition("=")
        if not separator or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name.strip()) is None:
            builder.unresolved(
                line,
                UnknownConstructReason.UNSUPPORTED_CONSTRUCT,
                start_line=line_number,
                end_line=line_number,
            )
            continue
        found = True
        env_id = builder.environment(name.strip())
        builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, env_id)
    if not found and not builder.unknown:
        raise IndexingValidationError(_ERR_PARSE)


def _asyncapi(builder: _Builder, document: Mapping[str, object]) -> None:
    version = document.get("asyncapi")
    if not isinstance(version, str) or version.split(".", 1)[0] not in {"2", "3"}:
        raise IndexingValidationError(_ERR_PARSE)
    channels = _mapping(document.get("channels", {}))
    if not channels:
        raise IndexingValidationError(_ERR_PARSE)
    for channel_name, raw in sorted(channels.items()):
        _asyncapi_channel(builder, version, channel_name, _mapping(raw))
    _asyncapi_operations(builder, _mapping(document.get("operations", {})))


def _asyncapi_channel(
    builder: _Builder,
    version: str,
    channel_name: str,
    channel: Mapping[str, object],
) -> None:
    channel_id = builder.entity(
        TopologyEntityKind.MESSAGE_CHANNEL,
        channel_name,
        qualifiers=(f"asyncapi-v{version}",),
    )
    for operation, relation in (
        ("publish", TopologyRelationKind.PRODUCES),
        ("subscribe", TopologyRelationKind.CONSUMES),
    ):
        if operation in channel:
            builder.relation(builder.evidence.repository_id, relation, channel_id)
            operation_document = _mapping(channel.get(operation, {}))
            for message in _message_names(operation_document.get("message", [])):
                schema_id = builder.entity(TopologyEntityKind.EVENT_SCHEMA, message)
                builder.relation(channel_id, TopologyRelationKind.DEPENDS_ON, schema_id)
    messages = channel.get("messages", channel.get("message", []))
    for message in _message_names(messages):
        schema_id = builder.entity(TopologyEntityKind.EVENT_SCHEMA, message)
        builder.relation(channel_id, TopologyRelationKind.DEPENDS_ON, schema_id)


def _asyncapi_operations(builder: _Builder, operations: Mapping[str, object]) -> None:
    for operation_name, raw in sorted(operations.items()):
        operation_document = _mapping(raw)
        action = operation_document.get("action")
        channel_ref = str(_mapping(operation_document.get("channel", {})).get("$ref", "")).rsplit(
            "/", 1
        )[-1]
        if action in {"send", "receive"} and channel_ref:
            channel_id = builder.entity(TopologyEntityKind.MESSAGE_CHANNEL, channel_ref)
            relation = (
                TopologyRelationKind.PRODUCES if action == "send" else TopologyRelationKind.CONSUMES
            )
            builder.relation(builder.evidence.repository_id, relation, channel_id)
        elif action is not None:
            builder.unresolved(
                f"{operation_name}\0{action}", UnknownConstructReason.UNSUPPORTED_CONSTRUCT
            )


def _event_schema(builder: _Builder, document: Mapping[str, object], schema_type: str) -> None:
    name = document.get("name", document.get("title", document.get("$id")))
    if not isinstance(name, str) or not name:
        raise IndexingValidationError(_ERR_PARSE)
    schema_id = builder.entity(
        TopologyEntityKind.EVENT_SCHEMA,
        name,
        qualifiers=(schema_type,),
    )
    builder.relation(builder.evidence.repository_id, TopologyRelationKind.DEPENDS_ON, schema_id)


def _message_names(value: object) -> tuple[str, ...]:
    if isinstance(value, Mapping):
        document = cast("Mapping[str, object]", value)
        if "$ref" in document:
            return (str(document["$ref"]).rsplit("/", 1)[-1],)
        if "name" in document:
            return (str(document["name"]),)
        return tuple(sorted(document))
    if isinstance(value, Sequence) and not isinstance(value, str):
        names: list[str] = []
        for item in cast("Sequence[object]", value):
            names.extend(_message_names(item))
        return tuple(sorted(set(names)))
    return ()


def _environment_block(builder: _Builder, subject: str, value: object) -> None:
    if isinstance(value, Mapping):
        document = cast("Mapping[str, object]", value)
        pairs: tuple[tuple[str, object], ...] = tuple(document.items())
    elif isinstance(value, Sequence) and not isinstance(value, str):
        pairs = tuple(
            (str(item).split("=", 1)[0], str(item).partition("=")[2])
            for item in cast("Sequence[object]", value)
        )
    else:
        raise IndexingValidationError(_ERR_PARSE)
    for name, raw in pairs:
        env_id = builder.environment(name)
        builder.relation(subject, TopologyRelationKind.DEPENDS_ON, env_id)
        _environment_references(builder, str(raw), subject=subject)


def _environment_references(builder: _Builder, value: str, subject: str | None = None) -> bool:
    references = {
        next(group for group in match.groups() if group is not None)
        for match in _ENV_INTERPOLATION.finditer(value)
    }
    for reference in sorted(references):
        sensitivity = (
            ReferenceSensitivity.SECRET_REFERENCE
            if "secrets." in value.lower() or _SECRET_NAME.search(reference)
            else ReferenceSensitivity.SENSITIVE_CONFIGURATION
        )
        env_id = builder.environment(reference, sensitivity)
        builder.relation(
            subject or builder.evidence.repository_id,
            TopologyRelationKind.DEPENDS_ON,
            env_id,
        )
    return bool(references)


def _python_requirement(value: str) -> tuple[str, str]:
    requirement = value.split(";", 1)[0].strip()
    match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?(.*)", requirement)
    if match is None:
        raise IndexingValidationError(_ERR_PARSE)
    name, version = match.groups()
    return name, version.strip() or "*"


def _qualifier(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._+-]+", "-", value).strip("-")
    return normalized or "unspecified"


def _sensitivity(name: str) -> ReferenceSensitivity:
    if _SECRET_NAME.search(name):
        return ReferenceSensitivity.SECRET_REFERENCE
    return ReferenceSensitivity.SENSITIVE_CONFIGURATION


def _text(content: bytes) -> str:
    try:
        value = content.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise IndexingValidationError(_ERR_PARSE) from error
    if "\x00" in value or any(len(line) > _MAX_LINE_LENGTH for line in value.splitlines()):
        raise IndexingValidationError(_ERR_PARSE)
    return value


def _json_mapping(value: str) -> Mapping[str, object]:
    try:
        document = json.loads(value)
    except json.JSONDecodeError as error:
        raise IndexingValidationError(_ERR_PARSE) from error
    return _bounded_mapping(document)


def _toml_mapping(value: str) -> Mapping[str, object]:
    try:
        document = tomllib.loads(value)
    except tomllib.TOMLDecodeError as error:
        raise IndexingValidationError(_ERR_PARSE) from error
    return _bounded_mapping(document)


def _yaml_documents(value: str) -> tuple[Mapping[str, object], ...]:
    if _YAML_ANCHOR.search(value):
        raise IndexingValidationError(_ERR_PARSE)
    try:
        raw = tuple(yaml.safe_load_all(value))
    except yaml.YAMLError as error:
        raise IndexingValidationError(_ERR_PARSE) from error
    documents = tuple(_bounded_mapping(item) for item in raw if item is not None)
    if not documents:
        raise IndexingValidationError(_ERR_PARSE)
    return documents


def _bounded_mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise IndexingValidationError(_ERR_PARSE)
    count = 0
    stack: list[tuple[object, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > _MAX_DOCUMENT_DEPTH:
            raise IndexingValidationError(_ERR_PARSE)
        count += 1
        if count > _MAX_DOCUMENT_NODES:
            raise IndexingValidationError(_ERR_PARSE)
        if isinstance(current, Mapping):
            current_mapping = cast("Mapping[object, object]", current)
            stack.extend((key, depth + 1) for key in current_mapping)
            stack.extend((item, depth + 1) for item in current_mapping.values())
        elif isinstance(current, Sequence) and not isinstance(current, (str, bytes)):
            stack.extend((item, depth + 1) for item in cast("Sequence[object]", current))
    return cast("Mapping[str, object]", value)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        return {}
    return cast("Mapping[str, object]", value)


def _sequence(value: object) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    return cast("Sequence[object]", value)
