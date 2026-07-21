"""Bounded deterministic IDX-004 OpenAPI, GraphQL, gRPC, and source-call plugins."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, cast
from uuid import UUID

import yaml

from agentmemory.indexing.domain.api_topology import (
    ApiProtocol,
    ApiTopologyCandidateBatch,
    ApiTopologyPluginKind,
    ApiTopologySourceArtifact,
    ClientCallCandidate,
    ContractBindingCandidate,
    EndpointCandidate,
    ServiceOwnershipCandidate,
    normalize_route_template,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

_PLUGIN_VERSION = "v1.0.0"
_MAX_DOCUMENT_NODES = 100_000
_MAX_TEXT_CHARS = 8 * 1024 * 1024
_HTTP_METHODS = frozenset({"delete", "get", "head", "options", "patch", "post", "put", "trace"})
_ERR_DOCUMENT = "API topology source document is invalid"
_DIRECTIVE = re.compile(
    r"agentmemory-(service|alias|base-url-ref|gateway-prefix|contract-operation|generated-client)"
    r"\s*:\s*([^\r\n]+)",
    re.IGNORECASE,
)
_GRAPHQL_OPERATION = re.compile(
    r"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)[^\{]*\{\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)
_GRAPHQL_ROOT = re.compile(r"\btype\s+(Query|Mutation|Subscription)\s*\{([^}]*)\}", re.DOTALL)
_GRAPHQL_FIELD = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:", re.MULTILINE)
_PROTO_SERVICE = re.compile(r"\bservice\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{([^}]*)\}", re.DOTALL)
_PROTO_RPC = re.compile(r"\brpc\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_EXPRESS_ROUTE = re.compile(
    r"\b(?:app|router)\s*\.\s*(get|post|put|patch|delete|options|head)\s*\(\s*"
    r"([`\"'])(.*?)\2",
    re.DOTALL | re.IGNORECASE,
)
_PYTHON_ROUTE = re.compile(
    r"@(?:app|router)\s*\.\s*(get|post|put|patch|delete|options|head)\s*\(\s*"
    r"([\"'])(.*?)\2",
    re.DOTALL | re.IGNORECASE,
)
_AXIOS_CALL = re.compile(
    r"\baxios\s*\.\s*(get|post|put|patch|delete|options|head)\s*\(\s*"
    r"([`\"'])(.*?)\2",
    re.DOTALL | re.IGNORECASE,
)
_FETCH_CALL = re.compile(r"\bfetch\s*\(\s*([`\"'])(.*?)\1", re.DOTALL)
_FETCH_METHOD = re.compile(r"\bmethod\s*:\s*['\"](GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)['\"]")
_GRPC_CALL = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*(?:Client|Stub))\s*\.\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
_TEMPLATE_EXPR = re.compile(r"\$\{([^}]+)\}")
_ENV_ACCESS = re.compile(
    r"(?:process\.env\.|import\.meta\.env\.|os\.environ\[['\"]|os\.getenv\(['\"])?"
    r"([A-Z][A-Z0-9_]{1,127})"
)


@dataclass(frozen=True, slots=True)
class OpenApiTopologyPlugin:
    """Extract REST endpoints, contracts, generated symbols, and ownership from OpenAPI."""

    def supports(self, relative_path: str) -> bool:
        """Own conventional OpenAPI JSON and YAML names only."""
        name = PurePosixPath(relative_path).name.casefold()
        return name in {
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "swagger.json",
            "swagger.yaml",
            "swagger.yml",
        }

    def extract(self, artifact: object) -> ApiTopologyCandidateBatch:
        """Parse a bounded mapping without resolving remote references."""
        source = _artifact(artifact)
        document = _mapping(_structured_document(source))
        if "openapi" not in document and "swagger" not in document:
            raise IndexingValidationError(_ERR_DOCUMENT)
        info = _optional_mapping(document.get("info"))
        service = _service_name(
            source.service_hint
            or _optional_string(document.get("x-agentmemory-service"))
            or _optional_string(info.get("title"))
            or PurePosixPath(source.evidence.relative_path).parent.name
            or "api"
        )
        endpoints: list[EndpointCandidate] = []
        contracts: list[ContractBindingCandidate] = []
        paths = _mapping(document.get("paths", {}))
        for route, path_item_value in sorted(paths.items()):
            if not route.startswith("/"):
                raise IndexingValidationError(_ERR_DOCUMENT)
            path_item = _mapping(path_item_value)
            for method, operation_value in sorted(path_item.items()):
                if method.casefold() not in _HTTP_METHODS:
                    continue
                operation = _mapping(operation_value)
                operation_id = _optional_string(operation.get("operationId"))
                endpoint = EndpointCandidate(
                    source.evidence,
                    _entity("endpoint", service, method.upper(), route),
                    ApiProtocol.REST,
                    service,
                    method.upper(),
                    normalize_route_template(route),
                    operation_id,
                )
                endpoints.append(endpoint)
                if operation_id is not None:
                    generated = _string_tuple(
                        operation.get("x-agentmemory-generated-client-symbols", ()),
                        fallback=(operation_id,),
                    )
                    contracts.append(
                        ContractBindingCandidate(
                            source.evidence,
                            ApiProtocol.REST,
                            operation_id,
                            service,
                            method.upper(),
                            normalize_route_template(route),
                            generated,
                        )
                    )
        aliases = _string_tuple(document.get("x-agentmemory-service-aliases", ()))
        base_refs = _env_tuple(document.get("x-agentmemory-base-url-refs", ()))
        gateways = _route_tuple(document.get("x-agentmemory-gateway-prefixes", ()))
        owners = (
            ServiceOwnershipCandidate(source.evidence, service, aliases, base_refs, gateways),
        )
        return _batch(
            source,
            ApiTopologyPluginKind.OPENAPI,
            endpoints=endpoints,
            contracts=contracts,
            ownership=owners,
        )


@dataclass(frozen=True, slots=True)
class GraphQlTopologyPlugin:
    """Extract GraphQL root fields and client operations from schema/document files."""

    def supports(self, relative_path: str) -> bool:
        """Own standalone GraphQL schema and operation files."""
        return PurePosixPath(relative_path).suffix.casefold() in {".graphql", ".gql"}

    def extract(self, artifact: object) -> ApiTopologyCandidateBatch:
        """Parse GraphQL root fields and named operations without executing a schema."""
        source = _artifact(artifact)
        text = _text(source)
        directives = _directives(text)
        service = _service_name(
            source.service_hint or _first(directives, "service") or "graphql-api"
        )
        endpoints: list[EndpointCandidate] = []
        contracts: list[ContractBindingCandidate] = []
        clients: list[ClientCallCandidate] = []
        for root_type, body in _GRAPHQL_ROOT.findall(text):
            for field in _GRAPHQL_FIELD.findall(body):
                operation_id = f"{root_type}.{field}"
                endpoints.append(
                    EndpointCandidate(
                        source.evidence,
                        _entity("graphql-endpoint", service, operation_id),
                        ApiProtocol.GRAPHQL,
                        service,
                        operation_id,
                        "/graphql",
                        operation_id,
                    )
                )
                contracts.append(
                    ContractBindingCandidate(
                        source.evidence,
                        ApiProtocol.GRAPHQL,
                        operation_id,
                        service,
                        operation_id,
                        "/graphql",
                        (),
                    )
                )
        for operation_type, generated_symbol, field in _GRAPHQL_OPERATION.findall(text):
            root = operation_type.capitalize()
            operation_id = f"{root}.{field}"
            clients.append(
                ClientCallCandidate(
                    source.evidence,
                    _entity("graphql-client", source.evidence.source_semantic_id, operation_id),
                    ApiProtocol.GRAPHQL,
                    operation_id,
                    "/graphql",
                    operation_id,
                    generated_symbol,
                    service,
                    _first(directives, "base-url-ref"),
                )
            )
        owners = _ownership(source, service, directives)
        return _batch(
            source,
            ApiTopologyPluginKind.GRAPHQL,
            endpoints=endpoints,
            clients=clients,
            contracts=contracts,
            ownership=owners,
        )


@dataclass(frozen=True, slots=True)
class ProtobufTopologyPlugin:
    """Extract gRPC services, RPC endpoints, and generated symbols from proto3 files."""

    def supports(self, relative_path: str) -> bool:
        """Own Protocol Buffer source files."""
        return PurePosixPath(relative_path).suffix.casefold() == ".proto"

    def extract(self, artifact: object) -> ApiTopologyCandidateBatch:
        """Parse declared services and RPC methods without invoking protoc."""
        source = _artifact(artifact)
        text = _text(source)
        directives = _directives(text)
        endpoints: list[EndpointCandidate] = []
        contracts: list[ContractBindingCandidate] = []
        ownership: list[ServiceOwnershipCandidate] = []
        for declared_service, body in _PROTO_SERVICE.findall(text):
            service = _service_name(source.service_hint or declared_service)
            ownership.extend(_ownership(source, service, directives))
            for method in _PROTO_RPC.findall(body):
                operation_id = f"{declared_service}.{method}"
                route = f"/{declared_service}/{method}"
                endpoints.append(
                    EndpointCandidate(
                        source.evidence,
                        _entity("grpc-endpoint", service, operation_id),
                        ApiProtocol.GRPC,
                        service,
                        operation_id,
                        route,
                        operation_id,
                    )
                )
                contracts.append(
                    ContractBindingCandidate(
                        source.evidence,
                        ApiProtocol.GRPC,
                        operation_id,
                        service,
                        operation_id,
                        route,
                        tuple(sorted({method, f"{declared_service}Client.{method}"})),
                    )
                )
        return _batch(
            source,
            ApiTopologyPluginKind.PROTOBUF,
            endpoints=endpoints,
            contracts=contracts,
            ownership=ownership,
        )


@dataclass(frozen=True, slots=True)
class SourceCallTopologyPlugin:
    """Extract common server routes, REST calls, GraphQL operations, and generated gRPC calls."""

    _SUFFIXES = frozenset(
        {".cjs", ".cs", ".go", ".java", ".js", ".jsx", ".mjs", ".py", ".ts", ".tsx"}
    )

    def supports(self, relative_path: str) -> bool:
        """Own supported source formats not handled by contract plugins."""
        return PurePosixPath(relative_path).suffix.casefold() in self._SUFFIXES

    def extract(self, artifact: object) -> ApiTopologyCandidateBatch:  # noqa: C901
        """Extract only call/decorator syntax; arbitrary matching strings are ignored."""
        source = _artifact(artifact)
        text = _text(source)
        directives = _directives(text)
        service = _service_name(
            source.service_hint or _first(directives, "service") or "application"
        )
        base_ref = _first(directives, "base-url-ref")
        contract_operation = _first(directives, "contract-operation")
        generated_client = _first(directives, "generated-client")
        endpoints: list[EndpointCandidate] = []
        clients: list[ClientCallCandidate] = []
        for expression in (_EXPRESS_ROUTE, _PYTHON_ROUTE):
            for match in expression.finditer(text):
                if not _is_code_position(text, match.start()):
                    continue
                method, _quote, route = match.groups()
                cleaned, _detected_ref, dynamic = _source_route(route)
                endpoints.append(
                    EndpointCandidate(
                        source.evidence,
                        _entity("source-endpoint", service, method.upper(), cleaned),
                        ApiProtocol.REST,
                        service,
                        method.upper(),
                        cleaned,
                        contract_operation,
                        dynamic,
                    )
                )
        for match in _AXIOS_CALL.finditer(text):
            if not _is_code_position(text, match.start()):
                continue
            method, _quote, route = match.groups()
            cleaned, detected_ref, dynamic = _source_route(route)
            clients.append(
                _client(
                    source,
                    ApiProtocol.REST,
                    method.upper(),
                    cleaned,
                    contract_operation,
                    generated_client,
                    service,
                    base_ref or detected_ref,
                    dynamic=dynamic,
                )
            )
        for match in _FETCH_CALL.finditer(text):
            if not _is_code_position(text, match.start()):
                continue
            route = match.group(2)
            tail = text[match.end() : min(len(text), match.end() + 1_024)]
            method_match = _FETCH_METHOD.search(tail)
            method = "GET" if method_match is None else method_match.group(1)
            cleaned, detected_ref, dynamic = _source_route(route)
            clients.append(
                _client(
                    source,
                    ApiProtocol.REST,
                    method,
                    cleaned,
                    contract_operation,
                    generated_client,
                    service,
                    base_ref or detected_ref,
                    dynamic=dynamic,
                )
            )
        for match in _GRAPHQL_OPERATION.finditer(text):
            if not _is_code_position(text, match.start()):
                continue
            operation_type, symbol, field = match.groups()
            operation_id = f"{operation_type.capitalize()}.{field}"
            clients.append(
                _client(
                    source,
                    ApiProtocol.GRAPHQL,
                    operation_id,
                    "/graphql",
                    operation_id,
                    symbol,
                    service,
                    base_ref,
                    dynamic=False,
                )
            )
        for match in _GRPC_CALL.finditer(text):
            if not _is_code_position(text, match.start()):
                continue
            client_symbol, method = match.groups()
            declared = client_symbol.removesuffix("Client").removesuffix("Stub")
            operation_id = contract_operation or f"{declared}.{method}"
            clients.append(
                _client(
                    source,
                    ApiProtocol.GRPC,
                    operation_id,
                    f"/{declared}/{method}",
                    operation_id if contract_operation is not None else None,
                    generated_client or f"{client_symbol}.{method}",
                    service,
                    base_ref,
                    dynamic=False,
                )
            )
        return _batch(
            source,
            ApiTopologyPluginKind.SOURCE_CALLS,
            endpoints=endpoints,
            clients=clients,
            ownership=_ownership(source, service, directives),
        )


def production_api_topology_plugins() -> tuple[
    OpenApiTopologyPlugin,
    GraphQlTopologyPlugin,
    ProtobufTopologyPlugin,
    SourceCallTopologyPlugin,
]:
    """Return every pinned deterministic plugin in non-overlapping ownership order."""
    return (
        OpenApiTopologyPlugin(),
        GraphQlTopologyPlugin(),
        ProtobufTopologyPlugin(),
        SourceCallTopologyPlugin(),
    )


def _artifact(value: object) -> ApiTopologySourceArtifact:
    if not isinstance(value, ApiTopologySourceArtifact):
        raise IndexingValidationError(_ERR_DOCUMENT)
    return value


def _text(source: ApiTopologySourceArtifact) -> str:
    try:
        text = source.content.decode("utf-8", "strict")
    except UnicodeDecodeError as error:
        raise IndexingValidationError(_ERR_DOCUMENT) from error
    if len(text) > _MAX_TEXT_CHARS or "\x00" in text:
        raise IndexingValidationError(_ERR_DOCUMENT)
    return text


def _structured_document(source: ApiTopologySourceArtifact) -> object:
    text = _text(source)
    try:
        value = json.loads(text) if text.lstrip().startswith(("{", "[")) else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as error:
        raise IndexingValidationError(_ERR_DOCUMENT) from error
    _bound_document(value)
    return value


def _bound_document(root: object) -> None:
    pending = [root]
    visited: set[int] = set()
    count = 0
    while pending:
        value = pending.pop()
        count += 1
        if count > _MAX_DOCUMENT_NODES:
            raise IndexingValidationError(_ERR_DOCUMENT)
        if isinstance(value, dict):
            mapping = cast("dict[object, object]", value)
            identity = id(mapping)
            if identity in visited:
                continue
            visited.add(identity)
            pending.extend(mapping.values())
        elif isinstance(value, list):
            sequence = cast("list[object]", value)
            identity = id(sequence)
            if identity in visited:
                continue
            visited.add(identity)
            pending.extend(sequence)
        elif value is not None and not isinstance(value, (str, int, float, bool)):
            raise IndexingValidationError(_ERR_DOCUMENT)


def _mapping(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise IndexingValidationError(_ERR_DOCUMENT)
    mapping = cast("dict[object, object]", value)
    if any(not isinstance(key, str) for key in mapping):
        raise IndexingValidationError(_ERR_DOCUMENT)
    return cast("Mapping[str, object]", mapping)


def _optional_mapping(value: object) -> Mapping[str, object]:
    return {} if value is None else _mapping(value)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise IndexingValidationError(_ERR_DOCUMENT)
    return value.strip()


def _string_tuple(value: object, *, fallback: tuple[str, ...] = ()) -> tuple[str, ...]:
    if value in (None, (), []):
        return tuple(sorted(set(fallback)))
    if isinstance(value, str):
        values: tuple[str, ...] = (value,)
    elif isinstance(value, list | tuple):
        sequence = cast("list[object] | tuple[object, ...]", value)
        if not all(isinstance(item, str) for item in sequence):
            raise IndexingValidationError(_ERR_DOCUMENT)
        values = tuple(cast("Iterable[str]", sequence))
    else:
        raise IndexingValidationError(_ERR_DOCUMENT)
    return tuple(sorted({item.strip() for item in values if item.strip()}))


def _env_tuple(value: object) -> tuple[str, ...]:
    values = _string_tuple(value)
    if any(_ENV_ACCESS.fullmatch(item) is None for item in values):
        raise IndexingValidationError(_ERR_DOCUMENT)
    return values


def _route_tuple(value: object) -> tuple[str, ...]:
    return tuple(sorted({normalize_route_template(item) for item in _string_tuple(value)}))


def _service_name(value: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9._/-]+", "-", value.strip()).strip("-")
    if not normalized or not normalized[0].isalpha():
        normalized = f"service-{normalized}"
    return normalized[:256]


def _entity(*parts: str) -> str:
    raw = bytearray(
        hashlib.sha256(("api-topology-entity.v1\0" + "\0".join(parts)).encode()).digest()[:16]
    )
    raw[6] = (raw[6] & 0x0F) | 0x70
    raw[8] = (raw[8] & 0x3F) | 0x80
    return str(UUID(bytes=bytes(raw)))


def _is_code_position(  # noqa: C901,PLR0912 -- Closed lexical-state transition table.
    text: str, position: int
) -> bool:
    """Return whether a token begins outside strings and line/block comments."""
    quote: str | None = None
    line_comment = False
    block_comment = False
    escaped = False
    index = 0
    while index < position:
        current = text[index]
        following = text[index + 1] if index + 1 < position else ""
        if line_comment:
            if current == "\n":
                line_comment = False
        elif block_comment:
            if current == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote is not None:
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = None
        elif current == "/" and following == "/":
            line_comment = True
            index += 1
        elif current == "/" and following == "*":
            block_comment = True
            index += 1
        elif current == "#":
            line_comment = True
        elif current in {'"', "'", "`"}:
            quote = current
        index += 1
    return quote is None and not line_comment and not block_comment


def _directives(text: str) -> dict[str, tuple[str, ...]]:
    values: dict[str, list[str]] = {}
    for key, raw in _DIRECTIVE.findall(text):
        values.setdefault(key.casefold(), []).append(raw.strip())
    return {key: tuple(items) for key, items in values.items()}


def _first(values: Mapping[str, tuple[str, ...]], key: str) -> str | None:
    items = values.get(key, ())
    return None if not items else items[0]


def _ownership(
    source: ApiTopologySourceArtifact,
    service: str,
    directives: Mapping[str, tuple[str, ...]],
) -> tuple[ServiceOwnershipCandidate, ...]:
    aliases = tuple(sorted(set(directives.get("alias", ()))))
    base_refs = tuple(sorted(set(directives.get("base-url-ref", ()))))
    gateways = tuple(
        sorted({normalize_route_template(value) for value in directives.get("gateway-prefix", ())})
    )
    return (ServiceOwnershipCandidate(source.evidence, service, aliases, base_refs, gateways),)


def _source_route(value: str) -> tuple[str, str | None, bool]:
    expressions = _TEMPLATE_EXPR.findall(value)
    base_reference: str | None = None
    dynamic = False
    cleaned = value
    for index, expression in enumerate(expressions):
        env = _ENV_ACCESS.fullmatch(expression.strip())
        if index == 0 and env is not None and value.startswith(f"${{{expression}}}"):
            base_reference = env.group(1)
            cleaned = cleaned.replace(f"${{{expression}}}", "", 1)
        else:
            cleaned = cleaned.replace(f"${{{expression}}}", "{}", 1)
    if re.search(r"(?:\+|\$\{)", cleaned):
        dynamic = True
    try:
        route = normalize_route_template(cleaned)
    except IndexingValidationError:
        route, dynamic = "/dynamic", True
    return route, base_reference, dynamic


def _client(  # noqa: PLR0913 -- Mirrors the governed candidate evidence fields.
    source: ApiTopologySourceArtifact,
    protocol: ApiProtocol,
    operation: str,
    route: str,
    contract_operation: str | None,
    generated_symbol: str | None,
    service: str | None,
    base_ref: str | None,
    *,
    dynamic: bool,
) -> ClientCallCandidate:
    return ClientCallCandidate(
        source.evidence,
        _entity("client", source.evidence.source_semantic_id, protocol.value, operation, route),
        protocol,
        operation,
        route,
        contract_operation,
        generated_symbol,
        service,
        base_ref,
        dynamic,
    )


def _batch(  # noqa: PLR0913 -- Four candidate families are one complete plugin result.
    source: ApiTopologySourceArtifact,
    kind: ApiTopologyPluginKind,
    *,
    endpoints: Iterable[EndpointCandidate] = (),
    clients: Iterable[ClientCallCandidate] = (),
    contracts: Iterable[ContractBindingCandidate] = (),
    ownership: Iterable[ServiceOwnershipCandidate] = (),
) -> ApiTopologyCandidateBatch:
    return ApiTopologyCandidateBatch(
        kind,
        _PLUGIN_VERSION,
        source.evidence.source_revision_context_id,
        source.evidence.source_file_id,
        source.commit_sha,
        tuple(sorted(set(endpoints), key=lambda item: item.id)),
        tuple(sorted(set(clients), key=lambda item: item.id)),
        tuple(sorted(set(contracts), key=lambda item: item.id)),
        tuple(sorted(set(ownership), key=lambda item: item.id)),
    )
