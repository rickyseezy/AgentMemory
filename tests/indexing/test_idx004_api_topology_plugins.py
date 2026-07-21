"""IDX-004 parser golden, environment, generated-client, and false-positive tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from agentmemory.indexing.adapters.outbound.api_topology_plugins import (
    GraphQlTopologyPlugin,
    OpenApiTopologyPlugin,
    ProtobufTopologyPlugin,
    SourceCallTopologyPlugin,
    production_api_topology_plugins,
)
from agentmemory.indexing.domain.api_topology import (
    ApiProtocol,
    ApiTopologyEvidence,
    ApiTopologySourceArtifact,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
COMMIT = "a" * 40


def test_openapi_yaml_emits_endpoint_contract_generated_symbol_and_ownership() -> None:
    batch = OpenApiTopologyPlugin().extract(
        _artifact(
            "contracts/openapi.yaml",
            b"""
openapi: 3.1.0
info: {title: User API}
x-agentmemory-service: user-api
x-agentmemory-service-aliases: [users]
x-agentmemory-base-url-refs: [USER_API_URL]
x-agentmemory-gateway-prefixes: [/gateway]
paths:
  /users/{user_id}:
    get:
      operationId: users.get
      x-agentmemory-generated-client-symbols: [UsersClient.get]
""",
        )
    )

    assert batch.endpoints[0].route_template == "/users/{}"
    assert batch.contract_bindings[0].generated_client_symbols == ("UsersClient.get",)
    assert batch.service_ownership[0].base_url_references == ("USER_API_URL",)


def test_graphql_and_grpc_contracts_use_canonical_operation_ids() -> None:
    graphql = GraphQlTopologyPlugin().extract(
        _artifact(
            "schema.graphql",
            b"""# agentmemory-service: user-api
type Query { user(id: ID!): User }
query GetUser { user(id: "1") { id } }
""",
        )
    )
    grpc = ProtobufTopologyPlugin().extract(
        _artifact(
            "user.proto",
            b"""syntax = "proto3";
service UserService { rpc GetUser (GetUserRequest) returns (User); }
""",
        )
    )

    assert graphql.endpoints[0].contract_operation_id == "Query.user"
    assert graphql.client_calls[0].contract_operation_id == "Query.user"
    assert grpc.endpoints[0].contract_operation_id == "UserService.GetUser"
    assert "UserServiceClient.GetUser" in grpc.contract_bindings[0].generated_client_symbols


def test_source_calls_extract_env_gateway_route_and_ignore_adversarial_strings() -> None:
    batch = SourceCallTopologyPlugin().extract(
        _artifact(
            "src/client.ts",
            b"""// agentmemory-service: user-api
// agentmemory-base-url-ref: USER_API_URL
const fake = 'axios.get("/should-not-match")';
const note = 'fetch("/also-not-a-call")';
axios.get(`${process.env.USER_API_URL}/gateway/users/${userId}`);
fetch('/users/active', { method: 'POST' });
""",
        )
    )

    assert len(batch.client_calls) == 2
    templated = next(item for item in batch.client_calls if item.transport_operation == "GET")
    assert templated.base_url_reference == "USER_API_URL"
    assert templated.route_template == "/gateway/users/{}"
    assert {item.transport_operation for item in batch.client_calls} == {"GET", "POST"}


def test_production_registry_has_non_overlapping_owners() -> None:
    plugins = production_api_topology_plugins()
    paths = ("openapi.yaml", "schema.graphql", "service.proto", "client.ts")
    assert [sum(plugin.supports(path) for plugin in plugins) for path in paths] == [1, 1, 1, 1]


def test_source_plugin_emits_server_graphql_and_generated_grpc_candidates() -> None:
    batch = SourceCallTopologyPlugin().extract(
        _artifact(
            "src/routes.ts",
            b"""// agentmemory-service: user-api
router.get('/users/:id', handler);
@app.post("/users")
query GetUser { user(id: "1") { id } }
UserServiceClient.GetUser(request);
/* axios.get('/comment-only'); */
""",
        )
    )

    assert {item.route_template for item in batch.endpoints} == {
        "/users/{}",
        "/users",
    }
    assert {item.protocol for item in batch.client_calls} == {
        ApiProtocol.GRAPHQL,
        ApiProtocol.GRPC,
    }


def test_openapi_json_without_operation_id_and_non_methods_is_complete() -> None:
    batch = OpenApiTopologyPlugin().extract(
        _artifact(
            "openapi.json",
            b'{"openapi":"3.1.0","paths":{"/health":{"parameters":[],"get":{}}}}',
        )
    )
    assert len(batch.endpoints) == 1
    assert batch.endpoints[0].contract_operation_id is None
    assert batch.contract_bindings == ()


@pytest.mark.parametrize(
    ("path", "content"),
    [
        ("openapi.json", b"[]"),
        ("openapi.yaml", b"paths: {}"),
        ("openapi.yaml", b"openapi: 3.1.0\npaths:\n  users: {get: {}}"),
        ("openapi.yaml", b"openapi: 3.1.0\ninfo: {title: 123}\npaths: {}"),
        (
            "openapi.yaml",
            b"openapi: 3.1.0\nx-agentmemory-service-aliases: [users, 2]\npaths: {}",
        ),
        (
            "openapi.yaml",
            b"openapi: 3.1.0\nx-agentmemory-service-aliases: 2\npaths: {}",
        ),
        (
            "openapi.yaml",
            b"openapi: 3.1.0\nx-agentmemory-base-url-refs: [https://secret]\npaths: {}",
        ),
        ("schema.graphql", b"\xff"),
        ("schema.graphql", b"type Query { health: String }\x00"),
    ],
)
def test_malformed_or_secret_bearing_documents_fail_closed(path: str, content: bytes) -> None:
    plugin = OpenApiTopologyPlugin() if path.startswith("openapi") else GraphQlTopologyPlugin()
    with pytest.raises(IndexingValidationError):
        plugin.extract(_artifact(path, content))


@pytest.mark.parametrize(
    ("path", "protocol"),
    [("schema.graphql", ApiProtocol.GRAPHQL), ("service.proto", ApiProtocol.GRPC)],
)
def test_contract_plugins_emit_declared_protocol(path: str, protocol: ApiProtocol) -> None:
    artifact = (
        _artifact(path, b"type Query { health: String }")
        if protocol is ApiProtocol.GRAPHQL
        else _artifact(path, b"service Health { rpc Check (In) returns (Out); }")
    )
    plugin = (
        GraphQlTopologyPlugin() if protocol is ApiProtocol.GRAPHQL else ProtobufTopologyPlugin()
    )
    assert plugin.extract(artifact).endpoints[0].protocol is protocol


def _artifact(path: str, content: bytes) -> ApiTopologySourceArtifact:
    suffix = "1" if path.endswith(("yaml", "graphql")) else "2"
    evidence = ApiTopologyEvidence(
        "018f0000-0000-7000-8000-000000000001",
        "018f0000-0000-7000-8000-000000000002",
        "018f0000-0000-7000-8000-000000000003",
        suffix * 64,
        "a" * 64,
        "b" * 64,
        "018f0000-0000-7000-8000-000000000004",
        path,
        "internal",
        NOW,
    )
    return ApiTopologySourceArtifact(evidence, COMMIT, content)
