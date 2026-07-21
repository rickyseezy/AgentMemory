"""IDX-004 deterministic topology matching policy tests."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone
from typing import cast
from uuid import uuid4

import pytest

from agentmemory.graph.domain.assertions import (
    AssertionCandidate,
    AssertionConfidence,
    AssertionExtractor,
    AssertionPredicate,
    AssertionScope,
    AssertionStatus,
    AssertionTemporal,
    EvidenceKind,
    ResolvedAssertionEvidence,
)
from agentmemory.indexing.domain.api_topology import (
    ApiMatchDisposition,
    ApiMatchRule,
    ApiProtocol,
    ApiTopologyCandidateBatch,
    ApiTopologyEvidence,
    ApiTopologyLinkDecision,
    ApiTopologyLinkPolicy,
    ApiTopologyPluginKind,
    ApiTopologySourceArtifact,
    ClientCallCandidate,
    ContractBindingCandidate,
    EndpointCandidate,
    ServiceOwnershipCandidate,
    normalize_route_template,
)
from agentmemory.indexing.domain.errors import IndexingValidationError

NOW = datetime(2026, 7, 21, 12, tzinfo=UTC)
BRAIN = "018f0000-0000-7000-8000-000000000001"
FRONTEND_PROJECT = "018f0000-0000-7000-8000-000000000002"
FRONTEND_REPOSITORY = "018f0000-0000-7000-8000-000000000003"
BACKEND_PROJECT = "018f0000-0000-7000-8000-000000000004"
BACKEND_REPOSITORY = "018f0000-0000-7000-8000-000000000005"
CLIENT_ENTITY = "018f0000-0000-7000-8000-000000000010"
ENDPOINT_A = "018f0000-0000-7000-8000-000000000011"
ENDPOINT_B = "018f0000-0000-7000-8000-000000000012"


def test_contract_operation_wins_and_retains_cross_project_proof_path() -> None:
    client = _client(contract="users.get", route="/gateway/users/:id")
    endpoint = _endpoint(ENDPOINT_A, contract="users.get", route="/users/{user_id}")
    contract = ContractBindingCandidate(
        _evidence(frontend=False, suffix="3"),
        ApiProtocol.REST,
        "users.get",
        "user-api",
        "GET",
        "/users/{}",
        ("UsersClient.get",),
    )
    decision = ApiTopologyLinkPolicy.link(client, (endpoint,), (contract,), ())

    assert decision.matches[0].rule is ApiMatchRule.CONTRACT_OPERATION
    assert decision.matches[0].disposition is ApiMatchDisposition.CONFIRMED
    assert decision.matches[0].confidence_basis_points == 9_800
    assert decision.matches[0].supporting_evidence_ids == tuple(
        sorted(
            {
                client.evidence.evidence_id,
                endpoint.evidence.evidence_id,
                contract.evidence.evidence_id,
            }
        )
    )


def test_equal_strength_candidates_are_qualified_in_stable_order() -> None:
    client = _client(contract="users.get")
    first = _endpoint(ENDPOINT_A, contract="users.get")
    second = _endpoint(ENDPOINT_B, contract="users.get", evidence_suffix="4")

    decision = ApiTopologyLinkPolicy.link(client, (second, first), (), ())

    assert tuple(match.endpoint_id for match in decision.matches) == tuple(
        sorted((first.id, second.id))
    )
    assert all(match.disposition is ApiMatchDisposition.QUALIFIED for match in decision.matches)
    assert all("requires_disambiguation" in match.qualification_codes for match in decision.matches)


def test_environment_service_and_gateway_match_is_explainable() -> None:
    client = _client(contract=None, route="/gateway/users/{}", base="USER_API_URL")
    endpoint = _endpoint(ENDPOINT_A, contract=None, route="/users/{}")
    owner = ServiceOwnershipCandidate(
        _evidence(frontend=False, suffix="5"),
        "user-api",
        ("users",),
        ("USER_API_URL",),
        ("/gateway",),
    )

    match = ApiTopologyLinkPolicy.link(client, (endpoint,), (), (owner,)).matches[0]

    assert match.rule is ApiMatchRule.SERVICE_BASE_URL
    assert "gateway_prefix_applied" in match.qualification_codes


def test_dynamic_route_never_becomes_authoritative() -> None:
    client = _client(contract="users.get", dynamic=True)
    match = ApiTopologyLinkPolicy.link(
        client, (_endpoint(ENDPOINT_A, contract="users.get"),), (), ()
    ).matches[0]
    assert match.disposition is ApiMatchDisposition.QUALIFIED
    assert match.confidence_basis_points == 8_000
    assert "dynamic_routing" in match.qualification_codes


def test_generated_symbol_then_heuristic_rules_and_protocol_rejection() -> None:
    client = _client(contract=None)
    endpoint = _endpoint(ENDPOINT_A, contract=None)
    contract = ContractBindingCandidate(
        _evidence(frontend=False, suffix="6"),
        ApiProtocol.REST,
        "users.get",
        "user-api",
        "GET",
        "/users/{}",
        ("UsersClient.get",),
    )
    generated = ApiTopologyLinkPolicy.link(client, (endpoint,), (contract,), ())
    heuristic = ApiTopologyLinkPolicy.link(
        replace(client, generated_client_symbol=None, service_reference=None),
        (endpoint,),
        (),
        (),
    )
    rejected = ApiTopologyLinkPolicy.link(
        replace(client, protocol=ApiProtocol.GRAPHQL), (endpoint,), (), ()
    )

    assert generated.matches[0].rule is ApiMatchRule.GENERATED_CLIENT_SYMBOL
    assert generated.matches[0].confidence_basis_points == 9_300
    assert heuristic.matches[0].rule is ApiMatchRule.HEURISTIC_PATH
    assert heuristic.matches[0].confidence_basis_points == 7_200
    assert rejected.matches == ()


def test_stronger_rule_ranks_before_weaker_rule_and_is_uniquely_confirmed() -> None:
    client = _client(contract="users.get")
    heuristic = _endpoint(ENDPOINT_A, contract=None, route="/users/{}")
    contract = _endpoint(
        ENDPOINT_B,
        contract="users.get",
        route="/different-route/{}",
        evidence_suffix="4",
    )

    decision = ApiTopologyLinkPolicy.link(client, (heuristic, contract), (), ())

    assert tuple(match.endpoint_id for match in decision.matches) == (contract.id, heuristic.id)
    assert tuple(match.rule for match in decision.matches) == (
        ApiMatchRule.CONTRACT_OPERATION,
        ApiMatchRule.HEURISTIC_PATH,
    )
    assert tuple(match.disposition for match in decision.matches) == (
        ApiMatchDisposition.CONFIRMED,
        ApiMatchDisposition.QUALIFIED,
    )
    assert tuple(match.confidence_basis_points for match in decision.matches) == (9_800, 6_400)


def test_candidate_universe_digest_binds_each_input_family() -> None:
    client = _client(contract=None)
    endpoint = _endpoint(ENDPOINT_A, contract=None)
    contract = ContractBindingCandidate(
        _evidence(frontend=False, suffix="6"),
        ApiProtocol.REST,
        "users.get",
        "user-api",
        "GET",
        "/users/{}",
    )
    owner = ServiceOwnershipCandidate(
        _evidence(frontend=False, suffix="7"),
        "user-api",
    )
    baseline = ApiTopologyLinkPolicy.link(client, (), (), ()).candidate_universe_digest

    assert (
        ApiTopologyLinkPolicy.link(client, (endpoint,), (), ()).candidate_universe_digest
        != baseline
    )
    assert (
        ApiTopologyLinkPolicy.link(client, (), (contract,), ()).candidate_universe_digest
        != baseline
    )
    assert (
        ApiTopologyLinkPolicy.link(client, (), (), (owner,)).candidate_universe_digest != baseline
    )
    assert (
        ApiTopologyLinkPolicy.link(
            replace(client, route_template="/accounts/{}"), (), (), ()
        ).candidate_universe_digest
        != baseline
    )


def test_method_and_route_mismatches_do_not_guess() -> None:
    client = replace(_client(contract=None), generated_client_symbol=None, service_reference=None)
    wrong_method = replace(_endpoint(ENDPOINT_A, contract=None), transport_operation="POST")
    wrong_route = replace(_endpoint(ENDPOINT_B, contract=None), route_template="/accounts/{}")
    assert ApiTopologyLinkPolicy.link(client, (wrong_method, wrong_route), (), ()).matches == ()


def test_candidate_models_fail_closed_on_invalid_security_coordinates() -> None:
    evidence = _evidence(frontend=True, suffix="7")
    with pytest.raises(IndexingValidationError):
        replace(evidence, classification="secret")
    with pytest.raises(IndexingValidationError):
        replace(evidence, relative_path="../escape.py")
    with pytest.raises(IndexingValidationError):
        replace(evidence, brain_id=str(uuid4()))
    with pytest.raises(IndexingValidationError):
        replace(evidence, observed_at=NOW.replace(tzinfo=None))
    with pytest.raises(IndexingValidationError):
        replace(_client(contract=None), base_url_reference="https://secret.invalid")
    with pytest.raises(IndexingValidationError):
        replace(_client(contract=None), protocol=cast("ApiProtocol", "rest"))
    with pytest.raises(IndexingValidationError):
        replace(_client(contract=None), dynamic=cast("bool", 1))
    with pytest.raises(IndexingValidationError):
        replace(_endpoint(ENDPOINT_A, contract=None), route_template="/users?token=secret")


def test_ownership_artifact_and_batch_invariants_fail_closed() -> None:
    evidence = _evidence(frontend=True, suffix="8")
    with pytest.raises(IndexingValidationError):
        ServiceOwnershipCandidate(evidence, "user-api", aliases=("z", "a"))
    with pytest.raises(IndexingValidationError):
        ServiceOwnershipCandidate(evidence, "user-api", base_url_references=("user-api-url",))
    with pytest.raises(IndexingValidationError):
        ServiceOwnershipCandidate(evidence, "user-api", gateway_prefixes=("/z", "/a"))
    with pytest.raises(IndexingValidationError):
        ApiTopologySourceArtifact(evidence, "not-a-commit", b"source")
    with pytest.raises(IndexingValidationError):
        ApiTopologySourceArtifact(evidence, "1" * 40, b"")
    with pytest.raises(IndexingValidationError):
        ApiTopologySourceArtifact(evidence, "1" * 40, b"source", "not valid")

    endpoint = _endpoint(ENDPOINT_A, contract=None, evidence_suffix="8")
    batch = ApiTopologyCandidateBatch(
        ApiTopologyPluginKind.SOURCE_CALLS,
        "v1.0.0",
        endpoint.evidence.source_revision_context_id,
        endpoint.evidence.source_file_id,
        "1" * 40,
        (endpoint,),
    )
    with pytest.raises(IndexingValidationError):
        replace(batch, commit_sha="bad")
    with pytest.raises(IndexingValidationError):
        replace(batch, endpoints=(endpoint, endpoint))
    with pytest.raises(IndexingValidationError):
        replace(batch, source_file_id="f" * 64)


def test_match_and_decision_invariants_reject_noncanonical_proofs() -> None:
    first = ApiTopologyLinkPolicy.link(
        _client(contract="users.get"),
        (_endpoint(ENDPOINT_A, contract="users.get"),),
        (),
        (),
    ).matches[0]
    with pytest.raises(IndexingValidationError):
        replace(first, rank=0)
    with pytest.raises(IndexingValidationError):
        replace(first, supporting_candidate_ids=(first.endpoint_id,))
    with pytest.raises(IndexingValidationError):
        replace(first, supporting_evidence_ids=(first.client_evidence_id,))
    with pytest.raises(IndexingValidationError):
        replace(
            first,
            supporting_evidence_ids=tuple(reversed(first.supporting_evidence_ids)),
        )

    ambiguous = ApiTopologyLinkPolicy.link(
        _client(contract="users.get"),
        (
            _endpoint(ENDPOINT_A, contract="users.get"),
            _endpoint(ENDPOINT_B, contract="users.get", evidence_suffix="9"),
        ),
        (),
        (),
    )
    with pytest.raises(IndexingValidationError):
        ApiTopologyLinkDecision(
            ambiguous.client_call_id,
            ambiguous.candidate_universe_digest,
            tuple(reversed(ambiguous.matches)),
        )
    with pytest.raises(IndexingValidationError):
        replace(ambiguous, matches=(replace(ambiguous.matches[0], rank=2),))
    with pytest.raises(IndexingValidationError):
        replace(
            ambiguous,
            matches=(
                ambiguous.matches[0],
                replace(ambiguous.matches[1], disposition=ApiMatchDisposition.CONFIRMED),
            ),
        )


def test_non_utc_offset_is_rejected() -> None:
    with pytest.raises(IndexingValidationError):
        replace(
            _evidence(frontend=True, suffix="0"),
            observed_at=NOW.astimezone(timezone(timedelta(hours=4))),
        )


def test_consumes_assertion_accepts_exact_client_and_cross_project_server_evidence() -> None:
    client_evidence = "018f0000-0000-7000-8000-000000000120"
    server_evidence = "018f0000-0000-7000-8000-000000000121"
    candidate = AssertionCandidate.create(
        candidate_id="018f0000-0000-7000-8000-000000000122",
        subject_id=CLIENT_ENTITY,
        predicate=AssertionPredicate.CONSUMES,
        object_id=ENDPOINT_A,
        scope=AssertionScope(BRAIN, FRONTEND_PROJECT, FRONTEND_REPOSITORY, None, "internal"),
        temporal=AssertionTemporal(NOW, None, NOW, None),
        confidence=AssertionConfidence(9_000, 9_000, 9_000),
        extractor=AssertionExtractor(
            "api-topology-linker", "api-topology-linker-1.0.0", "deterministic", "local-v1"
        ),
        evidence_ids=(client_evidence, server_evidence),
    )
    evidence = (
        ResolvedAssertionEvidence(
            client_evidence,
            "018f0000-0000-7000-8000-000000000123",
            EvidenceKind.SOURCE_SPAN,
            candidate.scope,
            "1" * 64,
            NOW,
            accessible=True,
            deleted=False,
            immutable=True,
        ),
        ResolvedAssertionEvidence(
            server_evidence,
            "018f0000-0000-7000-8000-000000000124",
            EvidenceKind.SOURCE_SPAN,
            AssertionScope(BRAIN, BACKEND_PROJECT, BACKEND_REPOSITORY, None, "internal"),
            "2" * 64,
            NOW,
            accessible=True,
            deleted=False,
            immutable=True,
        ),
    )

    assert candidate.activate(evidence, NOW).status is AssertionStatus.ACTIVE


@pytest.mark.parametrize(
    ("route", "expected"),
    [
        ("https://example.invalid/users/:id?debug=true", "/users/{}"),
        ("/users/{user_id}/orders/<order_id>", "/users/{}/orders/{}"),
        ("users//active/", "/users/active"),
        ("/", "/"),
        ("/users?first?second", "/users"),
        ("/users#first#second", "/users"),
    ],
)
def test_route_templates_are_canonical(route: str, expected: str) -> None:
    assert normalize_route_template(route) == expected


def _client(
    *,
    contract: str | None,
    route: str = "/users/{}",
    base: str | None = None,
    dynamic: bool = False,
) -> ClientCallCandidate:
    return ClientCallCandidate(
        _evidence(frontend=True, suffix="1"),
        CLIENT_ENTITY,
        ApiProtocol.REST,
        "GET",
        route,
        contract,
        "UsersClient.get",
        "user-api",
        base,
        dynamic,
    )


def _endpoint(
    entity_id: str,
    *,
    contract: str | None,
    route: str = "/users/{}",
    evidence_suffix: str = "2",
) -> EndpointCandidate:
    return EndpointCandidate(
        _evidence(frontend=False, suffix=evidence_suffix),
        entity_id,
        ApiProtocol.REST,
        "user-api",
        "GET",
        route,
        contract,
    )


def _evidence(*, frontend: bool, suffix: str) -> ApiTopologyEvidence:
    return ApiTopologyEvidence(
        BRAIN,
        FRONTEND_PROJECT if frontend else BACKEND_PROJECT,
        FRONTEND_REPOSITORY if frontend else BACKEND_REPOSITORY,
        suffix * 64,
        ("a" if frontend else "b") * 64,
        ("c" if frontend else "d") * 64,
        f"018f0000-0000-7000-8000-0000000001{suffix.zfill(2)}",
        "src/api.ts" if frontend else "src/routes.ts",
        "internal",
        NOW,
    )
