"""IDX-004 deterministic cross-project API topology candidates and linking policy."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from uuid import UUID

from agentmemory.indexing.domain.errors import IndexingValidationError

if TYPE_CHECKING:
    from datetime import datetime

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9._:/-]{0,255}$")
_OPERATION = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ENV_REF = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_PARAMETER = re.compile(r"(?:\{[^/{}]+\}|:[A-Za-z_][A-Za-z0-9_]*|<[^/<>]+>)")
_MAX_PATH_BYTES = 4_096
_MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_CANDIDATES = 100_000
_MAX_BASIS_POINTS = 10_000
_UUID7 = 7
_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted", "local_only")
_ERR_BATCH = "API topology candidate batch is invalid"
_ERR_CANDIDATE = "API topology candidate is invalid"
_ERR_LINK = "API topology link decision is invalid"


class ApiProtocol(StrEnum):
    """Closed API transports supported by deterministic topology plugins."""

    REST = "rest"
    GRAPHQL = "graphql"
    GRPC = "grpc"


class ApiTopologyPluginKind(StrEnum):
    """Pinned deterministic extractor families."""

    OPENAPI = "openapi"
    GRAPHQL = "graphql"
    PROTOBUF = "protobuf"
    SOURCE_CALLS = "source_calls"


class ApiMatchRule(StrEnum):
    """Precedence-ordered deterministic matching rules required by IDX-004."""

    CONTRACT_OPERATION = "contract_operation"
    GENERATED_CLIENT_SYMBOL = "generated_client_symbol"
    SERVICE_BASE_URL = "service_base_url"
    HEURISTIC_PATH = "heuristic_path"

    @property
    def precedence(self) -> int:
        """Return the governed priority; larger values are stronger evidence."""
        return {
            ApiMatchRule.CONTRACT_OPERATION: 4,
            ApiMatchRule.GENERATED_CLIENT_SYMBOL: 3,
            ApiMatchRule.SERVICE_BASE_URL: 2,
            ApiMatchRule.HEURISTIC_PATH: 1,
        }[self]


class ApiMatchDisposition(StrEnum):
    """Whether one match can become authoritative or remains qualified."""

    CONFIRMED = "confirmed"
    QUALIFIED = "qualified"


@dataclass(frozen=True, slots=True)
class ApiTopologyEvidence:
    """Exact retained source and graph-evidence coordinates for one candidate."""

    brain_id: str
    project_id: str
    repository_id: str
    source_file_id: str
    source_revision_context_id: str
    source_semantic_id: str
    evidence_id: str
    relative_path: str
    classification: str
    observed_at: datetime

    def __post_init__(self) -> None:
        """Reject cross-scope ambiguity, raw host paths, and unstable evidence."""
        for value in (self.brain_id, self.project_id, self.repository_id, self.evidence_id):
            _stable_id(value, _ERR_CANDIDATE)
        for value in (
            self.source_file_id,
            self.source_revision_context_id,
            self.source_semantic_id,
        ):
            _digest(value, _ERR_CANDIDATE)
        _path(self.relative_path)
        if self.classification not in _CLASSIFICATIONS:
            raise IndexingValidationError(_ERR_CANDIDATE)
        _utc(self.observed_at, _ERR_CANDIDATE)

    @property
    def scope_key(self) -> tuple[str, str, str]:
        """Return the Brain/Project/Repository authorization coordinates."""
        return self.brain_id, self.project_id, self.repository_id


@dataclass(frozen=True, slots=True)
class EndpointCandidate:
    """One server endpoint or RPC operation with exact source evidence."""

    evidence: ApiTopologyEvidence
    endpoint_entity_id: str
    protocol: ApiProtocol
    service_name: str
    transport_operation: str
    route_template: str
    contract_operation_id: str | None = None
    dynamic: bool = False

    def __post_init__(self) -> None:
        """Validate server identity, normalized route, operation, and protocol."""
        _stable_id(self.endpoint_entity_id, _ERR_CANDIDATE)
        _enum(self.protocol, ApiProtocol, _ERR_CANDIDATE)
        _token(self.service_name)
        _token(self.transport_operation)
        _route(self.route_template)
        if self.contract_operation_id is not None:
            _token(self.contract_operation_id)
        _bool(self.dynamic)

    @property
    def id(self) -> str:
        """Return immutable candidate identity independent of registration order."""
        return _identity(
            "api-endpoint-candidate.v1",
            {
                "contract_operation_id": self.contract_operation_id,
                "dynamic": self.dynamic,
                "endpoint_entity_id": self.endpoint_entity_id,
                "evidence_id": self.evidence.evidence_id,
                "protocol": self.protocol.value,
                "route": self.route_template,
                "service": self.service_name,
                "transport_operation": self.transport_operation,
            },
        )


@dataclass(frozen=True, slots=True)
class ClientCallCandidate:
    """One consumer call, generated SDK reference, or RPC invocation."""

    evidence: ApiTopologyEvidence
    consumer_entity_id: str
    protocol: ApiProtocol
    transport_operation: str
    route_template: str
    contract_operation_id: str | None = None
    generated_client_symbol: str | None = None
    service_reference: str | None = None
    base_url_reference: str | None = None
    dynamic: bool = False

    def __post_init__(self) -> None:
        """Validate exact consumer coordinates without accepting secret URL values."""
        _stable_id(self.consumer_entity_id, _ERR_CANDIDATE)
        _enum(self.protocol, ApiProtocol, _ERR_CANDIDATE)
        _token(self.transport_operation)
        _route(self.route_template)
        for value in (
            self.contract_operation_id,
            self.generated_client_symbol,
            self.service_reference,
        ):
            if value is not None:
                _token(value)
        if self.base_url_reference is not None and (
            _ENV_REF.fullmatch(self.base_url_reference) is None
        ):
            raise IndexingValidationError(_ERR_CANDIDATE)
        _bool(self.dynamic)

    @property
    def id(self) -> str:
        """Return immutable client candidate identity."""
        return _identity(
            "api-client-call-candidate.v1",
            {
                "base_url_reference": self.base_url_reference,
                "consumer_entity_id": self.consumer_entity_id,
                "contract_operation_id": self.contract_operation_id,
                "dynamic": self.dynamic,
                "evidence_id": self.evidence.evidence_id,
                "generated_client_symbol": self.generated_client_symbol,
                "protocol": self.protocol.value,
                "route": self.route_template,
                "service_reference": self.service_reference,
                "transport_operation": self.transport_operation,
            },
        )


@dataclass(frozen=True, slots=True)
class ContractBindingCandidate:
    """Canonical contract operation and its generated/server identities."""

    evidence: ApiTopologyEvidence
    protocol: ApiProtocol
    contract_operation_id: str
    service_name: str
    transport_operation: str
    route_template: str
    generated_client_symbols: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require a canonical operation and bounded sorted generated symbols."""
        _enum(self.protocol, ApiProtocol, _ERR_CANDIDATE)
        _token(self.contract_operation_id)
        _token(self.service_name)
        _token(self.transport_operation)
        _route(self.route_template)
        _sorted_tokens(self.generated_client_symbols)

    @property
    def id(self) -> str:
        """Return immutable contract binding identity."""
        return _identity(
            "api-contract-binding-candidate.v1",
            {
                "contract_operation_id": self.contract_operation_id,
                "evidence_id": self.evidence.evidence_id,
                "generated_client_symbols": list(self.generated_client_symbols),
                "protocol": self.protocol.value,
                "route": self.route_template,
                "service": self.service_name,
                "transport_operation": self.transport_operation,
            },
        )


@dataclass(frozen=True, slots=True)
class ServiceOwnershipCandidate:
    """Project ownership plus non-secret service, base-reference, and gateway aliases."""

    evidence: ApiTopologyEvidence
    service_name: str
    aliases: tuple[str, ...] = ()
    base_url_references: tuple[str, ...] = ()
    gateway_prefixes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Require canonical sorted aliases and configuration references only."""
        _token(self.service_name)
        _sorted_tokens(self.aliases)
        if self.base_url_references != tuple(sorted(set(self.base_url_references))) or any(
            _ENV_REF.fullmatch(value) is None for value in self.base_url_references
        ):
            raise IndexingValidationError(_ERR_CANDIDATE)
        if self.gateway_prefixes != tuple(sorted(set(self.gateway_prefixes))):
            raise IndexingValidationError(_ERR_CANDIDATE)
        for prefix in self.gateway_prefixes:
            _route(prefix)

    @property
    def id(self) -> str:
        """Return immutable service-ownership identity."""
        return _identity(
            "api-service-ownership-candidate.v1",
            {
                "aliases": list(self.aliases),
                "base_url_references": list(self.base_url_references),
                "evidence_id": self.evidence.evidence_id,
                "gateway_prefixes": list(self.gateway_prefixes),
                "service": self.service_name,
            },
        )


ApiTopologyCandidate = (
    EndpointCandidate | ClientCallCandidate | ContractBindingCandidate | ServiceOwnershipCandidate
)


@dataclass(frozen=True, slots=True)
class ApiTopologySourceArtifact:
    """Ephemeral authorized source supplied to one deterministic topology plugin."""

    evidence: ApiTopologyEvidence
    commit_sha: str
    content: bytes
    service_hint: str | None = None

    def __post_init__(self) -> None:
        """Bound parser input and require immutable commit and matching relative path evidence."""
        if _COMMIT.fullmatch(self.commit_sha) is None:
            raise IndexingValidationError(_ERR_BATCH)
        if not 0 < len(self.content) <= _MAX_ARTIFACT_BYTES:
            raise IndexingValidationError(_ERR_BATCH)
        if self.service_hint is not None:
            _token(self.service_hint)


@dataclass(frozen=True, slots=True)
class ApiTopologyCandidateBatch:
    """Complete plugin output for one immutable source revision context."""

    plugin_kind: ApiTopologyPluginKind
    plugin_version: str
    source_revision_context_id: str
    source_file_id: str
    commit_sha: str
    endpoints: tuple[EndpointCandidate, ...] = ()
    client_calls: tuple[ClientCallCandidate, ...] = ()
    contract_bindings: tuple[ContractBindingCandidate, ...] = ()
    service_ownership: tuple[ServiceOwnershipCandidate, ...] = ()

    def __post_init__(self) -> None:
        """Require complete canonical output, including an explicit empty removal batch."""
        _enum(self.plugin_kind, ApiTopologyPluginKind, _ERR_BATCH)
        _token(self.plugin_version)
        _digest(self.source_revision_context_id, _ERR_BATCH)
        _digest(self.source_file_id, _ERR_BATCH)
        if _COMMIT.fullmatch(self.commit_sha) is None:
            raise IndexingValidationError(_ERR_BATCH)
        collections = (
            self.endpoints,
            self.client_calls,
            self.contract_bindings,
            self.service_ownership,
        )
        if sum(len(values) for values in collections) > _MAX_CANDIDATES:
            raise IndexingValidationError(_ERR_BATCH)
        for values in collections:
            if tuple(item.id for item in values) != tuple(sorted({item.id for item in values})):
                raise IndexingValidationError(_ERR_BATCH)
            for item in values:
                if (
                    item.evidence.source_revision_context_id != self.source_revision_context_id
                    or item.evidence.source_file_id != self.source_file_id
                ):
                    raise IndexingValidationError(_ERR_BATCH)
        scopes = {item.evidence.scope_key for item in self.candidates}
        if len(scopes) > 1:
            raise IndexingValidationError(_ERR_BATCH)

    @property
    def candidates(self) -> tuple[ApiTopologyCandidate, ...]:
        """Return all candidates in stable kind and identity order."""
        return (
            *self.endpoints,
            *self.client_calls,
            *self.contract_bindings,
            *self.service_ownership,
        )

    @property
    def digest(self) -> str:
        """Bind the complete plugin output and empty-removal state."""
        return _identity(
            "api-topology-candidate-batch.v1",
            {
                "client_calls": [item.id for item in self.client_calls],
                "commit_sha": self.commit_sha,
                "contract_bindings": [item.id for item in self.contract_bindings],
                "endpoints": [item.id for item in self.endpoints],
                "plugin_kind": self.plugin_kind.value,
                "plugin_version": self.plugin_version,
                "service_ownership": [item.id for item in self.service_ownership],
                "source_file_id": self.source_file_id,
                "source_revision_context_id": self.source_revision_context_id,
            },
        )


@dataclass(frozen=True, slots=True)
class ApiTopologyMatch:
    """One explainable endpoint candidate for a client call."""

    client_call_id: str
    endpoint_id: str
    client_entity_id: str
    endpoint_entity_id: str
    rule: ApiMatchRule
    rule_version: str
    disposition: ApiMatchDisposition
    rank: int
    confidence_basis_points: int
    client_evidence_id: str
    server_evidence_id: str
    supporting_candidate_ids: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    qualification_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        """Require deterministic proof identities, ranking, and qualification."""
        for value in (self.client_call_id, self.endpoint_id):
            _digest(value, _ERR_LINK)
        for value in (
            self.client_entity_id,
            self.endpoint_entity_id,
            self.client_evidence_id,
            self.server_evidence_id,
        ):
            _stable_id(value, _ERR_LINK)
        _enum(self.rule, ApiMatchRule, _ERR_LINK)
        _token(self.rule_version)
        _enum(self.disposition, ApiMatchDisposition, _ERR_LINK)
        if (
            not 1 <= self.rank <= _MAX_CANDIDATES
            or not 0 <= self.confidence_basis_points <= _MAX_BASIS_POINTS
        ):
            raise IndexingValidationError(_ERR_LINK)
        _sorted_digests(self.supporting_candidate_ids)
        _sorted_stable_ids(self.supporting_evidence_ids)
        _sorted_tokens(self.qualification_codes)
        required = {self.client_call_id, self.endpoint_id}
        if not required <= set(self.supporting_candidate_ids):
            raise IndexingValidationError(_ERR_LINK)
        if not {self.client_evidence_id, self.server_evidence_id} <= set(
            self.supporting_evidence_ids
        ):
            raise IndexingValidationError(_ERR_LINK)

    @property
    def id(self) -> str:
        """Return stable match identity for assertion and receipt replay."""
        return _identity(
            "api-topology-match.v1",
            {
                "client_call_id": self.client_call_id,
                "endpoint_id": self.endpoint_id,
                "rule": self.rule.value,
                "rule_version": self.rule_version,
                "supporting_candidate_ids": list(self.supporting_candidate_ids),
            },
        )


@dataclass(frozen=True, slots=True)
class ApiTopologyLinkDecision:
    """Complete deterministic result for one client call and candidate universe."""

    client_call_id: str
    candidate_universe_digest: str
    matches: tuple[ApiTopologyMatch, ...]

    def __post_init__(self) -> None:
        """Require ordered ranks and at most one authoritative match."""
        _digest(self.client_call_id, _ERR_LINK)
        _digest(self.candidate_universe_digest, _ERR_LINK)
        if tuple(item.id for item in self.matches) != tuple(
            item.id for item in sorted(self.matches, key=lambda item: item.rank)
        ):
            raise IndexingValidationError(_ERR_LINK)
        if tuple(item.rank for item in self.matches) != tuple(range(1, len(self.matches) + 1)):
            raise IndexingValidationError(_ERR_LINK)
        confirmed = [
            item for item in self.matches if item.disposition is ApiMatchDisposition.CONFIRMED
        ]
        if len(confirmed) > 1 or (confirmed and confirmed[0].rank != 1):
            raise IndexingValidationError(_ERR_LINK)

    @property
    def digest(self) -> str:
        """Bind the complete ranked decision for idempotent persistence."""
        return _identity(
            "api-topology-link-decision.v1",
            {
                "candidate_universe_digest": self.candidate_universe_digest,
                "client_call_id": self.client_call_id,
                "matches": [item.id for item in self.matches],
            },
        )


class ApiTopologyLinkPolicy:
    """Apply explicit precedence without guessing through ambiguity."""

    RULE_VERSION = "api-topology-linker-1.0.0"

    @classmethod
    def link(
        cls,
        client: ClientCallCandidate,
        endpoints: tuple[EndpointCandidate, ...],
        contracts: tuple[ContractBindingCandidate, ...],
        ownership: tuple[ServiceOwnershipCandidate, ...],
    ) -> ApiTopologyLinkDecision:
        """Rank every compatible endpoint and qualify ties or dynamic routing."""
        universe_digest = _universe_digest(client, endpoints, contracts, ownership)
        ranked: list[tuple[EndpointCandidate, ApiMatchRule, tuple[str, ...], tuple[str, ...]]] = []
        for endpoint in endpoints:
            match = _strongest_match(client, endpoint, contracts, ownership)
            if match is not None:
                rule, candidate_ids, codes = match
                ranked.append((endpoint, rule, candidate_ids, codes))
        ranked.sort(key=lambda item: (-item[1].precedence, item[0].id))
        unique_top = (
            bool(ranked)
            and (len(ranked) == 1 or ranked[0][1].precedence > ranked[1][1].precedence)
            and not client.dynamic
            and not ranked[0][0].dynamic
        )
        matches: list[ApiTopologyMatch] = []
        for index, (endpoint, rule, candidate_ids, codes) in enumerate(ranked, start=1):
            confirmed = index == 1 and unique_top
            qualification_codes = set(codes)
            if not confirmed:
                qualification_codes.add("requires_disambiguation")
            if client.dynamic or endpoint.dynamic:
                qualification_codes.add("dynamic_routing")
            supporting: tuple[ContractBindingCandidate | ServiceOwnershipCandidate, ...] = (
                *contracts,
                *ownership,
            )
            evidence_ids = tuple(
                sorted(
                    {
                        client.evidence.evidence_id,
                        endpoint.evidence.evidence_id,
                        *(
                            item.evidence.evidence_id
                            for item in supporting
                            if item.id in candidate_ids
                        ),
                    }
                )
            )
            matches.append(
                ApiTopologyMatch(
                    client.id,
                    endpoint.id,
                    client.consumer_entity_id,
                    endpoint.endpoint_entity_id,
                    rule,
                    cls.RULE_VERSION,
                    (ApiMatchDisposition.CONFIRMED if confirmed else ApiMatchDisposition.QUALIFIED),
                    index,
                    _confidence(
                        rule, confirmed=confirmed, dynamic=client.dynamic or endpoint.dynamic
                    ),
                    client.evidence.evidence_id,
                    endpoint.evidence.evidence_id,
                    tuple(sorted({client.id, endpoint.id, *candidate_ids})),
                    evidence_ids,
                    tuple(sorted(qualification_codes)),
                )
            )
        return ApiTopologyLinkDecision(client.id, universe_digest, tuple(matches))


def normalize_route_template(value: str) -> str:
    """Normalize route parameters, slashes, and URL path without retaining query values."""
    if "://" in value:
        parsed = urlsplit(value)
        value = parsed.path
    value = value.split("?", 1)[0].split("#", 1)[0]
    value = re.sub(r"/+", "/", value.strip())
    if not value.startswith("/"):
        value = f"/{value}"
    normalized = _PARAMETER.sub("{}", value)
    if normalized != "/":
        normalized = normalized.rstrip("/")
    _route(normalized)
    return normalized


def _strongest_match(
    client: ClientCallCandidate,
    endpoint: EndpointCandidate,
    contracts: tuple[ContractBindingCandidate, ...],
    ownership: tuple[ServiceOwnershipCandidate, ...],
) -> tuple[ApiMatchRule, tuple[str, ...], tuple[str, ...]] | None:
    if client.protocol is not endpoint.protocol:
        return None
    operation_contracts = tuple(
        item
        for item in contracts
        if item.protocol is client.protocol
        and item.contract_operation_id
        in {client.contract_operation_id, endpoint.contract_operation_id}
    )
    if (
        client.contract_operation_id is not None
        and endpoint.contract_operation_id == client.contract_operation_id
    ) or any(
        item.contract_operation_id == client.contract_operation_id
        and _contract_targets(item, endpoint)
        for item in operation_contracts
    ):
        return (
            ApiMatchRule.CONTRACT_OPERATION,
            tuple(sorted(item.id for item in operation_contracts)),
            (),
        )
    symbol_contracts = tuple(
        item
        for item in contracts
        if client.generated_client_symbol is not None
        and client.generated_client_symbol in item.generated_client_symbols
        and _contract_targets(item, endpoint)
    )
    if symbol_contracts:
        return (
            ApiMatchRule.GENERATED_CLIENT_SYMBOL,
            tuple(sorted(item.id for item in symbol_contracts)),
            (),
        )
    owners = tuple(item for item in ownership if item.service_name == endpoint.service_name)
    matched_owners = tuple(
        item
        for item in owners
        if (
            client.service_reference is not None
            and client.service_reference in {item.service_name, *item.aliases}
        )
        or (
            client.base_url_reference is not None
            and client.base_url_reference in item.base_url_references
        )
    )
    if matched_owners and _route_compatible(client, endpoint, matched_owners):
        codes = (
            ("gateway_prefix_applied",)
            if _gateway_required(client, endpoint, matched_owners)
            else ()
        )
        return (
            ApiMatchRule.SERVICE_BASE_URL,
            tuple(sorted(item.id for item in matched_owners)),
            codes,
        )
    if not client.dynamic and not endpoint.dynamic and _route_compatible(client, endpoint, owners):
        return ApiMatchRule.HEURISTIC_PATH, (), ("heuristic_match",)
    return None


def _contract_targets(binding: ContractBindingCandidate, endpoint: EndpointCandidate) -> bool:
    return (
        binding.protocol is endpoint.protocol
        and binding.service_name == endpoint.service_name
        and binding.transport_operation.casefold() == endpoint.transport_operation.casefold()
        and normalize_route_template(binding.route_template)
        == normalize_route_template(endpoint.route_template)
    )


def _route_compatible(
    client: ClientCallCandidate,
    endpoint: EndpointCandidate,
    owners: tuple[ServiceOwnershipCandidate, ...],
) -> bool:
    if client.transport_operation.casefold() != endpoint.transport_operation.casefold():
        return False
    client_route = normalize_route_template(client.route_template)
    endpoint_route = normalize_route_template(endpoint.route_template)
    if client_route == endpoint_route:
        return True
    for owner in owners:
        for prefix in owner.gateway_prefixes:
            normalized_prefix = normalize_route_template(prefix)
            if client_route == f"{normalized_prefix.rstrip('/')}{endpoint_route}":
                return True
    return False


def _gateway_required(
    client: ClientCallCandidate,
    endpoint: EndpointCandidate,
    owners: tuple[ServiceOwnershipCandidate, ...],
) -> bool:
    return normalize_route_template(client.route_template) != normalize_route_template(
        endpoint.route_template
    ) and _route_compatible(client, endpoint, owners)


def _confidence(rule: ApiMatchRule, *, confirmed: bool, dynamic: bool) -> int:
    base = {
        ApiMatchRule.CONTRACT_OPERATION: 9_800,
        ApiMatchRule.GENERATED_CLIENT_SYMBOL: 9_300,
        ApiMatchRule.SERVICE_BASE_URL: 8_500,
        ApiMatchRule.HEURISTIC_PATH: 7_200,
    }[rule]
    if not confirmed:
        base -= 800
    if dynamic:
        base -= 1_000
    return max(0, base)


def _universe_digest(
    client: ClientCallCandidate,
    endpoints: tuple[EndpointCandidate, ...],
    contracts: tuple[ContractBindingCandidate, ...],
    ownership: tuple[ServiceOwnershipCandidate, ...],
) -> str:
    return _identity(
        "api-topology-candidate-universe.v1",
        {
            "client": client.id,
            "contracts": sorted(item.id for item in contracts),
            "endpoints": sorted(item.id for item in endpoints),
            "ownership": sorted(item.id for item in ownership),
        },
    )


def _identity(namespace: str, document: dict[str, object]) -> str:
    encoded = json.dumps(document, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(f"{namespace}\0{encoded}".encode()).hexdigest()


def _path(value: str) -> None:
    if not value or len(value.encode()) > _MAX_PATH_BYTES or "\\" in value or "\x00" in value:
        raise IndexingValidationError(_ERR_CANDIDATE)
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise IndexingValidationError(_ERR_CANDIDATE)


def _route(value: str) -> None:
    if (
        not value
        or len(value.encode()) > _MAX_PATH_BYTES
        or not value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or "?" in value
        or "#" in value
    ):
        raise IndexingValidationError(_ERR_CANDIDATE)


def _token(value: str) -> None:
    if _TOKEN.fullmatch(value) is None:
        raise IndexingValidationError(_ERR_CANDIDATE)


def _sorted_tokens(values: tuple[str, ...]) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(_ERR_CANDIDATE)
    for value in values:
        _token(value)


def _sorted_digests(values: tuple[str, ...]) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(_ERR_LINK)
    for value in values:
        _digest(value, _ERR_LINK)


def _sorted_stable_ids(values: tuple[str, ...]) -> None:
    if values != tuple(sorted(set(values))):
        raise IndexingValidationError(_ERR_LINK)
    for value in values:
        _stable_id(value, _ERR_LINK)


def _digest(value: object, error: str) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise IndexingValidationError(error)


def _stable_id(value: str, error: str) -> None:
    try:
        parsed = UUID(value)
    except ValueError as exception:
        raise IndexingValidationError(error) from exception
    if parsed.version != _UUID7 or str(parsed) != value:
        raise IndexingValidationError(error)


def _enum(value: object, expected: type[StrEnum], error: str) -> None:
    if not isinstance(value, expected):
        raise IndexingValidationError(error)


def _bool(value: object) -> None:
    if not isinstance(value, bool):
        raise IndexingValidationError(_ERR_CANDIDATE)


def _utc(value: datetime, error: str) -> None:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise IndexingValidationError(error)
