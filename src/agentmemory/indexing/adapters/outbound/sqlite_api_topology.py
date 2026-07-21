"""IDX-004 append-only SQLite API topology candidate and decision repository."""

from __future__ import annotations

import hashlib
import json
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import bindparam, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.indexing.domain.api_topology import (
    ApiMatchDisposition,
    ApiMatchRule,
    ApiProtocol,
    ApiTopologyCandidate,
    ApiTopologyCandidateBatch,
    ApiTopologyEvidence,
    ApiTopologyLinkDecision,
    ApiTopologyMatch,
    ApiTopologyPluginKind,
    ClientCallCandidate,
    ContractBindingCandidate,
    EndpointCandidate,
    ServiceOwnershipCandidate,
)
from agentmemory.indexing.domain.errors import (
    IndexingAuthorizationError,
    IndexingConflictError,
    IndexingUnavailableError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Mapping, Sequence

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.shared.clock import Clock

_ERR_ACTION = "API topology repository action is not authorized"
_ERR_AUTHORIZATION = "API topology repository scope is not authorized"
_ERR_CONFLICT = "API topology evidence conflicts with immutable history"
_ERR_STORAGE = "API topology storage is unavailable"
_WRITE_ROLES = frozenset({"owner", "admin", "editor", "worker"})
_READ_ROLES = frozenset({"owner", "admin", "editor", "reader", "auditor", "worker"})


class SqliteApiTopologyRepository:
    """Persist complete source outputs and explainable cross-project link decisions."""

    def __init__(self, store: SqliteCoreStore, clock: Clock) -> None:
        """Bind the canonical single-writer store and trusted authorization clock."""
        self._store = store
        self._clock = clock

    async def find_batch_by_operation(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ApiTopologyCandidateBatch | None:
        """Return an exact authorized registration replay."""
        _require_action(scope, "indexing.api_topology.register")
        try:
            async with self._store.engine.connect() as connection:
                row = await _batch_operation_row(connection, operation_id)
                if row is None:
                    return None
                await _authorize_row(connection, scope, row, self._clock.now(), write=True)
                _conflict_if(
                    str(row["principal_id"]) != scope.principal_id.value
                    or _blob(row["scope_fingerprint"]).hex() != scope.scope_fingerprint
                )
                return await _batch(connection, row)
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def register_batch(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        batch: ApiTopologyCandidateBatch,
        registered_at: datetime,
    ) -> ApiTopologyCandidateBatch:
        """Append a complete plugin result and supersede the prior result for its source."""
        _require_action(scope, "indexing.api_topology.register")
        try:
            async with _write_transaction(self._store) as connection:
                existing = await _batch_operation_row(connection, operation_id)
                if existing is not None:
                    await _authorize_row(connection, scope, existing, self._clock.now(), write=True)
                    stored = await _batch(connection, existing)
                    _conflict_if(
                        stored != batch
                        or _blob(existing["scope_fingerprint"]).hex() != scope.scope_fingerprint
                    )
                    return stored
                context = await _context_row(connection, batch.source_revision_context_id)
                _unauthorized_if(context is None)
                context = cast("RowMapping", context)
                await _authorize_row(connection, scope, context, self._clock.now(), write=True)
                _conflict_if(
                    str(context["source_file_id"]) != batch.source_file_id
                    or str(context["commit_sha"]) != batch.commit_sha
                )
                for candidate in batch.candidates:
                    await _validate_candidate(connection, candidate.evidence, context)
                previous = (
                    await connection.execute(
                        text(
                            "SELECT batch_id FROM api_topology_candidate_batches "
                            "WHERE brain_id=:brain AND repository_id=:repository "
                            "AND source_file_id=:source ORDER BY registered_at DESC,batch_id DESC "
                            "LIMIT 1"
                        ),
                        {
                            "brain": str(context["brain_id"]),
                            "repository": str(context["repository_id"]),
                            "source": batch.source_file_id,
                        },
                    )
                ).scalar_one_or_none()
                await connection.execute(
                    text(
                        "INSERT INTO api_topology_candidate_batches"
                        "(batch_id,operation_id,brain_id,project_id,repository_id,source_file_id,"
                        "source_revision_context_id,commit_sha,plugin_kind,plugin_version,"
                        "batch_digest,supersedes_batch_id,principal_id,scope_fingerprint,"
                        "registered_at,schema_version) VALUES(:batch,:operation,:brain,:project,"
                        ":repository,:source,:context,:commit,:kind,:version,:digest,:supersedes,"
                        ":principal,:scope,:registered,1)"
                    ),
                    {
                        "batch": batch.digest,
                        "operation": operation_id,
                        "brain": str(context["brain_id"]),
                        "project": str(context["project_id"]),
                        "repository": str(context["repository_id"]),
                        "source": batch.source_file_id,
                        "context": batch.source_revision_context_id,
                        "commit": batch.commit_sha,
                        "kind": batch.plugin_kind.value,
                        "version": batch.plugin_version,
                        "digest": bytes.fromhex(batch.digest),
                        "supersedes": previous,
                        "principal": scope.principal_id.value,
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "registered": _micros(registered_at),
                    },
                )
                await _insert_candidates(connection, batch, registered_at)
                return batch
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def load_link_universe(
        self,
        scope: AuthorizedScope,
        client_call_id: str,
        linked_at: datetime,
    ) -> tuple[
        ClientCallCandidate,
        tuple[EndpointCandidate, ...],
        tuple[ContractBindingCandidate, ...],
        tuple[ServiceOwnershipCandidate, ...],
    ]:
        """Load latest candidates at the cutoff from only explicitly authorized members."""
        _require_action(scope, "indexing.api_topology.link")
        try:
            async with self._store.engine.connect() as connection:
                await _authorize_all(connection, scope, self._clock.now(), write=False)
                repositories = tuple(value.value for value in scope.repository_ids)
                batches = await _latest_batch_ids(connection, repositories, linked_at)
                _unauthorized_if(not batches)
                clients = await _candidate_rows(
                    connection, "api_topology_client_call_candidates", batches
                )
                client_rows = [row for row in clients if str(row["candidate_id"]) == client_call_id]
                _unauthorized_if(len(client_rows) != 1)
                endpoints = await _candidate_rows(
                    connection, "api_topology_endpoint_candidates", batches
                )
                contracts = await _candidate_rows(
                    connection, "api_topology_contract_binding_candidates", batches
                )
                ownership = await _candidate_rows(
                    connection, "api_topology_service_ownership_candidates", batches
                )
                return (
                    _client(client_rows[0]),
                    tuple(_endpoint(row) for row in endpoints),
                    tuple(_contract(row) for row in contracts),
                    tuple(_ownership(row) for row in ownership),
                )
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def find_link_decision(
        self, scope: AuthorizedScope, operation_id: str
    ) -> ApiTopologyLinkDecision | None:
        """Return an exact scope-bound link replay."""
        _require_action(scope, "indexing.api_topology.link")
        try:
            async with self._store.engine.connect() as connection:
                row = await _link_row(connection, operation_id)
                if row is None:
                    return None
                _conflict_if(
                    str(row["brain_id"]) != scope.brain_id.value
                    or str(row["principal_id"]) != scope.principal_id.value
                    or _blob(row["scope_fingerprint"]).hex() != scope.scope_fingerprint
                )
                await _authorize_all(connection, scope, self._clock.now(), write=False)
                return await _decision(connection, row)
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def record_link_decision(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        decision: ApiTopologyLinkDecision,
        assertion_ids: tuple[str, ...],
        linked_at: datetime,
    ) -> ApiTopologyLinkDecision:
        """Atomically retain a complete ranked decision and its canonical assertion receipts."""
        _require_action(scope, "indexing.api_topology.link")
        _conflict_if(len(assertion_ids) != len(decision.matches))
        try:
            async with _write_transaction(self._store) as connection:
                existing = await _link_row(connection, operation_id)
                if existing is not None:
                    stored = await _decision(connection, existing)
                    _conflict_if(
                        stored != decision
                        or _blob(existing["scope_fingerprint"]).hex() != scope.scope_fingerprint
                    )
                    return stored
                await _authorize_all(connection, scope, self._clock.now(), write=True)
                await connection.execute(
                    text(
                        "INSERT INTO api_topology_link_operations(operation_id,brain_id,"
                        "principal_id,scope_fingerprint,client_call_id,candidate_universe_digest,"
                        "decision_digest,match_count,linked_at,schema_version) VALUES(:operation,"
                        ":brain,:principal,:scope,:client,:universe,:decision,:count,:linked,1)"
                    ),
                    {
                        "operation": operation_id,
                        "brain": scope.brain_id.value,
                        "principal": scope.principal_id.value,
                        "scope": bytes.fromhex(scope.scope_fingerprint),
                        "client": decision.client_call_id,
                        "universe": bytes.fromhex(decision.candidate_universe_digest),
                        "decision": bytes.fromhex(decision.digest),
                        "count": len(decision.matches),
                        "linked": _micros(linked_at),
                    },
                )
                for match, assertion_id in zip(decision.matches, assertion_ids, strict=True):
                    await _insert_match(connection, operation_id, match, assertion_id)
                return decision
        except IndexingAuthorizationError, IndexingConflictError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error


async def _insert_candidates(
    connection: AsyncConnection, batch: ApiTopologyCandidateBatch, registered_at: datetime
) -> None:
    for endpoint in batch.endpoints:
        await _insert_candidate(
            connection,
            "api_topology_endpoint_candidates",
            batch.digest,
            endpoint,
            {
                "endpoint_entity_id": endpoint.endpoint_entity_id,
                "protocol": endpoint.protocol.value,
                "service_name": endpoint.service_name,
                "transport_operation": endpoint.transport_operation,
                "route_template": endpoint.route_template,
                "contract_operation_id": endpoint.contract_operation_id,
                "dynamic": endpoint.dynamic,
            },
            registered_at,
        )
    for client in batch.client_calls:
        await _insert_candidate(
            connection,
            "api_topology_client_call_candidates",
            batch.digest,
            client,
            {
                "consumer_entity_id": client.consumer_entity_id,
                "protocol": client.protocol.value,
                "transport_operation": client.transport_operation,
                "route_template": client.route_template,
                "contract_operation_id": client.contract_operation_id,
                "generated_client_symbol": client.generated_client_symbol,
                "service_reference": client.service_reference,
                "base_url_reference": client.base_url_reference,
                "dynamic": client.dynamic,
            },
            registered_at,
        )
    for contract in batch.contract_bindings:
        await _insert_candidate(
            connection,
            "api_topology_contract_binding_candidates",
            batch.digest,
            contract,
            {
                "protocol": contract.protocol.value,
                "contract_operation_id": contract.contract_operation_id,
                "service_name": contract.service_name,
                "transport_operation": contract.transport_operation,
                "route_template": contract.route_template,
                "generated_client_symbols_json": _json(contract.generated_client_symbols),
            },
            registered_at,
        )
    for owner in batch.service_ownership:
        await _insert_candidate(
            connection,
            "api_topology_service_ownership_candidates",
            batch.digest,
            owner,
            {
                "service_name": owner.service_name,
                "aliases_json": _json(owner.aliases),
                "base_url_references_json": _json(owner.base_url_references),
                "gateway_prefixes_json": _json(owner.gateway_prefixes),
            },
            registered_at,
        )


async def _insert_candidate(  # noqa: PLR0913 -- Candidate persistence is append-only.
    connection: AsyncConnection,
    table: str,
    batch_id: str,
    candidate: ApiTopologyCandidate,
    specific: Mapping[str, object],
    registered_at: datetime,
) -> None:
    item = candidate
    values: dict[str, object] = {
        "candidate_id": item.id,
        "batch_id": batch_id,
        "evidence_id": item.evidence.evidence_id,
        "source_semantic_id": item.evidence.source_semantic_id,
        "relative_path": item.evidence.relative_path,
        "classification": item.evidence.classification,
        "observed_at": _micros(item.evidence.observed_at),
        "schema_version": 1,
        **specific,
    }
    columns = tuple(values)
    statement = text(
        f"INSERT INTO {table}({','.join(columns)}) "  # nosec B608
        f"VALUES({','.join(':' + column for column in columns)})"
    )
    await connection.execute(statement, values)
    dependency_id = hashlib.sha256(
        f"api-topology-dependency.v1\0{item.id}\0{item.evidence.source_semantic_id}\0"
        f"{item.evidence.evidence_id}".encode()
    ).hexdigest()
    await connection.execute(
        text(
            "INSERT INTO index_semantic_dependencies(dependency_id,repository_id,"
            "source_semantic_id,dependent_fact_id,assertion_evidence_id,registered_at,"
            "schema_version) VALUES(:id,:repository,:semantic,:fact,:evidence,:registered,1)"
        ),
        {
            "id": dependency_id,
            "repository": item.evidence.repository_id,
            "semantic": item.evidence.source_semantic_id,
            "fact": item.id,
            "evidence": item.evidence.evidence_id,
            "registered": _micros(registered_at),
        },
    )


async def _validate_candidate(
    connection: AsyncConnection, evidence: ApiTopologyEvidence, context: RowMapping
) -> None:
    _conflict_if(
        evidence.brain_id != str(context["brain_id"])
        or evidence.project_id != str(context["project_id"])
        or evidence.repository_id != str(context["repository_id"])
        or evidence.source_file_id != str(context["source_file_id"])
        or evidence.source_revision_context_id != str(context["context_id"])
        or evidence.relative_path != str(context["relative_path"])
    )
    row = (
        (
            await connection.execute(
                text(
                    "SELECT source.brain_id,source.project_id,source.repository_id,"
                    "source.classification,semantic.file_revision_id FROM "
                    "assertion_evidence_sources AS source JOIN "
                    "(SELECT file_revision_id FROM symbol_revisions WHERE id=:semantic "
                    "UNION ALL SELECT file_revision_id FROM symbol_occurrences "
                    "WHERE id=:semantic) AS semantic WHERE source.evidence_id=:evidence"
                ),
                {"semantic": evidence.source_semantic_id, "evidence": evidence.evidence_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    _conflict_if(
        row is None
        or str(row["brain_id"]) != evidence.brain_id
        or str(row["project_id"]) != evidence.project_id
        or str(row["repository_id"]) != evidence.repository_id
        or str(row["classification"]) != evidence.classification
        or str(row["file_revision_id"]) != str(context["file_revision_id"])
    )


async def _latest_batch_ids(
    connection: AsyncConnection, repositories: tuple[str, ...], linked_at: datetime
) -> tuple[str, ...]:
    statement = text(
        "SELECT batch.batch_id FROM api_topology_candidate_batches AS batch "
        "WHERE batch.repository_id IN :repositories AND batch.registered_at<=:cutoff "
        "AND NOT EXISTS(SELECT 1 FROM api_topology_candidate_batches AS newer "
        "WHERE newer.brain_id=batch.brain_id AND newer.repository_id=batch.repository_id "
        "AND newer.source_file_id=batch.source_file_id AND newer.registered_at<=:cutoff "
        "AND (newer.registered_at>batch.registered_at OR "
        "(newer.registered_at=batch.registered_at AND newer.batch_id>batch.batch_id))) "
        "ORDER BY batch.batch_id"
    ).bindparams(bindparam("repositories", expanding=True))
    rows = await connection.execute(
        statement, {"repositories": repositories, "cutoff": _micros(linked_at)}
    )
    return tuple(str(value) for value in rows.scalars())


async def _candidate_rows(
    connection: AsyncConnection, table: str, batches: tuple[str, ...]
) -> Sequence[RowMapping]:
    statement = text(
        f"SELECT candidate.*,batch.brain_id,batch.project_id,batch.repository_id,"  # noqa: S608  # nosec B608
        f"batch.source_file_id,batch.source_revision_context_id FROM {table} AS candidate "
        "JOIN api_topology_candidate_batches AS batch ON batch.batch_id=candidate.batch_id "
        "WHERE candidate.batch_id IN :batches ORDER BY candidate.candidate_id"
    ).bindparams(bindparam("batches", expanding=True))
    return (await connection.execute(statement, {"batches": batches})).mappings().all()


async def _batch_operation_row(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM api_topology_candidate_batches WHERE operation_id=:id"),
                {"id": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _context_row(connection: AsyncConnection, context_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM source_revision_contexts WHERE context_id=:id"),
                {"id": context_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _batch(connection: AsyncConnection, row: RowMapping) -> ApiTopologyCandidateBatch:
    batch_id = str(row["batch_id"])
    batches = (batch_id,)
    endpoints = await _candidate_rows(connection, "api_topology_endpoint_candidates", batches)
    clients = await _candidate_rows(connection, "api_topology_client_call_candidates", batches)
    contracts = await _candidate_rows(
        connection, "api_topology_contract_binding_candidates", batches
    )
    ownership = await _candidate_rows(
        connection, "api_topology_service_ownership_candidates", batches
    )
    return ApiTopologyCandidateBatch(
        ApiTopologyPluginKind(str(row["plugin_kind"])),
        str(row["plugin_version"]),
        str(row["source_revision_context_id"]),
        str(row["source_file_id"]),
        str(row["commit_sha"]),
        tuple(_endpoint(item) for item in endpoints),
        tuple(_client(item) for item in clients),
        tuple(_contract(item) for item in contracts),
        tuple(_ownership(item) for item in ownership),
    )


def _evidence(row: RowMapping) -> ApiTopologyEvidence:
    return ApiTopologyEvidence(
        str(row["brain_id"]),
        str(row["project_id"]),
        str(row["repository_id"]),
        str(row["source_file_id"]),
        str(row["source_revision_context_id"]),
        str(row["source_semantic_id"]),
        str(row["evidence_id"]),
        str(row["relative_path"]),
        str(row["classification"]),
        _datetime(int(row["observed_at"])),
    )


def _endpoint(row: RowMapping) -> EndpointCandidate:
    contract = row["contract_operation_id"]
    return EndpointCandidate(
        _evidence(row),
        str(row["endpoint_entity_id"]),
        ApiProtocol(str(row["protocol"])),
        str(row["service_name"]),
        str(row["transport_operation"]),
        str(row["route_template"]),
        None if contract is None else str(contract),
        bool(row["dynamic"]),
    )


def _client(row: RowMapping) -> ClientCallCandidate:
    return ClientCallCandidate(
        _evidence(row),
        str(row["consumer_entity_id"]),
        ApiProtocol(str(row["protocol"])),
        str(row["transport_operation"]),
        str(row["route_template"]),
        _optional(row["contract_operation_id"]),
        _optional(row["generated_client_symbol"]),
        _optional(row["service_reference"]),
        _optional(row["base_url_reference"]),
        bool(row["dynamic"]),
    )


def _contract(row: RowMapping) -> ContractBindingCandidate:
    return ContractBindingCandidate(
        _evidence(row),
        ApiProtocol(str(row["protocol"])),
        str(row["contract_operation_id"]),
        str(row["service_name"]),
        str(row["transport_operation"]),
        str(row["route_template"]),
        _json_tuple(row["generated_client_symbols_json"]),
    )


def _ownership(row: RowMapping) -> ServiceOwnershipCandidate:
    return ServiceOwnershipCandidate(
        _evidence(row),
        str(row["service_name"]),
        _json_tuple(row["aliases_json"]),
        _json_tuple(row["base_url_references_json"]),
        _json_tuple(row["gateway_prefixes_json"]),
    )


async def _insert_match(
    connection: AsyncConnection, operation_id: str, match: ApiTopologyMatch, assertion_id: str
) -> None:
    await connection.execute(
        text(
            "INSERT INTO api_topology_match_decisions(match_id,operation_id,client_call_id,"
            "rank,endpoint_id,"
            "client_entity_id,endpoint_entity_id,rule,rule_version,disposition,"
            "confidence_basis_points,client_evidence_id,server_evidence_id,"
            "supporting_candidate_ids_json,supporting_evidence_ids_json,"
            "qualification_codes_json,assertion_id,schema_version) VALUES(:match,:operation,"
            ":client,:rank,:endpoint,:client_entity,:endpoint_entity,:rule,:version,:disposition,"
            ":confidence,:client_evidence,:server_evidence,:candidates,:evidence,:codes,"
            ":assertion,1)"
        ),
        {
            "match": match.id,
            "operation": operation_id,
            "client": match.client_call_id,
            "rank": match.rank,
            "endpoint": match.endpoint_id,
            "client_entity": match.client_entity_id,
            "endpoint_entity": match.endpoint_entity_id,
            "rule": match.rule.value,
            "version": match.rule_version,
            "disposition": match.disposition.value,
            "confidence": match.confidence_basis_points,
            "client_evidence": match.client_evidence_id,
            "server_evidence": match.server_evidence_id,
            "candidates": _json(match.supporting_candidate_ids),
            "evidence": _json(match.supporting_evidence_ids),
            "codes": _json(match.qualification_codes),
            "assertion": assertion_id,
        },
    )


async def _link_row(connection: AsyncConnection, operation_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM api_topology_link_operations WHERE operation_id=:id"),
                {"id": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _decision(connection: AsyncConnection, row: RowMapping) -> ApiTopologyLinkDecision:
    matches = (
        (
            await connection.execute(
                text(
                    "SELECT * FROM api_topology_match_decisions WHERE operation_id=:id "
                    "ORDER BY rank"
                ),
                {"id": str(row["operation_id"])},
            )
        )
        .mappings()
        .all()
    )
    decision = ApiTopologyLinkDecision(
        str(row["client_call_id"]),
        _blob(row["candidate_universe_digest"]).hex(),
        tuple(_match(item) for item in matches),
    )
    _conflict_if(
        decision.digest != _blob(row["decision_digest"]).hex()
        or len(decision.matches) != int(row["match_count"])
    )
    return decision


def _match(row: RowMapping) -> ApiTopologyMatch:
    return ApiTopologyMatch(
        str(row["client_call_id"]),
        str(row["endpoint_id"]),
        str(row["client_entity_id"]),
        str(row["endpoint_entity_id"]),
        ApiMatchRule(str(row["rule"])),
        str(row["rule_version"]),
        ApiMatchDisposition(str(row["disposition"])),
        int(row["rank"]),
        int(row["confidence_basis_points"]),
        str(row["client_evidence_id"]),
        str(row["server_evidence_id"]),
        _json_tuple(row["supporting_candidate_ids_json"]),
        _json_tuple(row["supporting_evidence_ids_json"]),
        _json_tuple(row["qualification_codes_json"]),
    )


async def _authorize_all(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    now: datetime,
    *,
    write: bool,
) -> None:
    for member in scope.members:
        for repository_id in member.repository_ids:
            await _authorize(
                connection,
                scope,
                member.project_id.value,
                repository_id.value,
                now,
                write=write,
            )


async def _authorize_row(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    row: RowMapping,
    now: datetime,
    *,
    write: bool,
) -> None:
    await _authorize(
        connection,
        scope,
        str(row["project_id"]),
        str(row["repository_id"]),
        now,
        write=write,
    )


async def _authorize(  # noqa: PLR0913 -- Authority binds the complete repository scope.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    project_id: str,
    repository_id: str,
    now: datetime,
    *,
    write: bool,
) -> None:
    allowed = _WRITE_ROLES if write else _READ_ROLES
    _unauthorized_if(
        scope.role.value not in allowed
        or project_id not in {item.value for item in scope.project_ids}
        or repository_id not in {item.value for item in scope.repository_ids}
    )
    exists = (
        await connection.execute(
            text(
                "SELECT EXISTS(SELECT 1 FROM repositories AS repository JOIN "
                "project_repositories AS binding ON binding.repository_id=repository.id JOIN "
                "projects AS project ON project.id=binding.project_id WHERE "
                "repository.id=:repository AND project.id=:project AND repository.status='active' "
                "AND project.status='active' AND project.brain_id=:brain AND EXISTS(SELECT 1 "
                "FROM scope_grants AS grant_row WHERE grant_row.principal_id=:principal AND "
                "grant_row.brain_id=:brain AND grant_row.role=:role AND grant_row.valid_from<=:now "
                "AND (grant_row.valid_to IS NULL OR grant_row.valid_to>:now) AND "
                "(grant_row.project_id IS NULL OR grant_row.project_id=project.id) AND "
                "(grant_row.repository_id IS NULL OR grant_row.repository_id=repository.id)))"
            ),
            {
                "repository": repository_id,
                "project": project_id,
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
                "role": scope.role.value,
                "now": _micros(now),
            },
        )
    ).scalar_one()
    _unauthorized_if(not bool(exists))


def _require_action(scope: AuthorizedScope, action: str) -> None:
    if scope.action != action:
        raise IndexingAuthorizationError(_ERR_ACTION)


def _unauthorized_if(condition: bool) -> None:  # noqa: FBT001
    if condition:
        raise IndexingAuthorizationError(_ERR_AUTHORIZATION)


def _conflict_if(condition: bool) -> None:  # noqa: FBT001
    if condition:
        raise IndexingConflictError(_ERR_CONFLICT)


def _json(values: tuple[str, ...]) -> bytes:
    return json.dumps(values, separators=(",", ":")).encode()


def _json_tuple(value: object) -> tuple[str, ...]:
    parsed = json.loads(_blob(value))
    if not isinstance(parsed, list):
        raise IndexingConflictError(_ERR_CONFLICT)
    sequence = cast("list[object]", parsed)
    if any(not isinstance(item, str) for item in sequence):
        raise IndexingConflictError(_ERR_CONFLICT)
    return tuple(cast("list[str]", sequence))


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode()
    raise IndexingConflictError(_ERR_CONFLICT)


def _optional(value: object) -> str | None:
    return None if value is None else str(value)


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _datetime(value: int) -> datetime:
    return datetime.fromtimestamp(value / 1_000_000, UTC)


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    await store.write_lock.acquire()
    connection: AsyncConnection | None = None
    try:
        connection = await store.engine.connect()
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        yield connection
        await connection.commit()
    except BaseException:
        if connection is not None:
            await connection.rollback()
        raise
    finally:
        if connection is not None:
            await connection.close()
        store.write_lock.release()
