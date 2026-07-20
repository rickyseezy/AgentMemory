"""SQLite immutable capture-policy revisions and content-free decision evidence."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.ingestion.domain.agent_event import Classification
from agentmemory.ingestion.domain.errors import (
    IngestionConflictError,
    IngestionDependencyError,
    IngestionValidationError,
)
from agentmemory.ingestion.domain.privacy import (
    AllowedEgressRoute,
    CapturePolicy,
    CapturePolicyResult,
    EgressDestination,
    SensitiveAction,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_POLICY_UNAVAILABLE = "Capture privacy policy is unavailable"
_ERR_POLICY_MALFORMED = "Capture privacy policy storage is malformed"
_ERR_POLICY_CONFLICT = "Capture privacy policy revision conflicts with immutable history"
_ERR_DECISION_UNAVAILABLE = "Capture privacy decision could not be persisted"
_ERR_DECISION_CONFLICT = "Capture privacy decision identity was reused"
_BRAIN_SCOPE_KEY = "@brain"


class SqliteCapturePolicyRepository:
    """Resolve and activate immutable complete privacy-policy revisions."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical local store and its serialized writer lock."""
        self._store = store

    async def resolve(
        self,
        brain_id: str,
        repository_id: str | None,
        version: int | None,
    ) -> CapturePolicy:
        """Resolve exact repository scope, then Brain scope, then secure revision one."""
        try:
            async with self._store.engine.connect() as connection:
                row = await _policy_row(connection, brain_id, repository_id, version)
                if row is None and repository_id is not None:
                    row = await _policy_row(connection, brain_id, None, version)
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_POLICY_UNAVAILABLE) from error
        if row is None:
            if version not in {None, 1}:
                field = "policy_version"
                raise IngestionValidationError.single(field, "not_found")
            return CapturePolicy.secure_default(brain_id, repository_id)
        return _decode_policy(str(row["document_json"]))

    async def activate(self, policy: CapturePolicy, created_at_microseconds: int) -> None:
        """Append exactly the next revision and atomically supersede the active one."""
        await self._store.write_lock.acquire()
        try:
            async with self._store.engine.connect() as connection:
                await connection.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    await self._activate(connection, policy, created_at_microseconds)
                    await connection.commit()
                except BaseException:
                    await connection.rollback()
                    raise
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_POLICY_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_POLICY_UNAVAILABLE) from error
        finally:
            self._store.write_lock.release()

    async def _activate(
        self,
        connection: AsyncConnection,
        policy: CapturePolicy,
        created_at_microseconds: int,
    ) -> None:
        if created_at_microseconds < 0:
            field = "created_at"
            raise IngestionValidationError.single(field, "out_of_range")
        scope_key = _scope_key(policy.repository_id)
        existing = (
            (
                await connection.execute(
                    text(
                        "SELECT policy_version,policy_sha256,document_json,status "
                        "FROM capture_policy_versions WHERE brain_id=:brain AND "
                        "scope_key=:scope ORDER BY policy_version DESC LIMIT 1"
                    ),
                    {"brain": policy.brain_id, "scope": scope_key},
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing is not None and int(existing["policy_version"]) == policy.version:
            if (
                _bytes(existing["policy_sha256"]) == bytes.fromhex(policy.sha256)
                and str(existing["document_json"]).encode() == policy.canonical_bytes
            ):
                return
            raise IngestionConflictError(_ERR_POLICY_CONFLICT)
        expected = 1 if existing is None else int(existing["policy_version"]) + 1
        if policy.version != expected:
            raise IngestionConflictError(_ERR_POLICY_CONFLICT)
        if policy.repository_id is not None:
            brain_row = await _policy_row(connection, policy.brain_id, None, None)
            brain_policy = (
                CapturePolicy.secure_default(policy.brain_id, None)
                if brain_row is None
                else _decode_policy(str(brain_row["document_json"]))
            )
            if not _is_narrower(policy, brain_policy):
                field = "policy"
                raise IngestionValidationError.single(field, "repository_weakening")
        if existing is not None:
            await connection.execute(
                text(
                    "UPDATE capture_policy_versions SET status='superseded' "
                    "WHERE brain_id=:brain AND scope_key=:scope AND status='active'"
                ),
                {"brain": policy.brain_id, "scope": scope_key},
            )
        await connection.execute(
            text(
                "INSERT INTO capture_policy_versions "
                "(id,brain_id,repository_id,scope_key,policy_id,policy_version,policy_sha256,"
                "document_json,status,created_at,schema_version) VALUES "
                "(:id,:brain,:repository,:scope,:policy_id,:version,:digest,:document,'active',"
                ":created_at,1)"
            ),
            {
                "brain": policy.brain_id,
                "created_at": created_at_microseconds,
                "digest": bytes.fromhex(policy.sha256),
                "document": policy.canonical_bytes.decode(),
                "id": str(uuid7()),
                "policy_id": policy.policy_id,
                "repository": policy.repository_id,
                "scope": scope_key,
                "version": policy.version,
            },
        )


class SqliteCapturePolicyDecisionRepository:
    """Persist exclusion evidence outside an AgentEvent transaction."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the canonical store writer."""
        self._store = store

    async def record(
        self,
        event_id: str,
        brain_id: str,
        principal_id: str,
        result: CapturePolicyResult,
        decided_at_microseconds: int,
    ) -> None:
        """Serialize one exclusion decision without payload or secret values."""
        await self._store.write_lock.acquire()
        try:
            async with self._store.engine.connect() as connection:
                await connection.exec_driver_sql("BEGIN IMMEDIATE")
                try:
                    await _record_decision(
                        connection,
                        event_id,
                        brain_id,
                        principal_id,
                        result,
                        decided_at_microseconds,
                    )
                    await connection.commit()
                except BaseException:
                    await connection.rollback()
                    raise
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_DECISION_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_DECISION_UNAVAILABLE) from error
        finally:
            self._store.write_lock.release()


class SqliteTransactionPrivacyDecisionRepository:
    """Append stored-event privacy evidence inside the owning event transaction."""

    def __init__(self, connection: AsyncConnection) -> None:
        """Bind the already-open serialized transaction."""
        self._connection = connection

    async def record(
        self,
        event_id: str,
        brain_id: str,
        principal_id: str,
        result: CapturePolicyResult,
        decided_at_microseconds: int,
    ) -> None:
        """Append exactly the evaluated decision without committing."""
        try:
            await _record_decision(
                self._connection,
                event_id,
                brain_id,
                principal_id,
                result,
                decided_at_microseconds,
            )
        except IntegrityError as error:
            raise IngestionConflictError(_ERR_DECISION_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IngestionDependencyError(_ERR_DECISION_UNAVAILABLE) from error


async def _policy_row(
    connection: AsyncConnection,
    brain_id: str,
    repository_id: str | None,
    version: int | None,
) -> RowMapping | None:
    query = (
        "SELECT document_json,policy_sha256,policy_version,status "
        "FROM capture_policy_versions WHERE brain_id=:brain AND scope_key=:scope "
        "AND policy_version=:version LIMIT 1"
        if version is not None
        else "SELECT document_json,policy_sha256,policy_version,status "
        "FROM capture_policy_versions WHERE brain_id=:brain AND scope_key=:scope "
        "AND status='active' LIMIT 1"
    )
    return (
        (
            await connection.execute(
                text(query),
                {"brain": brain_id, "scope": _scope_key(repository_id), "version": version},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _record_decision(  # noqa: PLR0913 -- Immutable receipt requires exact authority/evidence.
    connection: AsyncConnection,
    event_id: str,
    brain_id: str,
    principal_id: str,
    result: CapturePolicyResult,
    decided_at_microseconds: int,
) -> None:
    if decided_at_microseconds < 0:
        field = "decided_at"
        raise IngestionValidationError.single(field, "out_of_range")
    counts_json = json.dumps(
        {kind.value: count for kind, count in result.finding_counts.items()},
        separators=(",", ":"),
        sort_keys=True,
    )
    stages_json = json.dumps(
        [
            {
                "outcome_code": stage.outcome_code,
                "rule_ids": list(stage.rule_ids),
                "stage": stage.stage.value,
            }
            for stage in result.stages
        ],
        separators=(",", ":"),
        sort_keys=True,
    )
    parameters = {
        "actor": principal_id,
        "brain": brain_id,
        "classification": result.classification.value,
        "decided_at": decided_at_microseconds,
        "disposition": result.disposition.value,
        "egress": result.egress.value,
        "finding_counts": counts_json,
        "id": str(uuid7()),
        "input_digest": bytes.fromhex(result.input_sha256),
        "output_digest": (
            None if result.output_sha256 is None else bytes.fromhex(result.output_sha256)
        ),
        "policy_digest": bytes.fromhex(result.policy_sha256),
        "policy_id": result.policy_id,
        "policy_version": result.policy_version,
        "reason": result.reason_code,
        "redactions": result.redaction_count,
        "stage_digest": bytes.fromhex(result.stage_sha256),
        "stages": stages_json,
        "subject": event_id,
    }
    existing = (
        (
            await connection.execute(
                text(
                    "SELECT policy_sha256,input_sha256,output_sha256,disposition,classification,"
                    "egress_decision,reason_code,finding_counts_json,redaction_count,stage_sha256,"
                    "stage_evidence_json FROM privacy_decisions "
                    "WHERE subject_kind='agent_event' AND subject_id=:subject"
                ),
                {"subject": event_id},
            )
        )
        .mappings()
        .one_or_none()
    )
    if existing is not None:
        if _decision_matches(existing, parameters):
            return
        raise IngestionConflictError(_ERR_DECISION_CONFLICT)
    await connection.execute(
        text(
            "INSERT INTO privacy_decisions "
            "(id,subject_kind,subject_id,brain_id,actor_id,policy_id,policy_version,policy_sha256,"
            "input_sha256,output_sha256,disposition,classification,egress_decision,reason_code,"
            "finding_counts_json,redaction_count,stage_sha256,stage_evidence_json,decided_at,"
            "schema_version) VALUES "
            "(:id,'agent_event',:subject,:brain,:actor,:policy_id,:policy_version,:policy_digest,"
            ":input_digest,:output_digest,:disposition,:classification,:egress,:reason,"
            ":finding_counts,:redactions,:stage_digest,:stages,:decided_at,1)"
        ),
        parameters,
    )


def _decision_matches(row: RowMapping, parameters: Mapping[str, object]) -> bool:
    return (
        _bytes(row["policy_sha256"]) == parameters["policy_digest"]
        and _bytes(row["input_sha256"]) == parameters["input_digest"]
        and _optional_bytes(row["output_sha256"]) == parameters["output_digest"]
        and str(row["disposition"]) == parameters["disposition"]
        and str(row["classification"]) == parameters["classification"]
        and str(row["egress_decision"]) == parameters["egress"]
        and str(row["reason_code"]) == parameters["reason"]
        and str(row["finding_counts_json"]) == parameters["finding_counts"]
        and int(row["redaction_count"]) == parameters["redactions"]
        and _bytes(row["stage_sha256"]) == parameters["stage_digest"]
        and str(row["stage_evidence_json"]) == parameters["stages"]
    )


def _decode_policy(document_json: str) -> CapturePolicy:
    try:
        raw = cast("dict[str, Any]", json.loads(document_json))
        limits = cast("dict[str, Any]", raw["limits"])
        routes_raw = cast("list[dict[str, Any]]", raw["egress_routes"])
        routes = tuple(_decode_route(item) for item in routes_raw)
        policy = CapturePolicy(
            policy_id=str(raw["policy_id"]),
            version=int(raw["version"]),
            brain_id=str(raw["brain_id"]),
            repository_id=(None if raw["repository_id"] is None else str(raw["repository_id"])),
            ignore_patterns=tuple(
                str(item) for item in cast("list[object]", raw["ignore_patterns"])
            ),
            private_block_pairs=tuple(
                (str(cast("list[object]", pair)[0]), str(cast("list[object]", pair)[1]))
                for pair in cast("list[object]", raw["private_block_pairs"])
            ),
            allowed_media_types=tuple(
                str(item) for item in cast("list[object]", raw["allowed_media_types"])
            ),
            secret_action=SensitiveAction(str(raw["secret_action"])),
            pii_action=SensitiveAction(str(raw["pii_action"])),
            base_classification=Classification(str(raw["base_classification"])),
            egress_routes=routes,
            max_input_bytes=int(limits["max_input_bytes"]),
            max_decoded_characters=int(limits["max_decoded_characters"]),
            max_json_depth=int(limits["max_json_depth"]),
            max_findings=int(limits["max_findings"]),
        )
    except (KeyError, TypeError, ValueError, IndexError, json.JSONDecodeError) as error:
        raise IngestionDependencyError(_ERR_POLICY_MALFORMED) from error
    if policy.canonical_bytes.decode() != document_json:
        raise IngestionDependencyError(_ERR_POLICY_MALFORMED)
    return policy


def _decode_route(raw: dict[str, Any]) -> AllowedEgressRoute:
    destination = cast("dict[str, Any]", raw["destination"])
    return AllowedEgressRoute(
        EgressDestination(
            provider_id=str(destination["provider_id"]),
            endpoint=str(destination["endpoint"]),
            region=str(destination["region"]),
            model_id=str(destination["model_id"]),
            purpose=str(destination["purpose"]),
        ),
        tuple(
            Classification(str(item))
            for item in cast("list[object]", raw["allowed_classifications"])
        ),
    )


def _is_narrower(candidate: CapturePolicy, brain: CapturePolicy) -> bool:
    action_rank = {
        SensitiveAction.REDACT: 0,
        SensitiveAction.LOCAL_ONLY: 1,
        SensitiveAction.EXCLUDE: 2,
    }
    classification_rank = {value: index for index, value in enumerate(Classification)}
    return (
        set(candidate.ignore_patterns).issuperset(brain.ignore_patterns)
        and set(candidate.private_block_pairs).issuperset(brain.private_block_pairs)
        and set(candidate.allowed_media_types).issubset(brain.allowed_media_types)
        and action_rank[candidate.secret_action] >= action_rank[brain.secret_action]
        and action_rank[candidate.pii_action] >= action_rank[brain.pii_action]
        and classification_rank[candidate.base_classification]
        >= classification_rank[brain.base_classification]
        and set(candidate.egress_routes).issubset(brain.egress_routes)
        and candidate.max_input_bytes <= brain.max_input_bytes
        and candidate.max_decoded_characters <= brain.max_decoded_characters
        and candidate.max_json_depth <= brain.max_json_depth
        and candidate.max_findings <= brain.max_findings
    )


def _scope_key(repository_id: str | None) -> str:
    return _BRAIN_SCOPE_KEY if repository_id is None else repository_id


def _bytes(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise IngestionDependencyError(_ERR_POLICY_MALFORMED)
    return value


def _optional_bytes(value: object) -> bytes | None:
    if value is None:
        return None
    return _bytes(value)
