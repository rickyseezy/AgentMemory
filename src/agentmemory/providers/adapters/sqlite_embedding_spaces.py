"""PRO-004 canonical SQLite repository for spaces and generation lifecycle."""

from __future__ import annotations

import hashlib
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Never, cast
from uuid import uuid7

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.providers.adapters.strict_json import (
    StrictJsonError,
    canonical_bytes,
    loads,
    require_object,
)
from agentmemory.providers.domain.embedding_space_ports import (
    EmbeddingGenerationBinding,
    EmbeddingGenerationReservation,
)
from agentmemory.providers.domain.embedding_spaces import (
    EmbeddingSpace,
    EmbeddingSpaceDescriptor,
    GenerationNames,
    IndexGeneration,
    IndexGenerationState,
)
from agentmemory.providers.domain.errors import (
    EmbeddingSpaceAuthorizationError,
    EmbeddingSpaceConflictError,
    EmbeddingSpaceDependencyError,
    EmbeddingSpaceValidationError,
)

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.identity.domain.retrieval_scope import AuthorizedScope
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ERR_AUTHORIZATION = "embedding space storage action is not authorized"
_ERR_ATTESTATION = "embedding space provider attestation does not match its descriptor"
_ERR_CONFLICT = "embedding space conflicts with immutable history"
_ERR_INTEGRITY = "embedding space storage failed integrity verification"
_ERR_STORAGE = "embedding space storage is unavailable"
_ACTION = "provider.embedding_space.ensure"
_BINDING_ACTIONS = frozenset(
    {
        "provider.embedding_migration.activate",
        "provider.embedding_migration.delete",
        "provider.embedding_migration.pause",
        "provider.embedding_migration.plan",
        "provider.embedding_migration.read",
        "provider.embedding_migration.resume",
        "provider.embedding_migration.rollback",
        "provider.embedding_migration.run",
    }
)
_ROLES = frozenset({"owner", "admin"})


class SqliteEmbeddingSpaceRepository:
    """Serialize semantic identity and generation reservations in canonical SQLite."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the sole canonical SQLite writer."""
        self._store = store

    async def get_binding(
        self,
        scope: AuthorizedScope,
        generation_id: str,
        at: datetime,
    ) -> EmbeddingGenerationBinding | None:
        """Resolve one exact Brain-scoped generation under current administrator authority."""
        try:
            async with self._store.engine.connect() as connection:
                await _authorize(
                    connection,
                    scope,
                    at,
                    allowed_actions=_BINDING_ACTIONS,
                )
                generation_row = await _generation_by_id(
                    connection,
                    scope.brain_id.value,
                    generation_id,
                )
                if generation_row is None:
                    return None
                generation = _decode_generation(generation_row)
                space_row = await _space_by_id(
                    connection,
                    scope.brain_id.value,
                    generation.space_id,
                )
                if space_row is None:
                    _integrity()
                return EmbeddingGenerationBinding(_decode_space(space_row), generation)
        except (
            EmbeddingSpaceAuthorizationError,
            EmbeddingSpaceConflictError,
            EmbeddingSpaceValidationError,
        ):
            raise
        except SQLAlchemyError as error:
            raise EmbeddingSpaceDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise EmbeddingSpaceConflictError(_ERR_INTEGRITY) from error

    async def reserve(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        request_digest: str,
        candidate_space: EmbeddingSpace,
        candidate_generation: IndexGeneration,
    ) -> EmbeddingGenerationReservation:
        """Reserve or replay exactly one Brain/space generation under live evidence."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, candidate_space.created_at)
                operation = await _operation_row(connection, operation_id)
                if operation is not None:
                    return await _replay_reservation(
                        connection,
                        operation,
                        scope,
                        request_digest,
                    )
                await _verify_attestation(connection, scope, candidate_space)
                space_row = await _space_by_fingerprint(
                    connection,
                    scope.brain_id.value,
                    candidate_space.immutable_fingerprint,
                )
                if space_row is None:
                    await _insert_space(
                        connection,
                        scope.brain_id.value,
                        candidate_space,
                    )
                    resolved_space = candidate_space
                else:
                    resolved_space = _decode_space(space_row)
                    if resolved_space.canonical_bytes != candidate_space.canonical_bytes:
                        _conflict()
                generation_row = await _generation_for_space(
                    connection,
                    scope.brain_id.value,
                    resolved_space.space_id,
                )
                if generation_row is None:
                    created = True
                    resolved_generation = IndexGeneration.create(
                        generation_id=candidate_generation.generation_id,
                        brain_id=scope.brain_id.value,
                        space=resolved_space,
                        state=IndexGenerationState.CREATING,
                        created_at=candidate_generation.created_at,
                    )
                    await _insert_generation(connection, resolved_generation)
                else:
                    created = False
                    resolved_generation = _decode_generation(generation_row)
                completed = resolved_generation.state is not IndexGenerationState.CREATING
                await _insert_operation(
                    connection,
                    operation_id,
                    scope.brain_id.value,
                    request_digest,
                    resolved_space.space_id,
                    resolved_generation.generation_id,
                    candidate_space.created_at,
                    completed=completed,
                )
                await _append_generation_evidence(
                    connection,
                    scope,
                    operation_id,
                    "ensured",
                    resolved_space,
                    resolved_generation,
                    candidate_space.created_at,
                    request_digest,
                    before=None,
                )
                return EmbeddingGenerationReservation(
                    space=resolved_space,
                    generation=resolved_generation,
                    request_digest=request_digest,
                    created=created,
                )
        except (
            EmbeddingSpaceAuthorizationError,
            EmbeddingSpaceConflictError,
            EmbeddingSpaceValidationError,
        ):
            raise
        except IntegrityError as error:
            raise EmbeddingSpaceConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise EmbeddingSpaceDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise EmbeddingSpaceConflictError(_ERR_INTEGRITY) from error

    async def complete(
        self,
        scope: AuthorizedScope,
        operation_id: str,
        generation_id: str,
        completed_at: datetime,
    ) -> IndexGeneration:
        """Publish population only after the physical index contract was verified."""
        try:
            async with _write_transaction(self._store) as connection:
                await _authorize(connection, scope, completed_at)
                operation = await _operation_row(connection, operation_id)
                return await _complete_reserved_generation(
                    connection,
                    operation,
                    scope,
                    operation_id,
                    generation_id,
                    completed_at,
                )
        except (
            EmbeddingSpaceAuthorizationError,
            EmbeddingSpaceConflictError,
            EmbeddingSpaceValidationError,
        ):
            raise
        except IntegrityError as error:
            raise EmbeddingSpaceConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise EmbeddingSpaceDependencyError(_ERR_STORAGE) from error
        except (StrictJsonError, KeyError, TypeError, ValueError) as error:
            raise EmbeddingSpaceConflictError(_ERR_INTEGRITY) from error


async def _complete_reserved_generation(  # noqa: PLR0913 -- Transaction result coordinates.
    connection: AsyncConnection,
    operation: RowMapping | None,
    scope: AuthorizedScope,
    operation_id: str,
    generation_id: str,
    completed_at: datetime,
) -> IndexGeneration:
    if (
        operation is None
        or str(operation["brain_id"]) != scope.brain_id.value
        or str(operation["generation_id"]) != generation_id
    ):
        _conflict()
    row = await _generation_by_id(
        connection,
        scope.brain_id.value,
        generation_id,
    )
    if row is None:
        _conflict()
    generation = _decode_generation(row)
    if generation.state is IndexGenerationState.CREATING:
        await connection.execute(
            text(
                "UPDATE embedding_index_generations "
                "SET state='populating',updated_at=:at,version=version+1 "
                "WHERE id=:generation AND brain_id=:brain AND state='creating'"
            ),
            {
                "at": _micros(completed_at),
                "brain": scope.brain_id.value,
                "generation": generation_id,
            },
        )
    elif generation.state is not IndexGenerationState.POPULATING:
        _conflict()
    if str(operation["status"]) == "reserved":
        await connection.execute(
            text(
                "UPDATE embedding_generation_operations "
                "SET status='complete',completed_at=:at "
                "WHERE operation_id=:operation AND status='reserved'"
            ),
            {"at": _micros(completed_at), "operation": operation_id},
        )
    refreshed = await _generation_by_id(
        connection,
        scope.brain_id.value,
        generation_id,
    )
    if refreshed is None:
        _conflict()
    completed = _decode_generation(refreshed)
    if generation.state is IndexGenerationState.CREATING:
        space_row = await _space_by_id(
            connection,
            scope.brain_id.value,
            completed.space_id,
        )
        if space_row is None:
            _conflict()
        await _append_generation_evidence(
            connection,
            scope,
            operation_id,
            "populating",
            _decode_space(space_row),
            completed,
            completed_at,
            str(operation["request_digest"]),
            before=generation,
        )
    return completed


async def _append_generation_evidence(  # noqa: PLR0913 -- Complete evidence coordinates.
    connection: AsyncConnection,
    scope: AuthorizedScope,
    operation_id: str,
    phase: str,
    space: EmbeddingSpace,
    generation: IndexGeneration,
    occurred_at: datetime,
    request_digest: str,
    *,
    before: IndexGeneration | None,
) -> None:
    """Append domain, outbox, and hash-chained audit evidence in the same transaction."""
    source_event_id = str(uuid7())
    integration_event_id = str(uuid7())
    event_name = f"EmbeddingIndexGeneration{phase.title()}"
    topic = f"provider.embedding_generation.{phase}.v1"
    now = _micros(occurred_at)
    data = _generation_evidence_document(space, generation, request_digest)
    payload = canonical_bytes(
        {
            "correlation_id": operation_id,
            "data": data,
            "datacontenttype": "application/json",
            "dataschema": f"urn:agentmemory:schema:provider:embedding-generation-{phase}:v1",
            "id": integration_event_id,
            "source": f"urn:agentmemory:brain:{generation.brain_id}:providers",
            "specversion": "1.0",
            "subject": f"embedding-generation/{generation.generation_id}",
            "time": occurred_at.isoformat(),
            "type": topic,
        }
    )
    payload_digest = hashlib.sha256(payload).digest()
    await connection.execute(
        text(
            "INSERT INTO agent_events "
            "(event_id,brain_id,type,payload_hash,classification,occurred_at,ingested_at,"
            "payload_ref,schema_version) VALUES "
            "(:event,:brain,:type,:payload_hash,'internal',:now,:now,NULL,1)"
        ),
        {
            "brain": generation.brain_id,
            "event": source_event_id,
            "now": now,
            "payload_hash": payload_digest,
            "type": event_name,
        },
    )
    await connection.execute(
        text(
            "INSERT INTO outbox_messages "
            "(id,source_event_id,topic,message_key,payload,status,priority,not_before,attempts,"
            "lease_owner,lease_until,completed_at,payload_sha256,last_error_code,created_at,"
            "schema_version) VALUES (:id,:source,:topic,:key,:payload,'ready',100,:now,0,NULL,"
            "NULL,NULL,:digest,NULL,:now,1)"
        ),
        {
            "digest": payload_digest,
            "id": integration_event_id,
            "key": generation.generation_id,
            "now": now,
            "payload": payload.decode(),
            "source": source_event_id,
            "topic": topic,
        },
    )
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = bytes(32) if previous is None else _blob(previous)
    before_digest = bytes(32) if before is None else _generation_snapshot_digest(before)
    after_digest = _generation_snapshot_digest(generation)
    audit_fact = canonical_bytes(
        {
            "action": f"provider.embedding_space.{phase}",
            "actor_id": scope.principal_id.value,
            "after_hash": after_digest.hex(),
            "before_hash": None if before is None else before_digest.hex(),
            "brain_id": generation.brain_id,
            "generation_id": generation.generation_id,
            "operation_id": operation_id,
            "space_fingerprint": space.immutable_fingerprint,
            "space_id": space.space_id,
        }
    )
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:now,1)"
        ),
        {
            "action": f"provider.embedding_space.{phase}",
            "actor": scope.principal_id.value,
            "after": after_digest,
            "before": before_digest,
            "brain": generation.brain_id,
            "event": hashlib.sha256(previous_hash + audit_fact).digest(),
            "key": f"provider.embedding-space.{phase}:{operation_id}",
            "now": now,
            "previous": previous_hash,
            "target": f"embedding-generation:{generation.generation_id}",
        },
    )


def _generation_evidence_document(
    space: EmbeddingSpace,
    generation: IndexGeneration,
    request_digest: str,
) -> dict[str, object]:
    return {
        "brain_id": generation.brain_id,
        "dimension": generation.dimension,
        "generation_id": generation.generation_id,
        "generated_label": generation.names.label,
        "request_digest": request_digest,
        "similarity": generation.similarity,
        "space_fingerprint": space.immutable_fingerprint,
        "space_id": space.space_id,
        "state": generation.state.value,
        "vector_index_name": generation.names.vector_index,
        "vector_property": generation.names.vector_property,
    }


def _generation_snapshot_digest(generation: IndexGeneration) -> bytes:
    return hashlib.sha256(
        canonical_bytes(
            {
                "brain_id": generation.brain_id,
                "dimension": generation.dimension,
                "generation_id": generation.generation_id,
                "generated_label": generation.names.label,
                "similarity": generation.similarity,
                "space_fingerprint": generation.space_fingerprint,
                "space_id": generation.space_id,
                "state": generation.state.value,
                "vector_index_name": generation.names.vector_index,
                "vector_property": generation.names.vector_property,
            }
        )
    ).digest()


async def _authorize(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    at: datetime,
    *,
    allowed_actions: frozenset[str] = frozenset({_ACTION}),
) -> None:
    if scope.action not in allowed_actions or scope.role.value not in _ROLES:
        raise EmbeddingSpaceAuthorizationError(_ERR_AUTHORIZATION)
    authorized = (
        await connection.execute(
            text(
                "SELECT 1 FROM brains AS brain JOIN principals AS principal "
                "ON principal.id=:principal JOIN scope_grants AS grant "
                "ON grant.principal_id=principal.id AND grant.brain_id=brain.id "
                "WHERE brain.id=:brain AND brain.status='active' AND principal.status='active' "
                "AND grant.role IN ('owner','admin') AND grant.project_id IS NULL "
                "AND grant.repository_id IS NULL AND grant.valid_from<=:at "
                "AND (grant.valid_to IS NULL OR grant.valid_to>:at) LIMIT 1"
            ),
            {
                "at": _micros(at),
                "brain": scope.brain_id.value,
                "principal": scope.principal_id.value,
            },
        )
    ).scalar_one_or_none()
    if authorized is None:
        raise EmbeddingSpaceAuthorizationError(_ERR_AUTHORIZATION)


async def _verify_attestation(
    connection: AsyncConnection,
    scope: AuthorizedScope,
    space: EmbeddingSpace,
) -> None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT profile.adapter_id,profile.model_id,profile.document_json,"
                    "profile.status,profile.active_probe_id,attestation.adapter_digest,"
                    "attestation.configuration_digest,probe.model_revision,"
                    "probe.revision_fingerprint,probe.dimension,probe.dtype,"
                    "probe.purposes_json,probe.evidence_json "
                    "FROM provider_profiles AS profile "
                    "JOIN provider_capability_attestations AS attestation "
                    "ON attestation.profile_id=profile.id "
                    "JOIN provider_probe_evidence AS probe "
                    "ON probe.evidence_id=attestation.attestation_id "
                    "WHERE profile.id=:profile AND profile.brain_id=:brain "
                    "AND attestation.attestation_id=:attestation "
                    "AND attestation.schema_version=1 AND probe.schema_version=2"
                ),
                {
                    "attestation": space.capability_attestation_id,
                    "brain": scope.brain_id.value,
                    "profile": space.profile_id,
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise EmbeddingSpaceValidationError(_ERR_ATTESTATION)
    profile_document = require_object(loads(_blob(row["document_json"])))
    configuration = require_object(profile_document["configuration"])
    evidence = require_object(loads(_blob(row["evidence_json"])))
    purposes = _strings(loads(_blob(row["purposes_json"])))
    descriptor = space.descriptor
    revision_matches = descriptor.model_revision is None or descriptor.model_revision == str(
        row["model_revision"]
    )
    weight_matches = (
        descriptor.model_weight_digest is None
        or descriptor.model_weight_digest == str(row["revision_fingerprint"])
    )
    if (
        str(row["status"]) != "active"
        or str(row["active_probe_id"]) != space.capability_attestation_id
        or str(row["adapter_id"]) != descriptor.adapter_id
        or str(row["model_id"]) != descriptor.model_id
        or str(row["adapter_digest"]) != descriptor.adapter_digest
        or configuration.get("execution_class") != descriptor.execution_class.value
        or int(row["dimension"]) != descriptor.dimension
        or str(row["dtype"]) != descriptor.dtype.value
        or evidence.get("normalization") != descriptor.normalization.value
        or evidence.get("similarity") != descriptor.similarity
        or descriptor.purpose.value not in purposes
        or not revision_matches
        or not weight_matches
    ):
        raise EmbeddingSpaceValidationError(_ERR_ATTESTATION)


async def _replay_reservation(
    connection: AsyncConnection,
    operation: RowMapping,
    scope: AuthorizedScope,
    request_digest: str,
) -> EmbeddingGenerationReservation:
    if (
        str(operation["brain_id"]) != scope.brain_id.value
        or str(operation["request_digest"]) != request_digest
    ):
        raise EmbeddingSpaceConflictError(_ERR_CONFLICT)
    space_row = await _space_by_id(
        connection,
        scope.brain_id.value,
        str(operation["space_id"]),
    )
    generation_row = await _generation_by_id(
        connection,
        scope.brain_id.value,
        str(operation["generation_id"]),
    )
    if space_row is None or generation_row is None:
        raise EmbeddingSpaceConflictError(_ERR_INTEGRITY)
    return EmbeddingGenerationReservation(
        space=_decode_space(space_row),
        generation=_decode_generation(generation_row),
        request_digest=request_digest,
        created=False,
    )


async def _operation_row(
    connection: AsyncConnection,
    operation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM embedding_generation_operations WHERE operation_id=:operation"),
                {"operation": operation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _space_by_fingerprint(
    connection: AsyncConnection,
    brain_id: str,
    fingerprint: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM embedding_spaces "
                    "WHERE brain_id=:brain AND immutable_fingerprint=:fingerprint"
                ),
                {"brain": brain_id, "fingerprint": fingerprint},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _space_by_id(
    connection: AsyncConnection,
    brain_id: str,
    space_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text("SELECT * FROM embedding_spaces WHERE brain_id=:brain AND id=:space"),
                {"brain": brain_id, "space": space_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _generation_for_space(
    connection: AsyncConnection,
    brain_id: str,
    space_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM embedding_index_generations "
                    "WHERE brain_id=:brain AND space_id=:space"
                ),
                {"brain": brain_id, "space": space_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _generation_by_id(
    connection: AsyncConnection,
    brain_id: str,
    generation_id: str,
) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT * FROM embedding_index_generations "
                    "WHERE brain_id=:brain AND id=:generation"
                ),
                {"brain": brain_id, "generation": generation_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _insert_space(
    connection: AsyncConnection,
    brain_id: str,
    space: EmbeddingSpace,
) -> None:
    descriptor = space.descriptor
    await connection.execute(
        text(
            "INSERT INTO embedding_spaces "
            "(id,brain_id,immutable_fingerprint,profile_id,capability_attestation_id,"
            "descriptor_json,adapter_digest,model_revision,dimension,dtype,"
            "normalization,similarity,purpose,created_at,schema_version) VALUES "
            "(:id,:brain,:fingerprint,:profile,:attestation,:descriptor,:adapter,:revision,"
            ":dimension,:dtype,:normalization,:similarity,:purpose,:created,1)"
        ),
        {
            "adapter": descriptor.adapter_digest,
            "attestation": space.capability_attestation_id,
            "brain": brain_id,
            "created": _micros(space.created_at),
            "descriptor": descriptor.canonical_bytes,
            "dimension": descriptor.dimension,
            "dtype": descriptor.dtype.value,
            "fingerprint": space.immutable_fingerprint,
            "id": space.space_id,
            "normalization": descriptor.normalization.value,
            "profile": space.profile_id,
            "purpose": descriptor.purpose.value,
            "revision": descriptor.model_revision,
            "similarity": descriptor.similarity,
        },
    )


async def _insert_generation(
    connection: AsyncConnection,
    generation: IndexGeneration,
) -> None:
    await connection.execute(
        text(
            "INSERT INTO embedding_index_generations "
            "(id,brain_id,space_id,space_fingerprint,generated_label,vector_index_name,"
            "vector_property,dimension,similarity,state,created_at,updated_at,version,"
            "schema_version) VALUES "
            "(:id,:brain,:space,:fingerprint,:label,:index_name,:property,:dimension,"
            ":similarity,:state,:created,:created,1,1)"
        ),
        {
            "brain": generation.brain_id,
            "created": _micros(generation.created_at),
            "dimension": generation.dimension,
            "fingerprint": generation.space_fingerprint,
            "id": generation.generation_id,
            "index_name": generation.names.vector_index,
            "label": generation.names.label,
            "property": generation.names.vector_property,
            "similarity": generation.similarity,
            "space": generation.space_id,
            "state": generation.state.value,
        },
    )


async def _insert_operation(  # noqa: PLR0913 -- Full idempotency/result coordinate.
    connection: AsyncConnection,
    operation_id: str,
    brain_id: str,
    request_digest: str,
    space_id: str,
    generation_id: str,
    created_at: datetime,
    *,
    completed: bool,
) -> None:
    at = _micros(created_at)
    await connection.execute(
        text(
            "INSERT INTO embedding_generation_operations "
            "(operation_id,brain_id,request_digest,space_id,generation_id,status,"
            "created_at,completed_at,schema_version) VALUES "
            "(:operation,:brain,:request,:space,:generation,:status,:created,:completed,1)"
        ),
        {
            "brain": brain_id,
            "completed": at if completed else None,
            "created": at,
            "generation": generation_id,
            "operation": operation_id,
            "request": request_digest,
            "space": space_id,
            "status": "complete" if completed else "reserved",
        },
    )


def _decode_space(row: RowMapping) -> EmbeddingSpace:
    descriptor = EmbeddingSpaceDescriptor.from_document(
        require_object(loads(_blob(row["descriptor_json"])))
    )
    return EmbeddingSpace(
        space_id=str(row["id"]),
        profile_id=str(row["profile_id"]),
        capability_attestation_id=str(row["capability_attestation_id"]),
        descriptor=descriptor,
        immutable_fingerprint=str(row["immutable_fingerprint"]),
        created_at=_instant(row["created_at"]),
    )


def _decode_generation(row: RowMapping) -> IndexGeneration:
    return IndexGeneration(
        generation_id=str(row["id"]),
        brain_id=str(row["brain_id"]),
        space_id=str(row["space_id"]),
        space_fingerprint=str(row["space_fingerprint"]),
        names=GenerationNames(
            label=str(row["generated_label"]),
            vector_index=str(row["vector_index_name"]),
            vector_property=str(row["vector_property"]),
        ),
        dimension=int(row["dimension"]),
        similarity=str(row["similarity"]),
        state=IndexGenerationState(str(row["state"])),
        created_at=_instant(row["created_at"]),
    )


def _instant(value: object) -> datetime:
    if not isinstance(value, int):
        raise TypeError
    return datetime.fromtimestamp(value / 1_000_000, tz=UTC)


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise TypeError
    items = cast("list[object]", value)
    if any(not isinstance(item, str) for item in items):
        raise TypeError
    return tuple(cast("str", item) for item in items)


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    if isinstance(value, str):
        return value.encode()
    raise TypeError


def _micros(value: datetime) -> int:
    return round(value.timestamp() * 1_000_000)


def _conflict() -> Never:
    raise EmbeddingSpaceConflictError(_ERR_CONFLICT)


def _integrity() -> Never:
    raise EmbeddingSpaceConflictError(_ERR_INTEGRITY)


@asynccontextmanager
async def _write_transaction(
    store: SqliteCoreStore,
) -> AsyncIterator[AsyncConnection]:
    async with store.write_lock, store.engine.connect() as connection:
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            await connection.rollback()
            raise
        else:
            await connection.commit()
