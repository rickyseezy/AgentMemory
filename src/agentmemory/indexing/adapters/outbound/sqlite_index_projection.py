"""IDX-002 local vector projection and assertion invalidation consumer."""

from __future__ import annotations

import hashlib
import json
import math
from contextlib import asynccontextmanager
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from agentmemory.graph.domain.assertions import (
    AssertionEvidenceRevocation,
    EvidenceRevocationReason,
)
from agentmemory.identity.domain.retrieval_scope import (
    AuthorizedScope,
    Classification,
    RetrievalRole,
    RetrievalScopeMode,
    ScopeMember,
    TemporalScope,
)
from agentmemory.identity.domain.value_objects import StableId
from agentmemory.indexing.domain.errors import (
    IndexingConflictError,
    IndexingUnavailableError,
    IndexingValidationError,
)
from agentmemory.indexing.domain.incremental import IndexRevisionContext

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from sqlalchemy.engine import RowMapping
    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.graph.domain.assertion_ports import ScopedAssertionEvidenceCatalogFactory
    from agentmemory.indexing.domain.incremental import IndexProjectionEvent
    from agentmemory.indexing.domain.incremental_ports import SemanticEmbeddingPort
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.domain.dependency_ports import EmbeddingVector

_ERR_CONFLICT = "incremental projection conflicts with durable history"
_ERR_INTEGRITY = "incremental projection input failed integrity verification"
_ERR_STORAGE = "incremental projection storage is unavailable"


class SqliteIndexProjectionConsumer:
    """Embed exact changed symbols and invalidate bounded dependent current evidence."""

    def __init__(
        self,
        store: SqliteCoreStore,
        embeddings: SemanticEmbeddingPort,
        evidence_catalogs: ScopedAssertionEvidenceCatalogFactory,
    ) -> None:
        """Bind canonical storage, the pinned local vector space, and evidence lifecycle."""
        self._store = store
        self._embeddings = embeddings
        self._evidence_catalogs = evidence_catalogs

    async def consume(self, event: IndexProjectionEvent) -> None:
        """Apply one event idempotently before its outbox delivery is acknowledged."""
        try:
            run = await self._run(event)
            if str(run["revision_context"]) == IndexRevisionContext.WORKTREE.value:
                await self._revoke_assertion_evidence(run, event)
            vectors = await self._embed_changed_semantics(event)
            async with _write_transaction(self._store) as connection:
                await _insert_invalidations(connection, event)
                for vector, content_digest in vectors:
                    await _insert_vector(connection, event, vector, content_digest)
                await _verify_projection(connection, event, vectors)
        except IndexingValidationError, IndexingConflictError:
            raise
        except IntegrityError as error:
            raise IndexingConflictError(_ERR_CONFLICT) from error
        except SQLAlchemyError as error:
            raise IndexingUnavailableError(_ERR_STORAGE) from error

    async def _run(self, event: IndexProjectionEvent) -> RowMapping:
        async with self._store.engine.connect() as connection:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT root.*,COALESCE(context.revision_context,'worktree') "
                            "AS revision_context FROM incremental_index_runs AS root LEFT JOIN "
                            "incremental_index_run_revision_contexts AS context "
                            "ON context.run_id=root.run_id WHERE root.run_id=:run "
                            "AND root.target_snapshot_id=:snapshot"
                        ),
                        {"run": event.run_id, "snapshot": event.snapshot_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise IndexingValidationError(_ERR_INTEGRITY)
        return row

    async def _revoke_assertion_evidence(
        self,
        run: RowMapping,
        event: IndexProjectionEvent,
    ) -> None:
        for evidence_id in event.assertion_evidence_ids:
            scope = await self._evidence_scope(run, evidence_id)
            if scope is None:
                continue
            operation_id = (
                "idx002-" + hashlib.sha256(f"{event.id}\0{evidence_id}".encode()).hexdigest()
            )
            await self._evidence_catalogs.evidence_catalog(scope).revoke(
                AssertionEvidenceRevocation(
                    operation_id,
                    evidence_id,
                    EvidenceRevocationReason.SOURCE_INVALIDATED,
                    event.occurred_at,
                )
            )

    async def _evidence_scope(self, run: RowMapping, evidence_id: str) -> AuthorizedScope | None:
        async with self._store.engine.connect() as connection:
            source = (
                (
                    await connection.execute(
                        text(
                            "SELECT brain_id,project_id,repository_id,checkout_id "
                            "FROM assertion_evidence_sources WHERE evidence_id=:evidence"
                        ),
                        {"evidence": evidence_id},
                    )
                )
                .mappings()
                .one_or_none()
            )
        if source is None:
            return None
        if (
            str(source["brain_id"]) != str(run["brain_id"])
            or str(source["project_id"]) != str(run["project_id"])
            or str(source["repository_id"]) != str(run["repository_id"])
        ):
            raise IndexingValidationError(_ERR_INTEGRITY)
        checkout = source["checkout_id"]
        return AuthorizedScope.create(
            brain_id=StableId(str(run["brain_id"])),
            principal_id=StableId(str(run["principal_id"])),
            role=RetrievalRole(str(run["role"])),
            mode=RetrievalScopeMode.CURRENT,
            members=(
                ScopeMember(
                    StableId(str(run["project_id"])),
                    (StableId(str(run["repository_id"])),),
                    () if checkout is None else (StableId(str(checkout)),),
                ),
            ),
            classification_ceiling=Classification.LOCAL_ONLY,
            temporal_scope=TemporalScope(None, None),
            grant_version=1,
            policy_version=1,
            security_epoch=1,
            action="graph.assertion.evidence.revoke",
            purpose="code_indexing",
        )

    async def _embed_changed_semantics(
        self, event: IndexProjectionEvent
    ) -> tuple[tuple[EmbeddingVector, bytes], ...]:
        projected: list[tuple[EmbeddingVector, bytes]] = []
        async with self._store.engine.connect() as connection:
            for semantic_id in event.reembed_semantic_ids:
                row = await _semantic_document(connection, semantic_id)
                if row is None:
                    raise IndexingValidationError(_ERR_INTEGRITY)
                content = json.dumps(
                    {
                        "display_name": str(row["display_name"]),
                        "kind": str(row["kind"]),
                        "source": str(row["source"]),
                        "stable_key": str(row["stable_key"]),
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                vector = await self._embeddings.embed_document(semantic_id, content)
                if (
                    vector.content_id != semantic_id
                    or not vector.values
                    or not all(math.isfinite(value) for value in vector.values)
                ):
                    raise IndexingValidationError(_ERR_INTEGRITY)
                projected.append((vector, hashlib.sha256(content.encode()).digest()))
        return tuple(projected)


async def _semantic_document(connection: AsyncConnection, semantic_id: str) -> RowMapping | None:
    return (
        (
            await connection.execute(
                text(
                    "SELECT symbol.display_name,symbol.kind,symbol.stable_key,revision.source "
                    "FROM symbol_revisions AS revision JOIN code_symbols AS symbol "
                    "ON symbol.id=revision.symbol_id WHERE revision.id=:semantic"
                ),
                {"semantic": semantic_id},
            )
        )
        .mappings()
        .one_or_none()
    )


async def _insert_invalidations(connection: AsyncConnection, event: IndexProjectionEvent) -> None:
    at = _micros(event.occurred_at)
    current_semantics = set(event.reembed_semantic_ids)
    for semantic_id in (
        value for value in event.affected_semantic_ids if value not in current_semantics
    ):
        await connection.execute(
            text(
                "INSERT OR IGNORE INTO code_semantic_vector_invalidations "
                "(event_id,semantic_id,invalidated_at) VALUES (:event,:semantic,:at)"
            ),
            {"event": event.id, "semantic": semantic_id, "at": at},
        )
    for fact_id in event.dependent_fact_ids:
        await connection.execute(
            text(
                "INSERT OR IGNORE INTO index_topology_fact_invalidations "
                "(event_id,fact_id,invalidated_at) VALUES (:event,:fact,:at)"
            ),
            {"event": event.id, "fact": fact_id, "at": at},
        )


async def _insert_vector(
    connection: AsyncConnection,
    event: IndexProjectionEvent,
    vector: EmbeddingVector,
    content_digest: bytes,
) -> None:
    await connection.execute(
        text(
            "INSERT OR IGNORE INTO code_semantic_vector_projections "
            "(event_id,semantic_id,snapshot_id,model_id,model_revision,dimension,vector_json,"
            "content_digest,projected_at) VALUES (:event,:semantic,:snapshot,:model,:revision,"
            ":dimension,:vector,:content,:at)"
        ),
        {
            "event": event.id,
            "semantic": vector.content_id,
            "snapshot": event.snapshot_id,
            "model": vector.model_id,
            "revision": vector.model_revision,
            "dimension": len(vector.values),
            "vector": json.dumps(vector.values, separators=(",", ":")).encode(),
            "content": content_digest,
            "at": _micros(event.occurred_at),
        },
    )


async def _verify_projection(
    connection: AsyncConnection,
    event: IndexProjectionEvent,
    vectors: tuple[tuple[EmbeddingVector, bytes], ...],
) -> None:
    expected_vectors = {vector.content_id for vector, _ in vectors}
    actual_vectors = {
        str(value)
        for value in (
            await connection.execute(
                text(
                    "SELECT semantic_id FROM code_semantic_vector_projections WHERE event_id=:event"
                ),
                {"event": event.id},
            )
        ).scalars()
    }
    vector_invalidations = await _count(connection, "code_semantic_vector_invalidations", event.id)
    fact_invalidations = await _count(connection, "index_topology_fact_invalidations", event.id)
    if (
        actual_vectors != expected_vectors
        or vector_invalidations
        != len(set(event.affected_semantic_ids) - set(event.reembed_semantic_ids))
        or fact_invalidations != len(event.dependent_fact_ids)
    ):
        raise IndexingConflictError(_ERR_CONFLICT)


async def _count(connection: AsyncConnection, table: str, event_id: str) -> int:
    if table == "code_semantic_vector_invalidations":
        statement = text(
            "SELECT COUNT(*) FROM code_semantic_vector_invalidations WHERE event_id=:event"
        )
    elif table == "index_topology_fact_invalidations":
        statement = text(
            "SELECT COUNT(*) FROM index_topology_fact_invalidations WHERE event_id=:event"
        )
    else:
        raise IndexingValidationError(_ERR_INTEGRITY)
    value = (
        await connection.execute(
            statement,
            {"event": event_id},
        )
    ).scalar_one()
    return int(value)


def _micros(value: object) -> int:
    if not isinstance(value, datetime):
        raise IndexingValidationError(_ERR_INTEGRITY)
    return round(value.timestamp() * 1_000_000)


@asynccontextmanager
async def _write_transaction(store: SqliteCoreStore) -> AsyncIterator[AsyncConnection]:
    async with store.engine.connect() as connection:
        await connection.exec_driver_sql("BEGIN IMMEDIATE")
        try:
            yield connection
            await connection.commit()
        except BaseException:
            await connection.rollback()
            raise
