"""Append-only SQLite PF-005 session credential and lease repository."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, cast

from sqlalchemy import text

from agentmemory.operations.domain.errors import ErrorCode, OperationError
from agentmemory.operations.domain.mcp_session import (
    McpGitCoverage,
    McpSession,
    McpSessionRegistration,
    McpSessionState,
)
from agentmemory.operations.domain.value_objects import Sha256Digest, Uuid7Id

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore

_ZERO_DIGEST: Final = bytes(32)
_DIGEST_BYTES: Final = 32
_MAX_RECOVERY_LIMIT: Final = 256


@dataclass(frozen=True, slots=True)
class _Snapshot:
    session: McpSession
    event_type: str
    record_json: str
    previous_digest: bytes
    record_digest: bytes
    occurred_at: datetime


class SqliteMcpSessionRepository:
    """Persist immutable credential registration and hash-chained aggregate snapshots."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind the sole canonical SQLite writer."""
        self._store = store

    async def register(self, registration: McpSessionRegistration) -> tuple[McpSession, bool]:
        """Create exact hash-only authority or return an exact replay."""
        session = McpSession.register(registration)
        record_json = _record_json(session)
        record_digest = _snapshot_digest(_ZERO_DIGEST, record_json)
        registration_digest = _registration_digest(registration)
        async with self._store.write_lock, self._store.engine.begin() as connection:
            await _require_active_installation(
                connection,
                registration,
                registration.issued_at,
            )
            existing_id = (
                await connection.execute(
                    text(
                        "SELECT session_id FROM mcp_session_credentials "
                        "WHERE session_id=:session OR credential_digest=:credential"
                    ),
                    {
                        "session": registration.session_id.value,
                        "credential": bytes.fromhex(registration.credential_digest.value),
                    },
                )
            ).scalar_one_or_none()
            if existing_id is not None:
                existing = await self._load(connection, Uuid7Id(_require_str(existing_id)))
                if existing.registration != registration:
                    raise OperationError(
                        ErrorCode.CONFLICT,
                        "MCP session registration conflicted",
                    )
                return existing, False
            await connection.execute(
                text(
                    "INSERT INTO mcp_session_credentials "
                    "(session_id,installation_id,brain_id,actor_id,grant_id,agent_id,"
                    "workspace_fingerprint,device_identity,git_repository_id,git_worktree_id,"
                    "git_coverage,project_id,repository_id,checkout_id,security_epoch,"
                    "credential_digest,issued_at,expires_at,registration_digest,schema_version) "
                    "VALUES (:session,:installation,:brain,"
                    ":actor,:grant,:agent,:workspace,:device,:repository,:worktree,:coverage,"
                    ":project,:canonical_repository,:checkout,:epoch,:credential,:issued,"
                    ":expires,:registration,1)"
                ),
                {
                    "session": registration.session_id.value,
                    "installation": registration.installation_id.value,
                    "brain": registration.brain_id.value,
                    "actor": registration.actor_id.value,
                    "grant": registration.grant_id.value,
                    "agent": registration.agent_id,
                    "workspace": bytes.fromhex(registration.workspace_fingerprint.value),
                    "device": registration.device_identity,
                    "repository": registration.git_repository_id,
                    "worktree": registration.git_worktree_id,
                    "coverage": registration.git_coverage.value,
                    "project": _optional_uuid(registration.project_id),
                    "canonical_repository": _optional_uuid(registration.repository_id),
                    "checkout": _optional_uuid(registration.checkout_id),
                    "epoch": str(registration.security_epoch),
                    "credential": bytes.fromhex(registration.credential_digest.value),
                    "issued": _microseconds(registration.issued_at),
                    "expires": _microseconds(registration.expires_at),
                    "registration": registration_digest,
                },
            )
            await self._insert_snapshot(
                connection,
                _Snapshot(
                    session,
                    "registered",
                    record_json,
                    _ZERO_DIGEST,
                    record_digest,
                    registration.issued_at,
                ),
            )
            await _append_audit(connection, session, "registered", _ZERO_DIGEST, record_digest)
        return session, True

    async def get(self, session_id: Uuid7Id) -> McpSession | None:
        """Load and authenticate one complete session chain."""
        async with self._store.engine.connect() as connection:
            exists = (
                await connection.execute(
                    text("SELECT 1 FROM mcp_session_credentials WHERE session_id=:session"),
                    {"session": session_id.value},
                )
            ).scalar_one_or_none()
            if exists is None:
                return None
            return await self._load(connection, session_id)

    async def get_by_credential(self, digest: Sha256Digest) -> McpSession | None:
        """Resolve a hash-only credential to its authenticated session chain."""
        async with self._store.engine.connect() as connection:
            session_id = (
                await connection.execute(
                    text(
                        "SELECT session_id FROM mcp_session_credentials "
                        "WHERE credential_digest=:credential"
                    ),
                    {"credential": bytes.fromhex(digest.value)},
                )
            ).scalar_one_or_none()
            if session_id is None:
                return None
            return await self._load(connection, Uuid7Id(_require_str(session_id)))

    async def authorize(
        self,
        digest: Sha256Digest,
        session_id: Uuid7Id,
        now: datetime,
    ) -> McpSession | None:
        """Authenticate current scope and epoch without exposing credential material."""
        timestamp = _datetime(_microseconds(now))
        async with self._store.engine.connect() as connection:
            resolved = (
                await connection.execute(
                    text(
                        "SELECT session_id FROM mcp_session_credentials "
                        "WHERE credential_digest=:credential"
                    ),
                    {"credential": bytes.fromhex(digest.value)},
                )
            ).scalar_one_or_none()
            if resolved != session_id.value:
                return None
            session = await self._load(connection, session_id)
            try:
                await _require_active_installation(connection, session.registration, timestamp)
            except OperationError as error:
                if error.code is ErrorCode.FORBIDDEN:
                    return None
                raise
            if (
                session.revoked_at is not None
                or session.state not in {McpSessionState.REGISTERED, McpSessionState.ACTIVE}
                or timestamp < session.registration.issued_at
                or timestamp >= session.registration.expires_at
            ):
                return None
            return session

    async def save(self, previous: McpSession, current: McpSession) -> None:
        """Append one exact optimistic revision and its hash-chained audit fact."""
        event_type, occurred_at = _event(previous, current)
        async with self._store.write_lock, self._store.engine.begin() as connection:
            persisted = await self._load(connection, previous.registration.session_id)
            if persisted == current:
                return
            if persisted != previous:
                raise OperationError(ErrorCode.CONFLICT, "MCP session revision conflicted")
            record_json = _record_json(current)
            prior_digest = await _latest_digest(connection, current.registration.session_id)
            record_digest = _snapshot_digest(prior_digest, record_json)
            await self._insert_snapshot(
                connection,
                _Snapshot(
                    current,
                    event_type,
                    record_json,
                    prior_digest,
                    record_digest,
                    occurred_at,
                ),
            )
            await _append_audit(
                connection,
                current,
                event_type,
                prior_digest,
                record_digest,
            )

    async def expired(self, now: datetime, limit: int) -> tuple[McpSession, ...]:
        """Return deterministic latest active snapshots beyond lease or credential expiry."""
        if limit < 1 or limit > _MAX_RECOVERY_LIMIT:
            raise OperationError(ErrorCode.VALIDATION, "MCP session recovery limit is invalid")
        timestamp = _microseconds(now)
        async with self._store.engine.connect() as connection:
            rows = (
                await connection.execute(
                    text(
                        "SELECT s.session_id FROM mcp_session_snapshots s "
                        "JOIN mcp_session_credentials c ON c.session_id=s.session_id "
                        "WHERE s.revision=(SELECT MAX(latest.revision) FROM mcp_session_snapshots "
                        "latest WHERE latest.session_id=s.session_id) AND s.state='active' "
                        "AND (s.lease_expires_at<=:now OR c.expires_at<=:now) "
                        "ORDER BY s.lease_expires_at,s.session_id LIMIT :limit"
                    ),
                    {"now": timestamp, "limit": limit},
                )
            ).scalars()
            sessions = [
                await self._load(connection, Uuid7Id(_require_str(value))) for value in rows
            ]
            return tuple(sessions)

    async def _load(self, connection: AsyncConnection, session_id: Uuid7Id) -> McpSession:
        credential = (
            (
                await connection.execute(
                    text("SELECT * FROM mcp_session_credentials WHERE session_id=:session"),
                    {"session": session_id.value},
                )
            )
            .mappings()
            .one_or_none()
        )
        if credential is None:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session authority is missing")
        snapshots = (
            (
                await connection.execute(
                    text(
                        "SELECT * FROM mcp_session_snapshots WHERE session_id=:session "
                        "ORDER BY revision"
                    ),
                    {"session": session_id.value},
                )
            )
            .mappings()
            .all()
        )
        if not snapshots:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session history is missing")
        previous: McpSession | None = None
        previous_digest = _ZERO_DIGEST
        for index, row in enumerate(snapshots):
            record_json = _require_str(row["record_json"])
            record_digest = _require_bytes(row["record_digest"])
            if (
                _require_int(row["revision"]) != index
                or _require_bytes(row["previous_digest"]) != previous_digest
                or _snapshot_digest(previous_digest, record_json) != record_digest
            ):
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "MCP session history integrity failed",
                )
            current = _decode_record(record_json)
            _require_row_projection(dict(row), current)
            event_type = _require_str(row["event_type"])
            if previous is None:
                if event_type != "registered" or current.revision != 0:
                    raise OperationError(
                        ErrorCode.INTEGRITY_VIOLATION,
                        "MCP session initial snapshot is invalid",
                    )
            elif not _transition_matches(previous, current, event_type):
                raise OperationError(
                    ErrorCode.INTEGRITY_VIOLATION,
                    "MCP session transition history is invalid",
                )
            previous, previous_digest = current, record_digest
        if (
            previous is None
            or previous.registration != _registration_from_row(dict(credential))
            or (
                _registration_digest(previous.registration)
                != _require_bytes(credential["registration_digest"])
            )
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "MCP session registration integrity failed",
            )
        return previous

    async def _insert_snapshot(
        self,
        connection: AsyncConnection,
        snapshot: _Snapshot,
    ) -> None:
        await connection.execute(
            text(
                "INSERT INTO mcp_session_snapshots "
                "(session_id,revision,state,lease_expires_at,revoked_at,finished_at,record_json,"
                "previous_digest,record_digest,occurred_at,event_type,schema_version) VALUES "
                "(:session,:revision,:state,:lease,:revoked,:finished,:record,:previous,:digest,"
                ":occurred,:event,1)"
            ),
            {
                "session": snapshot.session.registration.session_id.value,
                "revision": snapshot.session.revision,
                "state": snapshot.session.state.value,
                "lease": _optional_microseconds(snapshot.session.lease_expires_at),
                "revoked": _optional_microseconds(snapshot.session.revoked_at),
                "finished": _optional_microseconds(snapshot.session.finished_at),
                "record": snapshot.record_json,
                "previous": snapshot.previous_digest,
                "digest": snapshot.record_digest,
                "occurred": _microseconds(snapshot.occurred_at),
                "event": snapshot.event_type,
            },
        )


async def _require_active_installation(
    connection: AsyncConnection,
    registration: McpSessionRegistration,
    at: datetime,
) -> None:
    row = (
        (
            await connection.execute(
                text(
                    "SELECT i.installation_id,i.security_epoch FROM installation_state i "
                    "JOIN principals p ON p.id=:actor AND p.status='active' "
                    "JOIN brains b ON b.id=:brain AND b.status='active' "
                    "JOIN scope_grants g ON g.id=:grant AND g.principal_id=:actor "
                    "AND g.brain_id=:brain AND g.valid_from<=:at "
                    "AND (g.valid_to IS NULL OR g.valid_to>:at) "
                    "WHERE i.singleton_key='local' AND i.owner_principal_id=:actor"
                ),
                {
                    "actor": registration.actor_id.value,
                    "brain": registration.brain_id.value,
                    "grant": registration.grant_id.value,
                    "at": _microseconds(at),
                },
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None or row["installation_id"] != registration.installation_id.value:
        raise OperationError(ErrorCode.FORBIDDEN, "MCP session installation is not active")
    try:
        epoch = int(_require_str(row["security_epoch"]))
    except ValueError as error:
        raise OperationError(
            ErrorCode.INTEGRITY_VIOLATION,
            "active security epoch is invalid",
        ) from error
    if epoch != registration.security_epoch:
        raise OperationError(ErrorCode.FORBIDDEN, "MCP session security epoch is stale")


def _registration_from_row(row: Mapping[str, object]) -> McpSessionRegistration:
    return McpSessionRegistration(
        session_id=Uuid7Id(_require_str(row["session_id"])),
        installation_id=Uuid7Id(_require_str(row["installation_id"])),
        brain_id=Uuid7Id(_require_str(row["brain_id"])),
        actor_id=Uuid7Id(_require_str(row["actor_id"])),
        grant_id=Uuid7Id(_require_str(row["grant_id"])),
        agent_id=_require_str(row["agent_id"]),
        workspace_fingerprint=Sha256Digest(_require_bytes(row["workspace_fingerprint"]).hex()),
        device_identity=_require_str(row["device_identity"]),
        git_repository_id=_optional_str(row["git_repository_id"]),
        git_worktree_id=_optional_str(row["git_worktree_id"]),
        git_coverage=McpGitCoverage(_require_str(row["git_coverage"])),
        project_id=_optional_uuid_from_row(row["project_id"]),
        repository_id=_optional_uuid_from_row(row["repository_id"]),
        checkout_id=_optional_uuid_from_row(row["checkout_id"]),
        security_epoch=int(_require_str(row["security_epoch"])),
        credential_digest=Sha256Digest(_require_bytes(row["credential_digest"]).hex()),
        issued_at=_datetime(_require_int(row["issued_at"])),
        expires_at=_datetime(_require_int(row["expires_at"])),
    )


def _record_json(session: McpSession) -> str:
    registration = session.registration
    return json.dumps(
        {
            "agent_id": registration.agent_id,
            "actor_id": registration.actor_id.value,
            "brain_id": registration.brain_id.value,
            "credential_digest": registration.credential_digest.value,
            "device_identity": registration.device_identity,
            "expires_at": _timestamp(registration.expires_at),
            "finished_at": _optional_timestamp(session.finished_at),
            "installation_id": registration.installation_id.value,
            "git_coverage": registration.git_coverage.value,
            "git_repository_id": registration.git_repository_id,
            "git_worktree_id": registration.git_worktree_id,
            "grant_id": registration.grant_id.value,
            "project_id": _optional_uuid(registration.project_id),
            "repository_id": _optional_uuid(registration.repository_id),
            "checkout_id": _optional_uuid(registration.checkout_id),
            "issued_at": _timestamp(registration.issued_at),
            "last_heartbeat_at": _optional_timestamp(session.last_heartbeat_at),
            "lease_duration_microseconds": (
                None
                if session.lease_duration is None
                else session.lease_duration // timedelta(microseconds=1)
            ),
            "lease_expires_at": _optional_timestamp(session.lease_expires_at),
            "revision": session.revision,
            "revoked_at": _optional_timestamp(session.revoked_at),
            "schema_version": 1,
            "security_epoch": registration.security_epoch,
            "session_id": registration.session_id.value,
            "state": session.state.value,
            "workspace_fingerprint": registration.workspace_fingerprint.value,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_record(value: str) -> McpSession:
    try:
        record = _record_mapping(value)
        duration_value = record["lease_duration_microseconds"]
        duration = (
            None if duration_value is None else timedelta(microseconds=_integer(duration_value))
        )
        return McpSession(
            registration=McpSessionRegistration(
                session_id=Uuid7Id(_string(record["session_id"])),
                installation_id=Uuid7Id(_string(record["installation_id"])),
                brain_id=Uuid7Id(_string(record["brain_id"])),
                actor_id=Uuid7Id(_string(record["actor_id"])),
                grant_id=Uuid7Id(_string(record["grant_id"])),
                agent_id=_string(record["agent_id"]),
                workspace_fingerprint=Sha256Digest(_string(record["workspace_fingerprint"])),
                device_identity=_string(record["device_identity"]),
                git_repository_id=_optional_string(record["git_repository_id"]),
                git_worktree_id=_optional_string(record["git_worktree_id"]),
                git_coverage=McpGitCoverage(_string(record["git_coverage"])),
                project_id=_optional_uuid_from_record(record["project_id"]),
                repository_id=_optional_uuid_from_record(record["repository_id"]),
                checkout_id=_optional_uuid_from_record(record["checkout_id"]),
                security_epoch=_integer(record["security_epoch"]),
                credential_digest=Sha256Digest(_string(record["credential_digest"])),
                issued_at=_parse_timestamp(_string(record["issued_at"])),
                expires_at=_parse_timestamp(_string(record["expires_at"])),
            ),
            state=McpSessionState(_string(record["state"])),
            lease_duration=duration,
            lease_expires_at=_parse_optional_timestamp(record["lease_expires_at"]),
            last_heartbeat_at=_parse_optional_timestamp(record["last_heartbeat_at"]),
            revoked_at=_parse_optional_timestamp(record["revoked_at"]),
            finished_at=_parse_optional_timestamp(record["finished_at"]),
            revision=_integer(record["revision"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise OperationError(
            ErrorCode.INTEGRITY_VIOLATION,
            "MCP session snapshot cannot be decoded",
        ) from error


def _record_mapping(value: str) -> dict[str, object]:
    raw = cast("object", json.loads(value))
    expected = {
        "agent_id",
        "actor_id",
        "brain_id",
        "credential_digest",
        "device_identity",
        "expires_at",
        "finished_at",
        "installation_id",
        "git_coverage",
        "git_repository_id",
        "git_worktree_id",
        "grant_id",
        "project_id",
        "repository_id",
        "checkout_id",
        "issued_at",
        "last_heartbeat_at",
        "lease_duration_microseconds",
        "lease_expires_at",
        "revision",
        "revoked_at",
        "schema_version",
        "security_epoch",
        "session_id",
        "state",
        "workspace_fingerprint",
    }
    if not isinstance(raw, dict):
        raise TypeError
    record = cast("dict[str, object]", raw)
    if set(record) != expected or record["schema_version"] != 1:
        raise TypeError
    return record


def _transition_matches(previous: McpSession, current: McpSession, event_type: str) -> bool:
    try:
        if event_type == "began" and current.last_heartbeat_at is not None:
            expected = previous.begin(current.last_heartbeat_at, _required_duration(current))
        elif event_type == "heartbeat" and current.last_heartbeat_at is not None:
            expected = previous.heartbeat(current.last_heartbeat_at)
        elif event_type == "revoked" and current.revoked_at is not None:
            expected = previous.revoke(current.revoked_at)
        elif event_type in {"completed", "interrupted"} and current.finished_at is not None:
            expected = previous.finish(McpSessionState(event_type), current.finished_at)
        elif event_type == "expired" and current.finished_at is not None:
            expected = previous.interrupt_if_expired(current.finished_at)
        else:
            return False
    except ValueError, OperationError:
        return False
    return expected == current


def _event(previous: McpSession, current: McpSession) -> tuple[str, datetime]:
    if current.revision != previous.revision + 1 or current.registration != previous.registration:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session successor is invalid")
    if previous.state is McpSessionState.REGISTERED and current.state is McpSessionState.ACTIVE:
        event_type, occurred = "began", current.last_heartbeat_at
    elif (
        previous.state is current.state
        and previous.revoked_at is None
        and current.revoked_at is not None
    ):
        event_type, occurred = "revoked", current.revoked_at
    elif previous.state is McpSessionState.ACTIVE and current.state is McpSessionState.ACTIVE:
        event_type, occurred = "heartbeat", current.last_heartbeat_at
    elif current.state is McpSessionState.COMPLETED:
        event_type, occurred = "completed", current.finished_at
    elif current.state is McpSessionState.INTERRUPTED and previous.revoked_at is None:
        event_type, occurred = "expired", current.finished_at
    elif current.state is McpSessionState.INTERRUPTED:
        event_type, occurred = "interrupted", current.finished_at
    else:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session transition is invalid")
    if occurred is None or not _transition_matches(previous, current, event_type):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session transition is invalid")
    return event_type, occurred


def _require_row_projection(row: Mapping[str, object], session: McpSession) -> None:
    if (
        _require_str(row["session_id"]) != session.registration.session_id.value
        or _require_int(row["revision"]) != session.revision
        or _require_str(row["state"]) != session.state.value
        or row["lease_expires_at"] != _optional_microseconds(session.lease_expires_at)
        or row["revoked_at"] != _optional_microseconds(session.revoked_at)
        or row["finished_at"] != _optional_microseconds(session.finished_at)
    ):
        raise OperationError(
            ErrorCode.INTEGRITY_VIOLATION,
            "MCP session snapshot projection diverged",
        )


async def _latest_digest(connection: AsyncConnection, session_id: Uuid7Id) -> bytes:
    value = (
        await connection.execute(
            text(
                "SELECT record_digest FROM mcp_session_snapshots WHERE session_id=:session "
                "ORDER BY revision DESC LIMIT 1"
            ),
            {"session": session_id.value},
        )
    ).scalar_one()
    return _require_bytes(value)


async def _append_audit(
    connection: AsyncConnection,
    session: McpSession,
    event_type: str,
    before_hash: bytes,
    after_hash: bytes,
) -> None:
    session_id = session.registration.session_id.value
    idempotency_key = f"mcp-session:{session_id}:{session.revision}"
    existing = (
        await connection.execute(
            text("SELECT after_hash FROM audit_events WHERE idempotency_key=:key"),
            {"key": idempotency_key},
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing != after_hash:
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session audit diverged")
        return
    previous = (
        await connection.execute(
            text("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1")
        )
    ).scalar_one_or_none()
    previous_hash = previous if isinstance(previous, bytes) else _ZERO_DIGEST
    occurred_at = _event_time(session, event_type)
    payload = json.dumps(
        {
            "action": f"mcp.session.{event_type}",
            "actor_id": session.registration.actor_id.value,
            "brain_id": session.registration.brain_id.value,
            "occurred_at": _microseconds(occurred_at),
            "target_ref": session_id,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    event_hash = hashlib.sha256(previous_hash + payload).digest()
    await connection.execute(
        text(
            "INSERT INTO audit_events "
            "(brain_id,actor_id,action,target_ref,idempotency_key,before_hash,after_hash,"
            "previous_hash,event_hash,occurred_at,schema_version) VALUES "
            "(:brain,:actor,:action,:target,:key,:before,:after,:previous,:event,:at,1)"
        ),
        {
            "brain": session.registration.brain_id.value,
            "actor": session.registration.actor_id.value,
            "action": f"mcp.session.{event_type}",
            "target": session_id,
            "key": idempotency_key,
            "before": before_hash,
            "after": after_hash,
            "previous": previous_hash,
            "event": event_hash,
            "at": _microseconds(occurred_at),
        },
    )


def _event_time(session: McpSession, event_type: str) -> datetime:
    if event_type == "registered":
        return session.registration.issued_at
    if event_type in {"began", "heartbeat"} and session.last_heartbeat_at is not None:
        return session.last_heartbeat_at
    if event_type == "revoked" and session.revoked_at is not None:
        return session.revoked_at
    if session.finished_at is not None:
        return session.finished_at
    raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session event time is absent")


def _registration_digest(registration: McpSessionRegistration) -> bytes:
    value = json.dumps(
        {
            "agent_id": registration.agent_id,
            "actor_id": registration.actor_id.value,
            "brain_id": registration.brain_id.value,
            "credential_digest": registration.credential_digest.value,
            "device_identity": registration.device_identity,
            "expires_at": _timestamp(registration.expires_at),
            "git_coverage": registration.git_coverage.value,
            "git_repository_id": registration.git_repository_id,
            "git_worktree_id": registration.git_worktree_id,
            "grant_id": registration.grant_id.value,
            "project_id": _optional_uuid(registration.project_id),
            "repository_id": _optional_uuid(registration.repository_id),
            "checkout_id": _optional_uuid(registration.checkout_id),
            "installation_id": registration.installation_id.value,
            "issued_at": _timestamp(registration.issued_at),
            "schema_version": 1,
            "security_epoch": registration.security_epoch,
            "session_id": registration.session_id.value,
            "workspace_fingerprint": registration.workspace_fingerprint.value,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(value).digest()


def _snapshot_digest(previous: bytes, record_json: str) -> bytes:
    return hashlib.sha256(previous + record_json.encode()).digest()


def _required_duration(session: McpSession) -> timedelta:
    if session.lease_duration is None:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session lease is absent")
    return session.lease_duration


def _microseconds(value: datetime) -> int:
    normalized = value.astimezone(UTC)
    return int(normalized.timestamp()) * 1_000_000 + normalized.microsecond


def _optional_microseconds(value: datetime | None) -> int | None:
    return None if value is None else _microseconds(value)


def _datetime(value: int) -> datetime:
    seconds, microseconds = divmod(value, 1_000_000)
    return datetime.fromtimestamp(seconds, UTC).replace(microsecond=microseconds)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _optional_timestamp(value: datetime | None) -> str | None:
    return None if value is None else _timestamp(value)


def _parse_timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError
    parsed = datetime.fromisoformat(value)
    if _timestamp(parsed) != value:
        raise ValueError
    return parsed


def _parse_optional_timestamp(value: object) -> datetime | None:
    return None if value is None else _parse_timestamp(_string(value))


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError
    return value


def _optional_string(value: object) -> str | None:
    return None if value is None else _string(value)


def _integer(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError
    return value


def _require_str(value: object) -> str:
    if not isinstance(value, str):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session text is invalid")
    return value


def _optional_str(value: object) -> str | None:
    return None if value is None else _require_str(value)


def _optional_uuid(value: Uuid7Id | None) -> str | None:
    return None if value is None else value.value


def _optional_uuid_from_row(value: object) -> Uuid7Id | None:
    resolved = _optional_str(value)
    return None if resolved is None else Uuid7Id(resolved)


def _optional_uuid_from_record(value: object) -> Uuid7Id | None:
    resolved = _optional_string(value)
    return None if resolved is None else Uuid7Id(resolved)


def _require_int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session integer is invalid")
    return value


def _require_bytes(value: object) -> bytes:
    if not isinstance(value, bytes) or len(value) != _DIGEST_BYTES:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "MCP session digest is invalid")
    return value
