"""Single-writer async SQLite outbound adapter and transaction coordinator."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, cast

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine

from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from pathlib import Path

MINIMUM_SQLITE_VERSION: Final = (3, 53, 3)
REQUIRED_COMPILE_OPTIONS: Final = frozenset({"ENABLE_FTS5", "THREADSAFE=1"})
_SQLITE_FULL_SYNCHRONOUS: Final = 2
_MINIMUM_BUSY_TIMEOUT_MS: Final = 5_000
_VERSION_PART_COUNT: Final = 3
_CONNECTION_PRAGMAS: Final = (
    "PRAGMA synchronous=FULL",
    "PRAGMA foreign_keys=ON",
    "PRAGMA busy_timeout=5000",
    "PRAGMA secure_delete=ON",
    "PRAGMA trusted_schema=OFF",
    "PRAGMA temp_store=MEMORY",
    "PRAGMA wal_autocheckpoint=1000",
)


class _DbapiCursor(Protocol):
    def execute(self, statement: str) -> object:
        """Execute one trusted static connection pragma."""
        ...

    def close(self) -> None:
        """Release the temporary configuration cursor."""
        ...


class _DbapiConnection(Protocol):
    def cursor(self) -> _DbapiCursor:
        """Return a synchronous adapted DB-API cursor."""
        ...


@dataclass(frozen=True, slots=True)
class SqliteRuntimePolicy:
    """Immutable packaged-SQLite requirements selected by the composition root."""

    minimum_version: tuple[int, int, int]
    required_compile_options: frozenset[str]

    @classmethod
    def production(cls) -> SqliteRuntimePolicy:
        """Return the non-configurable release policy."""
        return cls(MINIMUM_SQLITE_VERSION, REQUIRED_COMPILE_OPTIONS)


@dataclass(frozen=True, slots=True)
class SqliteObservation:
    """Non-secret facts proven against one live SQLite connection."""

    version: tuple[int, int, int]
    compile_options: frozenset[str]
    journal_mode: str
    synchronous: int
    foreign_keys: int
    busy_timeout: int
    secure_delete: int
    trusted_schema: int


class SqliteCoreStore:
    """Own the active SQLite engine and serialize every write UoW."""

    def __init__(self, engine: AsyncEngine, policy: SqliteRuntimePolicy) -> None:
        """Bind one active engine to an immutable runtime policy."""
        self.engine = engine
        self.policy = policy
        self.write_lock = asyncio.Lock()

    @classmethod
    def create(cls, database_path: Path, policy: SqliteRuntimePolicy) -> SqliteCoreStore:
        """Create the sole active async engine without opening the database eagerly."""
        url = f"sqlite+aiosqlite:///{database_path}"
        engine = create_async_engine(url, pool_pre_ping=True)
        event.listen(engine.sync_engine, "connect", _configure_connection)
        return cls(engine, policy)

    async def close(self) -> None:
        """Dispose all connection resources during graceful shutdown."""
        await self.engine.dispose()

    async def observe_and_enforce_policy(self) -> SqliteObservation:
        """Set/read back every required pragma and validate the packaged engine."""
        async with self.engine.connect() as connection:
            await connection.exec_driver_sql("PRAGMA journal_mode=WAL")
            observation = await _observe(connection)
        if observation.version < self.policy.minimum_version:
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "packaged SQLite version is not certified",
                retryable=False,
            )
        if not self.policy.required_compile_options.issubset(observation.compile_options):
            raise OperationError(
                ErrorCode.DEPENDENCY_UNAVAILABLE,
                "packaged SQLite compile options are not certified",
                retryable=False,
            )
        if (
            observation.journal_mode != "wal"
            or observation.synchronous != _SQLITE_FULL_SYNCHRONOUS
            or observation.foreign_keys != 1
            or observation.busy_timeout < _MINIMUM_BUSY_TIMEOUT_MS
            or observation.secure_delete != 1
            or observation.trusted_schema != 0
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "SQLite durability policy could not be enforced",
                retryable=False,
            )
        return observation


def _configure_connection(dbapi_connection: object, connection_record: object) -> None:
    """Apply every connection-local security and durability pragma before use."""
    del connection_record
    connection = cast("_DbapiConnection", dbapi_connection)
    cursor = connection.cursor()
    try:
        for statement in _CONNECTION_PRAGMAS:
            cursor.execute(statement)
    finally:
        cursor.close()


async def _observe(connection: AsyncConnection) -> SqliteObservation:
    version_value = await _scalar_text(connection, "SELECT sqlite_version()")
    try:
        version = tuple(int(part) for part in version_value.split("."))
    except ValueError as error:
        raise OperationError(
            ErrorCode.INTEGRITY_VIOLATION,
            "SQLite returned an invalid version",
            retryable=False,
        ) from error
    if len(version) != _VERSION_PART_COUNT:
        raise OperationError(
            ErrorCode.INTEGRITY_VIOLATION,
            "SQLite returned an invalid version",
            retryable=False,
        )
    options_result = await connection.exec_driver_sql("PRAGMA compile_options")
    compile_options = frozenset(str(row[0]) for row in options_result.fetchall())
    return SqliteObservation(
        version=(version[0], version[1], version[2]),
        compile_options=compile_options,
        journal_mode=(await _scalar_text(connection, "PRAGMA journal_mode")).lower(),
        synchronous=await _scalar_int(connection, "PRAGMA synchronous"),
        foreign_keys=await _scalar_int(connection, "PRAGMA foreign_keys"),
        busy_timeout=await _scalar_int(connection, "PRAGMA busy_timeout"),
        secure_delete=await _scalar_int(connection, "PRAGMA secure_delete"),
        trusted_schema=await _scalar_int(connection, "PRAGMA trusted_schema"),
    )


async def _scalar_text(connection: AsyncConnection, statement: str) -> str:
    result = await connection.exec_driver_sql(statement)
    value = result.scalar_one()
    if not isinstance(value, str):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "SQLite result type was invalid")
    return value


async def _scalar_int(connection: AsyncConnection, statement: str) -> int:
    result = await connection.exec_driver_sql(statement)
    value = result.scalar_one()
    if not isinstance(value, int):
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "SQLite result type was invalid")
    return value
