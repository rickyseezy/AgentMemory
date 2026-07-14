"""Optimized read-only SQLite readiness status query."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import text

from agentmemory.operations.adapters.outbound.receipt_codec import decode_receipt
from agentmemory.operations.domain.errors import ErrorCode, OperationError

if TYPE_CHECKING:
    from agentmemory.operations.adapters.outbound.sqlite_store import SqliteCoreStore
    from agentmemory.operations.domain.readiness import ReadinessReceipt


class SqliteReadinessStatusQuery:
    """Read and authenticate the latest readiness receipt without a write UoW."""

    def __init__(self, store: SqliteCoreStore) -> None:
        """Bind to the active canonical store."""
        self._store = store

    async def latest(self) -> ReadinessReceipt | None:
        """Return the latest complete receipt or fail closed on corruption."""
        async with self._store.engine.connect() as connection:
            payload = (
                await connection.execute(
                    text(
                        "SELECT record_json FROM readiness_receipts "
                        "ORDER BY evaluated_at DESC LIMIT 1"
                    )
                )
            ).scalar_one_or_none()
        if payload is None:
            return None
        if not isinstance(payload, str):
            raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "readiness status was malformed")
        try:
            return decode_receipt(payload)
        except ValueError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "readiness status failed integrity validation",
            ) from error
