"""SQLite repository for the crash-resumable Core active-release mirror."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from sqlalchemy import text

from agentmemory.operations.adapters.outbound.receipt_codec import decode_receipt
from agentmemory.operations.domain.active_release import (
    ActiveReleasePointer,
    active_release_stage_digest,
    permits_replacement,
)
from agentmemory.operations.domain.errors import DomainValidationError, ErrorCode, OperationError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.ext.asyncio import AsyncConnection

    from agentmemory.operations.domain.value_objects import OperationId, Sha256Digest
    from agentmemory.shared.clock import Clock


class SqliteActiveReleaseRepository:
    """Persist stage intent and the exact active pointer under one writer lock."""

    def __init__(self, connection: AsyncConnection, clock: Clock) -> None:
        """Bind all operations to the caller's explicit SQLite transaction."""
        self._connection = connection
        self._clock = clock

    async def stage(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> tuple[Sha256Digest, bool]:
        """Stage only an exact locally persisted all-probe readiness receipt."""
        await self._verify_installation(pointer)
        await self._verify_readiness(operation_id, pointer)
        current = await self._load_active_pointer()
        if not permits_replacement(current, pointer):
            raise OperationError(ErrorCode.CONFLICT, "active-release stage is a rollback")
        expected_stage = active_release_stage_digest(operation_id, pointer)
        existing = await self._load_stage(operation_id.value)
        if existing is not None:
            self._verify_stage_row(existing, operation_id.value, expected_stage, pointer)
            return expected_stage, True
        now = _unix_microseconds(self._clock)
        await self._connection.execute(
            text(
                "INSERT INTO active_release_stages "
                "(operation_id, pointer_digest, readiness_receipt_digest, stage_digest, "
                "pointer_record_json, state, created_at, committed_at, schema_version) VALUES "
                "(:operation_id, :pointer_digest, :readiness_digest, :stage_digest, "
                ":record_json, 'staged', :created_at, NULL, 1)"
            ),
            {
                "operation_id": operation_id.value,
                "pointer_digest": bytes.fromhex(pointer.pointer_digest.value),
                "readiness_digest": bytes.fromhex(pointer.readiness_receipt_digest.value),
                "stage_digest": bytes.fromhex(expected_stage.value),
                "record_json": _encode_pointer(pointer),
                "created_at": now,
            },
        )
        return expected_stage, False

    async def commit(
        self,
        operation_id: OperationId,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> Sha256Digest:
        """Atomically promote only the exact staged pointer and update its mirror."""
        expected_stage = active_release_stage_digest(operation_id, pointer)
        if expected_stage != stage_digest:
            raise OperationError(ErrorCode.CONFLICT, "active-release stage receipt mismatched")
        row = await self._load_stage(operation_id.value)
        if row is None:
            raise OperationError(ErrorCode.CONFLICT, "active-release stage was not found")
        self._verify_stage_row(row, operation_id.value, expected_stage, pointer)
        current = await self._load_active_pointer()
        if not permits_replacement(current, pointer):
            raise OperationError(ErrorCode.CONFLICT, "active-release commit is a rollback")
        now = _unix_microseconds(self._clock)
        await self._connection.execute(
            text(
                "INSERT INTO active_release_pointers "
                "(singleton_key, installation_id, pointer_digest, pointer_record_json, "
                "release_sequence, resource_inventory_version, security_epoch, activated_at, "
                "created_at, updated_at, schema_version) VALUES "
                "('local', :installation_id, :pointer_digest, :record_json, :release_sequence, "
                ":inventory_version, :security_epoch, :activated_at, :now, :now, 1) "
                "ON CONFLICT(singleton_key) DO UPDATE SET "
                "installation_id = excluded.installation_id, "
                "pointer_digest = excluded.pointer_digest, "
                "pointer_record_json = excluded.pointer_record_json, "
                "release_sequence = excluded.release_sequence, "
                "resource_inventory_version = excluded.resource_inventory_version, "
                "security_epoch = excluded.security_epoch, activated_at = excluded.activated_at, "
                "updated_at = excluded.updated_at, schema_version = excluded.schema_version"
            ),
            {
                "installation_id": pointer.installation_id.value,
                "pointer_digest": bytes.fromhex(pointer.pointer_digest.value),
                "record_json": _encode_pointer(pointer),
                "release_sequence": str(pointer.release_sequence),
                "inventory_version": str(pointer.resource_inventory_version),
                "security_epoch": str(pointer.security_epoch),
                "activated_at": _datetime_microseconds(pointer.activated_at),
                "now": now,
            },
        )
        installation_update = await self._connection.execute(
            text(
                "UPDATE installation_state SET active_release_digest = :pointer_digest, "
                "active_data_generation = :generation_id, security_epoch = :security_epoch, "
                "updated_at = :updated_at WHERE singleton_key = 'local' "
                "AND installation_id = :installation_id"
            ),
            {
                "pointer_digest": bytes.fromhex(pointer.pointer_digest.value),
                "generation_id": pointer.generation_id.value,
                "security_epoch": str(pointer.security_epoch),
                "updated_at": now,
                "installation_id": pointer.installation_id.value,
            },
        )
        if installation_update.rowcount != 1:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "active-release installation mirror is incomplete",
            )
        await self._connection.execute(
            text(
                "UPDATE active_release_stages SET state = 'committed', committed_at = :now "
                "WHERE operation_id = :operation_id AND stage_digest = :stage_digest"
            ),
            {
                "now": now,
                "operation_id": operation_id.value,
                "stage_digest": bytes.fromhex(stage_digest.value),
            },
        )
        return pointer.pointer_digest

    async def matches(self, pointer: ActiveReleasePointer) -> bool:
        """Authenticate both durable mirrors before returning exact equality."""
        current = await self._load_active_pointer()
        if current is None:
            return False
        installation = (
            (
                await self._connection.execute(
                    text(
                        "SELECT installation_id, active_release_digest, "
                        "active_data_generation, security_epoch FROM installation_state "
                        "WHERE singleton_key = 'local'"
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if installation is None:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "active-release installation mirror is absent",
            )
        digest = installation["active_release_digest"]
        if (
            not isinstance(digest, bytes)
            or installation["installation_id"] != current.installation_id.value
            or digest.hex() != current.pointer_digest.value
            or installation["active_data_generation"] != current.generation_id.value
            or installation["security_epoch"] != str(current.security_epoch)
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "active-release mirrors disagree",
            )
        return current == pointer

    async def _verify_installation(self, pointer: ActiveReleasePointer) -> None:
        installation_id = (
            await self._connection.execute(
                text("SELECT installation_id FROM installation_state WHERE singleton_key = 'local'")
            )
        ).scalar_one_or_none()
        if installation_id != pointer.installation_id.value:
            raise OperationError(ErrorCode.CONFLICT, "active-release installation mismatched")

    async def _verify_readiness(
        self,
        operation_id: OperationId,
        pointer: ActiveReleasePointer,
    ) -> None:
        payload = (
            await self._connection.execute(
                text(
                    "SELECT record_json FROM readiness_receipts "
                    "WHERE receipt_digest = :receipt_digest"
                ),
                {"receipt_digest": bytes.fromhex(pointer.readiness_receipt_digest.value)},
            )
        ).scalar_one_or_none()
        if not isinstance(payload, str):
            raise OperationError(ErrorCode.CONFLICT, "active-release readiness proof was not found")
        try:
            receipt = decode_receipt(payload)
        except ValueError as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "active-release readiness proof failed integrity validation",
            ) from error
        binding = receipt.binding
        if (
            binding.operation_id != operation_id
            or receipt.digest != pointer.readiness_receipt_digest
            or binding.release_id != pointer.release_id
            or binding.generation_id != pointer.generation_id
            or binding.manifest_digest != pointer.manifest_digest
            or binding.compose_digest != pointer.compose_digest
        ):
            raise OperationError(ErrorCode.CONFLICT, "active-release readiness binding mismatched")

    async def _load_stage(self, operation_id: str) -> Mapping[str, object] | None:
        row = (
            (
                await self._connection.execute(
                    text(
                        "SELECT operation_id, pointer_digest, readiness_receipt_digest, "
                        "stage_digest, pointer_record_json, state FROM active_release_stages "
                        "WHERE operation_id = :operation_id"
                    ),
                    {"operation_id": operation_id},
                )
            )
            .mappings()
            .one_or_none()
        )
        return None if row is None else dict(row)

    def _verify_stage_row(
        self,
        row: Mapping[str, object],
        operation_id: str,
        stage_digest: Sha256Digest,
        pointer: ActiveReleasePointer,
    ) -> None:
        pointer_digest = row["pointer_digest"]
        readiness_digest = row["readiness_receipt_digest"]
        persisted_stage = row["stage_digest"]
        payload = row["pointer_record_json"]
        if (
            row["operation_id"] != operation_id
            or not isinstance(pointer_digest, bytes)
            or pointer_digest.hex() != pointer.pointer_digest.value
            or not isinstance(readiness_digest, bytes)
            or readiness_digest.hex() != pointer.readiness_receipt_digest.value
            or not isinstance(persisted_stage, bytes)
            or persisted_stage.hex() != stage_digest.value
            or row["state"] not in {"staged", "committed"}
            or not isinstance(payload, str)
            or _decode_pointer(payload) != pointer
        ):
            raise OperationError(ErrorCode.CONFLICT, "active-release stage already conflicted")

    async def _load_active_pointer(self) -> ActiveReleasePointer | None:
        row = (
            (
                await self._connection.execute(
                    text(
                        "SELECT installation_id, pointer_digest, pointer_record_json, "
                        "release_sequence, resource_inventory_version, security_epoch, "
                        "activated_at, schema_version FROM active_release_pointers "
                        "WHERE singleton_key = 'local'"
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        payload = row["pointer_record_json"]
        digest = row["pointer_digest"]
        if not isinstance(payload, str) or not isinstance(digest, bytes):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "active-release pointer mirror is malformed",
            )
        try:
            pointer = _decode_pointer(payload)
        except (DomainValidationError, TypeError, ValueError) as error:
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "active-release pointer mirror failed integrity validation",
            ) from error
        if (
            digest.hex() != pointer.pointer_digest.value
            or row["installation_id"] != pointer.installation_id.value
            or row["release_sequence"] != str(pointer.release_sequence)
            or row["resource_inventory_version"] != str(pointer.resource_inventory_version)
            or row["security_epoch"] != str(pointer.security_epoch)
            or row["activated_at"] != _datetime_microseconds(pointer.activated_at)
            or row["schema_version"] != 1
        ):
            raise OperationError(
                ErrorCode.INTEGRITY_VIOLATION,
                "active-release pointer mirror failed integrity validation",
            )
        return pointer


def _encode_pointer(pointer: ActiveReleasePointer) -> str:
    return json.dumps(pointer.record(), separators=(",", ":"), sort_keys=True)


def _decode_pointer(payload: str) -> ActiveReleasePointer:
    decoded = json.loads(payload, object_pairs_hook=_unique_object)
    if not isinstance(decoded, dict):
        msg = "active-release pointer document is invalid"
        raise TypeError(msg)
    pointer = ActiveReleasePointer.restore(cast("dict[str, object]", decoded))
    if _encode_pointer(pointer) != payload:
        msg = "active-release pointer document is not canonical"
        raise ValueError(msg)
    return pointer


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            msg = "active-release pointer document contains duplicate keys"
            raise ValueError(msg)
        output[key] = value
    return output


def _unix_microseconds(clock: Clock) -> int:
    return _datetime_microseconds(clock.now())


def _datetime_microseconds(value: object) -> int:
    from datetime import datetime  # noqa: PLC0415 -- Avoid runtime-only clock import cycle.

    if not isinstance(value, datetime) or value.tzinfo is None:
        raise OperationError(ErrorCode.INTEGRITY_VIOLATION, "active-release time was invalid")
    return int(value.timestamp()) * 1_000_000 + value.microsecond
