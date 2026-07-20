"""Strict authenticated loopback uploader for interruption-recovery batches."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast
from urllib.parse import urlsplit

import httpx

from agentmemory.ingestion.domain.errors import IngestionDependencyError
from agentmemory.ingestion.domain.spool_reconciliation import (
    SpoolUploadDisposition,
    SpoolUploadResult,
)

if TYPE_CHECKING:
    from agentmemory.ingestion.domain.spool_reconciliation import SpoolRecord

_CREDENTIAL_BYTES = 32
_MAXIMUM_ITEMS = 100
_MAXIMUM_CANONICAL_BYTES = 1024 * 1024
_MAXIMUM_RESPONSE_BYTES = 64 * 1024
_HTTP_OK = 200
_CONFLICT_HTTP_STATUSES = frozenset({409})
_REJECTED_HTTP_STATUSES = frozenset({400, 401, 403, 404, 405, 413, 415, 422})
_ERR_UNAVAILABLE = "AgentEvent Core replay is unavailable"
_ERR_RECEIPT = "AgentEvent Core returned an invalid replay receipt"


@dataclass(frozen=True, slots=True)
class HttpSpoolBatchUploader:
    """Upload bounded canonical bytes without following redirects or exposing content."""

    client: httpx.AsyncClient
    endpoint: str
    credential: bytes

    def __post_init__(self) -> None:
        """Refuse non-loopback, credential-bearing, and path-bearing destinations."""
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or len(self.credential) != _CREDENTIAL_BYTES
        ):
            msg = "spool batch endpoint or credential is invalid"
            raise ValueError(msg)

    async def upload(self, records: tuple[SpoolRecord, ...]) -> tuple[SpoolUploadResult, ...]:
        """Post one bounded batch and strictly validate exact ordered item identities."""
        if not records:
            return ()
        if len(records) > _MAXIMUM_ITEMS:
            msg = "spool upload batch exceeds the item bound"
            raise ValueError(msg)
        canonical_bytes = sum(len(item.canonical_event) for item in records)
        if canonical_bytes > _MAXIMUM_CANONICAL_BYTES:
            msg = "spool upload batch exceeds the byte bound"
            raise ValueError(msg)
        body = b'{"events":[' + b",".join(item.canonical_event for item in records) + b"]}"
        try:
            response = await self.client.post(
                f"{self.endpoint.rstrip('/')}/v1/agent-events:append-batch",
                content=body,
                headers={
                    "Authorization": f"Bearer {self.credential.hex()}",
                    "Content-Type": "application/json",
                },
                follow_redirects=False,
            )
        except httpx.RequestError as error:
            raise IngestionDependencyError(_ERR_UNAVAILABLE) from error
        if response.status_code == _HTTP_OK:
            return _parse_receipt(response.content, records)
        disposition = _failure_disposition(response.status_code)
        return tuple(SpoolUploadResult(item.event_id, disposition) for item in records)


def _failure_disposition(status_code: int) -> SpoolUploadDisposition:
    if status_code in _CONFLICT_HTTP_STATUSES:
        return SpoolUploadDisposition.CONFLICT
    if status_code in _REJECTED_HTTP_STATUSES:
        return SpoolUploadDisposition.REJECTED
    return SpoolUploadDisposition.RETRYABLE


def _parse_receipt(
    raw: bytes,
    records: tuple[SpoolRecord, ...],
) -> tuple[SpoolUploadResult, ...]:
    if not raw or len(raw) > _MAXIMUM_RESPONSE_BYTES:
        raise IngestionDependencyError(_ERR_RECEIPT)
    document = _strict_json(raw)
    if not isinstance(document, dict):
        raise IngestionDependencyError(_ERR_RECEIPT)
    mapping = cast("dict[object, object]", document)
    if set(mapping) != {"results"}:
        raise IngestionDependencyError(_ERR_RECEIPT)
    items = mapping["results"]
    if not isinstance(items, list):
        raise IngestionDependencyError(_ERR_RECEIPT)
    item_values = cast("list[object]", items)
    if len(item_values) != len(records):
        raise IngestionDependencyError(_ERR_RECEIPT)
    results = tuple(_parse_item(item) for item in item_values)
    if tuple(item.event_id for item in results) != tuple(item.event_id for item in records):
        raise IngestionDependencyError(_ERR_RECEIPT)
    return results


def _parse_item(value: object) -> SpoolUploadResult:
    if not isinstance(value, dict):
        raise IngestionDependencyError(_ERR_RECEIPT)
    item = cast("dict[object, object]", value)
    event_id = item.get("event_id")
    status = item.get("status")
    if not isinstance(event_id, str) or not isinstance(status, str):
        raise IngestionDependencyError(_ERR_RECEIPT)
    try:
        disposition = SpoolUploadDisposition(status)
    except ValueError as error:
        raise IngestionDependencyError(_ERR_RECEIPT) from error
    durable_keys = {
        "event_id",
        "status",
        "ingested_at_microseconds",
        "clock_skew_microseconds",
    }
    if disposition.durable:
        if set(item) != durable_keys:
            raise IngestionDependencyError(_ERR_RECEIPT)
        ingested_at = item["ingested_at_microseconds"]
        clock_skew = item["clock_skew_microseconds"]
        if (
            not isinstance(ingested_at, int)
            or isinstance(ingested_at, bool)
            or not isinstance(clock_skew, int)
            or isinstance(clock_skew, bool)
        ):
            raise IngestionDependencyError(_ERR_RECEIPT)
        try:
            return SpoolUploadResult(event_id, disposition, ingested_at, clock_skew)
        except (TypeError, ValueError) as error:
            raise IngestionDependencyError(_ERR_RECEIPT) from error
    if set(item) != {"event_id", "status"}:
        raise IngestionDependencyError(_ERR_RECEIPT)
    return SpoolUploadResult(event_id, disposition)


def _strict_json(raw: bytes) -> object:
    def reject_constant(_: str) -> None:
        raise ValueError

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        document: dict[str, object] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError
            document[key] = value
        return document

    try:
        return cast(
            "object",
            json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise IngestionDependencyError(_ERR_RECEIPT) from error
