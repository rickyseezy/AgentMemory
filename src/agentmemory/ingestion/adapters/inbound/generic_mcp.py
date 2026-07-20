"""Bounded stdio MCP checkpoint tool for hookless agent hosts."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from agentmemory.ingestion.application.generic_adapter import (
    GENERIC_CHECKPOINT_TOOL,
    CheckpointGenericTaskCommand,
)
from agentmemory.ingestion.domain.capture import AppendAgentEventResult, AppendDisposition

if TYPE_CHECKING:
    from typing import BinaryIO

    from agentmemory.ingestion.application.generic_adapter import (
        CheckpointGenericTaskHandler,
        GenericAdapterContext,
    )

_MAX_FRAME_BYTES = 65_536
_SUPPORTED_PROTOCOLS = ("2025-11-25", "2025-06-18", "2025-03-26")
_LATEST_PROTOCOL = _SUPPORTED_PROTOCOLS[0]
_SERVER_NAME = "agentmemory-generic-checkpoint"
_SERVER_VERSION = "1.0.0"


@dataclass(slots=True)
class GenericCheckpointMcpServer:
    """Serve exactly initialize, ping, tool discovery, and explicit checkpoint calls."""

    handler: CheckpointGenericTaskHandler
    context: GenericAdapterContext
    _initialize_seen: bool = False
    _initialized: bool = False

    async def serve(self, reader: BinaryIO, writer: BinaryIO) -> None:
        """Process newline-delimited JSON-RPC until clean stdin EOF."""
        while frame := await asyncio.to_thread(reader.readline, _MAX_FRAME_BYTES + 1):
            response = await self.handle_frame(frame)
            if response is not None:
                await asyncio.to_thread(_write_frame, writer, response)

    async def handle_frame(self, frame: bytes) -> dict[str, object] | None:
        """Validate one complete MCP frame before dispatching any side effect."""
        try:
            request = _parse_frame(frame)
        except _McpProtocolError as error:
            return _error(error.request_id, error.code, error.message)
        return await self._dispatch(request)

    async def _dispatch(self, request: _McpRequest) -> dict[str, object] | None:
        response: dict[str, object] | None
        if request.method == "initialize":
            response = self._initialize(request.request_id, request.params)
        elif request.method == "notifications/initialized":
            response = self._mark_initialized(request.request_id)
        elif not self._initialized:
            response = _error(request.request_id, -32002, "Server not initialized")
        elif request.method == "ping":
            response = _result(request.request_id, {})
        elif request.method == "tools/list":
            response = self._list_tools(request.request_id, request.params)
        elif request.method == "tools/call":
            response = await self._call_tool(request.request_id, request.params)
        else:
            response = _error(request.request_id, -32601, "Method not found")
        return response

    def _initialize(
        self,
        request_id: str | int | None,
        params: dict[object, object],
    ) -> dict[str, object]:
        if self._initialize_seen or request_id is None:
            return _error(request_id, -32600, "Invalid Request")
        version = params.get("protocolVersion")
        capabilities = params.get("capabilities")
        client_info = params.get("clientInfo")
        if (
            not isinstance(version, str)
            or not isinstance(capabilities, dict)
            or not isinstance(client_info, dict)
        ):
            return _error(request_id, -32602, "Invalid params")
        self._initialize_seen = True
        negotiated = version if version in _SUPPORTED_PROTOCOLS else _LATEST_PROTOCOL
        return _result(
            request_id,
            {
                "capabilities": {"tools": {"listChanged": False}},
                "instructions": (
                    "Use agentmemory_checkpoint only for explicit task checkpoints. "
                    "Prompt, turn, tool, and hidden-reasoning provenance remain unknown."
                ),
                "protocolVersion": negotiated,
                "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
            },
        )

    def _mark_initialized(self, request_id: str | int | None) -> dict[str, object] | None:
        if not self._initialize_seen or request_id is not None:
            return _error(request_id, -32600, "Invalid Request")
        self._initialized = True
        return None

    def _list_tools(
        self,
        request_id: str | int | None,
        params: dict[object, object],
    ) -> dict[str, object]:
        if request_id is None or any(key != "cursor" for key in params):
            return _error(request_id, -32602, "Invalid params")
        cursor = params.get("cursor")
        if cursor is not None and cursor != "":
            return _error(request_id, -32602, "Invalid params")
        return _result(request_id, {"tools": [GENERIC_CHECKPOINT_TOOL]})

    async def _call_tool(
        self,
        request_id: str | int | None,
        params: dict[object, object],
    ) -> dict[str, object]:
        try:
            checkpoint_id, summary = _parse_tool_arguments(request_id, params)
            receipt = await self.handler.execute(
                CheckpointGenericTaskCommand(
                    checkpoint_id,
                    summary,
                    self.context,
                )
            )
        except _McpProtocolError as error:
            response = _error(error.request_id, error.code, error.message)
        except OSError, RuntimeError, ValueError:
            response = _tool_failure(request_id)
        else:
            response = _tool_receipt(request_id, receipt)
        return response


@dataclass(frozen=True, slots=True)
class _McpRequest:
    request_id: str | int | None
    method: str
    params: dict[object, object]


@dataclass(frozen=True, slots=True)
class _McpProtocolError(Exception):
    request_id: str | int | None
    code: int
    message: str


def _parse_frame(frame: bytes) -> _McpRequest:
    if not frame.endswith(b"\n") or len(frame) > _MAX_FRAME_BYTES:
        raise _McpProtocolError(None, -32700, "Parse error")
    try:
        value = json.loads(frame, object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise _McpProtocolError(None, -32700, "Parse error") from error
    if not isinstance(value, dict):
        raise _McpProtocolError(None, -32600, "Invalid Request")
    document = cast("dict[object, object]", value)
    raw_request_id = document.get("id")
    request_id = _request_id(raw_request_id)
    if "id" in document and request_id is None:
        raise _McpProtocolError(None, -32600, "Invalid Request")
    method = document.get("method")
    if document.get("jsonrpc") != "2.0" or not isinstance(method, str):
        raise _McpProtocolError(request_id, -32600, "Invalid Request")
    params = document.get("params", {})
    if not isinstance(params, dict):
        raise _McpProtocolError(request_id, -32602, "Invalid params")
    return _McpRequest(request_id, method, cast("dict[object, object]", params))


def _parse_tool_arguments(
    request_id: str | int | None,
    params: dict[object, object],
) -> tuple[str, str]:
    if request_id is None or set(params) != {"name", "arguments"}:
        raise _McpProtocolError(request_id, -32602, "Invalid params")
    if params.get("name") != GENERIC_CHECKPOINT_TOOL["name"]:
        raise _McpProtocolError(request_id, -32602, "Unknown tool")
    arguments = params.get("arguments")
    if not isinstance(arguments, dict):
        raise _McpProtocolError(request_id, -32602, "Invalid params")
    typed_arguments = cast("dict[object, object]", arguments)
    if set(typed_arguments) != {"checkpoint_id", "summary"}:
        raise _McpProtocolError(request_id, -32602, "Invalid params")
    checkpoint_id = typed_arguments.get("checkpoint_id")
    summary = typed_arguments.get("summary")
    if not isinstance(checkpoint_id, str) or not isinstance(summary, str):
        raise _McpProtocolError(request_id, -32602, "Invalid params")
    return checkpoint_id, summary


def _tool_failure(request_id: str | int | None) -> dict[str, object]:
    return _result(
        request_id,
        {
            "content": [{"text": "Checkpoint capture failed", "type": "text"}],
            "isError": True,
        },
    )


def _tool_receipt(
    request_id: str | int | None,
    receipt: AppendAgentEventResult,
) -> dict[str, object]:
    if receipt.disposition not in {
        AppendDisposition.ACCEPTED,
        AppendDisposition.DUPLICATE,
    }:
        return _tool_failure(request_id)
    structured = {
        "event_id": receipt.event_id,
        "status": receipt.disposition.value,
    }
    return _result(
        request_id,
        {
            "content": [{"text": "Checkpoint persisted", "type": "text"}],
            "isError": False,
            "structuredContent": structured,
        },
    )


def _request_id(value: object) -> str | int | None:
    if value is None or isinstance(value, bool):
        return None
    return value if isinstance(value, (str, int)) else None


def _result(request_id: str | int | None, result: dict[str, object]) -> dict[str, object]:
    return {"id": request_id, "jsonrpc": "2.0", "result": result}


def _error(
    request_id: str | int | None,
    code: int,
    message: str,
) -> dict[str, object]:
    return {
        "error": {"code": code, "message": message},
        "id": request_id,
        "jsonrpc": "2.0",
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            msg = "duplicate JSON key"
            raise ValueError(msg)
        document[key] = value
    return document


def _write_frame(writer: BinaryIO, document: dict[str, object]) -> None:
    payload = json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    writer.write(f"{payload}\n".encode())
    writer.flush()
