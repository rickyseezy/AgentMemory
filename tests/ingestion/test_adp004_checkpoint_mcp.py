"""ADP-004 MCP 2025-11-25 explicit-checkpoint conformance tests."""

from __future__ import annotations

import io
import json
from typing import cast

import pytest

from agentmemory.ingestion.adapters.generic_transcript import RegexSensitiveTextRedactor
from agentmemory.ingestion.adapters.inbound.generic_mcp import GenericCheckpointMcpServer
from agentmemory.ingestion.application.generic_adapter import CheckpointGenericTaskHandler
from agentmemory.ingestion.infrastructure.generic_cli import create_generic_cli_parser
from tests.ingestion.test_adp004_observers_and_wrapper import RecordingAdapter
from tests.ingestion.test_adp004_transcript_and_application import context


def frame(document: dict[str, object]) -> bytes:
    return f"{json.dumps(document, separators=(',', ':'))}\n".encode()


def initialize(request_id: int = 1, version: str = "2025-11-25") -> bytes:
    return frame(
        {
            "id": request_id,
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
                "protocolVersion": version,
            },
        }
    )


def initialized() -> bytes:
    return frame({"jsonrpc": "2.0", "method": "notifications/initialized"})


def server(adapter: RecordingAdapter) -> GenericCheckpointMcpServer:
    return GenericCheckpointMcpServer(
        CheckpointGenericTaskHandler(RegexSensitiveTextRedactor(), adapter),
        context(),
    )


@pytest.mark.asyncio
@pytest.mark.contract
async def test_stdio_mcp_initializes_lists_and_calls_checkpoint_with_stdout_purity() -> None:
    adapter = RecordingAdapter()
    request = b"".join(
        (
            initialize(),
            initialized(),
            frame({"id": 2, "jsonrpc": "2.0", "method": "tools/list", "params": {}}),
            frame(
                {
                    "id": 3,
                    "jsonrpc": "2.0",
                    "method": "tools/call",
                    "params": {
                        "arguments": {
                            "checkpoint_id": "018f0000-0000-7000-8000-000000000223",
                            "summary": "token=private-value next step",
                        },
                        "name": "agentmemory_checkpoint",
                    },
                }
            ),
        )
    )
    output = io.BytesIO()

    await server(adapter).serve(io.BytesIO(request), output)

    lines = output.getvalue().splitlines()
    assert len(lines) == 3
    responses = [cast("dict[str, object]", json.loads(line)) for line in lines]
    assert _result_document(responses[0])["protocolVersion"] == "2025-11-25"
    tools = _result_document(responses[1])["tools"]
    assert isinstance(tools, list)
    tool = cast("dict[str, object]", tools[0])
    assert tool["name"] == "agentmemory_checkpoint"
    output_schema = cast("dict[str, object]", tool["outputSchema"])
    assert output_schema["additionalProperties"] is False
    call_result = _result_document(responses[2])
    assert call_result["isError"] is False
    structured = cast("dict[str, object]", call_result["structuredContent"])
    assert structured["status"] == "accepted"
    assert all(json.dumps(response, separators=(",", ":")).encode() for response in responses)
    assert len(adapter.events) == 1
    assert adapter.events[0].payload is not None
    assert b"private-value" not in adapter.events[0].payload.value


@pytest.mark.asyncio
async def test_mcp_negotiates_latest_stable_version_for_unsupported_client_version() -> None:
    response = await server(RecordingAdapter()).handle_frame(initialize(version="future-version"))

    assert response is not None
    assert _result_document(response)["protocolVersion"] == "2025-11-25"


@pytest.mark.asyncio
async def test_mcp_rejects_preinitialize_calls_unknown_tools_and_extra_arguments() -> None:
    adapter = RecordingAdapter()
    mcp = server(adapter)
    before = await mcp.handle_frame(
        frame({"id": 1, "jsonrpc": "2.0", "method": "tools/list", "params": {}})
    )
    await mcp.handle_frame(initialize())
    await mcp.handle_frame(initialized())
    unknown = await mcp.handle_frame(
        frame(
            {
                "id": 2,
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"arguments": {}, "name": "unknown"},
            }
        )
    )
    extra = await mcp.handle_frame(
        frame(
            {
                "id": 3,
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "arguments": {
                        "checkpoint_id": "one",
                        "extra": True,
                        "summary": "safe",
                    },
                    "name": "agentmemory_checkpoint",
                },
            }
        )
    )

    assert before is not None
    assert _error_code(before) == -32002
    assert unknown is not None
    assert _error_code(unknown) == -32602
    assert extra is not None
    assert _error_code(extra) == -32602
    assert not adapter.events


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "invalid",
    [
        b"not-json\n",
        b'{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":true,"method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":1,"method":"ping"}',
        b"x" * 65_537 + b"\n",
    ],
)
async def test_mcp_rejects_malformed_duplicate_unterminated_or_oversized_frames(
    invalid: bytes,
) -> None:
    response = await server(RecordingAdapter()).handle_frame(invalid)

    assert response is not None
    assert _error_code(response) in {-32700, -32600}


@pytest.mark.asyncio
async def test_mcp_clean_eof_emits_no_frame() -> None:
    output = io.BytesIO()

    await server(RecordingAdapter()).serve(io.BytesIO(), output)

    assert output.getvalue() == b""


def test_cli_exposes_checkpoint_mcp_operation() -> None:
    arguments = create_generic_cli_parser().parse_args(["--config", "/private/context", "mcp"])

    assert arguments.operation == "mcp"


def _result_document(response: dict[str, object]) -> dict[str, object]:
    result = response.get("result")
    assert isinstance(result, dict)
    return cast("dict[str, object]", result)


def _error_code(response: dict[str, object]) -> int:
    error = response.get("error")
    assert isinstance(error, dict)
    document = cast("dict[str, object]", error)
    code = document.get("code")
    assert isinstance(code, int)
    return code
