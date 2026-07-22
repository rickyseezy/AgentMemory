"""Black-box conformance for the Python and Go PRO-002 reference adapters."""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

if TYPE_CHECKING:
    from collections.abc import Sequence

ROOT = Path(__file__).resolve().parents[2]


def _frame(method: str) -> bytes:
    request = {
        "jsonrpc": "2.0",
        "id": "reference-operation-1",
        "method": method,
        "params": {
            "protocol_version": 1,
            "operation_id": "reference-operation-1",
            "profile_id": "018f0000-0000-7000-8000-000000000711",
            "purpose": "retrieval_document",
            "content_ids": ["a", "b"],
            "classification": "internal",
            "deadline_unix_micros": 1784707230000000,
            "idempotency_key": "reference-operation-1",
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "payload": {"texts": ["alpha", "beta"]},
        },
    }
    payload = json.dumps(request, separators=(",", ":")).encode()
    return struct.pack(">I", len(payload)) + payload


def _run(command: Sequence[str]) -> dict[str, object]:
    completed = subprocess.run(  # noqa: S603 -- fixed repository-owned executable/argv fixtures.
        command,
        input=_frame("embed_documents") + _frame("shutdown"),
        capture_output=True,
        check=False,
        cwd=ROOT,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    length = struct.unpack(">I", completed.stdout[:4])[0]
    assert length <= 8 * 1024 * 1024
    return cast("dict[str, object]", json.loads(completed.stdout[4 : 4 + length]))


@pytest.mark.parametrize(
    "command",
    [
        (sys.executable, "-I", "conformance/provider-adapters/python-reference/adapter.py"),
        ("go", "run", "./conformance/provider-adapters/go-reference"),
    ],
    ids=["python-oci", "go-oci"],
)
def test_pro002_reference_adapter_preserves_order_and_declared_dimensions(
    command: Sequence[str],
) -> None:
    response = _run(command)
    result = cast("dict[str, object]", response["result"])
    items = cast("list[dict[str, object]]", result["items"])
    assert result["operation_id"] == "reference-operation-1"
    assert result["content_ids"] == ["a", "b"]
    assert [item["content_id"] for item in items] == ["a", "b"]
    assert result["dimensions"] == 8
    assert all(len(cast("list[object]", item["vector"])) == 8 for item in items)
