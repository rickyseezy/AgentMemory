# ruff: noqa: INP001
"""Deterministic PRO-002 framed-stdio reference adapter using only the Python stdlib."""

from __future__ import annotations

import hashlib
import json
import math
import struct
import sys
from typing import Any

MAX_FRAME = 8 * 1024 * 1024
FRAME_PREFIX_BYTES = 4
MODEL_REVISION = "agentmemory-reference-sha256-v1"


def _read_exact(size: int) -> bytes:
    value = sys.stdin.buffer.read(size)
    if len(value) != size:
        raise EOFError
    return value


def _vector(text: str) -> list[float]:
    raw = hashlib.sha256(text.encode("utf-8")).digest()
    values = [(byte - 127.5) / 127.5 for byte in raw[:8]]
    norm = math.sqrt(sum(value * value for value in values)) or 1.0
    return [value / norm for value in values]


def _response(request: dict[str, Any]) -> dict[str, Any]:
    operation_id = request["params"]["operation_id"]
    content_ids = request["params"]["content_ids"]
    method = request["method"]
    payload = request["params"]["payload"]
    texts = payload.get("texts", [""] * len(content_ids))
    items: list[dict[str, Any]] = []
    for index, content_id in enumerate(content_ids):
        item: dict[str, Any] = {"content_id": content_id}
        if method in ("embed_documents", "embed_queries", "probe"):
            item["vector"] = _vector(str(texts[index]))
        elif method == "rerank":
            item["score"] = float(len(str(texts[index])))
        items.append(item)
    return {
        "jsonrpc": "2.0",
        "id": request["id"],
        "result": {
            "operation_id": operation_id,
            "content_ids": content_ids,
            "items": items,
            "dimensions": 8 if any("vector" in item for item in items) else 0,
            "usage": {"input_tokens": 0, "output_tokens": 0, "billable_units": 0},
            "model_revision": MODEL_REVISION,
        },
    }


def main() -> int:
    """Serve bounded consecutive frames until EOF or shutdown."""
    while True:
        prefix = sys.stdin.buffer.read(4)
        if not prefix:
            return 0
        if len(prefix) != FRAME_PREFIX_BYTES:
            return 2
        length = struct.unpack(">I", prefix)[0]
        if length == 0 or length > MAX_FRAME:
            return 2
        try:
            request = json.loads(_read_exact(length))
            response = json.dumps(_response(request), separators=(",", ":")).encode()
        except EOFError, KeyError, TypeError, ValueError, json.JSONDecodeError:
            return 2
        sys.stdout.buffer.write(struct.pack(">I", len(response)) + response)
        sys.stdout.buffer.flush()
        if request["method"] == "shutdown":
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
