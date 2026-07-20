"""Export or verify the immutable ADP-001 AgentEvent JSON Schema."""

from __future__ import annotations

import argparse
from pathlib import Path

from agentmemory.ingestion.adapters.inbound.agent_event_schema import (
    render_agent_event_json_schema,
)

_DEFAULT_OUTPUT = Path("contracts/agent-events/agent-event-envelope.v1.schema.json")


def main() -> int:
    """Write deterministic schema bytes, or fail when the checked-in file drifts."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT)
    arguments = parser.parse_args()
    expected = render_agent_event_json_schema()
    if arguments.check:
        if not arguments.output.is_file() or arguments.output.read_bytes() != expected:
            return 1
        return 0
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_bytes(expected)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess contract.
    raise SystemExit(main())
