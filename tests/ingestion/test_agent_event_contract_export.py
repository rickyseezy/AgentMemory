"""ADP-001 checked-in language-neutral contract reproducibility tests."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from agentmemory.ingestion.adapters.inbound.agent_event_schema import (
    render_agent_event_json_schema,
)

_ROOT = Path(__file__).parents[2]
_CONTRACT = _ROOT / "contracts/agent-events/agent-event-envelope.v1.schema.json"


def test_checked_in_agent_event_schema_exactly_matches_shared_generated_type() -> None:
    assert _CONTRACT.read_bytes() == render_agent_event_json_schema()


def test_schema_export_check_command_is_release_usable() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/export_agent_event_schema.py", "--check"],
        cwd=_ROOT,
        check=False,
        capture_output=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr.decode()
