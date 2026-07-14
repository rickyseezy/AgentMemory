from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).parents[2]
_WORKFLOW = _ROOT / ".github/workflows/pf001-model-qualification.yml"


def test_pf001_model_qualification_workflow_is_release_only_and_immutable() -> None:
    workflow = _WORKFLOW.read_text(encoding="utf-8")

    assert "pull_request:" not in workflow
    assert 'tags:\n      - "v*"' in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "python -m tools.qualify_default_models" in workflow
    assert "deploy/model-source-lock.v1.json" in workflow
    assert "qualified/models/embedding/model.gguf" in workflow
    assert "qualified/models/reranking/model.gguf" in workflow
    assert "qualified/models/extraction/model.gguf" in workflow
    assert "path: ${{ runner.temp }}/qualified/qualification.json" in workflow
    assert "path: ${{ runner.temp }}/qualified/models" not in workflow
    uses = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, flags=re.MULTILINE)
    assert uses
    assert all(re.fullmatch(r"[^@]+@[0-9a-f]{40}", value) for value in uses)
