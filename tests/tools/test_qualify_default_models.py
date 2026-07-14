from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlparse

import pytest
from tools.qualify_default_models import QualificationError, qualify_default_models
from tools.verify_model_source_lock import JSONObject, validate_model_source_lock

_ROOT = Path(__file__).parents[2]
_LOCK = _ROOT / "deploy/model-source-lock.v1.json"


def _fixture_lock(tmp_path: Path) -> tuple[Path, dict[str, bytes], bytes]:
    document = copy.deepcopy(validate_model_source_lock(_LOCK.read_bytes()))
    sources: dict[str, bytes] = {}
    models = cast("list[JSONObject]", document["models"])
    for model in models:
        source = cast("JSONObject", model["source"])
        files = cast("list[JSONObject]", source["files"])
        for item in files:
            path = cast("str", item["path"])
            contents = f"source:{model['role']}:{path}".encode()
            sources[path] = contents
            item["sha256"] = hashlib.sha256(contents).hexdigest()
            item["size"] = len(contents)
        assembly = cast("JSONObject", model["assembly"])
        if assembly["kind"] == "direct-gguf":
            direct = sources[cast("str", assembly["input"])]
            assembly["output_sha256"] = hashlib.sha256(direct).hexdigest()
            assembly["output_size"] = len(direct)
    converted = b"deterministic converted reranker"
    reranking = cast("JSONObject", models[1]["assembly"])
    reranking["output_sha256"] = hashlib.sha256(converted).hexdigest()
    reranking["output_size"] = len(converted)
    lock = tmp_path / "model-lock.json"
    lock.write_text(json.dumps(document), encoding="utf-8")
    return lock, sources, converted


def test_pf001_release_qualification_is_reproducible_and_network_isolated(
    tmp_path: Path,
) -> None:
    lock, sources, converted = _fixture_lock(tmp_path)
    commands: list[tuple[str, ...]] = []

    def download(url: str, destination: Path) -> None:
        path = unquote(urlparse(url).path.split("/resolve/", 1)[1].split("/", 1)[1])
        destination.write_bytes(sources[path])

    def execute(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if "/app/convert_hf_to_gguf.py" in command:
            output_mount = next(value for value in command if value.endswith(":/work/output:rw"))
            Path(output_mount.split(":", 1)[0], "model.gguf").write_bytes(converted)
        return subprocess.CompletedProcess(command, 0, "", "")

    output = tmp_path / "qualified"
    inventory = qualify_default_models(lock, output, downloader=download, executor=execute)
    inventory_models = cast("list[JSONObject]", inventory["models"])

    assert [item["role"] for item in inventory_models] == [
        "embedding",
        "reranking",
        "extraction",
    ]
    assert (output / "qualification.json").read_bytes().endswith(b"\n")
    assert (output / "models/reranking/model.gguf").read_bytes() == converted
    conversions = [command for command in commands if "/app/convert_hf_to_gguf.py" in command]
    assert len(conversions) == 2
    assert all("--network" in command and "none" in command for command in conversions)
    assert all("--read-only" in command for command in conversions)
    extraction_server = next(
        command
        for command in commands
        if command[:3] == ("docker", "run", "--detach")
        and any(value.endswith("qualification-extraction") for value in command)
    )
    reasoning_index = extraction_server.index("--reasoning-format")
    assert extraction_server[reasoning_index : reasoning_index + 2] == (
        "--reasoning-format",
        "deepseek",
    )


def test_pf001_release_qualification_rejects_source_digest_drift(tmp_path: Path) -> None:
    lock, _, _ = _fixture_lock(tmp_path)

    def corrupt(_url: str, destination: Path) -> None:
        destination.write_bytes(b"corrupt")

    with pytest.raises(QualificationError, match="source artifact"):
        qualify_default_models(
            lock,
            tmp_path / "qualified",
            downloader=corrupt,
            executor=lambda command: subprocess.CompletedProcess(command, 0, "", ""),
        )
