"""Assemble and live-qualify the immutable default local model set."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess  # nosec B404 -- exact argv is the release boundary
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn, cast
from urllib.parse import quote

from tools.verify_model_source_lock import (
    JSONObject,
    JSONValue,
    ModelLockError,
    validate_model_source_lock,
)

type Downloader = Callable[[str, Path], None]
type Executor = Callable[[tuple[str, ...]], subprocess.CompletedProcess[str]]

_DOWNLOAD_CHUNK: Final = 1024 * 1024
_HEALTH_ATTEMPTS: Final = 120
_CONVERTER_TMPFS: Final = "/tmp:rw,noexec,nosuid,size=1g"  # noqa: S108
_SERVER_TMPFS: Final = "/tmp:rw,noexec,nosuid,size=64m"  # noqa: S108


class QualificationError(RuntimeError):
    """A locked artifact, conversion, or live capability failed qualification."""


@dataclass(frozen=True, slots=True)
class _AssemblyContext:
    output_root: Path
    work: Path
    converter: str
    executor: Executor


def _sha256(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_DOWNLOAD_CHUNK):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _verify(path: Path, expected_digest: str, expected_size: int, label: str) -> None:
    digest, size = _sha256(path)
    if digest != expected_digest or size != expected_size:
        message = f"{label} does not match its immutable source artifact"
        raise QualificationError(message)


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "AgentMemory-release/1"}
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    temporary = destination.with_suffix(destination.suffix + ".partial")
    with opener.open(request, timeout=120) as response, temporary.open("xb") as output:  # nosec B310
        if response.geturl().split(":", 1)[0] != "https":
            message = "model source redirected outside HTTPS"
            raise QualificationError(message)
        shutil.copyfileobj(response, output, length=_DOWNLOAD_CHUNK)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(destination)


def _execute(command: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603  # nosec B603 -- closed, digest-bound argv
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=900,
    )


def _run(executor: Executor, command: tuple[str, ...], label: str) -> None:
    result = executor(command)
    if result.returncode != 0:
        message = f"{label} failed"
        raise QualificationError(message)


def _conversion_command(image: str, source: Path, output: Path) -> tuple[str, ...]:
    return (
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        _CONVERTER_TMPFS,
        "--volume",
        f"{source}:/work/source:ro",
        "--volume",
        f"{output}:/work/output:rw",
        "--entrypoint",
        "python3",
        image,
        "/app/convert_hf_to_gguf.py",
        "--outtype",
        "q8_0",
        "--outfile",
        "/work/output/model.gguf",
        "/work/source",
    )


def _probe_code(role: str) -> str:
    if role == "embedding":
        return (
            "import json,math,urllib.request;"
            "p=json.dumps({'input':['frontend user API','graph storage'],"
            "'encoding_format':'float'}).encode();"
            "q=urllib.request.Request('http://127.0.0.1:8090/v1/embeddings',data=p,"
            "headers={'Content-Type':'application/json'});d=json.load(urllib.request.urlopen(q));"
            "v=[x['embedding'] for x in d['data']];"
            "assert len(v)==2 and all(len(x)==1024 for x in v) and "
            "all(math.isfinite(y) for x in v for y in x)"
        )
    if role == "reranking":
        return (
            "import json,urllib.request;"
            "p=json.dumps({'query':'Which frontend consumes the user API?',"
            "'documents':['The frontend consumes the user API.',"
            "'Neo4j stores graph relationships.'],'top_n':2}).encode();"
            "q=urllib.request.Request('http://127.0.0.1:8090/rerank',data=p,"
            "headers={'Content-Type':'application/json'});d=json.load(urllib.request.urlopen(q));"
            "s={x['index']:x['relevance_score'] for x in d['results']};assert s[0]>s[1]"
        )
    return (
        "import json,urllib.request;"
        "p={'messages':[{'role':'system','content':'Extract the shortest noun phrase naming the "
        "central subject. Return only the requested JSON object.'},{'role':'user','content':"
        "'The frontend application consumes the user API.'}],'temperature':0,'max_tokens':32,"
        "'chat_template_kwargs':{'enable_thinking':False},'response_format':{'type':'json_schema',"
        "'schema':{'type':'object','additionalProperties':False,'required':['subject'],"
        "'properties':{'subject':{'type':'string','minLength':1,'maxLength':128}}}}};"
        "q=urllib.request.Request('http://127.0.0.1:8090/v1/chat/completions',"
        "data=json.dumps(p).encode(),headers={'Content-Type':'application/json'});"
        "d=json.load(urllib.request.urlopen(q));x=json.loads(d['choices'][0]['message']['content']);"
        "assert set(x)=={'subject'} and isinstance(x['subject'],str) and x['subject']"
    )


def _server_arguments(role: str) -> tuple[str, ...]:
    if role == "embedding":
        return ("--ctx-size", "4096", "--embedding", "--pooling", "last")
    if role == "reranking":
        return ("--ctx-size", "4096", "--embedding", "--pooling", "rank", "--reranking")
    return ("--ctx-size", "2048", "--jinja", "--reasoning-format", "deepseek", "--n-predict", "32")


def _probe_command(image: str, server_name: str, code: str) -> tuple[str, ...]:
    return (
        "docker",
        "run",
        "--rm",
        "--network",
        f"container:{server_name}",
        "--read-only",
        "--tmpfs",
        _SERVER_TMPFS,
        "--entrypoint",
        "python3",
        image,
        "-c",
        code,
    )


def _smoke(
    executor: Executor,
    server_image: str,
    probe_image: str,
    role: str,
    model: Path,
) -> None:
    name = f"agentmemory-qualification-{role}"
    executor(("docker", "rm", "--force", name))
    command = (
        "docker",
        "run",
        "--detach",
        "--name",
        name,
        "--network",
        "none",
        "--read-only",
        "--tmpfs",
        _SERVER_TMPFS,
        "--volume",
        f"{model}:/models/model.gguf:ro",
        server_image,
        "--host",
        "127.0.0.1",
        "--port",
        "8090",
        "--model",
        "/models/model.gguf",
        *_server_arguments(role),
    )
    _run(executor, command, f"{role} server startup")
    try:
        health = _probe_command(
            probe_image,
            name,
            "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8090/health').read()",
        )
        for attempt in range(_HEALTH_ATTEMPTS):
            if executor(health).returncode == 0:
                break
            if attempt + 1 == _HEALTH_ATTEMPTS:
                message = f"{role} server did not become healthy"
                raise QualificationError(message)
            time.sleep(1)
        _run(
            executor,
            _probe_command(probe_image, name, _probe_code(role)),
            f"{role} live capability probe",
        )
    finally:
        executor(("docker", "rm", "--force", name))


def _models(document: JSONObject) -> list[JSONObject]:
    return cast("list[JSONObject]", document["models"])


def _download_sources(model: JSONObject, work: Path, downloader: Downloader) -> Path:
    role = cast("str", model["role"])
    source = cast("JSONObject", model["source"])
    source_root = work / "source" / role
    source_root.mkdir(parents=True)
    for item in cast("list[JSONObject]", source["files"]):
        relative = cast("str", item["path"])
        destination = source_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        url = (
            f"https://huggingface.co/{source['repository']}/resolve/"
            f"{source['revision']}/{quote(relative, safe='/')}?download=true"
        )
        downloader(url, destination)
        _verify(
            destination,
            cast("str", item["sha256"]),
            cast("int", item["size"]),
            f"{role} source artifact",
        )
    return source_root


def _assemble_model(
    model: JSONObject,
    source_root: Path,
    context: _AssemblyContext,
) -> tuple[Path, str, int]:
    assembly = cast("JSONObject", model["assembly"])
    final = context.output_root / cast("str", assembly["output"])
    final.parent.mkdir(parents=True, exist_ok=True)
    if assembly["kind"] == "direct-gguf":
        shutil.copyfile(source_root / cast("str", assembly["input"]), final)
    else:
        first, second = context.work / "conversion-a", context.work / "conversion-b"
        first.mkdir()
        second.mkdir()
        _run(
            context.executor,
            _conversion_command(context.converter, source_root, first),
            "reranker conversion A",
        )
        _run(
            context.executor,
            _conversion_command(context.converter, source_root, second),
            "reranker conversion B",
        )
        first_model, second_model = first / "model.gguf", second / "model.gguf"
        if _sha256(first_model) != _sha256(second_model):
            message = "reranker conversion is not reproducible"
            raise QualificationError(message)
        shutil.copyfile(first_model, final)
    expected_digest = cast("str", assembly["output_sha256"])
    expected_size = cast("int", assembly["output_size"])
    _verify(final, expected_digest, expected_size, f"{model['role']} assembled model")
    return final, expected_digest, expected_size


def _qualification_record(model: JSONObject, digest: str, size: int) -> JSONObject:
    source = cast("JSONObject", model["source"])
    assembly = cast("JSONObject", model["assembly"])
    return {
        "license": model["license"],
        "model_id": model["model_id"],
        "output": assembly["output"],
        "role": model["role"],
        "sha256": digest,
        "size": size,
        "source_repository": source["repository"],
        "source_revision": source["revision"],
    }


def qualify_default_models(
    lock_path: Path,
    output_root: Path,
    *,
    downloader: Downloader = _download,
    executor: Executor = _execute,
) -> dict[str, JSONValue]:
    """Rebuild, reproduce, live-test, and inventory the locked default models."""
    try:
        document = validate_model_source_lock(lock_path.read_bytes())
    except (OSError, ModelLockError) as error:
        message = "model source lock is invalid"
        raise QualificationError(message) from error
    if output_root.exists() and any(output_root.iterdir()):
        message = "qualification output must be absent or empty"
        raise QualificationError(message)
    output_root.mkdir(parents=True, exist_ok=True)
    work = output_root / ".work"
    work.mkdir(mode=0o700)
    llama = cast("JSONObject", document["llama_cpp"])
    converter = cast("str", llama["converter_container"])
    server = cast("str", llama["server_container"])
    assembly_context = _AssemblyContext(output_root, work, converter, executor)
    inventory_models: list[JSONValue] = []
    try:
        for model in _models(document):
            role = cast("str", model["role"])
            source_root = _download_sources(model, work, downloader)
            final, expected_digest, expected_size = _assemble_model(
                model, source_root, assembly_context
            )
            _smoke(executor, server, converter, role, final)
            inventory_models.append(_qualification_record(model, expected_digest, expected_size))
    finally:
        shutil.rmtree(work, ignore_errors=True)
    inventory: dict[str, JSONValue] = {
        "llama_cpp_revision": llama["revision"],
        "models": inventory_models,
        "schema_version": 1,
        "server_container": server,
    }
    encoded = json.dumps(inventory, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    (output_root / "qualification.json").write_text(encoded + "\n", encoding="utf-8")
    return inventory


def _fail(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> None:
    """Run release model qualification from a clean output directory."""
    parser = argparse.ArgumentParser()
    parser.add_argument("lock", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    try:
        qualify_default_models(arguments.lock, arguments.output)
    except QualificationError as error:
        _fail(str(error))


if __name__ == "__main__":
    main()
