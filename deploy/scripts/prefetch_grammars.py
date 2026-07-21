"""Verify and prefetch the release-certified Tree-sitter grammar set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import cast

from tree_sitter_language_pack import PackConfig, configure, get_parser, prefetch


def main() -> None:
    """Prefetch every locked runtime grammar into an explicit image directory."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    arguments = parser.parse_args()
    document = cast("dict[str, object]", json.loads(arguments.lock.read_text()))
    if document.get("schema_version") != 1:
        message = "unsupported indexing language lock"
        raise SystemExit(message)
    languages = cast("list[dict[str, object]]", document["languages"])
    runtime_names = sorted(
        {
            str(runtime)
            for language in languages
            for runtime in cast("list[object]", language["runtime_names"])
        }
    )
    arguments.cache.mkdir(parents=True, exist_ok=True)
    configure(PackConfig(cache_dir=str(arguments.cache)))
    prefetch(runtime_names)
    for language in runtime_names:
        get_parser(language)


if __name__ == "__main__":
    main()
