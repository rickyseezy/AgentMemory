"""Build-time proof for the release SQLite contract."""

from __future__ import annotations

import sqlite3
from typing import NoReturn


def _fail(message: str) -> NoReturn:
    raise SystemExit(message)


def main() -> None:
    """Prove version, compile flags, FTS5, threadsafety, and extension denial."""
    if sqlite3.sqlite_version_info < (3, 53, 3):
        _fail("SQLite is older than the reviewed 3.53.3 release")
    connection = sqlite3.connect(":memory:")
    options = {row[0] for row in connection.execute("PRAGMA compile_options")}
    required = {"ENABLE_FTS5", "OMIT_LOAD_EXTENSION", "THREADSAFE=1"}
    if not required.issubset(options):
        _fail(f"SQLite compile contract is incomplete: {sorted(options)}")
    connection.execute("CREATE VIRTUAL TABLE proof USING fts5(content)")
    try:
        connection.enable_load_extension(True)  # noqa: FBT003 - positional-only stdlib API
    except sqlite3.Error:
        pass
    else:
        _fail("SQLite loadable extensions can be enabled")
    try:
        connection.load_extension("/does/not/exist")
    except sqlite3.Error:
        pass
    else:
        _fail("SQLite accepted a loadable extension request")
    connection.close()


if __name__ == "__main__":
    main()
