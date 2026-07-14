# SQLite v3.53.3 dependency review

| Field | Reviewed value |
|---|---|
| Upstream | SQLite canonical source |
| Release | 3.53.3, 2026-06-26 |
| Autoconf archive | `sqlite-autoconf-3530300.tar.gz` |
| SHA-256 | `c917d7db16648ec95f714974ace5e5dcf46b7dc70e26600a0a102a3141125db0` |
| Upstream SHA3-256 | `98f2b3f3c11be6a03ea32346937b032c2472ebbd7a716bed36ca2f5693e7ce8b` |
| Source ID | `2026-06-26 20:14:12 d4c0e51e4aeb96955b99185ab9cde75c339e2c29c3f3f12428d364a10d782c62` |
| License | Public domain |
| Decision | Approved for the Core image with the exact policy below |

The review used the canonical [SQLite 3.53.3 release history](https://sqlite.org/changes.html) and [download](https://sqlite.org/download.html). The locally computed archive SHA3-256 matched SQLite's published value; SHA-256 is recorded because AgentMemory's signed resource inventory uses SHA-256.

## Build and runtime policy

The Core image must build the shared library from this exact archive with thread safety and FTS5 enabled, JSON support retained, and loadable extensions disabled. It must not silently use the older Debian library from the Python base image. The final CPython `_sqlite3` module must resolve to the reviewed library in the runtime stage.

Release verification runs live SQL and rejects the image unless all of the following hold:

- `sqlite3.sqlite_version == "3.53.3"`;
- `sqlite3.threadsafety == 3` and `PRAGMA compile_options` contains `THREADSAFE=1`;
- `PRAGMA compile_options` contains `ENABLE_FTS5`;
- foreign keys, WAL, `synchronous=FULL`, `secure_delete`, and `trusted_schema=OFF` read back exactly as required by Core policy;
- `load_extension` cannot load an arbitrary shared object;
- the relational migration, integrity check, FTS query, transaction rollback, WAL recovery, and interrupted-migration suites pass inside both target-architecture images.

The release history identifies 3.53.3 as a maintenance patch over 3.53.0–3.53.2. A SQLite update requires a new source/archive review plus migration, durability, query-plan, corruption-recovery, and image-architecture certification. The source archive is an installer/release input and must carry its own signed provenance and SBOM association in AgentMemory's release evidence; upstream hashes alone are not sufficient release authority.
