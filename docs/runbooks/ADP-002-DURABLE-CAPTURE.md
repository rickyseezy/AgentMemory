# ADP-002 durable capture runbook

## Normal operation

The adapter validates and redacts an AgentEvent, then calls the fixed authenticated loopback endpoint.
Treat `accepted` and `duplicate` as durable. `duplicate` means Core already has the same event ID and exact
canonical/payload digests; do not allocate a replacement ID. Enrichment happens asynchronously from the
Core outbox and must never be added to the hook.

The launcher creates the private spool directory/key as part of installation and calls spool initialization
before starting an agent host. Users do not configure SQLite, AES, Docker, or credentials manually.

## Status handling

| Status | Meaning | Action |
|---|---|---|
| `accepted` | Event, outbox, and audit committed | Continue immediately |
| `duplicate` | Exact durable retry exists | Continue; acknowledge local copy |
| `deferred` | Core unavailable; encrypted spool committed | Continue; ADP-005 reconciles later |
| `spool_full` | Bounded capacity exhausted | Warn without content; restore Core/reconcile, do not delete unacknowledged items |
| `spool_unavailable` | Spool key/path/disk/integrity failure | Warn without content; stop claiming capture durability |
| `invalid` | Redaction/schema/domain validation failed | Quarantine safe metadata; fix adapter, never force-insert |

HTTP 409 is an immutable event/order conflict and must be treated as an integrity incident. HTTP 503 is
retryable through the encrypted spool. Authentication/authorization failures require session/adapter/scope
repair and must not be bypassed by changing claimed IDs or manifests.

## Diagnose latency

1. Confirm the adapter reuses one `AsyncClient`; creating a client per hook defeats keep-alive.
2. Confirm endpoint is exactly `/v1/agent-events:append` on loopback and that proxies/environment trust are
   disabled in production composition.
3. Measure separately: validation/redaction, IPC wait, key unwrap/encryption, single-writer wait, and FULL
   commit. Never log canonical bytes, keys, prompt/tool/file payload, raw paths, or credentials.
4. Inspect only counts, durations, event ID, ordering key, status, safe error code, and disk health.
5. If p95 reaches 50 ms, preserve evidence and fail the release/profile gate. Do not weaken FULL durability,
   authentication, encryption, audit, or ACK-after-commit semantics to improve the number.

## Diagnose spool failure

- Verify owner-only non-symlink directory and `0600` regular key/file ownership.
- Verify the exact protected spool key is available; never replace it while pending ciphertext exists.
- Check bounded count/byte use and Core recovery. Only ADP-005 may delete accepted/duplicate IDs.
- AAD/tag failure means tamper, corruption, or wrong key. Stop reconciliation and preserve safe hashes and
  file metadata for incident handling. Never return partially decrypted bytes.
- Back up/restore rules are governed by OPS stories; copying a live spool manually is unsupported.

## Verification commands

```shell
uv run pytest tests/ingestion/test_adp002_*.py
uv run coverage run -m pytest
uv run coverage report
uv run mutmut run --max-children 4
uv run python tools/check_python_mutation.py mutants --minimum 80
uv run ruff check src tests tools migrations
uv run mypy src apps tests tools
uv run pyright
uv run lint-imports
uv run bandit -q -r src apps
uv run pip-audit --strict
```

Release certification also requires complete Python, Go race, UI, OpenAPI, migration, package, Docker,
and supported-host CI. Do not call the story release-complete from a reduced local subset.
