# ING-006 event-schema evolution runbook

## Normal operation

1. Verify Core readiness reports `alembic:0014_ing006_schema_evolution`.
2. Verify `deploy/event-schema-compatibility.v1.json` with
   `uv run python tools/verify_event_schema_compatibility.py` before releasing any producer/consumer.
3. Register only reviewed adjacent upcasters. Never advertise a producer version until every edge to
   the current consumer is present and its golden-byte tests pass.
4. Start a migration with a globally stable operation ID, exact target family/major/version, and a
   bounded batch size. Repeat the same command until state is `completed`.
5. Monitor `scanned`, `total`, `upcasted`, `current`, `quarantined`, and cursor. Counts contain no event
   content.

## Interrupted migration

- Preserve the operation ID and target. Do not create a replacement run to bypass evidence.
- Repair the typed dependency/integrity failure, then execute the same operation again.
- The worker resumes after the last atomically committed event. It does not overwrite canonical
  envelopes or duplicate counters.
- If progress does not advance, inspect SQLite integrity, foreign keys, key access, capacity, and the
  exact upcaster registry shipped by the active release.

## Quarantine response

| Reason | Operator action |
|---|---|
| `unsupported_major` | Install a release explicitly supporting that major or retain the source for future recovery. |
| `future_version` | Upgrade consumers; never downcast or discard fields. |
| `missing_upcaster` | Add and review every missing adjacent edge, golden bytes, and replay test. |
| `invalid_transform` | Correct the deterministic transform; retain original encrypted bytes unchanged. |
| `extension_loss` | Preserve every unknown field exactly or explicitly version a reviewed breaking major. |

Quarantine is fail-closed derived state. Never edit the source envelope, manually mark it current, or
copy plaintext into a diagnostic table.

## Adding a schema revision

1. Define the new immutable schema and one `n -> n+1` upcaster.
2. Declare all fields the transform understands; everything else is an opaque extension.
3. Add golden canonical bytes, unknown-field/property tests, malformed/breaking cases, and replay
   equivalence.
4. Update producer/consumer versions and adjacent edges in the checked compatibility manifest.
5. Run formatting, lint, Mypy, Pyright, import contracts, full tests, package/branch/changed coverage,
   mutation coverage, Bandit, dependency audit, deterministic OpenAPI, and locked build gates.
6. Release consumers before producers when compatibility requires it.

## Backup and rollback

Back up SQLite, installation/Brain key material, and the active release together. Derived views can be
rebuilt only while original envelopes and keys remain available. Downgrade across migration `0014`
refuses while any schema lineage or migration evidence exists; restore the pre-upgrade backup instead
of deleting audit evidence.
