# MEM-005 lifecycle and deletion runbook

Never edit `memory_lifecycle`, lifecycle receipts/events, deletion manifests/targets, tombstones,
projection records, or Neo4j nodes manually. Use the authenticated commands and durable workers.

## Pin, archive, and expiry

1. Read the memory's current root lifecycle version.
2. Submit the chosen pin, archive, or expiry endpoint with a new UUIDv7 operation, exact actor/grant/
   Brain coordinates, current expected version, canonical UTC request time, and deadline.
3. Retain the returned action, state, pin, expiry, version, policy, and result digest.
4. On `AM_CONFLICT`, refresh lifecycle state and submit a new operation. Never reuse an operation ID
   with changed input.
5. For expiry, verify the boundary is strictly after request time. The background scheduler expires
   the item at the exact boundary and uses the same event/outbox/audit transaction.

Archived and expired memory is absent from ordinary recall but remains available to explicitly
authorized historical explanation/correction-history queries. Pin affects ranking only after all
authorization, scope, valid-time, and recorded-time filters.

## Forget and deletion progress

1. Submit `DELETE /memories/{memory_id}` with confirmation exactly `forget-memory`.
2. Treat the successful receipt as immediate denial: ordinary recall and explanation must no longer
   return the memory even while physical derived deletion is pending.
3. Locate the content-free `memory_deletion_manifests` row by operation or job ID. Expected states
   are `tombstoned`, `purging`, `verification`, then `completed`.
4. Confirm the authorized scheduler job kind is `governance.memory_deletion` and is not dead-lettered.
5. At completion, every linked tombstone must be `completed`, and no local or Neo4j
   `ProjectionRecord` may match a row in `memory_deletion_targets`.
6. Run a governed PF-002 rebuild when repair evidence is required. The forgotten stable IDs must be
   counted as skipped tombstones and must not appear in the activated generation.

The executor is idempotent. Retry the same durable job after a local or Neo4j outage; do not create a
second forget command, remove tombstones, or force the manifest state forward.

## Failure response

- `AM_NOT_FOUND` deliberately covers absent, unauthorized, forgotten, and tombstoned targets.
- `AM_CONFLICT` means a stale version, invalid state transition, concurrent change, or divergent
  operation reuse. Refresh and use a new operation.
- `AM_DEPENDENCY_UNAVAILABLE` is retryable with the exact request.
- `AM_INTEGRITY_VIOLATION` requires stopping lifecycle writes and preserving the local database.

For deletion jobs, `dependency_unavailable` or `transient_storage` is retried by the scheduler.
Integrity failures dead-letter and require checking migration head `0019_mem005_memory_lifecycle`,
manifest/target identity, SQLite integrity, audit-chain continuity, and Neo4j projection counts.

## Recovery and downgrade

After restore, start the Core normally. The expiry scheduler reselects due active/archive rows, the
job scheduler recovers expired leases, and the deletion executor resumes from `purging` or
`verification`. Tombstones deny reads and replay throughout recovery.

Downgrade to MEM-004 is allowed only before any lifecycle mutation or deletion evidence exists. Once
a receipt, event, versioned lifecycle change, expiry, pin, forget tombstone, manifest, or target is
present, downgrade fails closed. Migrate forward; never delete evidence to force rollback.
