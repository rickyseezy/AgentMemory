# MEM-004 correction runbook

This runbook handles governed correction of false or outdated memory. Never update a memory or
correction statement, evidence hash, relationship, scope, actor, grant, reason, or valid range
directly in SQLite or Neo4j.

## Normal operation

1. Explain or recall the memory and retain its assertion ID and aggregate version.
2. Submit `POST /memories/{assertion_id}/corrections` using the current owner capability, explicit
   actor/grant/Brain coordinates, expected version, corrected statement, same or checkout-narrower
   scope, valid range, reason token, and optional canonical evidence IDs.
3. Retain the correction ID, relation, source status/version, policy version, and result digest.
4. Query `GET /memories/{root_memory_id}/corrections` with the intended scope, valid time, and
   recorded time. Confirm `selected.assertion_id` is the expected effective assertion.
5. If graph projection freshness is behind, allow normal outbox processing or run the governed
   PF-002 graph rebuild. Do not patch Neo4j manually.

## Conflict handling

`AM_CONFLICT` means the assertion or receipt changed between read and commit, the expected version is
stale, the source recorded range is closed, or the operation ID was reused with a different request.
Fetch correction history again, choose the assertion active at the intended scope, and submit a new
UUIDv7 operation with its current version. Do not alter and retry the old operation ID.

Concurrent exact duplicates return the same authenticated receipt. Concurrent distinct commands
against one source cannot both silently win. One succeeds; the other receives a conflict and must
become an explicit subsequent correction or remain a visible dispute.

## Scope mistakes

The correction scope must preserve Brain, project, and repository. A project/repository assertion may
be narrowed to a checkout. A checkout assertion cannot be broadened or moved to a sibling checkout.
For a checkout-specific correction, query another checkout and confirm the source remains selected.

## Authorization and not-found responses

`AM_NOT_FOUND` intentionally covers absent targets, absent evidence, wrong actor, wrong grant, wrong
Brain, revoked or expired authority, read-only roles, and out-of-scope resources. Confirm the local
owner capability and explicit coordinates without probing alternate IDs. Never weaken the SQL join
or return target metadata to diagnose authorization.

## Integrity or dependency failures

- `AM_DEPENDENCY_UNAVAILABLE`: SQLite or another required local dependency was unavailable. The
  command has no partial effect unless the authenticated idempotency receipt exists; retry exactly.
- `AM_INTEGRITY_VIOLATION`: stop correction processing. Preserve the database and logs, then verify
  SQLite integrity, migration head `0018_mem004_memory_correction`, audit-chain continuity, canonical
  receipt JSON/hash, correction content hash, evidence lineage hash, and event payload hash.
- Do not delete a receipt, relax an immutable trigger, rewrite the audit chain, or edit the graph to
  hide a failed correction.

## Recovery and rebuild

SQLite is canonical. After recovery, verify the receipt, source version, assertion, evidence,
`MemoryCorrected` event, `memory.corrected.v1` outbox message, and `memory.corrected` audit record all
exist together or not at all. Use PF-002 to rebuild graph/search state from canonical events. A
rebuild must retain both assertion nodes and the exact `SUPERSEDES`/`CONTRADICTS` edge and continue
honoring deletion tombstones.

## Downgrade

Downgrade is allowed only when there are no correction receipts, assertions, evidence links,
disputed memories, or superseded memories. Once correction evidence exists, downgrade fails closed.
Export and migrate forward; do not remove correction history to force a downgrade.
