# ING-001 durable acknowledgement and repair runbook

## Normal behavior

An agent receives `accepted` only after the encrypted AgentEvent, optional artifact reference, outbox
intent, and acceptance audit fact commit in canonical SQLite. `duplicate` means the same event/content
identity was already durably committed. A connection loss or typed dependency failure before either
response is safe to retry with the identical event ID and content.

Core startup performs these operations before steady-state ingestion processing:

1. enforce and read back SQLite WAL/FULL durability policy;
2. return every expired ingestion lease to `ready`;
3. scan acknowledged canonical events for a missing outbox intent and open bounded repair alerts;
4. claim ready messages in priority, due-time, UUIDv7 order;
5. authenticate each message, event envelope, SQL index, and artifact reference; and
6. commit a terminal receipt or a repair-required alert.

Do not infer semantic graph/memory freshness from the ingestion receipt. It proves canonical
durability and consumability only; downstream projection freshness is reported by its own generation
and watermark.

## Expected restart recovery

After an abrupt Core/container/host restart, allow the launcher to start the same signed release and
data generation. Do not delete the SQLite WAL/SHM files, change volume ownership, copy only the main
database file, or run SQLite repair commands manually. The worker reclaims only expired leases and
continues from canonical outbox state.

A normal recovery has these properties:

- acknowledged events remain present;
- ready/expired work eventually becomes `completed` with one terminal receipt;
- active unexpired leases are not stolen;
- attempts increase only when a lease is claimed;
- duplicate capture returns the recorded duplicate result; and
- no repair alert is created.

## Repair-required response

`canonical_integrity_violation` means the outbox checksum/JSON, encrypted envelope, decrypted schema,
event index, or artifact binding diverged. `outbox_missing` means a committed event has no atomic
dispatch intent. Both are fail-closed local critical conditions: the affected event is not projected
and its canonical history is not edited or deleted.

When a repair alert appears:

1. stop agent capture through the launcher so no new governed mutations enter the affected data
   generation;
2. preserve the complete state volume, WAL/SHM files, protected installation key, and diagnostic
   evidence without exposing their contents;
3. run the packaged SQLite integrity, foreign-key, migration-head, audit-chain, key-access, and backup
   verification diagnostics;
4. identify the last verified encrypted backup whose manifest covers the affected event/outbox
   watermark;
5. restore through the supported isolated restore workflow—never promote Neo4j or a derived receipt
   as canonical source and never patch a checksum/ciphertext directly;
6. restart the signed release; startup reconciliation rechecks the restored record and drains it only
   if every integrity binding passes; and
7. retain the original repair alert/audit evidence according to the incident and retention policy.

If no verified backup covers the event, leave the alert open and preserve the acknowledged canonical
record for forensic/export support. Do not mark it completed, synthesize an outbox checksum, decrypt it
with an alternate key, or recapture it under a different event ID while claiming recovery.

## Safe retry guidance

- Retry only with the identical event ID and canonical content after a transport/dependency failure.
- A changed payload with the same ID is a conflict, not a repair.
- Never retry a `repair_required` record by direct SQL state changes.
- Do not reduce `synchronous`, switch journal mode, disable foreign keys, or bypass the installation
  key to improve availability.
- Do not clear alerts merely because Neo4j or retrieval appears to contain similar derived content.

## Verification after recovery

Recovery is successful only when all of the following are true:

- SQLite integrity/foreign-key/migration/readiness checks pass under WAL/FULL policy;
- the event/envelope/outbox hashes and optional artifact metadata authenticate;
- exactly one terminal receipt binds the event and outbox message;
- the outbox message is `completed` with no active lease;
- no duplicate event, outbox, receipt, or acceptance audit exists; and
- downstream consumers can resume from the canonical receipt/watermark without using derived state as
  authority.
