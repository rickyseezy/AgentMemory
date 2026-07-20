# ING-002 idempotent delivery and conflict runbook

## Normal retry behavior

Agents and internal workers may retry after a transport timeout, process exit, daemon restart, or
typed dependency failure. A safe retry always reuses the original operation/event ID, idempotency key,
and byte-identical canonical input. The expected outcomes are:

- an active identical operation waits without executing another side effect;
- a completed identical operation replays the committed result;
- an expired processing lease is reclaimed with an incremented attempt;
- an event retry returns `duplicate` only when its canonical hashes match;
- a consumer redelivery creates no second projection or audit outcome; and
- a provider recovery forwards exactly the same downstream idempotency key.

Do not interpret a nonzero attempt count as duplication. It records ownership attempts; the terminal
receipt/result count and digest establish the effective outcome.

## Expected restart recovery

After an abrupt Core/container/host restart, start the same signed AgentMemory release against the
same complete state volume and protected installation key. Do not copy only the SQLite main file or
delete WAL/SHM files. Startup releases expired source outbox leases. When the message is claimed again,
the inbox reservation is replayed or reclaimed according to its durable state.

For a provider operation, an active lease remains unavailable until its deadline. After expiry, the
new worker reuses the stored semantic identity and exact downstream key. The provider adapter must
never generate a fresh vendor key during this recovery.

## Diagnosing consumer state

Use packaged diagnostics and authenticated operational surfaces. The expected relational evidence for
one completed canonical event consumer is:

- one canonical event and one source outbox message;
- one `inbox_receipts` row in `completed` state with no lease and exact request/result digests;
- one `event_projection_receipts` row;
- one `projection_idempotency_receipts` row for the consumer/source/generation; and
- one `ingestion.event_projected` audit fact.

A processing inbox must have a lease owner/until and no result/processed time. A completed inbox must
have no lease and must have both result and processed time. Any other shape is a schema/integrity
failure, not an invitation to patch the row.

## Diagnosing provider state

A provider reservation in `processing` has a lease owner/until, retry time, attempt count, and no
result/usage/completion. A `completed` reservation has no lease and contains a SHA-256 result, exact
content-addressed result reference, usage units, and completion time.

For suspected duplicate billing, preserve:

1. operation ID, profile ID, and one-way caller-key identity;
2. semantic cache digest and downstream idempotency key digest;
3. attempts, owners, lease/retry times, and local completion state;
4. the provider adapter/version/model revision and its vendor response metadata; and
5. the relevant content-free audit-chain segment.

Verify that every vendor request used the same downstream key. A provider adapter that discarded,
rewrote, or failed to support this key is nonconforming and must be disabled until corrected.

## Identity conflict response

An idempotency conflict means the same event, inbox, command, job, provider-operation, or projection
identity was presented with a different request/content digest. It is not a transient duplicate.

For an event or inbox conflict:

1. stop capture/processing for the affected Brain through the launcher;
2. preserve the complete state volume, protected installation key, and diagnostic evidence;
3. confirm the original canonical record and its hashes through packaged integrity diagnostics;
4. identify the agent/adapter version that reused the identity;
5. correct the producer so a new logical operation receives a new UUIDv7/idempotency identity;
6. restore only through the supported verified backup/repair workflow if canonical integrity failed;
   and
7. retain the original deduplicated conflict and hash-chain evidence according to policy.

For a provider conflict, disable the offending provider caller, verify its semantic dimensions and
operation lifecycle, then correct identity generation. Do not retry the changed input under the old
key.

## Prohibited recovery actions

Never:

- edit or delete inbox, provider, projection, command, job, conflict, or audit rows manually;
- change a request/result digest so that mismatched content appears identical;
- clear `repair_required` by direct SQL;
- reset attempts, leases, or completion state to force a second side effect;
- assign a new provider downstream key after an uncertain response;
- bypass the provider cache for paid or rate-limited work;
- delete conflict evidence to make a schema downgrade succeed; or
- infer canonical success from Neo4j, a provider dashboard, or another derived store.

These actions destroy the evidence needed to distinguish replay from duplication and can create an
unrecoverable double charge or derived-state divergence.

## Verification after recovery

Recovery is complete only when all of the following are true:

- SQLite integrity, foreign-key, migration-head, WAL/FULL, and audit-chain checks pass;
- every completed receipt/result satisfies its database state-shape constraints;
- the source request digest matches the immutable canonical input;
- each effective event, inbox consumer, job, provider semantic key, and projection identity has one
  effective terminal outcome;
- repeated identical delivery replays without a second side effect or audit outcome;
- repeated changed input is still rejected and its conflict evidence remains present; and
- a controlled provider retry proves the same downstream key and one billable operation.
