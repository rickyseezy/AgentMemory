# ING-004 backpressure and dead-letter runbook

Use this runbook when capture reports `AM_CAPACITY_EXHAUSTED`, background work is delayed, scheduler
jobs stop progressing, or a typed failure appears in the dead-letter list. All commands address the
authenticated loopback Core API. Never edit `jobs`, `dead_letters`, replay receipts, scheduler state,
or SQLite pragmas manually.

## Interpret capacity responses

HTTP 507 with `AM_CAPACITY_EXHAUSTED` means AgentMemory rejected a new unacknowledgeable write before
canonical persistence. It is retryable after local capacity recovers. Previously acknowledged event
IDs remain queryable and exact retries still return their durable duplicate receipt.

Check the local machine in this order:

1. Confirm the AgentMemory state volume has more free bytes than the configured hard threshold and
   preferably more than the soft threshold.
2. Check for unusually large unrelated files on the same volume. Do not delete the SQLite database,
   WAL, artifacts, Neo4j data, backups, or installer rollback generations.
3. Allow interactive/capture workers to drain. Background work intentionally slows at soft pressure.
4. If work does not drain, inspect Core/container health and logs for typed dependency or storage
   failures. Arbitrary job input is never logged.
5. Retry the original event with its exact event ID and bytes after recovery. Do not mint a replacement
   ID for a write whose ACK outcome is uncertain.

Queue reservations are expected behavior: standard/background admission can stop before capture, and
capture can stop before interactive work. Raising limits without verifying disk durability is unsafe.

## Inspect scheduler and dead letters

Retrieve one job with:

```text
GET /v1/scheduler/jobs/{job_id}
Authorization: Bearer <local-capability>
```

List newest failures for an active owner grant with:

```text
GET /v1/dead-letters?actor_id=<actor>&grant_id=<grant>&brain_id=<brain>&maximum=100
Authorization: Bearer <local-capability>
```

The response intentionally contains only state, digests, attempt counts, typed error/diagnostic codes,
lineage IDs, and timestamps. Resolve the diagnostic through the documented code table; do not expect
raw exceptions, prompts, source paths, provider content, or job input references.

Common codes:

- `invalid_input` / `poison_job`: correct or regenerate content-addressed input before replay;
- `authorization_denied`: establish a current valid grant; never reuse an expired grant;
- `integrity_violation`: stop replay and run the applicable integrity/repair procedure;
- `rate_limited`: wait for the recorded bounded retry sequence;
- `capacity_exhausted`: restore queue/disk capacity;
- `dependency_unavailable` / `transient_storage`: restore the local dependency and allow recovery; and
- `internal_error`: inspect content-free Core diagnostics and the release health, then correct before
  replay.

## Replay after correction

Replay requires a new job ID, one stable operation ID used as `Idempotency-Key`, a current actor/grant,
the corrected request SHA-256, and optionally an immutable `artifact://`, `cas://`, or
`local-object://` reference.

```text
POST /v1/dead-letters/{dead_letter_id}:replay
Authorization: Bearer <local-capability>
Idempotency-Key: <operation_uuidv7>
Content-Type: application/json

{
  "operation_id": "<same_operation_uuidv7>",
  "new_job_id": "<new_job_uuidv7>",
  "actor_id": "<current_actor_uuidv7>",
  "grant_id": "<current_grant_uuidv7>",
  "corrected_request_sha256": "<64-lowercase-hex>",
  "corrected_input_ref": "cas://sha256/<digest>"
}
```

An exact repeated request returns the same linked job. A changed body under the same operation is a
409 conflict. A revoked/expired/wrong-Brain grant is forbidden. Replay does not remove the original
failure; verify `parent_job_id` and `source_dead_letter_id` on the new job.

## Worker and lease recovery

The Core recovers expired scheduler leases at startup. Recovery preserves the attempt count, clears
the dead owner/lease, records `transient_storage`, and schedules the job immediately. A live stale
worker cannot later commit because completion uses exact owner, lease deadline, and attempt
compare-and-swap.

If a recovered job repeatedly expires:

1. verify the Core is not being repeatedly killed or suspended;
2. verify local SQLite and the state volume are healthy;
3. verify the job-kind executor is registered in the active release;
4. inspect the content-free job state and timestamps; and
5. allow the bounded RetryPolicy to finish or enter DLQ. Do not force state transitions manually.

## Alert response and closure

`scheduler_alerts` records content-free threshold evidence. Queue alerts correspond to configured
percentages of the hard pending limit. Disk alerts correspond to soft/hard free-byte pressure. Alerts
are idempotent per metric/threshold so repeated admission cannot create an unbounded alert storm.

Close the incident only after:

- free disk is above the soft threshold;
- pending work trends downward and reserved capture/interactive work progresses;
- no lease remains expired;
- corrected DLQ replays reach a terminal success or a newly explained typed failure;
- exact event retry confirms acknowledged history is intact; and
- normal Core readiness/integrity checks pass.

Keep the immutable dead-letter and replay lineage as audit evidence. Deletion or retention workflows,
not this runbook, govern later evidence removal.
