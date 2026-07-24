# PRO-008 live embedding migration runbook

This runbook operates a provider/model migration without mixing vector spaces or interrupting
ingestion. All commands require a local capability credential and a current Brain-wide owner or
administrator grant. Never edit SQLite, Neo4j generation metadata, active pointers, or generated
index names manually.

## Preconditions

1. Core is ready and reports relational migration head `0041_pro008_embedding_migrations`.
2. The source generation is `active`; the target generation belongs to a different immutable
   embedding space and is `populating`.
3. Both provider profiles and capability attestations are current.
4. There is capacity for both complete generations plus migration headroom.
5. PRO-009 contained provider execution is available before running provider-backed phases.
6. Keep the owner/admin grant ID used for explicit cutover approval.

The common scope fields are `brain_id`, `actor_id`, `grant_id`, `project_id`, and `repository_id`.
Authentication must precede every operation.

## Start and inspect

Call `POST /v1/providers/embedding-migrations` with:

- one stable `operation_id`, repeated as `Idempotency-Key`;
- the active `source_generation_id`;
- the new `target_generation_id`; and
- the complete current scope fields.

An exact retry returns the original migration. Reusing the operation ID with different generations or
a different captured watermark conflicts.

Inspect with `GET /v1/providers/embedding-migrations/{migration_id}` and the scope query fields.
Record the response `ETag`. Status exposes only identities, state, cursors, validation digest,
rollback/retirement times, and version; it never returns content, vectors, credentials, or provider
payloads.

## Run, pause, and resume

`POST /v1/providers/embedding-migrations/{id}:run` advances committed phases until `ready`, `paused`,
or `failed`. A crash is safe: repeat the same call and replay resumes at the stored cursor.

To stop work safely, call `POST .../{id}:pause` with the current scope and `If-Match` copied from the
latest status response. Pause records the exact prior phase and does not rewind a cursor or disable an
already-required dual-write route.

Resume with `POST .../{id}:resume` and the new ETag. A stale ETag returns a conflict/validation problem;
fetch status and investigate rather than retrying blindly.

During migration:

- `backfilling` reads canonical content only through the fixed source watermark;
- `catching_up` replays the gap captured when dual-write became active;
- `validating` and `shadowing` keep the source active and both write targets current; and
- `ready` means all gates passed but no cutover occurred.

## Investigate a failed migration

`failed` is terminal. The source remains the active read/write generation and the target is removed
from the write route. Inspect content-safe diagnostics for:

- structural count/hash mismatch;
- missing, stale, or duplicate records;
- privacy-policy denial;
- quality regression greater than 0.04;
- p95 latency greater than 1.25 times baseline;
- fewer than 100 shadow samples or any mismatch;
- provider drift or changed capability attestation; or
- unavailable canonical content/provider containment.

Do not relax the policy or reuse the failed target space. Correct the cause, create a new immutable
space/generation where semantic evidence changed, and start a new migration.

## Cut over

Cutover is never automatic. Fetch the latest Ready status and send:

`POST /v1/providers/embedding-migrations/{id}:cutover`

with:

- `If-Match: "embedding-migration:{id}:{ready_version}"`;
- a stable operation ID repeated as `Idempotency-Key`;
- `approval_id` equal to a current Brain-wide owner/admin grant; and
- current scope fields for that same principal.

Success atomically switches reads and writes to the target, marks the source rollback-ready, stores
the approval receipt, and emits one cache-invalidation/change event. If the response is lost, repeat
the exact request. Do not change the operation ID, approval, principal, scope, or ETag.

After cutover, verify:

1. status is `active`;
2. provider status reports the target as active and source as rollback-ready;
3. new writes resolve only the target generation;
4. recall probes succeed with the target fingerprint; and
5. no privacy, quality, latency, drift, queue, or error-budget alert is active.

## Roll back

Within 35 days, call `POST /v1/providers/embedding-migrations/{id}:rollback` with current scope fields.
Rollback atomically restores source reads/writes and leaves the target read-only as rollback evidence.
Verify source recall and cache invalidation immediately. A rollback at or after the immutable deadline
is refused.

## Retire the source

Never delete merely because 35 days elapsed. `POST .../{id}:delete-source` additionally requires the
retention port to prove:

- a verified OPS-004 recovery point includes the new active pointer;
- the rollback deadline passed;
- the source is not active or a secondary write target; and
- no live migration, rollback, route, or backup dependency references it.

Until OPS-004 supplies canonical backup proof, this operation returns a typed dependency-unavailable
problem and changes nothing. After proof exists, Core first retires the source in SQLite, then drops
only the UUID-derived Neo4j index/records/metadata, and finally records completion. A graph failure is
retryable because completion is not recorded early.

## Escalation

Stop and preserve status, ETag, migration ID, safe diagnostics, and Core logs when:

- cursors decrease, exceed a watermark, or stop advancing across healthy retries;
- the active pointer and write route disagree;
- both generations receive reads after cutover;
- the source disappears before verified retirement;
- an activation receipt differs from the request; or
- a response contains content, raw vectors, secrets, vendor bodies, or credentials.

Do not include source content, vectors, credentials, or raw provider responses in an incident bundle.
