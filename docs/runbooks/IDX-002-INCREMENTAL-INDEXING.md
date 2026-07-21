# IDX-002 incremental indexing operations runbook

## Normal operation

1. The ephemeral MCP session resolves the current Repository and computes the Git/content manifest
   under the read-only workspace policy.
2. Start the run with one stable operation ID and use the same value as `Idempotency-Key`.
3. Poll the returned run ID. `coverage_micros` is deterministic progress from 0 to 1,000,000.
4. Treat `completed` as canonical snapshot completion. Projection freshness follows through the
   durable outbox; a projection lease failure does not roll back canonical code evidence.
5. If the agent session ends, request cancellation. The worker completes the current atomic file,
   then records `cancelled`.

Never mount a source directory into the persistent Core. The Git source adapter is for the transient
session boundary only. The session must send only policy-authorized changed artifacts; it must not
widen `/workspace` to a parent in order to recover external worktree metadata.

## Run states

| State | Meaning | Operator action |
|---|---|---|
| `queued` | immutable plan is durable | wait; verify worker health if prolonged |
| `running` | worker is checkpointing file operations | poll status |
| `cancelling` | cancellation is durable | wait for the next file boundary |
| `cancelled` | no further operation will run | start a new operation for newer state |
| `completed` | all bindings and canonical results are durable | verify projection freshness if needed |
| `failed` | bounded failure code is durable | fix the classified cause and start a new operation |

`source_unavailable` means the exact planned artifact was unavailable or its digest changed.
`worker_failure` means a bounded parser, persistence, or integrity boundary failed. Neither status
contains raw source or dependency diagnostics.

## Diagnosing unexpected rebuilds

Compare the previous and new run implementation fingerprints, then inspect these reviewed inputs:

- language lock digest;
- plugin/parser version;
- grammar revision and query-pack digest;
- extraction configuration digest;
- privacy policy version;
- normalized repository-relative path and content digest.

A difference in any input is a deliberate cache miss. A rename also changes a path-sensitive cache
identity and creates a new revision plus lineage. Do not copy cache rows or edit plan operations to
force reuse.

## Diagnosing stale projections

1. Confirm `index_projection_events` contains the operation ordinal.
2. Read the latest append-only delivery snapshot. An expired `leased` row is retryable after the
   fixed lease; `completed` means vector, topology, and evidence effects were accepted.
3. Check that the event lists only the expected affected/re-embed/evidence identifiers. Do not log
   vectors or source text.
4. Confirm the local embedding provider still reports the configured model ID, revision, dimension,
   cancellation support, and local-only attestation.
5. Confirm the recorded run principal still has current repository authority. Evidence revocation
   fails closed when authority or scope no longer matches.

Projection recovery is a retry, not a deletion or update. Never update delivery rows, remove an
event, or mark delivery complete manually.

## Assertion invalidation check

For a deleted or changed semantic unit with registered assertion evidence:

- one `source_invalidated` evidence revocation must exist;
- assertions left without sufficient evidence must have a new disputed lifecycle revision;
- the previous active revision remains historical;
- the materialized graph worker may lag but must converge from the canonical lifecycle event.

If an evidence ID belongs to another Brain/Project/Repository, stop. This is an integrity failure,
not an operator-repairable mismatch.

## Freshness qualification

The release workload is `deploy/index-freshness-profile.v1.json`: 10,000 manifest entries, one
changed file, three warmups, twenty measured plans, and p95 below 30 seconds. Qualification must run
on the certified local resource profile together with parsing, local embedding, SQLite checkpoint,
and projection delivery measurements. The unit profile proves deterministic planning cost; release
qualification records the complete observed freshness interval from detection to completed
projection.

## Safe rollback and migration

Migration `0027_idx002_incremental_index` can be downgraded only before it contains incremental
history. Once runs, lineage, dependencies, or projection events exist, downgrade refuses to destroy
evidence. Use the signed backup/restore and release rollback procedure; do not disable immutable
triggers, delete rows, copy an older database over live state, or reset migration metadata.

## Security rules

- Keep absolute host paths, source bytes, parser stderr, vectors, and credentials out of logs.
- Use fixed executables and argv arrays; never invoke Git through a shell or ambient repository
  configuration.
- Preserve file count, byte, subprocess output, timeout, dependency closure, and lease bounds.
- Do not parse generated files unless the exact run policy authorizes them.
- Do not acknowledge an outbox event before embedding, invalidation, and evidence revocation all
  succeed.
- Never bypass current Repository authorization to unblock a worker.
