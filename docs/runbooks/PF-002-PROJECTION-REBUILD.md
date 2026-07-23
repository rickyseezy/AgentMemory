# PF-002 projection rebuild runbook

## Purpose

Use this runbook to repair graph, memory, search, code, or vector derived state from canonical local
events. Never delete or edit canonical events, tombstones, grants, audit records, generation records,
or active pointers to force a repair.

## Preconditions

- AgentMemory Core is Ready and its SQLite/Neo4j migration heads are the exact heads certified by the
  active release (currently `0037_pro004_embedding_spaces` and
  `0005_pro004_embedding_space_constraints`). PF-002 introduced the earlier `0002` schemas; do not downgrade
  an active installation to match an old example.
- The operator has an active grant for the target Brain.
- The manifest contains exact immutable application, schema, parser, extractor, provider/model, and
  embedding-space pins. Do not use aliases such as `latest`.
- Required local artifacts/providers are available. A remote provider may be used only through its
  separately approved provider route; Core itself remains local and has no general egress.

## Start a rebuild

Send an authenticated loopback request with a unique operation ID and matching `Idempotency-Key`:

```http
POST /operations/rebuilds
Authorization: Bearer <launcher-credential>
Idempotency-Key: rebuild-2026-07-20-001
Content-Type: application/json

{
  "operation_id": "rebuild-2026-07-20-001",
  "brain_id": "<uuid-v7>",
  "actor_id": "<uuid-v7>",
  "grant_id": "<uuid-v7>",
  "projection_type": "graph",
  "requested_watermark": null,
  "manifest": {
    "application_build": "<immutable-build>",
    "relational_schema": "0037_pro004_embedding_spaces",
    "graph_schema": "0005_pro004_embedding_space_constraints",
    "parser_version": "<immutable-parser-revision>",
    "extractor_version": "<immutable-extractor-revision>",
    "provider_versions": ["<provider:model@immutable-revision>"],
    "embedding_space": "<immutable-space-fingerprint>",
    "implementation_fingerprint": "<lowercase-sha256>"
  }
}
```

Omit `requested_watermark` to capture the current committed watermark. A future or negative watermark
is rejected. Reusing the exact normative identity returns the existing operation; reusing an operation
ID with a different binding returns a conflict.

## Monitor

Poll `GET /operations/rebuilds/{operation_id}` with the launcher credential. Interpret states as:

| State | Meaning | Operator action |
|---|---|---|
| `queued` | Durable, waiting for local worker | Wait; verify Core worker health if prolonged |
| `building` | Shadow generation is being replayed | Do not alter canonical or projection tables |
| `partial` | Safe dependency/artifact reason recorded; cursor retained | Restore the exact dependency; automatic retry is delayed and bounded |
| `validating` | Shadow is complete but not visible | Wait; investigate only if the worker lease expires |
| `ready` | Validation passed; activation CAS pending | Wait; never edit the pointer |
| `active` | Atomic activation succeeded | Verify application golden queries |
| `superseded` | Another valid generation won the activation race | Keep for evidence or start a new rebuild against the current pointer |
| `failed` | Integrity/policy validation quarantined the generation | Preserve evidence; correct canonical inputs or pins and start a new operation |

Progress is `cursor / source_watermark`. `record_count` excludes tombstoned sources and exact retries;
`skipped_tombstones` is expected to be nonzero when canonical history contains deleted targets.

## Partial and outage recovery

For `artifact_unavailable` or a dependency-unavailable code:

1. Do not modify the cursor, state, or shadow rows.
2. Restore the exact digest-addressed artifact or pinned provider revision.
3. Verify the dependency independently and wait for the scheduled retry.
4. Confirm the operation resumes from the same cursor and that `record_count` does not increase for
   already written stable IDs.

An unexpected worker stop leaves a bounded lease. The replacement worker may reclaim only after lease
expiry; concurrent claims before expiry return a retryable conflict.

## Failed validation

Treat an integrity failure as security/repair evidence:

- preserve the operation response, Core audit chain, manifest digest, source watermark, generation
  digest, release/data generation, and local logs;
- compare canonical source/content hashes, tombstone state, grant validity, SQLite count/digest, and
  Neo4j count/digest;
- never copy rows from another generation or mark a failed generation active;
- correct the canonical event/artifact or immutable implementation pin, then create a new operation.

No raw memory content, vectors, code, paths, provider payloads, credentials, SQL, or Cypher should be
placed in an incident ticket or diagnostic bundle.

## Rollback

To restore prior behavior, start a new rebuild using the prior approved manifest pins and the intended
committed watermark. The rebuild creates a new generation, validates it, and atomically replaces the
current pointer. A direct SQL/Neo4j pointer edit is unsupported and invalidates audit/integrity
evidence.

## Escalation thresholds

- Escalate immediately for any divergent duplicate, manifest mismatch, audit-chain failure,
  tombstoned record in validation, unauthorized activation attempt, or SQLite/Neo4j digest mismatch.
- Escalate operationally when a queued/partial operation makes no progress after its retry window or a
  building lease repeatedly expires.
- Freeze release promotion when the 10,000-record tripwire exceeds 30 seconds or the signed ADR-014
  benchmark exceeds its absolute/regression budget.
