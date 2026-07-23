# GRA-006 graph integrity operations runbook

## Healthy state

- Core reports Ready at relational head `0039_pro006_provider_scheduling` or a later certified head.
- A completed migration has cursor equal to source watermark and state `completed`.
- The migration ID is `gra006-integrity-v1`; its checksum must equal the running release's registered
  checksum. Never copy a checksum from another binary or edit persisted migration rows.
- Every finding is content-free, scope-bound, immutable, and has a stable finding ID.
- Every completed repair has one immutable receipt and one hash-chained central audit fact.
- Canonical SQLite history is unchanged by graph shadow writes and quarantines.

## Start and run a graph migration

Call `POST /graph/integrity/migrations/start` with current Brain, actor, grant, Project, Repository,
operation ID, the registered migration ID/checksum, and a batch size from 1 through 4096. The result
captures cursor zero and a fixed source watermark in SQLite before graph mutation.

Call `POST /graph/integrity/migrations/run` with the same operation and scope. The worker resumes from
the last durable cursor, applies bounded idempotent shadow batches, checkpoints each successful
batch, validates every shadow checksum, and then marks the run completed. Exact retries of a
completed operation return the completed run. Do not create a new operation ID merely because a
response was interrupted.

If execution stops, inspect only migration state, cursor, watermark, checksum, and counts. Resume the
same operation. A graph batch may have committed before its SQLite checkpoint; `MERGE` makes replay
safe. If the cursor does not advance, validation fails, or a checksum is rejected, stop retries and
verify that the binary, release manifest, and database belong to the same installed release. Never
advance the cursor manually.

## Validate integrity

Call `POST /graph/integrity/validate` with current scope, a unique operation ID, and the expected
64-character current generation digest. The global scan is capped at 10,000 projection observations.
It can return multiple findings for one projection. Handle the closed finding kinds as follows:

- `unsupported_assertion`: verify the missing Evidence lineage; default repair is a shadow write.
- `orphan_vector`: preserve the canonical database and quarantine the derived vector.
- `orphan_edge`: preserve the canonical database and quarantine the derived relationship.
- `invalid_temporal_range`: verify canonical bitemporal values; default repair is a shadow write.
- `scope_mismatch`: treat as a security/integrity event and quarantine the derived projection.
- `stale_generation`: confirm the active generation digest; default repair is a shadow write.

An empty result means no defect was found in the authorized bounded projection set for that
generation. It does not prove the health of unauthorized scopes. An over-limit, malformed, or
out-of-scope result fails closed instead of returning a partial clean report.

## Repair a finding

Call `POST /graph/integrity/repair` with the finding ID, current scope, operation ID, and
`destructive: false` for the normal path. The server selects `shadow_write` or `quarantine` from the
finding type; callers cannot select arbitrary Cypher or an arbitrary action. Retry the exact
operation after an interrupted response. Divergent operation reuse or a second repair for the same
finding is rejected.

Use `destructive: true` only after an owner/admin explicitly approves rebuilding the graph. Include
that active grant as `approval_id`. The server independently verifies principal, role, Brain,
Project, Repository, grant validity, relational head, SQLite health, foreign keys, and release
manifest. Successful verification starts an isolated PF-002 graph generation; it does not delete or
rewrite the active graph in place. Follow
[PF-002 projection rebuild operations](PF-002-PROJECTION-REBUILD.md) through validation and atomic
activation. Never attempt to send an internal `canonical_rebuild_verified` flag; the API rejects it.

## Failure and recovery

- `401/403`: refresh authentication and resolve a current grant for the exact action and scope.
- `409`: inspect operation/finding identity, completed state, or divergent replay; do not mutate rows.
- `422`: correct the closed request values, registered checksum, generation digest, or approval.
- `503`: retain the same operation ID and retry only after SQLite or Neo4j health is restored.
- validation/integrity failure: stop repair, preserve SQLite and Neo4j, and collect content-free
  operation IDs, finding IDs, digests, cursor/counts, release version, and health results.

Do not update/delete GRA-006 tables, migration shadows, findings, audit events, or canonical history.
SQLite triggers intentionally reject evidence mutation and downgrade refuses after evidence exists.
For canonical corruption, use the signed backup/recovery procedure before any PF-002 rebuild. Support
bundles and logs must not contain assertion/evidence content, source code, embeddings, filesystem
paths, credentials, SQL/Cypher text, or hidden model reasoning.
