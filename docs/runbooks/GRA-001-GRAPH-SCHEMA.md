# GRA-001 Brain-scoped graph schema runbook

## Purpose

Use this runbook when graph migration, constraint inventory, schema integrity, scoped reads, or
idempotent projection fails. Neo4j is derived state. SQLite canonical events, grants, tombstones, and
audit history remain authoritative; never invent or repair graph facts without canonical lineage.

## Healthy state

- Neo4j server is the locally pinned 2026.06 Community build and the official Python driver is 6.2.0.
- `AgentMemorySchema` reports `0003_gra001_brain_scoped_schema`.
- All 53 GRA-001 `(brain_id, id)` uniqueness constraints exist and the vector index is online with its
  certified provider and filtered properties.
- The startup entity and relationship integrity counts are both zero.
- Only authenticated loopback Core/MCP interfaces are published; Bolt and Neo4j HTTP are not exposed
  outside the private Compose network in a product installation.

## Migration failure

1. Stop Core and projection workers; do not enable writers against a partial schema.
2. Preserve content-free migration logs, image digest, release manifest, graph schema head, and
   constraint names. Do not copy credentials, node properties, source text, paths, or vectors.
3. Verify the exact signed migration digest and pinned Neo4j/driver versions.
4. Correct storage availability or version drift, then rerun the idempotent migration. `IF NOT EXISTS`
   makes already installed constraints safe to revisit.
5. Require migration head, all constraints, vector-index compatibility, and both integrity scans to
   pass before restarting writers.

Never rename, drop, or recreate a constraint manually while writers are active.

## Integrity failure

An integrity failure means a `GraphEntity` or managed relationship bypassed the repository, was
corrupted, or no longer matches the certified schema.

1. Keep Core unready and stop graph projection.
2. Take a protected local backup and preserve the content-free operation/audit evidence.
3. Identify only the invalid stable IDs and Brain IDs with a reviewed, local administrative query.
   Do not export arbitrary properties into logs or tickets.
4. Resolve each ID against canonical SQLite events, active grants, deletion tombstones, and the active
   projection generation.
5. Quarantine/delete the derived malformed record, then run the governed PF-002 rebuild for the graph
   projection. Do not patch missing properties by hand.
6. Re-run constraint inventory, entity integrity, relationship integrity, cross-Brain canary, and a
   golden authorized query before service activation.

If canonical lineage cannot be resolved, keep the record excluded and escalate as an integrity event.

## Conflict and concurrency diagnosis

- One `created=true` with subsequent exact `created=false` results is healthy retry convergence.
- `GraphConflictError` for the same `(brain_id, id)` with a different revision is a divergent source
  or identity-mapping defect. Preserve both content fingerprints and source event IDs, not content.
- An empty relationship write result usually means an endpoint is absent or outside the authorized
  project/repository/classification scope. Reauthorize and rebuild the endpoint first.
- A cross-Brain read returning any record is a release-blocking security incident. Stop service,
  preserve evidence, rotate affected local capabilities, and run the complete isolation suite.

## Rollback

Forward repair is the default. If rollback is unavoidable:

1. Stop Core and every graph/projection worker and take a verified protected backup.
2. Confirm no GRA-002-or-later data or application release requires schema head `0003`.
3. Restore the prior signed application, migration bundle, and compatible derived-store backup as one
   release operation. Never merely edit `AgentMemorySchema.version`.
4. If no GRA-001 graph data exists and a reviewed rollback plan explicitly authorizes it, constraints
   may be removed only while all writers are stopped. Otherwise rebuild a fresh derived Neo4j volume
   from canonical SQLite state using the prior compatible release.
5. Run that release's full readiness and cross-Brain tests before activation.

Do not roll back SQLite canonical history or deletion tombstones to accommodate derived graph state.

## Escalation

Freeze release promotion for a missing constraint, malformed managed record, divergent retry,
relationship endpoint Brain mismatch, unauthorized dynamic identifier, cross-Brain result, migration
digest mismatch, or any readiness result that differs between repeated runs on unchanged state.
