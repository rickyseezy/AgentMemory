# GRA-003 materialized-edge projection runbook

## Purpose

Use this runbook when an assertion does not become directly traversable, a projected edge remains
active after dispute, the projection queue retries or quarantines work, an integrity finding appears,
or traversal omits an expected relationship. Neo4j is derived state. Never insert, update, delete, or
unquarantine a relationship manually.

## Healthy state

- Core is Ready at relational head `0039_pro006_provider_scheduling` and graph head
  `0005_pro004_embedding_space_constraints` or a later release-certified pair.
- Every committed assertion lifecycle event has one `assertion_edge_projection_jobs` row.
- Each completed job has one immutable receipt with the active graph generation and exact projection
  digest.
- Active assertions have one non-quarantined direct edge in the active generation; disputed or
  invalidated assertions have no retrieval-visible direct edge.
- Every direct edge carries the canonical assertion/revision/event IDs, exact scope and classification,
  valid/recorded time, aggregate version, generation, and projection digest.
- The periodic integrity worker produces no new unrepaired findings.

## Projection job diagnosis

Inspect only content-free columns: source event/assertion IDs, Brain/project/repository/Checkout IDs,
aggregate version, state, attempt count, lease owner/expiry, safe error code, and timestamps.

| State | Meaning | Action |
|---|---|---|
| `ready` | Durable and due now or after `not_before` | Wait for the local worker; verify Core worker health if it does not lease |
| `leased` | One exact worker attempt owns the job | Wait until completion or lease expiry; never clear the lease manually |
| `completed` | Immutable receipt committed | Verify the receipt generation is still the current active graph generation |
| `quarantined` | Automatic replay stopped after policy/integrity failure or retry exhaustion | Preserve evidence, correct the owning canonical/dependency problem, then use governed replay/rebuild |

Safe failure codes are `authorization_revoked`, `concurrent_conflict`, `dependency_unavailable`,
`generation_unavailable`, `integrity_violation`, and `internal_error`. They intentionally omit raw
exceptions and content.

For `generation_unavailable`, confirm PF-002 has an active `graph` generation in
`active_projection_generations`. For `dependency_unavailable`, confirm Neo4j is Ready and that the
subject/object `GraphEntity` projections exist in the same Brain and authorized scope. The worker
retries these conditions exponentially up to five minutes and recovers expired leases automatically.

For `authorization_revoked`, verify the originating principal, Brain, topology, and covering grant are
currently active. Do not restore access merely to clear a derived job. If revocation is intentional,
quarantine is correct and retrieval must continue to exclude the content.

For `concurrent_conflict` or `integrity_violation`, stop manual repair, retain a protected backup, and
compare the canonical lifecycle event/digest with the projected assertion/revision/generation digest.
Use the integrity worker or PF-002 rebuild after correcting the owning canonical input.

## Stale activation or retirement diagnosis

The worker always reloads the latest lifecycle revision. It is therefore normal for an activation job
to produce a retired version-2 result when a dispute committed before the delayed job executed.
Confirm:

1. the trigger is a canonical `AssertionActivated` or `AssertionDisputed` event for that assertion;
2. the latest `assertion_lifecycle` row and joined domain event agree on status, version, digest, and
   occurrence time;
3. the edge names the latest lifecycle event while the receipt binds its trigger event to the
   resulting edge digest; and
4. traversal filters the active generation and excludes retired/quarantined edges.

An old activation that makes a retired edge active is an integrity incident. Preserve both event IDs,
aggregate versions, generation, and content-free digests and stop release promotion.

## Integrity findings and repair

Each finding is one of:

- `missing`: canonical active assertion has no effective edge;
- `orphan`: effective edge has no canonical assertion in the authorized scope; or
- `mismatch`: the effective edge differs or duplicate effective edges exist.

The finding is appended before repair. A missing edge is reprojected. An orphan is quarantined. A
mismatch is quarantined by assertion plus generation, then the exact canonical edge is reprojected.
Only after success is the immutable repair receipt appended.

To investigate an unrepaired finding:

1. verify current principal/Brain/grant/topology authorization;
2. verify the finding generation still matches the active graph generation;
3. load the current canonical assertion and latest lifecycle event from SQLite;
4. compare assertion revision, source event, scope, temporal fields, aggregate version, relationship
   type, and projection digest;
5. verify Neo4j relationship type equals its stored `relationship_type` property and both endpoints
   are same-Brain `GraphEntity` nodes; and
6. restore the dependency or canonical input and allow the next integrity pass to repair forward.

Do not delete a quarantined edge: it is derived incident evidence and remains retrieval-invisible.
Repeated scans ignore an already-quarantined orphan. A restored canonical active edge is explicitly
unquarantined only through exact reprojection.

## Traversal omission

Confirm all of these before treating omission as a defect:

- the assertion is currently active and its recorded interval is open;
- predicate maps to one of the seven closed direct relationship types;
- edge Brain, project, repository, optional Checkout, and classification are inside the resolved
  `AuthorizedScope`;
- edge generation equals the current active graph generation;
- edge is not quarantined;
- subject and object graph entities exist and remain authorized; and
- the requested relationship-type set and result limit are valid and bounded.

Traversal returns an authority explanation rather than arbitrary relationship properties. Use its
assertion/revision/event IDs to inspect canonical evidence through the owning GRA-002 workflow.

## Recovery and rollback

For a broad projection mismatch, run PF-002 with the exact certified manifest and canonical watermark.
It builds and validates a shadow generation before activation. Never change
`active_projection_generations` or Neo4j generation properties manually.

Relational downgrade to `0021_gra002_evidence_assertions` is allowed only before any GRA-003 job,
receipt, finding, or repair exists. Once evidence exists, downgrade refuses. Graph migration 0004 is
forward-only in an active installation; application rollback must select a signed release declared
compatible with both current schema heads or restore the complete prior SQLite/Neo4j backup and
application release together.

Never place assertion content, prompts, code, paths, vectors, credentials, raw SQL/Cypher, or hidden
reasoning in logs, support bundles, or incident tickets.
