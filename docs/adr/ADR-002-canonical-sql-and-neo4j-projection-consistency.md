# ADR-002: Canonical SQL state, Neo4j projection ownership, and outbox consistency

- Status: Accepted
- Decision owners: Data Architecture Owner and Ingestion Owner
- Consulted owners: Graph, Governance, Audit, Operations
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before adding a persistent store or changing an acknowledgement boundary
- Supersedes: None
- Related requirements: Technical Requirements Sections 1.6-1.7, 4.1-4.6, 5.3-5.4, 6.6-6.7, and 11.4

## Context

AgentMemory needs durable event acceptance and rich graph/vector queries without distributed
transactions. Neo4j outages must not lose acknowledged work, and every derived fact must be
rebuildable, idempotent, Brain-scoped, and deletion-aware.

## Decision

### Canonical ownership

Packaged SQLite is the only canonical runtime database. It owns installation/Brain identity,
principals/grants/policies, authorized AgentEvents and artifact references, aggregate domain-event
streams and snapshots, corrections/approvals/holds/tombstones, provider configuration without secret
values, operations, outbox/inbox/jobs/DLQ, audit events, and migration/activation pointers.

Owner-only pre-core install journal/resource inventory/active pointers are canonical for host setup;
SQLite mirrors them after readiness and disagreement fails closed. Source repositories/documents remain
canonical for their own content. Encrypted CAS holds large canonical authorized bytes.

Neo4j, full-text/vector records, memories/summaries derived from events, graph assertions/materialized
edges, code projections, briefings, evaluation read models, and caches are rebuildable projections.
Operational aggregate snapshots in SQLite are rebuildable from append-only domain events and explicit
user/admin records.

### Command transaction

One command UoW performs, in order:

1. authenticate and authorize;
2. claim command idempotency using principal, route/use case, and normalized request hash;
3. load aggregates at expected versions;
4. apply domain transitions;
5. append each next `domain_event` with unique aggregate type/ID/version;
6. update aggregate snapshots by compare-and-swap;
7. append canonical AgentEvent/artifact, tombstone, outbox, and required audit facts applicable to the
   command; and
8. commit once.

Repositories never commit. Governed success is not returned if the audit append cannot join the SQL
transaction. An AgentEvent ACK is returned only after the transaction containing the event and outbox
has committed under ADR-003 durability settings.

No application transaction writes Neo4j. A graph/vector/full-text operation is requested by an
immutable outbox record in the same canonical transaction. There is no XA/two-phase commit, best-
effort dual write, or compensation that deletes committed canonical history.

### Outbox, jobs, and inbox

Outbox IDs are UUIDv7. A unique `(source_event_id, topic)` prevents duplicate logical publication.
Topics use `am.local.<brain>.<context>.<event-name>.v<major>`. The dispatcher selects in stable
priority, `not_before`, and ID order; claims a bounded 60-second lease in a short write transaction;
and dispatches to SQLite jobs rather than an external broker. Lease heartbeat is 20 seconds.

Consumers first evaluate tombstones/current authorization, then claim `(consumer, message_id)`. Their
successful UoW writes effective canonical results, inbox result hash, derived-work status, subsequent
outbox messages, and required audit facts atomically. A receipt with a different result hash is
`AM_INTEGRITY_VIOLATION`. A crash before commit permits retry; after commit, receipt replay returns the
recorded result without repeating side effects.

Retryable typed failures receive at most eight job attempts over 24 hours with exponential full
jitter. Schema, authorization, invariant, and privacy failures enter DLQ immediately. Exhaustion enters
DLQ; source events are never discarded or edited. Replay creates a linked new attempt/run.

### Projection contract

Every projection mutation includes source event/artifact IDs, source content hash, schema version,
parser/extractor/provider/embedding-space fingerprint, projection generation, and idempotency key.
Neo4j writes use parameterized Cypher and constrained stable keys. Materialized relationships retain
authoritative assertion ID. A duplicate request must produce the same projection digest or an
integrity incident.

Projection workers advance a canonical watermark only after Neo4j transaction success and inbox/UoW
completion. Query responses report generation and freshness/watermark. A projection unavailable or
behind does not alter canonical state; retrieval uses healthy channels and discloses degradation.

### Ordering and replay

AgentEvent ordering is defined by ADR-005. Per-ordering-key gaps remain pending until resolved or a
versioned gap policy records an explicit gap outcome. Independent ordering keys may process
concurrently.

Replay reads immutable canonical inputs at a fixed watermark and writes a new shadow generation. It
uses recorded nondeterministic model results or reruns a newly identified projection version; it never
silently calls today's model while claiming deterministic reproduction. Activation follows counts,
lineage, digest, authorization, tombstone, integrity, and golden-query validation.

### Failure and reconciliation

- SQL commit failure: no ACK/outbox visibility; idempotent retry is safe.
- Neo4j/provider failure: canonical request stays queued with visible degraded state.
- Worker death: lease expires and another attempt resumes idempotently.
- Canonical/projection digest disagreement: quarantine generation, alert, and rebuild; do not edit
  canonical history.
- Tombstone/grant change: deny synchronously in canonical queries and invalidate caches; queued
  projection work rechecks before side effect.
- Neo4j corruption/loss: discard affected projection generation and rebuild from SQLite/CAS.
- SQLite corruption: enter read-only recovery and restore a verified backup; Neo4j is never promoted to
  canonical source.

## Security and privacy impact

Authorization occurs before candidate access and again in projection consumers. Every record and
idempotency/cache key is Brain-scoped. Tombstones prevent queued/replayed work from resurrecting data.
Outbox/audit payloads contain only classified minimum data or encrypted references. Neo4j compromise
cannot grant canonical authority.

## Compatibility, migration, and rollback

Domain/integration events are immutable and versioned; one-step upcasters preserve originals. Snapshot
schema changes rebuild from events. SQL migrations use expand/migrate/contract. Neo4j changes build a
shadow generation. Rollback selects the previous compatible application/projection generation; it
never reverses or deletes canonical events. Older consumers remain supported for the published window.

## Rejected alternatives

- Neo4j as canonical memory/event store: weakens local transactional acknowledgement and rebuild.
- SQL+Neo4j synchronous dual write: cannot be made atomic without unsuitable distributed machinery.
- External broker/Redis/NATS: unnecessary stateful dependency for one local owner.
- Polling domain tables without outbox: can miss committed intent.
- Exactly-once infrastructure claim: does not protect external/provider side effects.
- Rebuilding in place: exposes partial/corrupt projections.

## Consequences

Projection freshness is eventual and workers need idempotency/watermarks. In return, ACK durability,
repair, graph replacement, and provider outages have one explicit consistency model.

## Verification

- Kill at SQL begin/write/commit/ACK, outbox lease, consumer side effect, Neo4j commit, inbox commit,
  and watermark boundaries.
- Duplicate storms and conflicting result hashes prove one effective mutation/billing event.
- Neo4j/provider outage and recovery preserve canonical queue and degradation reporting.
- Replay/shadow digest, deletion non-resurrection, grant revocation, and generation activation tests.
- Repository/UoW contracts reject commits and cross-store dual writes.
- Chaos compares AgentEvent/domain/outbox/inbox/job/projection watermarks after recovery.
