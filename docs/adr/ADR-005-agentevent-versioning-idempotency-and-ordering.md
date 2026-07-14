# ADR-005: AgentEvent versioning, idempotency, and ordering

- Status: Accepted
- Decision owners: Ingestion Owner and Agent Adapter Owner
- Consulted owners: Sessions, Governance, Audit, SDK/Contracts
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before a schema-major or ordering-policy change
- Supersedes: None
- Related requirements: PRD Sections 4 and 6; Technical Requirements Sections 4.2, 5.1, 5.3-5.4, and 11.3-11.4

## Context

Different agent hosts expose different lifecycle detail and may retry, buffer offline, reorder, or
arrive after clock changes. Canonical capture must preserve what was observable without fabrication,
acknowledge durably, and replay old versions deterministically.

## Decision

### Envelope and schema identity

AgentEvent is a CloudEvents-compatible JSON envelope. It has `specversion`, lowercase UUIDv7 `id`,
stable adapter `source`, versioned `type`, `subject`, UTC occurrence `time`, `datacontenttype`, and an
immutable `dataschema` URI. Extensions include Brain/project/repository/checkout, agent/adapter/model/
session/task/turn, correlation/causation, ordering key/sequence, classification, retention policy,
capture capability/method, content SHA-256, and either inline `data` or `dataref`—never both.

Inline canonical payload limit is 64 KiB. Larger authorized payload is encrypted in CAS before event
commit and referenced by digest. Event JSON is strict at producer and ingestion boundaries; duplicate
keys and non-finite numbers fail. Integration readers preserve unknown additive fields.

Schema IDs are immutable and semantic-versioned. The event `type` includes its major
(`agentmemory.<family>.<name>.v<major>`); compatible minor/patch additions do not change type major.
The original validated bytes/schema are immutable. One-step deterministic upcasters produce a current
internal view and retain unknown fields; unsupported major is quarantined with
`AM_SCHEMA_UNSUPPORTED`.

### Identity and idempotency

The adapter generates event UUIDv7 once and persists it in its spool before first send. Retry reuses
the same ID and exact content hash. Ingestion has unique `event_id`; same ID/same hash returns
`duplicate`, while same ID/different hash is rejected, audited as provenance/integrity conflict, and
never overwrites the original.

Batch append accepts at most 100 events or 1 MiB. Atomicity is per event. Every item returns exactly
`accepted`, `duplicate`, `rejected`, or `deferred` with safe typed detail. Accepted means the SQLite
event/outbox/audit transaction met ADR-003's commit boundary, not that projections completed.

### Ordering stream

Every adapter session or observer stream allocates an opaque UUIDv7 `ordering_key` and a monotonically
increasing unsigned 64-bit `sequence` starting at 1. One key represents one causal producer stream;
independent streams never share a key to manufacture global order. A retry preserves both. Events with
no host ordering capability still use adapter observation order and declare that capability as
`inferred` or `explicit_tool_only`, not native.

The ledger uniquely constrains `(ordering_key, sequence)` when sequence is present. Same pair/different
event is an integrity conflict. Projection maintains next expected sequence and watermark per key.
Future events wait in bounded pending state. A missing sequence does not silently advance; after the
configured 24-hour ordering-gap window, the processor records an explicit `OrderingGapObserved`
decision and may continue only for projection classes whose versioned policy declares gap tolerance.
Strict session/task lifecycle projections remain blocked or dead-lettered until repair. A late event
after a recorded gap creates a new linked projection attempt and may supersede derived state; history
is not rewritten.

Correlation groups a user operation/task across streams. Causation identifies the direct observable
predecessor where known. Neither field replaces per-key sequence or establishes model causality.

### Time semantics

`time` is occurrence time supplied/observed by adapter; `ingested_at` is assigned by core's injected
clock. Both are UTC RFC 3339 with microseconds. Clock skew is recorded separately and occurrence time
is never rewritten. Naive, impossible, or unbounded-future timestamps are rejected or quarantined by
the versioned clock-skew policy; they are not used to reorder a sequence stream.

### Capability and provenance

Each event binds adapter ID/version/digest, agent host/model when observable, signed/registered adapter
identity, capability-manifest digest, capture method (`native`, `inferred`, `explicit_tool_only`,
`unsupported`, `permission_denied`), and source hash. Missing host data remains explicit null/unknown
only where schema permits. Hidden reasoning fields are prohibited and dropped/rejected by adapter
conformance.

### Replay

Replay selects Brain, immutable event ID/time range, ordering keys, target shadow projection, schema/
upcaster fingerprint, and code fingerprint. It processes per-key sequence deterministically and may
parallelize keys. Model/provider reductions use a recorded result/version or are identified as a new
projection generation; replay never calls a current model while claiming reproduction.

## Security and privacy impact

Adapters cannot grant scope: ingestion re-resolves Brain/project identity and authorization. Capture
exclusion, decoding, secret/PII scan, classification, redaction, and payload policy run before event/CAS
persistence. IDs, ordering, and hashes are metadata; logs avoid payload, path, prompt, and secret.
Conflicting IDs and fabricated provenance are audited.

## Compatibility, migration, and rollback

Additive optional fields preserve major. Breaking meaning/required fields create a new major and a
one-step upcaster if deterministic. Producers/consumers support the ADR-016 window. Migrations never
rewrite original events; rollback uses the previous reader/upcaster and builds a new shadow projection.
Removing a field requires the full deprecation window and fixtures for old bytes.

## Rejected alternatives

- Server-generated retry IDs: cannot deduplicate offline retries.
- Timestamps as order: clocks skew and concurrent events collide.
- One global sequence: unnecessary contention and fabricated order.
- Batch-level atomic ACK: one poison item would block unrelated capture.
- Overwriting events after upcast: destroys audit/replay evidence.
- Fabricating unsupported lifecycle fields: converts absence into false evidence.

## Consequences

Ordering gaps can delay strict projections and require visible repair. Immutable originals and
upcasters consume storage but make adapter evolution and replay explainable.

## Verification

- Golden canonical bytes for every supported schema and one fixture per required event family.
- Schema/duplicate-key/encoding/time/hash/capability fuzzing and hidden-field privacy fixtures.
- Concurrent duplicate/conflicting ID and ordering-pair storms.
- Reorder, missing/late sequence, multiple-key parallelism, clock jump, offline spool, and gap-policy
  state-machine tests.
- Kill before/after commit and ACK; only committed events report accepted.
- Upcaster chains, unknown field round-trip, unsupported major quarantine, and deterministic replay
  digest tests.
- Cross-adapter equivalence and original provenance tests.
