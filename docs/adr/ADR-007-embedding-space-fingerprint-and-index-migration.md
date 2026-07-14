# ADR-007: Embedding-space fingerprint, index names, and migration state machine

- Status: Accepted
- Decision owners: Provider Platform Owner and Retrieval Owner
- Consulted owners: Graph, Indexing, Governance, Operations
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before changing fingerprint fields, vector representation, or cutover policy
- Supersedes: None
- Related requirements: PRD Section 11; Technical Requirements Sections 4.6, 4.9, 11.8 PRO-003/PRO-004/PRO-008

## Context

Vectors are comparable only when provider, model, revision, preprocessing, purpose, dimension, and
numeric semantics agree. Provider changes must coexist and migrate under live ingestion without
padding/projecting vectors or contaminating indexes. Neo4j schema identifiers must not contain user or
provider text.

## Decision

### Immutable embedding-space contract

An `EmbeddingSpaceDescriptorV1` is RFC 8785 canonical JSON with these required fields:

- descriptor version and operation `embedding`;
- provider adapter ID and implementation digest/version;
- endpoint class (`local`, approved provider service class, or equivalent endpoint set ID), never a
  credential or mutable hostname alias by itself;
- explicit model ID and immutable model revision or local weight digest;
- tokenizer ID/revision/digest, pooling, preprocessing pipeline version, Unicode/line normalization,
  chunking contract where it affects input, and truncation policy;
- output dimension, dtype, vector encoding, normalization, similarity, and quantization/inference
  settings;
- canonical purpose plus query/document asymmetry mapping;
- instruction/template canonical bytes SHA-256;
- runtime/serving image digest and relevant deterministic inference settings; and
- privacy/residency execution class where it changes semantic execution.

`immutable_fingerprint = sha256(JCS(descriptor))`, lowercase hex. Every field is explicit; omitted and
null are not interchangeable. Credentials, request quotas, prices, health, routes, and display names
are not semantic fields. A validated live probe attestation is separately bound to the descriptor,
adapter digest, endpoint, configuration hash, and model-revision evidence.

An EmbeddingSpace receives UUIDv7 ID and unique fingerprint. It is immutable after creation. Any
semantic-field change creates another space, including a provider's silent model revision, tokenizer,
instruction, dimension, normalization, dtype, or quantization change.

### Vector record

Each vector record contains Brain/source entity/content hash, space ID/fingerprint, index generation,
provider instance, model/revision, adapter digest, dimension/dtype/normalization/similarity, purpose/
instruction profile, embedded time, and safe usage/request metadata. The idempotency key is
`sha256(brain_id || source_entity_id || source_content_hash || embedding_space_fingerprint || purpose)`.

Before one atomic batch write, validate output count/order/content IDs, exact dimension, finite values,
dtype/encoding, normalization tolerance, Brain/classification, source hash, active target state, and
generation/space match. No padding, truncation, projection, conversion between spaces, or old-vector
transformation is permitted.

### Closed Neo4j names

Let `<gid>` be generation UUID bytes rendered as 32 lowercase hexadecimal characters. Names are:

- label: `AMVector_<gid>`;
- vector index: `am_vec_<gid>`;
- full-text companion, if present: `am_text_<gid>`;
- vector property: fixed `embedding`.

Only a validated UUID generates these names. Provider/model/corpus/user text never enters a label,
index, property, or Cypher string. A generation maps to exactly one label/index and one declared Brain/
corpus route set; its records still carry Brain and narrower authorization filter properties.

### Generation and migration state

Physical `IndexGeneration` transitions are:

`Planned -> Creating -> Populating -> Validating -> ShadowReady -> Active -> RollbackReady -> Retired ->
DeletionPending -> Deleted`, with pre-active states allowed to `Failed`.

The coordinating `EmbeddingMigration` transitions are:

`Planned -> Building -> Backfilling -> DualWrite -> CatchingUp -> Validating -> Shadowing -> Ready ->
Active`, any nonterminal to `Paused`/`Failed`, `Paused` back to its stored resume state, and activated
migration to `RolledBack`.

Public PRD terms map `Building/Backfilling/CatchingUp/Shadowing/Active/Retiring/Retired` to these two
closed internal aggregates; APIs return both state and state-machine version so no phase is ambiguous.

### Migration algorithm

1. Resolve target descriptor, trusted adapter/probe, policy, source corpus, capacity, and baseline.
2. Create space and empty named index/constraints; prove filtered authorization.
3. Record a consistent canonical source watermark and resumable stable cursor.
4. Backfill canonical source content, never old vectors, under target privacy/route policy.
5. Enable idempotent dual-write from SQL outbox to old active and target generations.
6. Catch target up to recorded and then current outbox watermarks.
7. Validate coverage/counts/content hashes/vector numeric integrity/Brain isolation/deletion guard,
   latency/resource/privacy, and provider attestation.
8. Run shadow reads on the versioned golden/evaluation corpus and compare rank/evidence metrics.
9. Under `BEGIN IMMEDIATE`, verify expected active generation/watermark/approvals and atomically update
   the canonical active-generation pointer; publish cache invalidation.
10. Mark old generation RollbackReady and read-only. Stop dual-write after cutover proof.

Activation fails on any missing content, unresolved deletion, policy change, quality/safety regression,
provider drift, or stale watermark. Different spaces are queried independently and fused by rank under
ADR-012; raw scores are never compared.

### Rollback and retirement

Rollback atomically restores the prior active pointer and invalidates caches within 15 minutes; it
does not alter source content or target history. Exactly one prior active generation is retained by
default for 35 days and until at least one verified backup includes the new active pointer, whichever
is later. Capacity is reserved before migration. Additional retention requires explicit capacity
policy. Retirement/deletion uses governance deletion, verifies no active/rollback/backup dependency,
and preserves non-content audit receipts.

## Security and privacy impact

Space/generation isolation prevents cross-Brain and semantic contamination. Filter properties are
applied inside Neo4j SEARCH per ADR-004. Vectors inherit source classification and deletion. Space
metadata contains no credential or raw content; instruction hashes avoid exposing templates in traces.
Remote backfill remains subject to per-item egress authorization and cannot mix Brain/classification.

## Compatibility, migration, and rollback

Descriptor schema changes add a new descriptor version and fingerprint; V1 fingerprints never change.
Readers support descriptor versions in the product window. Changing vector storage or Neo4j behavior
builds a new generation. Rollback is pointer-based to a preserved compatible generation. An older
application never writes a newer unknown generation.

## Rejected alternatives

- Provider/model ID only fingerprint: omits tokenizer, instructions, numeric behavior, and revision.
- Mutable space metadata: silently changes vector meaning.
- Padding/truncating/projecting old vectors: manufactures false comparability.
- One index across dimensions/providers/Brains: violates semantic and authorization isolation.
- Provider/model text in index names: injection and lifecycle collision risk.
- In-place re-embedding/cutover: no complete shadow validation or rollback.

## Consequences

Model/configuration changes consume temporary duplicate storage and require backfill. This is the cost
of trustworthy concurrent providers, quality comparison, and reversible cutover.

## Verification

- Canonical fingerprint golden/property tests change the digest for every semantic field and not for
  irrelevant display/credential fields.
- Wrong count/order/dimension/NaN/Infinity/dtype/norm/content/Brain/generation tests fail before write.
- Index-name injection fuzzing proves only UUID-derived identifiers.
- Interrupt/resume every migration transition under continuous ingestion and deletion/grant changes.
- Shadow quality/privacy/latency/coverage gates, atomic cutover races, cache invalidation, drift, and
  15-minute rollback tests.
- Prove source re-embedding rather than vector transformation and one-space-per-index isolation.
