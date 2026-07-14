# ADR-011: Deletion dependency manifests, tombstones, restore guards, and providers

- Status: Accepted
- Decision owners: Governance Owner and Data Protection Owner
- Consulted owners: Every data context, Providers, Backup/Restore, Audit
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before adding a canonical/projection/cache/provider store
- Supersedes: None
- Related requirements: PRD Sections 8.10 and 15; Technical Requirements Sections 6.7, 7.4, 11.12 SEC-008, and 11.13 OPS-004

## Context

One source can have descendants in SQL, CAS, Neo4j, full-text/vector indexes, queues, caches, memories,
learning/evaluation fixtures, exports, backups, and optional provider batches. Immediate user control
cannot wait for physical purge, but asynchronous purge/rebuild/restore must never resurrect data.

## Decision

### Deletion aggregate and immediate deny

`RequestDeletionCommand` authenticates, authorizes exact target/scope, evaluates legal hold, and builds
a versioned dependency manifest at a canonical watermark. In one `BEGIN IMMEDIATE` UoW it appends:

- Deletion aggregate `Requested -> Tombstoned`;
- `deletion_tombstone` with Brain, target type, HMAC target ID, effective time, manifest/rules version,
  source watermark, restore-guard version, and request actor;
- synchronous grant/read/job/replay/cache exclusion state;
- purge outbox messages; and
- tamper-evident audit event.

After commit, all read/search/explain/export/replay/index/provider/job paths check the authoritative
tombstone before candidate/content access. Cache/tombstone epoch invalidates synchronously. Physical
purge may continue, but recall exclusion is immediate.

A deletion may be cancelled only before tombstone commit. After commit there is no undelete/rollback
of that ID or content lineage. Explicitly reintroducing equivalent content creates new source/event IDs
and remains subject to the old source tombstone; it cannot revive descendants by hash.

### Dependency manifest

`DeletionDependencyManifestV1` is immutable and contains target, Brain/scope, canonical watermark,
lineage-rule version, direct source IDs, descendant classes, store operations, legal-hold decisions,
provider artifacts, backup key generations, and expected verification queries/counts—never deleted
content. Its digest is stored in SQL/audit/deletion journal.

Closed dependency rules include:

- Brain -> every scoped project/repository/checkout/session/task/event/artifact/memory/assertion/code/
  vector/learning/evaluation/provider route/export plus Brain keys;
- project/repository/checkout -> scoped identities, source revisions/evidence, sessions/events and all
  descendants whose remaining independent authorized lineage count becomes zero;
- session/task/event/evidence/artifact -> memories/assertions/edges/chunks/vectors/briefings/recall
  traces/learning hypotheses/procedures/evaluations/exposures/applications/caches/jobs derived from it;
- memory/assertion/procedure -> every revision, projection, vector, context, feedback/deployment and
  dependent assertion/lesson allowed by lineage; and
- credential/provider profile -> resolved secret/cache/queued/provider artifact without deleting
  unrelated canonical content unless separately requested.

Shared CAS/evidence is reference-counted by authorized independent lineage within one Brain. Removing
one link does not delete content still required by another retained authorized source; the deleted
target can no longer reach it. Cross-Brain objects are never physically shared under one key.

### Purge saga and receipts

State is `Requested -> Tombstoned -> Purging -> Verifying -> Completed`; a hold produces `Held`, and
failure `PartialFailure -> Purging`. Each store implements one idempotent `DeletionPort` and emits a
signed/HMAC non-content receipt with deletion ID, store/type, operation version, target HMAC, attempt,
watermark, outcome, remaining reason, provider request ID hash, and time.

Required ports cover canonical SQL rows/events when policy permits destruction, CAS envelopes/keys,
Neo4j nodes/edges/full-text/vectors, in-process caches, outbox/jobs/DLQ, local provider caches, learning/
evaluation cases and contexts, generated exports, telemetry containing target pseudonyms, and tracked
remote provider artifacts. Purge order removes active search/queue references first, then projections/
objects, then keys where cryptographic erasure is selected. Original immutable event/history is removed
when deletion scope requires it; preserving audit does not preserve content.

Completion requires targeted absence queries, lineage/refcount verification, cache epoch, provider
receipt status, and sample scans. Primary-store targets are p95 24 hours, maximum 72 hours. A supported
provider deletion is requested immediately and verified by its published maximum. Unsupported or
unverifiable provider deletion remains visible `PartialFailure`; local denial and future-request
suppression still hold. No success message claims remote erasure without evidence.

### Legal hold

Hold blocks destructive purge and transitions `Held`, but access revocation/tombstone exclusion still
applies where authorized. Release of hold reauthorizes the original exact deletion and resumes; it does
not require content recallability. Hold facts contain no content and are audited.

### Non-resurrection ledger and restore guard

The append-only deletion journal stores tombstones/receipts/checkpoints without content, HMAC/hash
chained and signed with audit checkpoints. Tombstones remain for installation lifetime and in every
backup until full installation cryptographic purge; retention cannot expire while any recovery point,
export, queued replay, or provider artifact could reintroduce the target.

Every projector/rebuilder/importer checks a local tombstone index plus authoritative SQL lookup before
writing. False positives in an acceleration filter perform the lookup; false negatives are forbidden.

Restore creates isolated volumes, verifies archive deletion head, and applies the newest trusted local
deletion/access-revocation journal before opening any query. A recovery point older than a later
deletion cannot activate without a signed head at least as new as the installation's declared head.
Missing, forked, stale, or unverifiable proof fails closed for affected scopes. Provider egress remains
disabled, so restore cannot recreate remote artifacts.

### Backup deletion

Backups retain encrypted deleted bytes only until backup expiry unless policy requires faster removal.
If faster deletion applies, per-backup/Brain key granularity performs cryptographic erasure within 24
hours and updates signed backup inventory. An archive with an erased key remains non-decryptable and is
not represented as physically overwritten removable media. Retention defaults follow ADR-015.

## Security and privacy impact

Immediate deny protects the user before asynchronous purge. HMAC target IDs and non-content receipts
preserve non-resurrection/audit without retaining deleted payload. Manifest queries are authorization-
scoped; deletion errors do not disclose other scopes. A provider that retained content outside its
contract is residual third-party risk and is reported rather than hidden.

## Compatibility, migration, and rollback

Every new store/projection/provider capability must add dependency rules, port, receipt schema,
absence verifier, restore guard, and tests before release. Rule upgrades run old and new closure in
shadow and union them; deletion safety never narrows on downgrade. Tombstones/heads are forward
compatible through the archive window. There is no rollback after tombstone; operational retry resumes
idempotently.

## Rejected alternatives

- Soft-delete flag only: leaves vectors/caches/jobs/backups/provider descendants active.
- Purge first, deny later: allows recall during a long saga.
- Delete by content hash alone: can destroy independently retained sources or resurrect lineage.
- Dropping tombstones after primary purge: replay/restore can recreate data.
- Claiming provider deletion success when unsupported: misleading privacy guarantee.
- Restoring in place then deleting: briefly exposes erased content and risks active state.

## Consequences

Every data adapter must implement deletion and lineage, and non-content tombstones live a long time.
Shared-evidence handling is more complex, but deletion becomes measurable and restore-safe.

## Verification

- Target/store matrix for Brain, project, repository, checkout, session, task, event, memory,
  assertion, evidence, procedure, provider, and user-visible export.
- Concurrent recall/search/job/replay/index/provider send at tombstone commit proves immediate denial.
- Nested/shared-lineage/refcount, legal hold/release, idempotent retry, partial provider, and receipt
  tamper tests.
- Restore/rebuild/replay/import from pre-deletion data cannot recreate content; missing/forked journal
  head blocks activation.
- Backup expiry/cryptographic-erasure and key-unavailability tests.
- Maximum 72-hour purge/SLO monitors and secret/content-free ledger scans.
