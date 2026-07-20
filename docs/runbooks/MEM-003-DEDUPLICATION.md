# MEM-003 deduplication and merge-lineage runbook

## Normal operation

The durable memory-consolidation worker invokes deduplication automatically for each promoted memory.
Operators should not run ad-hoc SQL or use vector similarity as a merge decision. Exact fingerprint
candidates run first. The local embedding provider is contacted only after an exact miss, and the
deterministic compatibility policy must still approve every non-semantic coordinate.

Expected successful mutation artifacts share the operation/result identity:

- one `memory_deduplication_operations` canonical receipt;
- one `memory_redirects` row per merged source;
- source-specific `memory_merge_evidence` rows;
- one `MemoryMerged` domain event and graph projection source;
- one `memory.merged.v1` outbox message; and
- one `memory.deduplicated` hash-chained audit event.

A no-op scan has only the receipt and audit record. This is normal and prevents a retry from changing
meaning if new candidates appear later.

## Diagnose a merge

Inspect content-free lineage first:

```sql
SELECT d.operation_id,d.requested_memory_id,d.survivor_memory_id,d.mode,
       d.policy_version,hex(d.result_sha256),r.source_memory_id,r.created_at
FROM memory_deduplication_operations d
LEFT JOIN memory_redirects r ON r.operation_id=d.operation_id
WHERE d.operation_id=:operation_id;
```

Then verify evidence preservation without modifying creation provenance:

```sql
SELECT survivor_memory_id,source_memory_id,event_id,
       hex(canonical_event_sha256),operation_id
FROM memory_merge_evidence
WHERE survivor_memory_id=:survivor_id
ORDER BY source_memory_id,event_id;
```

The source memory must remain present with `status='merged'`, a finite `recorded_to`, and a redirect.
The survivor must be `active`. Follow redirect chains recursively when a prior survivor is later
merged; never flatten them by deleting historical rows.

## False merge or contradiction

Do not update `memories`, `memory_redirects`, or evidence tables directly. Preserve the database,
operation receipt, domain event, provider identity/revision, and audit tail. A suspected false merge
is corrected through MEM-004's explicit correction/dispute workflow so history remains explainable.
Until MEM-004 is invoked, exclude the affected survivor from ordinary recall through an authorized
incident policy rather than deleting lineage.

## Failure handling

- Dependency or embedding failure: the consolidation work item remains retryable under its bounded
  lease policy; do not mark it succeeded manually.
- Integrity failure: quarantine the data copy and compare result, event, payload, evidence, and audit
  hashes with a coherent backup.
- Conflict: another writer changed a profile or committed the same operation. Exact replay is safe;
  a divergent operation requires fresh authorized planning.
- Missing target: it may already be a source redirected by an earlier item in the same batch. Verify
  `memory_redirects`; do not infer authorization from absence.

## Upgrade, backup, and rollback

Back up SQLite, encrypted AgentEvents/CAS, keys, graph-generation metadata, and release state as one
coherent set. Migration `0017` permits `merged` history and adds append-only merge tables. Downgrade
is refused while any deduplication receipt, redirect, merge evidence, merged status, or aggregate
version above one exists. Restore a coherent pre-upgrade backup or deploy a forward repair; never
drop lineage to force downgrade.
