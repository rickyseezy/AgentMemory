# MEM-001 memory consolidation runbook

## Normal operation

1. Verify Core readiness reports relational migration
   `0015_mem001_memory_consolidation` and the pinned local extraction provider is healthy.
2. Confirm the single historical row is `completed`:

   ```sql
   SELECT state, scanned, indexed, ignored, total, last_error_code
   FROM memory_task_lineage_backfills
   WHERE operation_id = 'mem001-task-lineage-v1';
   ```

   `scanned` must equal `indexed + ignored` and `total`. `ignored` means a valid canonical event had
   no task ID; it is not an extraction failure.
3. Monitor durable work by state and closed error code. Never include memory content in operational
   logs or support bundles:

   ```sql
   SELECT state, last_error_code, COUNT(*)
   FROM memory_consolidation_work
   GROUP BY state, last_error_code;
   ```

4. Treat a completed consolidation receipt as immutable. A later extractor/model revision or newly
   arrived task evidence creates a different key and work record.

## Interrupted historical backfill

- `dependency_unavailable` means SQLite/key access/decryption was temporarily unavailable. Restore
  the exact dependency and restart Core; the same operation resumes after the committed cursor.
- `integrity_violation` means source digest, canonical identity, existing lineage, or progress state
  diverged. Stop automatic remediation, preserve SQLite and key material, run SQLite integrity and
  foreign-key checks, and compare the encrypted envelope/source lineage with a trusted backup.
- `interrupted` records process shutdown after committed progress. Restart normally.
- Never delete the progress row, advance the cursor, fabricate lineage, copy plaintext into SQLite,
  or enable consolidation before the run reaches `completed`.

The watermark is immutable. A newly captured event can appear in `event_task_lineage` even when it is
outside the historical `total`; that is expected write-through behavior.

## Work failures

| Error code | Meaning | Action |
|---|---|---|
| `dependency_unavailable` | Local extractor, SQLite, or key dependency unavailable | Restore the dependency; bounded automatic retry retains the same snapshot. |
| `internal_error` | Unexpected bounded worker/provider fault | Inspect privacy-safe diagnostics; automatic retry stops after its smaller ceiling. |
| `authorization_denied` | Actor/grant/Brain is no longer write-authorized | Correct canonical grants only if policy requires it; the failed work stays terminal. |
| `invalid_input` | Terminal snapshot is absent, too large, or schema-invalid | Preserve evidence and investigate capture/schema compatibility; never truncate silently. |
| `integrity_violation` | Identity, digest, receipt, lease, or persistence evidence diverged | Quarantine the release/data copy and perform integrity recovery from trusted evidence. |

`dead_lettered` is evidence, not a command queue for manual SQL replay. After a reviewed root-cause
fix, a new release/extractor fingerprint or new evidence watermark creates governed work. Do not
reset attempts, leases, state, or result digests directly.

## Local extractor response

1. Verify the exact extractor image/model revision in the active release manifest and BOM.
2. Verify the protected extraction capability file remains owner-only and is mounted only into Core
   and the local extractor.
3. Verify no proxy or redirect is involved and Core reaches only `local-extractor:8080` on
   `am_internal`.
4. A malformed, oversized, duplicate-key, identity-drifted, or digest-drifted response is an
   integrity failure. Do not weaken schema validation to accept it.
5. Extraction evidence is local-only. Never send task evidence to a remote embedding/provider
   profile; MEM-001 extraction is always local.

## Policy or model change

Changing any threshold, explicit-evidence rule, candidate schema, extractor implementation, prompt,
model, tokenizer/template, or model revision requires:

1. a new immutable policy/extractor/model coordinate;
2. updated golden, adversarial, privacy, and migration tests;
3. the full 80% line/branch/changed-code/mutation gates;
4. provider conformance and offline packet-soak qualification; and
5. a signed release/BOM update.

Never silently reuse an extractor fingerprint after behavior changes.

## Backup and rollback

Back up SQLite, installation/Brain keys, and the active release together. Raw encrypted AgentEvents
are the reconstruction authority; memory tables alone are not a sufficient backup. Downgrade across
`0015` refuses while MEM-001 evidence exists. Restore the coherent pre-upgrade backup or deploy a
forward repair that preserves receipts, audit chain, and canonical envelopes.
