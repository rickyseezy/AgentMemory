# IDX-003 source revision history operations runbook

## Normal operation

1. The transient indexing boundary classifies a source inspection as `committed` or `worktree`.
2. The incremental worker commits its source result and content-free projection event atomically.
3. For a committed run, the source-revision worker leases the event, revalidates current authority,
   pins the canonical commit graph, and appends context, invalidation, lineage, re-extraction job,
   and receipt in one transaction.
4. Query history by repository-relative path plus exactly one commit SHA or branch name and an
   explicit UTC `recorded_at`.
5. Use returned graph digest and answer IDs when auditing why a context is current, stale, deleted,
   or absent from the selected revision.

Do not send dirty worktree events through committed history. Worktree evidence represents mutable
current state and keeps immediate current-evidence revocation. Committed evidence is invalidated by
ancestry, not globally.

## Interpreting a history result

| Applicability | Meaning at the pinned target | Operator action |
|---|---|---|
| `current` | introducing commit is reachable and no invalidating commit is reachable | none |
| `stale` | introducing and at least one invalidating commit are reachable | inspect the listed invalidating commits |
| `deleted` | a reachable deletion marker exists | confirm retraction/re-extraction processing |
| absent | introducing commit is not an ancestor or the row is outside recorded time/authority | verify selector, time, retention, and grant |

An identical `content_digest` on two rows is not duplication if context IDs, commits, events, or
file revisions differ. `reintroduced_from_context_id` explicitly explains a revert or reappearance;
never merge those rows or extend the old validity interval.

## Diagnosing pending revision processing

1. Confirm the incremental run completed and has an
   `incremental_index_run_revision_contexts` row equal to `committed`.
2. Confirm `target_commit_id` is present and the event has no processing receipt.
3. Inspect the latest immutable claim. An unexpired lease means another worker owns it; an expired
   lease is reclaimable and does not require deleting the claim.
4. Verify the recorded principal still has the same current Brain/Project/Repository authority,
   role, and scope fingerprint. Revocation deliberately fails closed.
5. Verify the target and base commits exist in the canonical VCS DAG at the event's recorded time.
6. Check bounded failure logs by operation/event identity only; never log path or source content.

Do not mark a receipt complete manually. Fix the authority or canonical VCS input and let the worker
retry after lease expiry.

## Diagnosing unexpected branch results

- Confirm the branch ref observation selected at `recorded_at`; current branch state is irrelevant
  to a historical query.
- Confirm the returned graph digest is identical across every answer ID in one response.
- For `stale`, each returned invalidating commit must be an ancestor of the pinned target.
- For an unaffected divergent branch, the invalidating commit must not be reachable and the older
  context should remain current.
- After a merge, invalidation becomes reachable only if the merge contains the changed side.
- After a force-push, query the earlier recorded time to audit the old ref; do not expect the new
  history to overwrite it.
- A cherry-pick creates a distinct commit context. Patch or blob similarity is not ancestry.
- Multiple merge bases are valid; the adapter records all best bases, matching `git merge-base --all`.

## Evidence-lineage registration

Use one stable operation ID and send the same value as `Idempotency-Key`. Retrying the exact
context/evidence/assertion tuple returns its original registration digest. Reusing an operation ID
for different input returns conflict and must not be retried as if it succeeded.

Before registration, verify evidence and assertion belong to the same Brain, Project, and
Repository as the source context. Cross-scope lineage is an integrity or authorization failure, not
an operator-repairable mapping.

## Re-extraction jobs

Every non-deletion context schedules exactly one `extract` job. Every deletion context schedules
exactly one `retract` job. The job identity contains the revision context and action, so a byte-for-
byte reintroduction gets new work. Job rows are immutable queued authority for the later extraction
pipeline; do not update or delete them to unblock processing.

## Safe migration and rollback

Migration `0028_idx003_revision_history` may downgrade only while every IDX-003 table is empty.
Any run-context row, graph answer, source context, invalidation, lineage row, registration, job,
claim, or processing receipt blocks destructive downgrade.

For a populated installation:

1. stop the local Core through the normal launcher path;
2. preserve the signed SQLite backup and release metadata;
3. use the certified release rollback/restore procedure; and
4. restart only after migration-head and integrity readiness probes pass.

Never disable immutable triggers, delete history, alter commit answers, edit Alembic metadata, or
copy an older database over live state.

## Security and privacy rules

- Keep absolute host paths, repository source, diffs, branch input, credentials, and parser output
  out of logs and problem responses.
- Authenticate before resolving request scope or inspecting repository claims.
- Revalidate current grants at claim, completion, lineage registration, and history query time.
- Bound history results, commit-graph traversal depth, parent cardinality, identifiers, paths, and
  worker leases.
- Use only the canonical persisted commit graph in Core; never add a persistent source mount or
  invoke Git from the Core container.
- Treat graph digest or answer mismatch as integrity failure. Never silently recompute against a
  different watermark and attach it to an old receipt.
