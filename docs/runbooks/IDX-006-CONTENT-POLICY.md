# IDX-006 content-policy operations runbook

## Normal operation

The secure default policy excludes symlinks, content over 2 MiB, repository policy files,
generated/vendor paths, binary data, encrypted files, and private blocks. Repository
`.agentmemoryignore` and `.gitignore` files are detected during source preparation. Operators do not
need to submit them through the API.

Activate a complete next revision with
`POST /v1/indexing/content-policies/revisions`. Use owner/admin authority for exactly one current
Project and Repository. Send `Idempotency-Key: <operation_id>` and the same `operation_id` in the
body. Include the immutable policy ID, exact next version, ordered Brain rules, maximum byte size,
all private delimiter pairs, and the three classification switches. Store the returned `change_id`;
the response reports deletion/reindex work counts without returning paths or rule contents.

Read the content-free activation result with
`GET /v1/indexing/content-policies/changes/{change_id}` and current repository scope. An exact POST
retry is safe. Reusing an operation ID with a different revision is a conflict and must not be
worked around by editing database rows.

## Rule behavior

- `pattern` excludes a match; `!pattern` in an ignore file cancels that file's exclusion and falls
  through to lower policy layers.
- A slash anchors the pattern structure to repository-relative paths; a leading slash anchors it at
  repository root.
- A trailing slash covers a directory and descendants.
- `*`, `**`, `?`, and character classes follow the supported Git-style matcher.
- Escape a leading `#` or `!` in an ignore file as `\#` or `\!`; escape a retained trailing space
  as `\ `.
- Brain rules are explicit ordered include/exclude rules. A Brain include may override private,
  ignore, binary, encrypted, and generated classification, but never permits symlink traversal or
  an oversized read.

Use the narrowest Brain include possible. Never add a broad include merely to make an indexing
count rise; it changes the local privacy boundary.

## Tightening and loosening policy

A policy activation is immediately authoritative for new reads. Existing derivatives are removed
asynchronously through bounded reconciliation work.

For tightening:

1. record the returned `change_id`, delete count, and reindex count;
2. allow the local reconciliation worker to drain;
3. verify no old code result or assertion resolves from invalidated evidence; and
4. investigate any work item whose lease repeatedly expires.

For loosening, eligible paths receive reindex requests. Source discovery must observe the request
under the new policy digest before content becomes visible. Do not manually copy content into code,
graph, memory, or vector tables.

## Diagnosing missing or unexpected content

1. Confirm the repository identity and active policy version.
2. Inspect the latest path decision's layer, reason, rule ID/version, source hash, and policy digest.
3. If the path decision includes content, inspect the final content decision for binary, encrypted,
   or private classification.
4. Confirm `.agentmemoryignore` and `.gitignore` hashes changed when their files changed.
5. Confirm the source-session policy digest caused a full scan.
6. For a loosened path, confirm an `index_policy_reindex_requests` receipt exists and the source
   subsequently recorded a final content-include decision.
7. For a tightened path, confirm an `index_policy_derivative_invalidations` receipt exists and its
   semantic/dependent/assertion evidence closure is non-stale.
8. If a claimed item is abandoned, wait for its five-minute lease to expire; the worker will append
   a new claim snapshot. Never update the lease row.

## Privacy or egress incident

If excluded bytes appear in a parser call, persistence payload, embedding/provider request, graph
write, log, or response:

1. stop local indexing/provider workers without copying the bytes into a ticket or command line;
2. preserve content-free operation, decision, policy, and audit IDs;
3. rotate any exposed credential through its owning system;
4. tighten policy with a new version and retain its `change_id`;
5. run the governed deletion/privacy workflow for affected local data and backups;
6. repair the earliest policy/source boundary and add a pre-open plus egress-spy regression test;
7. verify derivative invalidation and restore-resurrection guards before resuming; and
8. treat a missing decision before content access as a release-blocking control failure.

Do not query raw source or private fragments into diagnostic logs. Policy evidence is intentionally
content-free and is sufficient for correlation.

## Integrity, backup, and migration

All IDX-006 tables are append-only. Do not update or delete policy revisions, rule sources,
decisions, changes, reconciliation snapshots, or projection receipts. Back up the local Core before
schema maintenance and use the signed migration path. Downgrade below
`0031_idx006_content_policy` is supported only before any IDX-006 evidence exists; retained policy
or reconciliation history deliberately blocks destructive downgrade.
