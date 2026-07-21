# IDX-004 API topology operations runbook

## Normal operation

The local indexing pipeline submits a complete supported source revision to
`POST /v1/indexing/api-topology/extractions`. The request must reference already-canonical source,
semantic, evidence, and revision-context IDs. Successful responses are content-free and identify
the immutable batch digest and candidate counts.

To answer which frontend or service consumes an API, submit the client-call candidate ID and an
explicit list of authorized Project IDs to `POST /v1/indexing/api-topology/links`. Read the results
in rank order:

- `confirmed` is a unique strongest non-dynamic match and may have an active `CONSUMES` assertion;
- `qualified` requires disambiguation; inspect `qualification_codes` and every returned evidence ID;
- an empty `matches` array means no governed rule connected the call to a current endpoint.

Never select projects the user did not request. Repository membership and grants are resolved from
durable identity state; request claims alone do not grant access.

## Diagnosing missing or ambiguous links

1. Confirm the source path is owned by exactly one production plugin.
2. Confirm the extraction receipt has the expected candidate count.
3. Verify the contract operation ID on client and server before using weaker rules.
4. For generated clients, verify the generated symbol is present in the retained contract binding.
5. For service routing, retain only configuration names such as `USER_API_URL` and declare gateway
   prefixes; never provide environment values.
6. If multiple results share the strongest rule, treat all as qualified and add canonical contract
   or ownership evidence rather than manually activating one.

Arbitrary strings containing call-like text are not source calls. If a parser fixture produces a
false positive, add the fixture to the adversarial matrix before changing the bounded lexical rule.

## Source changes and removals

Extraction is complete-output replacement. When a source no longer contains topology, register an
empty batch for its new revision context. Do not delete the previous batch. IDX-003 lineage and
semantic dependencies will stale affected assertions only where the changing revision applies.

If an expected assertion remains current, inspect:

- `index_semantic_dependencies` for the source semantic and evidence ID;
- `source_revision_evidence_lineage` for both client and server context edges;
- the selected branch/commit ancestry and pending revision/projection worker queues;
- the assertion's evidence status and current authorization.

## Integrity and recovery

All IDX-004 tables are immutable. Do not update or delete rows to repair a result. Re-run the same
operation for exact replay, or submit a new extraction/link operation against corrected canonical
evidence. An operation ID reused with different input is an intentional conflict.

Migration `0029_idx004_api_topology` may downgrade only when every IDX-004 table is empty. Retained
candidate or decision history blocks downgrade by design. Back up the local Core database before
schema maintenance and use the normal signed migration path.
