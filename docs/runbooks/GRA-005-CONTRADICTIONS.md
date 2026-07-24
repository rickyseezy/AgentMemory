# GRA-005 contradiction operations runbook

## Healthy state

- Core reports Ready at relational head `0040_pro007_provider_resilience` or a later certified head.
- Detection operations are append-only and exact retries return the same conflict IDs.
- Every conflict links two current canonical assertion IDs and all supporting evidence IDs.
- Unresolved conflicts cause retrieval to qualify or abstain; rank never hides them.
- Resolved conflicts retain the original dispute and one immutable resolution authority record.

## Detect contradictions

Call `POST /graph/contradictions/detect` with current Brain, actor, grant, Project, Repository,
operation ID, and UTC detection time. The detector loads content-free assertion metadata only after
current authorization. Preserve the returned conflict IDs and detection digests in diagnostic
records. Retry the exact operation ID and body after an interrupted response; do not invent a new
operation ID until the first result is known.

An empty result means no decisive conflict matched the current versioned rule table. It does not mean
model-generated suggestions were promoted, nor that every possible natural-language inconsistency
was disproved.

## Evaluate retrieval candidates

After fusion, call `POST /graph/contradictions/evaluate` with the bounded assertion IDs, basis-point
ranks, and canonical authority flags. Apply the returned decision before synthesis:

- `certain`: synthesize only `selected_assertion_ids`;
- `qualified`: state the limitation and include authorized dispute evidence where useful; or
- `unknown`: abstain from a factual answer and surface authorized conflicting candidates/evidence.

Never bypass `unknown` because one candidate has a higher vector, graph, rerank, or confidence score.

## Resolve a dispute

Call `POST /graph/contradictions/resolve` only after the user has made an explicit choice and current
editor-or-stronger grant authority has been resolved. Supply a closed outcome, governed reason code,
and at least one current unrevoked evidence ID in the same Repository. Exact replay is safe.

If resolution returns forbidden, re-resolve the current principal/grant and evidence authorization;
do not copy an earlier grant or evidence snapshot. If it returns conflict, inspect whether another
resolution already committed or whether the operation ID was reused with different content.

## Integrity and recovery

Do not update or delete contradiction, evidence, operation, or resolution rows. Database triggers
reject mutation. Preserve the canonical database, run SQLite integrity and foreign-key checks, and
restore through the normal signed backup/recovery workflow if corruption is detected. A downgrade is
refused after any contradiction operation exists because doing otherwise would erase truth history.

Operational logs and support bundles may contain IDs, digests, states, counts, and policy versions.
They must not include assertion source content, raw evidence payloads, credentials, SQL, filesystem
paths, or hidden model reasoning.
