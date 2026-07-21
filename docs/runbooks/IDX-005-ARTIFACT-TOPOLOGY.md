# IDX-005 artifact topology operations runbook

## Normal operation

The local indexing pipeline submits one complete supported artifact revision to
`POST /v1/indexing/artifact-topology/extractions`. The request must reference canonical IDX-001
source/semantic IDs, an IDX-003 revision context, and immutable GRA-002 artifact or source-span
evidence. The `Idempotency-Key` must equal `operation_id`. A successful response contains only the
batch digest, parser identity, counts, and registration time.

Query `POST /v1/indexing/artifact-topology/queries` with an explicit authorized Project selection
and cutoff. Results are latest-per-source at that cutoff. Relations include their evidence and
valid interval; they are observations, not mutable deployment fields.

## Secret handling

Never send runtime `.env` files. Only example, sample, template, or schema files are supported.
Parsers retain normalized names such as `DATABASE_PASSWORD`, `USER_API_URL`, or
`KAFKA_SASL_USERNAME` and their sensitivity class. They discard values before constructing domain
objects. Unknown constructs retain a digest and line coordinates, not raw text.

If a response, database export, or graph fingerprint contains a raw environment value, stop the
local service, preserve logs without copying the value, and treat it as a privacy incident. Do not
repair rows in place. Correct the parser/domain boundary, rotate the affected credential, register
the corrected new source revision, and use the governed deletion/privacy workflow for contaminated
local backups.

## Diagnosing missing topology

1. Confirm the relative path is owned by exactly one production parser.
2. Confirm source bytes are valid UTF-8 and within the 8 MiB bound.
3. Check the extraction receipt's parser and candidate/relation/unknown counts.
4. For lock files, verify the declared supported generation rather than inferring from a manifest.
5. For Kubernetes templates or Kustomize overlays, inspect digest-only unknown evidence and provide
   a rendered canonical artifact as a separate authorized source when exact topology is required.
6. Confirm `index_semantic_dependencies` contains every candidate/relation/unknown fact.
7. Confirm `artifact_topology_projection_receipts` and the assertion lifecycle when a graph
   relation is missing.
8. Confirm IDX-003 lineage and the requested branch/commit/cutoff when a historical observation is
   unexpectedly current or stale.

Do not use a model to promote unresolved syntax manually. Optional enrichment must pass the future
governed provider, privacy, and evidence policies before it may supplement deterministic output.

## Changes, conflicts, and replay

Extraction is complete-output replacement for current reads. When an artifact no longer contains
topology, register an empty batch at its new revision; never delete the old batch. Multiple sources
that disagree remain separate temporal assertions with their evidence. Retrieval may qualify or
surface the conflict; storage must not overwrite one observation with another.

Retry the same operation ID only with identical scope and input. Reusing it with different content
is an intentional conflict. To correct data, submit a new operation for new canonical evidence.

## Integrity, backup, and migration

All IDX-005 tables are immutable. Do not update or delete rows with SQL. Back up the local Core
database before schema maintenance and use the signed migration path. Migration
`0030_idx005_artifact_topology` can downgrade only when every IDX-005 table is empty; any retained
batch, observation, or projection receipt blocks destructive downgrade by design.
