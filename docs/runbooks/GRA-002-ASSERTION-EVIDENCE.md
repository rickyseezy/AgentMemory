# GRA-002 assertion-evidence runbook

## Purpose

Use this runbook when a claim remains Candidate, activation fails, evidence cannot be resolved, a
revocation does not produce the expected dispute, an exact retry conflicts, or assertion integrity
fails. Do not edit assertion or evidence tables, domain events, canonical agent events, artifacts,
grants, or tombstones to force a result.

## Healthy state

- Core is Ready at relational head `0021_gra002_evidence_assertions` or later.
- The Brain, owner principal, grant, project, repository, and optional Checkout are active.
- Every evidence handle resolves to a captured event or its event-bound CAS artifact/span.
- Every active assertion has at least one usable activation snapshot and matching
  `AssertionActivated` event.
- Every fully unsupported assertion is `disputed` with a matching `AssertionDisputed` event.
- All six GRA-002 tables and assertion domain events reject update/delete attempts.

## Candidate does not activate

1. Preserve the assertion ID, operation ID, revision ID, scope fingerprint, evidence IDs, extractor
   identity, confidence components, and content-free error code. Do not log source content.
2. Confirm the predicate is in the closed registry and subject differs from object.
3. Confirm the candidate evidence set exactly matches the resolved set.
4. Confirm every source was registered from a canonical captured event, is in the same exact scope,
   was observed before activation, and has no revocation or deletion tombstone.
5. For a user-authorized claim, confirm the source event is `agentmemory.prompt.received.v1` and its
   principal is the current authorized owner.
6. For automated activation, confirm all confidence components are at least 7,000 and the evidence
   spans at least two independent source IDs.
7. Retry the exact command with the same operation/event/time only after correcting a dependency. Use
   a new operation ID for an intentionally changed request.

A Candidate is the safe expected result when any of these checks is not proven.

## Evidence registration failure

- `source was not found or authorized` means the captured event is absent, outside current scope,
  above classification, after the registration time, owned by another principal for a user statement,
  or hidden by a revoked grant.
- An artifact failure means the event does not name that exact artifact in `payload_ref` or its Brain
  differs.
- A span failure means the range is empty, negative, or beyond immutable artifact length.
- An integrity failure means stored source metadata no longer matches the canonical event/artifact
  digest. Stop assertion activation and investigate canonical storage; do not recompute the stored
  handle in place.

URLs and free-form strings are never evidence. Capture the source through the normal agent-event and
CAS workflow first, then register its typed UUIDv7 reference.

## Revocation and dispute diagnosis

Evidence revocation and all newly required disputes commit together. After a successful revocation:

1. confirm one immutable `assertion_evidence_revocations` row exists;
2. list only dependent assertion IDs from `assertion_evidence_snapshots`;
3. resolve the complete evidence set for each assertion at the revocation time;
4. expect assertions with another usable source to remain active; and
5. expect assertions with no usable source to have lifecycle version 2 and one
   `AssertionDisputed` event.

If the transaction fails, neither the revocation nor any dispute may be present. Retry the exact
revocation operation. If a deletion tombstone or later authorization change removed support, run the
governed `ReconcileAssertionEvidenceCommand`; do not insert a dispute row manually.

## Conflict handling

An exact retry is identical only when operation ID, principal, Brain, scope fingerprint, assertion and
revision IDs, lifecycle event ID/digest, status, version, and time all match. `GraphConflictError`
means an operation ID or stable assertion identity was reused for divergent content. Preserve both
content fingerprints and content-free operation metadata, stop projection of that assertion, and
issue a new identity only for a genuinely new claim. Never overwrite the first receipt.

## Integrity or authorization incident

Immediately stop assertion activation for:

- an active assertion with no usable evidence;
- a cross-Brain/scoped assertion or evidence result;
- a forged candidate, revision, source, or event digest;
- a user statement attributed to a non-owner event principal;
- a mutable or out-of-range source span;
- a missing activation/dispute event; or
- any successful update/delete against protected history.

Take a protected local backup. Preserve UUIDs, digests, schema head, policy versions, and content-free
logs. Check current grants, tombstones, source envelope/artifact binding, operation receipts, lifecycle
versions, and domain events. Repair forward through the owning capture, identity, deletion, or replay
workflow. Never export prompts, artifact bytes, paths, credentials, hidden reasoning, or source text in
incident logs.

## Rollback

Forward repair is the default. Database downgrade to `0020_mem006_session_briefing` is allowed only
before any GRA-002 evidence source, operation, or revocation exists. Once evidence exists, the migration
refuses downgrade because removal would destroy authority, idempotency, and audit history.

For application rollback, stop Core and workers, retain schema 0021 and a verified protected backup,
then select only a signed release declared compatible with that schema. If no compatible release
exists, restore the complete prior protected database and application release together according to a
reviewed disaster-recovery plan. Never drop triggers or tables to force rollback.
