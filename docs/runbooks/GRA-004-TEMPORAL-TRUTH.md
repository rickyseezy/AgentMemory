# GRA-004 temporal truth runbook

## Purpose

Use this runbook to record immutable Git revision observations and query what an assertion claimed at
a valid time, recorded time, branch, or commit. Never repair history by updating or deleting VCS,
anchor, impact, assertion lifecycle, domain-event, or audit rows.

## Preconditions

- Core is Ready at relational head `0025_gra006_graph_integrity`.
- The caller has a current grant for the selected Brain, Project, and Repository.
- Commit SHAs are lowercase full 40- or 64-character object IDs. Abbreviations are rejected.
- Nodes, refs, parents, and impacts are sorted canonically before submission.
- A scanner must report the complete direct-parent set for every submitted commit.

## Record an observation

The host-neutral scanner posts the observed commit graph and refs to the authenticated loopback API:

```http
POST /graph/revisions/observations
Authorization: Bearer <launcher-credential>
Content-Type: application/json

{
  "operation_id": "vcs-observation-0001",
  "brain_id": "<brain-uuid-v7>",
  "actor_id": "<principal-uuid-v7>",
  "grant_id": "<grant-uuid-v7>",
  "project_id": "<project-uuid-v7>",
  "repository_id": "<repository-uuid-v7>",
  "nodes": [
    {"commit_sha": "<root-sha>", "parent_shas": []},
    {"commit_sha": "<head-sha>", "parent_shas": ["<root-sha>"]}
  ],
  "refs": [
    {"branch_name": "main", "commit_sha": "<head-sha>", "observed_at": "<UTC>"}
  ],
  "impacts": [],
  "observed_at": "<UTC>",
  "source_digest": "<lowercase-sha256>"
}
```

Retain the returned `batch_digest`. Repeating the byte-equivalent semantic request is safe. Reusing
the operation ID with different content returns `AM_CONFLICT`. A new commit may name parents from a
prior batch, but every referenced parent must already be known at or before this batch's observation
time. Submit a ref-only batch when a branch moves to an already-known commit.

An evidence impact identifies the first commit whose change invalidates that exact evidence item:

```json
{
  "evidence_id": "<evidence-uuid-v7>",
  "invalidating_commit_sha": "<change-sha>",
  "changed_at": "<UTC>"
}
```

Do not mark unrelated evidence or an entire branch stale. The query engine derives affected
descendants from ancestry.

## Query truth

Current truth is explicit and unqualified:

```http
GET /graph/assertions/truth?operation_id=truth-1&brain_id=<id>&actor_id=<id>&grant_id=<id>&project_id=<id>&repository_id=<id>&mode=current
```

Historical truth requires at least one coordinate. Repeat `predicates` parameters to supply the
closed predicate allowlist.

```http
GET /graph/assertions/truth?operation_id=truth-2&brain_id=<id>&actor_id=<id>&grant_id=<id>&project_id=<id>&repository_id=<id>&mode=historical&as_of_valid=2026-07-20T12:00:00Z&as_of_recorded=2026-07-21T12:00:00Z&branch=main&predicates=consumes
```

Use either `branch` or `commit`, never both. A branch response includes `resolved_commit`,
`ref_observation_id`, `graph_digest`, and `force_pushed`. Preserve these fields when a result informs
an automated decision.

Interpret evidence applicability as follows:

| Value | Meaning |
|---|---|
| `unversioned` | The evidence is not code-revision scoped and remains globally applicable. |
| `reachable` | The captured commit is an ancestor and no applicable impact is reachable. |
| `unreachable` | The evidence belongs to another repository/history or is not an ancestor. |
| `stale` | One or more evidence-specific invalidating commits are ancestors of the target. |

An assertion is returned only when at least one authorized evidence item supports the selected
revision. `currency=historical` always means the result is a historical view, even when
`currently_authoritative=true` happens to be reported separately.

## Failure and recovery

- `AM_VALIDATION`: correct malformed IDs, UTC timestamps, ordering, bounds, or selector ambiguity.
- `AM_FORBIDDEN`: refresh the launcher credential/grant; do not bypass authorization in SQLite.
- `AM_CONFLICT`: preserve the batch and graph watermark, then compare operation ID, parent set,
  Repository, source digest, and observation time. Never overwrite the recorded batch.
- `AM_DEPENDENCY_UNAVAILABLE`: restore Core/SQLite and retry the exact operation.
- `AM_INTEGRITY_VIOLATION`: stop automated use, preserve local logs and digests, and run the governed
  integrity/rebuild path. Do not include code, prompts, credentials, or paths in an incident ticket.

A force-push is not itself corruption. Confirm that `resolved_commit` matches the intended ref and
review `force_pushed=true`; the engine already evaluates evidence against the new immutable ancestry.
