# ID-001 workspace identity runbook

## Purpose and safety boundary

Use this runbook when `POST /v1/projects:resolve` returns `not_found`, `ambiguous`, `AM_CONFLICT`, or
`AM_DEPENDENCY_UNAVAILABLE`. Resolution is read-only. Do not edit SQLite rows, replace keyed
fingerprints, copy a manifest between repositories, expose a raw remote/path in diagnostics, or merge
candidate IDs manually.

## Expected outcomes

- `resolved`: one authorized candidate was found at the reported precedence tier.
- `ambiguous`: at least two distinct authorized candidates exist at the first non-empty tier. No
  selection or merge occurred.
- `not_found`: no existing manifest, checkout, repository fingerprint, or approved heuristic mapping
  exists. A later create/observe story must establish identity.
- `AM_FORBIDDEN`: the principal/grant/Brain binding is absent, expired, revoked, or inactive.
- `AM_CONFLICT`: a known manifest Project is incompatible with observed Repository evidence.
- `AM_DEPENDENCY_UNAVAILABLE`: SQLite or the local observation dependency was unavailable.

## Triage

1. Record only the operation/correlation ID, status, source, explanation codes, and candidate UUIDs.
   Never record the raw directory, remote, machine identifier, API credential, or fingerprint.
2. Verify authenticated Core readiness and the active release pointer before retrying.
3. For `AM_FORBIDDEN`, inspect the local grant lifecycle through an authorized owner surface. A retry
   is valid only after the owner intentionally restores a grant.
4. For `AM_CONFLICT`, verify that `.agentmemory/project.json` belongs to this workspace and that its
   declared Project/Repository UUIDs were not copied. Preserve both identities; use the future
   confirmation/correction command rather than changing database state.
5. For `ambiguous`, present every returned candidate with authorized user-facing aliases and require
   explicit owner confirmation. Do not rank by directory name, content similarity, or remote text.
6. For `not_found`, leave the result separate. The create/checkout-observation workflow may create a
   new local identity; this query must not do so.
7. For dependency failure, verify the SQLite migration head is
   `0003_id001_workspace_identity`, integrity/readiness gates are green, and disk policy is not in a
   fail-closed state. Retry the same query after recovery.

## Privacy verification

Inspect only structured product logs. A resolution record or response containing a raw path, remote,
machine ID, credential, query string, or Git command output is a security incident: stop governed
mutation, retain content-free correlation evidence, and follow the security incident procedure.

## Rollback

Code rollback may select the previous signed release only when its relational reader supports the
current schema. Do not downgrade the identity tables while canonical identity mappings exist.
Fingerprint changes use a shadow alias version and comparison corpus; canonical Project, Repository,
Checkout, and Device UUIDs remain unchanged. A failed new algorithm is deactivated by versioned alias
policy, never by deleting entity history.
