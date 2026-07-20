# ID-003 repository topology runbook

## Purpose

Use this runbook when AgentMemory discovers, confirms, corrects, or diagnoses a relationship between
Projects and Repositories. Never repair topology by editing SQLite, Neo4j, `.gitmodules`, Repository
IDs, domain events, or history rows behind the application commands.

## Preconditions

1. Core readiness reports relational migration head `0005_id003_repository_topology`.
2. The local session bridge is authenticated and the actor has an active owner grant for the Brain.
3. Every Repository that will be confirmed has already received a stable UUIDv7 identity in the same
   Brain. `unresolved_repositories > 0` means discovery is incomplete and must not be guessed.
4. Explicit `.agentmemory/project.json` and `.agentmemory/repository-id` files are regular files owned
   by the workspace trust boundary, not symlinks.

## Discover

The host bridge runs the bounded topology adapter against the workspace and sends only its keyed
candidate observations to:

```http
POST /v1/repositories:discover-topology
Authorization: Bearer <launcher-capability>
Content-Type: application/json

{
  "operation_id": "discover-topology-2026-07-20-001",
  "brain_id": "<uuid-v7>",
  "actor_id": "<uuid-v7>",
  "grant_id": "<uuid-v7>",
  "observations": [
    {
      "subject_type": "repository",
      "subject_id": "<uuid-v7>",
      "relation_type": "submodule_of",
      "target_type": "repository",
      "target_id": "<uuid-v7>",
      "component_root_fingerprint": null,
      "evidence": [
        {
          "digest": "<lowercase-64-hex-keyed-digest>",
          "kind": "gitlink",
          "strength": "deterministic_vcs"
        }
      ]
    }
  ]
}
```

Discovery is read-only. An empty candidate list is valid and must not be replaced with a content/name
heuristic. Treat a conflict as stale or cross-Brain identities; treat a validation failure as malformed
or noncanonical bridge evidence.

## Review evidence

- `contains_repository`: verify the parent and child are distinct Repository IDs. A nested `.git`
  marker supports containment but does not prove a submodule.
- `submodule_of`: require both a contained `.gitmodules` declaration and matching index mode `160000`.
- `fork_of`: deterministic direction requires explicit upstream evidence. Shared Git roots without
  direction remains a candidate and needs user confirmation. Similar remotes or file trees alone are
  insufficient.
- `project_uses_repository`: verify the manifest Project/Repository IDs and intended component scope.
  Raw component roots are reviewed locally; Core retains only their keyed canonical set fingerprint.
- non-Git: require an explicit manifest. Never accept directory-name or content similarity as portable
  identity evidence.

## Confirm

Send one reviewed candidate unchanged with a unique operation ID:

```http
POST /v1/repository-links:confirm
Authorization: Bearer <launcher-capability>
Idempotency-Key: confirm-topology-2026-07-20-001
Content-Type: application/json

{
  "operation_id": "confirm-topology-2026-07-20-001",
  "brain_id": "<uuid-v7>",
  "actor_id": "<uuid-v7>",
  "grant_id": "<uuid-v7>",
  "candidate": { "...": "the complete discovery candidate" },
  "confirmation_source": "deterministic_vcs",
  "link_id": null,
  "expected_version": null,
  "correction_reason": null
}
```

Use `deterministic_vcs` only when candidate evidence has that exact strength, and
`deterministic_manifest` only for exact manifest evidence. Use `user` when a person has reviewed an
otherwise inferred link. Repeating the exact operation returns the original aggregate. Reusing its
operation ID with any changed field returns conflict.

## Correct

Corrections retain the existing `link_id`, Brain, subject, and target. Send the desired corrected
candidate plus current aggregate version and a lowercase closed-format reason:

```json
{
  "operation_id": "correct-topology-2026-07-20-001",
  "link_id": "<existing-link-uuid-v7>",
  "expected_version": 1,
  "correction_reason": "user_verified_submodule",
  "confirmation_source": "user"
}
```

A stale version, changed endpoint, duplicate effective link, missing reason, reversed effective time,
or revoked grant fails without a partial write. Fetch current authorized state, review intervening
history, and issue a new operation rather than retrying stale evidence under a new version guess.

## Diagnose

For a missing nested/submodule candidate:

1. Confirm discovery did not hit its repository, manifest, directory, depth, output, or file-size bound.
2. Confirm no symlink or path escape is involved.
3. Confirm every endpoint has a stable Repository ID in the Brain.
4. For submodules, check `.gitmodules` and the parent index independently; do not edit either merely to
   satisfy AgentMemory.

For an unexpected fork candidate, compare only credential-free root-set and upstream evidence locally.
Do not place remote credentials, raw paths, file content, SQL, event payloads, or keyed digests in an
external ticket. A resemblance-only candidate can be left unconfirmed without affecting identity.

For persistence failures, preserve the correlation/operation ID, link ID, aggregate version, event ID,
closed error code, migration head, and local audit chain. Append-only-trigger failures or aggregate
history mismatches are integrity incidents; do not disable triggers or mutate rows.

## Rollback and migration

Before any canonical link exists, migration `0005_id003_repository_topology` can downgrade to ID-002.
After confirmation, downgrade is deliberately refused. Correct the aggregate through the command or
restore a full signed backup; never drop the topology tables or delete domain events to force rollback.
