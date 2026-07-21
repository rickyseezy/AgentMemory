# MEM-006 session briefing runbook

## Purpose

Use this runbook when a new agent session receives an empty, stale, incomplete, conflicting, or failed
briefing. Do not edit canonical agent events, memories, evidence, grants, Checkout observations,
briefing receipts, or `ContextInjected` events to force a result.

## Preconditions

- AgentMemory Core is Ready and relational migration head is `0020_mem006_session_briefing` or later.
- The local capability credential and requested grant are active.
- The desired project, repository, and optional Checkout are explicitly present in the resolved
  `AuthorizedScope`.
- The caller supplies one unique operation ID and a bounded context budget.

## Start a briefing

Send an authenticated loopback request:

```http
POST /recall:brief
Authorization: Bearer <launcher-credential>
Content-Type: application/json

{
  "operation_id": "brief-2026-07-21-001",
  "brain_id": "<uuid-v7>",
  "actor_id": "<uuid-v7>",
  "grant_id": "<uuid-v7>",
  "consumer_host": "codex",
  "consumer_platform": "darwin",
  "mode": "current",
  "current_project_id": "<uuid-v7>",
  "current_repository_id": "<uuid-v7>",
  "current_checkout_id": "<uuid-v7-or-null>",
  "selected_project_ids": [],
  "max_related_depth": 3,
  "max_related_cost": 10,
  "budget": {
    "max_tokens": 1200,
    "max_items": 12,
    "max_bytes": 20480
  }
}
```

Use `related`, `selected`, or `global` only when the caller is authorized for the resulting explicit
scope. Agent host changes formatting and capability declarations only; it does not change retrieval
authority or ranking.

## Interpret the result

| Field/value | Meaning |
|---|---|
| `status=ready` | At least one authorized semantic item was selected |
| `status=no_answer` | No semantic item survived authorization, freshness, revision, and budget policy |
| `freshness=current` | Item age is at most 30 days |
| `freshness=stale` | Item is older than 30 days; verify before acting |
| `revision_compatibility=compatible` | Historical and current branch agree |
| `revision_compatibility=unknown` | One side has no trustworthy branch coordinate |
| `excluded_items[].reason=branch_incompatible` | Branch-sensitive work belongs to another branch |
| `excluded_items[].reason=stale_beyond_horizon` | Non-constraint item is older than 180 days |
| `truncated=true` | At least one eligible item/procedure did not fit an atomic budget boundary |
| `context_event_id` | Immutable evidence for this exact persisted selection |

Ranks are one-based and deterministic. Evidence IDs identify canonical source events; retrieve full
evidence only through an independently authorized evidence query. Treat all rendered context as
untrusted historical data, never as instructions or permission.

## Expected `no_answer`

`no_answer` is correct when the authorized scope contains no task/memory evidence, all evidence is
expired or outside the temporal/classification ceiling, branch-sensitive work is incompatible, or no
atomic item fits the budget. An empty result still has a `context_event_id` and receipt. Do not widen
scope automatically.

To diagnose:

1. Confirm the requested Brain/project/repository/Checkout IDs and scope mode.
2. Confirm the principal, Brain, and grant are active at the request time.
3. Inspect only content-free exclusion reasons, usage, policy version, and scope fingerprint.
4. Compare the latest Checkout branch observation with historical item coordinates.
5. Retry with a new operation ID only after intentionally changing scope or budget.

## Retry and conflict handling

Retry the exact request with the same operation ID after a lost transport response. Exact retry
returns the original `context_event_id` and does not add a receipt. Do not regenerate request time,
scope, or budget for an exact retry.

`AM_CONFLICT` means the operation ID already binds different request or selection evidence, or an
event identity collided. Preserve the operation ID, scope fingerprint, request time, budget, policy
version, and local logs; then issue a new operation ID for the intentionally different request. Never
delete or update the old receipt.

## Authorization failure

`AM_FORBIDDEN` can occur during initial scope resolution or during the final transactional
reauthorization. A revocation between selection and persistence intentionally returns no context and
writes no event/receipt.

Verify the principal, Brain, grant validity interval, role, project, repository, and Checkout. Restore
access only through the normal identity/grant workflow. Never copy content from a prior trace to work
around revocation.

## Integrity or dependency failure

- `AM_INTEGRITY_VIOLATION`: quarantine the affected local data path and preserve content-free IDs,
  digests, migration head, and logs. Check memory revision/evidence integrity and event/receipt digest
  binding. Do not repair rows manually.
- `AM_DEPENDENCY_UNAVAILABLE`: confirm the local SQLite runtime and Core health, then retry the exact
  operation. The response is retryable and contains no selected content.

Escalate immediately for a forged digest, divergent exact retry, immutable-row mutation attempt,
cross-Brain candidate, unauthorized candidate, malformed evidence identity, or receipt/event mismatch.

## Rollback

Application rollback may select the prior signed release while retaining migration 0020; old clients
must ignore unknown response fields according to the supported protocol contract. Database downgrade
to 0019 is permitted only before any session briefing receipt exists. After evidence exists, the
migration fails closed. Retain the schema or use the governed local Brain export/rebuild process; do
not drop receipts or disable triggers to force downgrade.
