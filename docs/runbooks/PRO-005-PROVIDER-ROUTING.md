# PRO-005 provider-routing runbook

## Purpose

Use this runbook to publish, restrict, resolve, or diagnose provider routes. A route chooses an
already active provider profile; it does not create, probe, schedule, retry, or migrate one.

## Preconditions

- Core is Ready at relational head `0039_pro006_provider_scheduling` or a later certified head.
- Every referenced profile is active and has current live capability evidence.
- The caller has a current Brain-wide owner/admin grant for publication, or an authorized
  owner/admin/editor/adapter/worker grant for resolution.
- Remote profiles have an explicit approved egress policy and residency declaration.
- `Idempotency-Key` exactly equals `operation_id`.

## Publish a policy

Send a complete replacement policy to `POST /v1/providers/routing/policies`. Supply the current
policy version (`0` for the first publication), the Brain guard, and canonically ordered unique draft
keys. Every draft identifies one profile, operation, optional selectors, enabled state, and stable
reason code.

Treat a `409` as a stale-version or divergent-idempotency conflict. Reload current authority and
review the difference; never edit a policy row or retry with broader privacy settings.

## Publish a repository restriction

Send a filter to `POST /v1/providers/routing/repository-restrictions`. The repository must be inside
the resolved scope. Empty profile, purpose, or workload lists mean no allowlist for that dimension;
nonempty lists filter the Brain policy. The request may reduce remote access, residency regions, and
classification ceiling but cannot increase them.

## Resolve a route

Send content-free coordinates to `POST /v1/providers/routes:resolve`: Brain, project, repository,
operation, corpus, normalized lowercase language, classification, purpose, and workload. The response
contains only policy/rule/profile identities and versions, precedence, reason, and request digest.
It contains no prompt, source content, credential, endpoint, provider response, or raw error.

## Interpret failures

| HTTP/status | Meaning | Action |
|---|---|---|
| `403 forbidden` | Scope, role, privacy, residency, repository filter, or egress policy denies the route | Correct authority or choose an allowed local route; never widen policy as an incident workaround |
| `409 conflict` | Expected version, idempotency receipt, or immutable history differs | Reload the current policy/restriction and preserve evidence |
| `422 validation_failed` | Input, ambiguity, profile capability, selector, ID, enum, or time is invalid | Correct the policy or activate a compatible exact profile |
| `503 dependency_unavailable` | Canonical SQLite is unavailable | Restore the pinned local resource and replay the identical operation |

## Diagnose a surprising decision

1. Verify the request digest and all content-free coordinates.
2. List matching enabled rules for the exact operation.
3. Compare `(project_specificity, constrained_dimensions)`; no other tiebreaker exists.
4. Verify the selected rule's exact profile version and snapshot digest.
5. Verify current active status, operation, purpose, execution class, and residency.
6. Apply the Brain egress/classification/residency guard.
7. Apply the repository filter.
8. Verify grant version, authorization-policy version, security epoch, restriction version, and all
   referenced profile versions in the cache identity.
9. Confirm the decision journal, policy/restriction operation receipt, outbox event, and audit chain.

Do not delete cache or database history to force another result. A changed version naturally creates
a cache miss.

## Incident escalation

Escalate immediately if equal-precedence overlapping rules were persisted, a repository restriction
broadens its Brain guard, a route uses a stale or incompatible profile, `local_only` content selects a
remote profile, a denied rule falls through to a broader route, an exact idempotent replay changes,
or immutable/audit/migration verification fails.
