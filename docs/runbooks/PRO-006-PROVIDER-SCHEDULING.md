# PRO-006 provider-scheduling runbook

## Purpose

Use this runbook to enqueue, observe, cancel, or diagnose provider work. Scheduling chooses when and
how already-routed work executes. It does not create profiles, choose a route, weaken egress policy,
or make non-equivalent providers interchangeable.

## Preconditions

- Core is Ready at relational head `0039_pro006_provider_scheduling` or a later certified head.
- The exact provider profile revision is active and its capability evidence is current.
- The exact embedding space and fingerprint are active for vector-producing work.
- Routing has already produced the approved profile, purpose, classification, and workload.
- The protected local payload exists under a `cas://`, `artifact://`, or `local-object://` reference.
- The caller has the exact schedule action and current Brain/project/repository scope.
- `Idempotency-Key` exactly equals `operation_id` for enqueue and cancel.

## Enqueue work

Send content-free work metadata to `POST /v1/providers/work-items`. Include the complete batch key,
stable caller ordinal, protected payload reference, content digest, item token and byte counts,
estimated cost in integer micros, and an absolute deadline in epoch microseconds.

The response is `202 Accepted` with only item identity, operation identity, state, attempts, workload,
deadline class, and timing. Persist the returned `item_id`. Never send raw prompt, document, code,
credential, vector, or provider response through this API.

A replay with the same operation and identical request returns the original item. A divergent replay
returns `409 conflict`; do not generate a new key to hide an uncertain enqueue.

## Observe progress

Read `GET /v1/providers/work-items/{item_id}` with the exact Brain/project/repository scope. The
states are:

| State | Meaning |
|---|---|
| `queued` | Eligible when due, within deadline, and admitted by quota and budget |
| `leased` | Reserved atomically by one scheduler worker |
| `retry_scheduled` | Only a retryable child is waiting until its safe retry time |
| `completed` | Provider child result succeeded |
| `cancelled` | Cancellation closed the item |
| `failed` | A permanent result or exhausted deadline closed the item |

A `404` does not reveal whether an item exists in another Brain.

## Cancel work

Send `POST /v1/providers/work-items/{item_id}:cancel` with a new cancellation operation ID and exact
idempotency key. Queued and retry-scheduled work closes immediately. Leased work records a
cancellation request; the mandatory final authorization check then prevents materialization or
gateway dispatch. Cancellation is idempotent but does not rewrite completed or permanently failed
history.

## Diagnose a queue that is not dispatching

1. Confirm the item is due and its deadline has not passed.
2. Confirm cancellation is not requested.
3. Verify the exact profile revision and embedding-space fingerprint remain active.
4. Verify the principal grant, authorization-policy version, security epoch, and scope fingerprint
   still match.
5. Check the profile's persisted `blocked_until` provider hint.
6. Check request-bucket and token-bucket balances.
7. Check `in_flight` against maximum concurrency.
8. Check monthly cost spent plus this batch's estimate against the configured budget.
9. Confirm the workload appears in the persisted weighted-fair cursor cycle.
10. Check for an expired lease and run the normal lease-recovery path; never edit lease columns.

## Diagnose a partial provider response

Each child must appear exactly once, in original batch order, under the same batch operation ID.
Successful results require a result digest and protected result reference. Failed results require a
safe error code; only `retryable_failure` may return to the queue.

If a response is missing, duplicated, reordered, or contains a foreign item, the worker releases the
lease as `malformed_provider_response`. Preserve the provider response in approved diagnostic
storage without content in logs, correct the adapter, and replay through the scheduler. Never insert
fabricated child results.

## Interpret API failures

| HTTP/status | Meaning | Action |
|---|---|---|
| `403 forbidden` | Authentication, role, scope, current authority, or final egress policy denied work | Correct authority or use an allowed route; never bypass the final check |
| `404 not_found` | No item is visible in the resolved Brain scope | Verify the item and scope without probing another Brain |
| `409 conflict` | Idempotency, immutable history, state transition, or lease ownership differs | Reload canonical state and preserve the conflict evidence |
| `422 validation_failed` | Batch coordinates, counts, digest, reference, deadline, or response shape is invalid | Correct the producer or adapter; do not coerce invalid data |
| `503 dependency_unavailable` | Canonical SQLite, payload storage, or provider gateway is unavailable | Restore the pinned local dependency and let retry policy reschedule safely |

## Incident escalation

Escalate immediately if one batch contains mixed Brain/classification/profile/space/purpose/
retention/preprocessing/deadline coordinates; interactive and background work mix; any exact limit
is exceeded; fairness starvation exceeds one closed cycle; payload materializes before final
authorization; cancellation still reaches the gateway; a nonretryable child retries; a child result
changes after commit; sensitive content appears in API, audit, or log output; or migration,
foreign-key, lease, or immutable-history verification fails.
