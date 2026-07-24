# PRO-007 provider-resilience runbook

## Purpose

Use this runbook to publish safe endpoint equivalence, interpret provider retries and circuits, and
recover provider-backed indexing or recall without mixing semantic spaces or causing duplicate
provider charges.

## Preconditions

- Core is Ready at relational head `0040_pro007_provider_resilience` or a later certified head.
- The primary and every fallback profile are active in the same Brain.
- Every exact profile revision has current live capability evidence.
- Every endpoint has the same immutable output contract and points to the same embedding space.
- The caller is an owner or administrator for publication.
- `Idempotency-Key` exactly equals the request `operation_id`.
- Provider payloads remain in protected local storage and are materialized only after final
  authorization.

## Publish equivalent endpoints

Send `POST /v1/providers/equivalent-endpoint-sets` with current scope coordinates, one primary, and
the ordered fallback list. Include the complete content-free output contract and capability
attestation for every endpoint. The API never accepts a credential, secret reference, prompt,
document, vector, or provider response.

The Core independently verifies every submitted coordinate against canonical profile, probe,
capability, and embedding-space records. A successful `201` returns the content-addressed `set_id`,
output-contract digest, endpoint attestation digests, and the reviewed coordinates.

An exact replay returns the same set. Reusing an operation ID for different evidence returns
`409 conflict`. A different set cannot bind an already-attested primary profile revision and space.
Re-probe and publish under a new provider revision instead of overwriting history.

## Inspect equivalence

Read `GET /v1/providers/equivalent-endpoint-sets/{set_id}` with current Brain/project/repository
scope. Owners, administrators, and auditors may inspect the content-free evidence. A `404` does not
reveal whether the set exists in another Brain.

Check all of the following before enabling an operation:

1. every endpoint has the same `output_contract`;
2. the exact model and revision fingerprints match;
3. dimension, dtype, normalization, and similarity match for embeddings;
4. purpose and preprocessing digest match;
5. suite, canary, and validation digests match;
6. endpoint fingerprints are distinct; and
7. primary and fallback order reflects the intended operational priority.

## Interpret retry behavior

The production policy permits at most three total attempts and never runs past the caller deadline.
Transient upstream, timeout, rate-limit, and adapter-crash errors may retry. Authentication,
permission, configuration, missing model, oversize, quota, cancellation, model drift, dimension
mismatch, privacy denial, malformed response, and unsupported capability fail according to the
closed error policy.

`Retry-After` is normalized to an absolute epoch-microsecond time by the gateway. It is a minimum
delay. If the hint reaches or exceeds the deadline, the operation exhausts instead of extending the
caller budget.

Do not add retries in an HTTP client, vendor SDK, worker, or queue around the PRO-007 policy. Stacked
retry layers multiply calls and can violate the three-attempt limit.

Do not enable a provider-scheduler execution adapter until PRO-009 containment binds final egress
authorization, the isolated runtime/provider gateway, protected result manifests, and
`ResilientProviderOperationHandler`. A direct vendor or placeholder gateway is not a valid
operational shortcut.

## Interpret circuit state

| State | Meaning | Operator action |
|---|---|---|
| `closed` | Normal dispatch; qualifying failures are counted in the current 30-second window | No action unless failure rate is rising |
| `open` | Five qualifying failures opened the exact endpoint for 30 seconds | Restore the endpoint; allow eligible proven-equivalent fallback or queued retry |
| `half_open` | One due recovery probe is in flight | Do not force another probe or edit circuit state |

Rate limiting does not poison a healthy closed circuit. A half-open failure reopens the endpoint.
Success resets the exact circuit. Circuits are endpoint-attestation-specific and must never be
copied to another endpoint.

## Degraded recall

When vector provider execution is unavailable, recall continues through available exact, lexical,
and graph channels. The response must list the vector channel as degraded and include freshness; it
must not silently present partial recall as complete.

An equivalence or persisted-attestation conflict is an integrity failure, not an optional-channel
outage. Stop the operation and investigate canonical evidence. Authorization failures also fail
closed.

## Diagnose queued work

1. Confirm the caller deadline has not expired.
2. Inspect the last canonical provider error code.
3. Confirm the attempt count is below three.
4. Check the endpoint circuit and its `open_until` time.
5. Confirm an equivalent set resolves for the exact Brain/profile revision/space.
6. Confirm every profile remains active and its active probe ID is unchanged.
7. Confirm the embedding-space fingerprint and output contract are unchanged.
8. Confirm the operation claim is not held by an unexpired worker lease.
9. Confirm the protected payload still exists and matches every content digest.
10. Restore the dependency and allow the durable retry schedule to proceed.

Never change `attempts`, `retry_at`, circuit version, set membership, profile revision, result cache,
or terminal failure rows manually.

## Duplicate-charge investigation

Every primary, fallback, and retry call must carry the same
`am-provider-v1:<semantic-cache-key>` downstream idempotency key. Compare content-free dispatch facts
by operation-key digest, attempt, endpoint fingerprint, fallback ordinal, and outcome code.

If a provider reports a charge but Core has no committed result:

1. preserve provider billing evidence outside content-bearing logs;
2. verify the downstream idempotency key was honored;
3. allow lease recovery to reclaim the same operation;
4. confirm the retried call uses the identical key; and
5. escalate if the provider bills an exact-key replay again.

Do not generate a new operation or idempotency key to hide an uncertain result.

## Interpret API and operation failures

| Failure | Meaning | Action |
|---|---|---|
| `403 forbidden` | Authentication, role, or current scope denied the action | Correct authority; never bypass scope resolution |
| `404 not_found` | No set is visible in the resolved Brain | Verify set ID and scope without probing other Brains |
| `409 conflict` | Idempotency, canonical attestation, immutable set, or circuit evidence diverged | Re-read canonical profiles/probes/spaces; preserve the conflict |
| `422 validation_failed` | Identifier, digest, output contract, endpoint shape, or header is invalid | Correct the producer; do not coerce evidence |
| `503 dependency_unavailable` | SQLite, provider gateway, endpoint, or protected result storage is unavailable | Restore the pinned local dependency and use the durable retry path |
| `provider retry scheduled` | A retryable code received a safe time inside the caller deadline | Leave the operation queued until that exact time |
| `provider operation failed permanently` | Nonretryable behavior or attempt/deadline exhaustion was committed | Correct the cause and create a genuinely new semantic operation only when input or authority changes |

## Migration and rollback

The migration creates immutable equivalence sets/members/receipts, dispatch facts, terminal provider
failures, and versioned circuit state. Downgrade refuses while any PRO-007 evidence exists.

For release rollback, stop new provider dispatch, preserve the SQLite volume, verify no operation is
mid-claim, and use the signed AgentMemory release rollback procedure. Never drop PRO-007 tables or
disable immutable triggers. A release unable to read this schema is not a valid rollback target.

## Incident escalation

Escalate immediately if a fallback differs by model revision, space, purpose, preprocessing,
dimension, dtype, normalization, similarity, or validation evidence; more than three attempts occur;
a nonretryable error is retried; an open circuit is bypassed; two half-open probes run; fallback
changes the downstream idempotency key; a completed or terminal operation calls a provider again;
deleted/revoked content reaches a provider; partial recall is reported as complete; sensitive
content enters logs/API/audit; or immutable resilience evidence changes.
