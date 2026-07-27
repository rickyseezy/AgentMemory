# PRO-010 provider observability runbook

This runbook applies to the local AgentMemory Core. Pricing, budgets, telemetry, canaries, alerts,
and status remain on the user machine.

Never paste content, prompts, vectors, credentials, provider bodies, repository paths, secret
references, protected-file data, or raw container/database output into a ticket or diagnostic
bundle. Use Brain/profile/space/generation IDs, immutable version or attestation IDs, operation IDs,
safe error/reason codes, counts, and timestamps only.

## Normal status

Read the authenticated `GET /v1/providers/status` view through the local operator surface.

Normal means:

- no unexpected unavailable/suspended profile;
- circuit counts agree with current resilience state;
- queue age, retries, and dead letters remain within the installation policy;
- pricing and budget currency/profile versions match;
- spent plus reserved cost is understood and remaining cost is nonnegative;
- every active embedding generation is `pinned` unless its profile intentionally uses a mutable
  alias; and
- no active drift or budget alert lacks an owner action.

Do not query SQLite directly for routine monitoring and never expose the local Core API on an
untrusted interface.

## Budget exhaustion

| Safe status | Meaning | Required action |
|---|---|---|
| `budget_queued` | The serialized estimate would exceed the finite active period | Leave work queued. Confirm pricing version, period, spent, and reserved totals. Wait for the next governed period or publish an explicitly approved new immutable budget version. |
| `budget_degraded` | Vector dispatch was denied and configured exact/lexical/graph channels remain eligible | Confirm the response reports degraded retrieval. Do not silently re-enable vector work or select a different provider. |
| Spent exceeds limit after reconciliation | Actual provider usage exceeded its estimate | Preserve the operation ID, pricing snapshot, estimate, actual cost, and alert digest. Pause new provider dispatch and review the pricing catalog/estimation policy. |
| Missing pricing authority | No exact effective catalog matched the profile/version/operation/time | Keep dispatch disabled. Publish a reviewed finite pricing version; never hardcode a temporary price or edit a reservation. |

Never edit budget accounts, reservations, operation facts, active pointers, or alerts. Publish a new
immutable policy/catalog through the authenticated API.

## Drift alert

A safe reason is one of:

- `model_revision_mismatch`;
- `vector_fingerprint_mismatch`;
- `vector_norm_mismatch`; or
- `distance_order_mismatch`.

On any drift alert:

1. Stop treating the affected generation as writable. The database already denies new document
   vector work; do not bypass the guard.
2. Record the profile/version, capability attestation, space, generation, canary, observation,
   alert digest, safe reason, and timestamp.
3. Confirm the profile and egress route still bind the expected immutable model revision. For a
   mutable alias, assume semantic change even when the alias text is unchanged.
4. Create and probe a new provider profile revision when provider identity/capability changed.
5. Create a new embedding space and generation.
6. Run the PRO-008 shadow migration from canonical source content, validate quality, and activate
   atomically.
7. Retain the old suspended generation for governed rollback/retention evidence; do not delete or
   unsuspend it manually.

An old generation suspension is permanent evidence. “Retry until it passes,” overwriting the
baseline, relaxing tolerance after the alert, editing the active pointer, or copying old vectors
into the new space is prohibited.

## Probe failure without drift verdict

`dependency_unavailable` means the probe could not produce valid safe evidence. It does not prove
that the model is stable or drifted.

- Local profile: check authenticated local-provider readiness and exact model identity.
- Remote profile: check the active PRO-009 policy route, capability attestation, encrypted credential
  binding, gateway health, and vendor availability without printing secrets or response bodies.
- Invalid corpus/profile/generation binding: quarantine the registration or runtime revision; the
  shipped public corpus and exact active authority must match.

The scheduled worker releases a failed lease to a bounded retry time and isolates the failure from
other canaries. Repeated failures require operator attention; do not disable the scheduler.

## Queue, retry, and dead-letter response

1. Check oldest queue age and profile/circuit state.
2. Separate budget queueing, retryable provider errors, authorization denial, and drift suspension by
   their closed safe code.
3. Preserve the operation/item IDs and timestamps.
4. Follow the provider resilience or containment runbook for rate, quota, timeout, authentication,
   policy, or gateway failures.
5. Replay a dead letter only through the governed replay action after its underlying cause is fixed.

Never bulk-update queue states or retry counters.

## Pricing or budget publication

Before publishing:

- bind the exact Brain, profile ID/version, operation, ISO currency, version, finite effective/period
  window, and integer micro-unit rates/limit;
- verify windows do not overlap the current authority incorrectly;
- choose `queue` or `degrade` explicitly;
- for degradation, list only the reviewed exact/lexical/graph channels; and
- use one stable operation ID and matching `Idempotency-Key`.

A conflicting replay is an incident or caller bug. Do not change the idempotency key merely to force
different content through.

## Privacy or cardinality incident

Treat any content, prompt, vector value, credential, secret reference, provider body, path, arbitrary
exception text, or high-cardinality identity in metrics/logs/status as a release-blocking privacy
incident:

1. disable affected dispatch and diagnostic export;
2. preserve content-free operation/release evidence;
3. identify the emitting build and adapter;
4. rotate credentials if exposure is possible;
5. remove unsafe diagnostics through the governed local deletion procedure; and
6. rerun telemetry canary scans, cardinality tests, and the complete release qualification before
   re-enabling.

## Release checklist

Retain evidence for:

- pricing version/replay and integer-cost tests;
- concurrent reservation and actual reconciliation tests;
- queue/degrade behavior before gateway invocation;
- local and active-attested remote drift probes;
- vector privacy and zeroization scans;
- drift mismatch, immutable suspension, and database write-denial tests;
- health/circuit/queue/retry/DLQ/usage/latency/budget/generation aggregation tests;
- strict authenticated API and deterministic complete OpenAPI tests;
- migration upgrade, integrity constraints, downgrade refusal, backup/restore, and reinstall tests;
- at least 80% changed-code line and branch coverage;
- at least 80% configured mutation score;
- Ruff, strict mypy, Pyright, Bandit, architecture contracts, and dependency audit; and
- hosted product-quality and launcher workflows.

Any skipped required cell, surviving threshold failure, unresolved privacy/cardinality issue,
unhandled drift alert, or writable suspended generation blocks release.
