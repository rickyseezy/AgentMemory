# PRO-001 provider-profile operations runbook

This runbook covers certified built-in provider profiles. It does not authorize direct provider
network access, manual database edits, arbitrary custom adapters, or replacement of an active
embedding generation. Custom adapter installation is PRO-002; provider containment is PRO-009;
embedding-space migration and cutover are PRO-004 and PRO-008.

The default Qwen local profile needs no provider credential or user configuration. A nontechnical
user can keep the default offline installation indefinitely. Remote configuration is an explicit
administrator action and is never required for installation or ordinary agent use.

## Profile states

| State | Meaning | Query/write eligibility |
|---|---|---|
| `draft` | Configuration and certified manifest were validated; no live attestation is bound | Not eligible for embedding/reranking routing |
| `active` | A live probe is bound to the exact manifest, model, purpose, limits, and revision fingerprint | Eligible only for a compatible governed embedding space |

There is no force-active transition. Never modify `provider_profiles`, revision history, probe
evidence, operation receipts, audit events, or outbox rows manually.

## Configure the default local provider

Select adapter `qwen-local`, execution class `local`, the exact release-pinned embedding or reranking
model ID, its operation, purposes, and limits. Do not provide endpoint policy, credential, egress
approval, retention declaration, quota, or budget. The live probe uses the already authenticated
PF-001 local sidecar and validates model ID, revision, dimension where applicable, local-only
identity, and cancellation.

If the local probe reports `missing_model`, do not change the profile model ID to match an unexpected
runtime. Verify the active signed release and model inventory using the PF-001 installation runbook.
A sidecar identity mismatch is an installation-integrity failure.

## Configure a remote built-in

Before create, record all of the following through the management surface:

1. certified adapter ID: `openai`, `openai-compatible`, `cohere`, `voyage`, or `google`;
2. exact provider model ID, never an intentionally mutable alias when the provider offers a dated or
   revision-pinned ID;
3. embedding or reranking operation and every intended canonical purpose;
4. limits no broader than the adapter manifest;
5. an approved `policy://` destination-policy reference;
6. an owner-approved `approval://` egress reference;
7. a protected `secret://` credential reference—never the credential value;
8. versioned retention days, training permission, and residency declaration;
9. request/token/monthly quota; and
10. monthly budget in integer currency micros.

Create returns a `draft`. It performs no provider network call. Check the returned profile ID,
manifest digest, explicit model ID, operation, purposes, limits, and the boolean indicators that
remote policy and credential references are configured. Responses intentionally do not disclose the
references. Retain the strong `ETag` response header for the probe request.

Submit probe with a new idempotency operation ID and the draft's exact ETag in `If-Match`. A missing,
malformed, cross-profile, or stale ETag fails before the provider call. Activation succeeds only if
the same installed manifest is still present and the gateway returns one stable model
revision/fingerprint, valid operation shape, every requested purpose, adequate limits, and
cancellation evidence. Repeating the same operation ID returns the original result without another
provider call.

## Failure diagnosis

| Safe outcome | Meaning | Operator action |
|---|---|---|
| `validation_failed` | Missing/malformed field, local/remote field mix, invalid model ID, duplicate purpose, or limits outside bounds | Correct the draft request; do not edit persisted rows |
| `forbidden` | Caller is not a current Brain owner/admin or the broad grant was revoked/expired | Restore the correct governed grant or use an authorized administrator |
| `conflict` during create | Idempotency key was reused with different input or an identical configuration already exists | Retrieve the existing operation/profile or submit a genuinely new operation/configuration |
| `conflict` during probe | Profile version, manifest digest, immutable evidence, or model revision changed | Do not retry blindly; inspect the current profile and manifest |
| `provider_rejected` | The provider returned a safe canonical protocol/capability error | Check the code in local diagnostics; upstream body and credential are intentionally unavailable |
| `dependency_unavailable` | Gateway, local sidecar, capability file, or canonical store is unavailable | Restore the signed local dependency, then replay the same operation ID |
| `model_drift` | Same configured model ID now resolves to another revision fingerprint | Suspend use and follow the model-drift procedure below |

Authentication, permission, missing-model, quota, rate-limit, timeout, cancellation, malformed
response, dimension mismatch, and privacy denial are intentionally distinct internal safe codes.
Never request raw upstream response bodies in logs; they may contain sensitive provider material.

## Model drift procedure

1. Stop new writes for the affected profile/embedding generation. Do not delete the active profile
   or old vectors.
2. Confirm that the installed adapter manifest and destination policy are still the approved
   versions.
3. Check the provider's official model-version/deprecation notice outside AgentMemory. Do not accept
   a mutable alias change as equivalent.
4. Create a new profile with an explicit model ID and a new operation ID.
5. Probe it to produce a new immutable revision fingerprint.
6. Use the governed embedding-space and migration workflow to backfill from canonical content,
   validate quality/privacy/coverage, shadow the new generation, and atomically cut over.
7. Retain the previous generation through its rollback window. Never mix vectors from the old and
   new profile fingerprints.

## Gateway and credential safety

- Core addresses only `http://provider-gateway:8080`; a different scheme, host, port, user info,
  path, query, or fragment is rejected during composition.
- The request path is relative, POST-only, traversal-free, bounded, and sent without ambient proxy
  configuration or redirects.
- Core sends the opaque endpoint and credential references. It never resolves a credential into a
  provider request.
- The internal gateway call uses a 32-byte owner-only capability file. Missing, linked, shared,
  changed, or incorrectly sized capability files fail closed.
- The default installation has egress disabled. Do not add a direct external network to Core or a
  provider sidecar.

PRO-009 adds independent per-operation content classification, destination, DNS/redirect/TLS,
region, quota, budget, and telemetry enforcement at the gateway. Until that signed gateway service
and a controlled live-provider certification are present, remote profiles must remain draft.

## Recovery and verification

After a storage or process interruption, replay the same operation ID. A completed operation returns
its exact historical profile revision. An uncommitted transaction leaves no partial current profile,
revision, probe, outbox, AgentEvent, or audit entry.

For integrity verification:

1. verify SQLite integrity and canonical migration head `0032_pro001_provider_profiles` (or its
   signed successor);
2. verify every active profile references an existing immutable probe and revision;
3. verify each probe evidence ID equals its canonical content digest;
4. verify provider audit entries continue the global audit hash chain;
5. verify each provider outbox payload digest and CloudEvents ID/type; and
6. verify no outbox, audit, API response, exception, or telemetry record contains `secret://`,
   `policy://`, `approval://`, credential values, canary vectors, or upstream bodies.

If canonical provider history fails verification, stop governed mutations and restore from the
latest verified signed local backup. Do not reconstruct a profile from a provider dashboard or
manually patch a fingerprint.
