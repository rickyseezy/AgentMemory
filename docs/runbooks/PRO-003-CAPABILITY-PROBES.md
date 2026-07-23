# PRO-003 provider capability probe runbook

## Purpose

Use this procedure to activate or re-attest a local or remote provider profile. A successful response
means the exact installed adapter, endpoint, configuration, model revision, purposes, and vector
contract passed the release-pinned live probe. It does not authorize a different model alias,
destination, adapter build, or configuration.

Never edit provider profile, probe, capability-attestation, revision, operation, audit, or outbox
tables manually. Never paste a provider credential, raw provider response, vector, score, prompt,
canary body, endpoint URL, or source content into a diagnostic bundle.

## Preconditions

1. AgentMemory reports the certified relational migration head including
   `0036_pro003_capability_attestations`.
2. The caller is the Brain owner or an administrator with current `provider.profile.probe` authority.
3. The provider profile already exists and its ETag is current.
4. The exact adapter implementation digest is installed and certified.
5. For a remote profile, owner egress approval, endpoint policy, credential reference, retention and
   training declaration, residency, quota, and budget are current. The credential value remains in
   the protected secret store.
6. For Qwen/local, the exact release-attested sidecar image, model artifact, role, and revision are
   healthy.

## Run the probe

Read the profile and retain the returned `ETag`, then submit one idempotent probe request:

```http
GET /v1/providers/profiles/<profile-id>?brain_id=<brain-id>&actor_id=<actor-id>&grant_id=<grant-id>&project_id=<project-id>&repository_id=<repository-id>
Authorization: Bearer <launcher-capability>
```

```http
POST /v1/providers/profiles/<profile-id>/probe
Authorization: Bearer <launcher-capability>
If-Match: "<exact ETag from GET>"
Idempotency-Key: provider-probe-2026-07-23-001
Content-Type: application/json

{
  "operation_id": "provider-probe-2026-07-23-001",
  "brain_id": "<brain-id>",
  "actor_id": "<actor-id>",
  "grant_id": "<grant-id>",
  "project_id": "<project-id>",
  "repository_id": "<repository-id>"
}
```

The operation ID must be unique for this exact request. Reusing it with different coordinates is a
conflict. A stale `If-Match` is rejected before provider work. Do not retry by changing the profile
version or database row; fetch the current profile and make a new governed decision.

## Interpret a successful response

Require:

- `status` is `active`;
- `active_probe` is present;
- `configuration_digest` matches the profile configuration;
- `adapter_digest`, `endpoint_fingerprint`, `model_revision`, and `revision_fingerprint` are present;
- `validated_batches` equals the number of configured purposes;
- `cancellation_verified` is true; and
- embedding dimension and dtype agree with the intended immutable embedding-space contract.

Record only the operation ID, profile ID, evidence ID, safe digests, model revision, status, and
timestamp in an operational ticket. The API deliberately returns no secret reference or value and no
raw inference data.

## `reprobe_required`

An upgraded installation may expose a previously active profile as `reprobe_required`. This is
expected when its historical evidence predates the PRO-003 validator. AgentMemory does not fabricate
an attestation for that evidence and does not expose it as active.

1. Confirm the immutable profile configuration is still intended.
2. Confirm the currently installed adapter digest, endpoint policy, and model are approved.
3. Fetch the current ETag.
4. Run a new probe with a new operation ID.
5. Confirm the response is `active` and contains a new schema-v2 evidence identity.

If the configuration must change, create a new profile. Do not alter the old immutable configuration
or copy its evidence.

## Safe failure handling

| Safe class | Meaning | Action |
|---|---|---|
| `authentication` / `permission` | Provider rejected the configured credential authority | Repair the protected credential reference or provider permission; never include the value in logs |
| `privacy_denial` | Local egress policy rejected the destination or classification | Correct governance approval; do not bypass the gateway |
| `missing_model` | Exact configured model/revision is unavailable | Restore that immutable revision or create a separately approved profile |
| `rate_limit` | Provider quota rejected the probe | Wait for the governed retry window; do not widen budget/quota implicitly |
| `timeout` / `cancellation` | Deadline or cancellation contract failed | Verify gateway/sidecar health and cancellation; activation remains denied |
| `malformed_response` | Count, order, ID, shape, dtype, finite/range/norm, purpose, or schema validation failed | Quarantine the adapter/model combination and run its conformance suite |
| `dimension_mismatch` | Dimension changed within the probe or conflicts with the declared contract | Treat as embedding-space drift; never pad, truncate, or project |
| `model_drift` | Model revision, revision fingerprint, or endpoint changed during probing or refresh | Freeze routing/index writes and investigate the immutable provider coordinates |
| `oversized_input` / `oversized_response` | A hard request/response ceiling was exceeded | Correct the adapter contract; do not increase limits without a reviewed release |
| `transient_upstream` | Bounded provider dependency failure | Retry with a new operation ID after health recovers |
| integrity/conflict | Durable evidence, normalized binding, profile version, or immutable history disagrees | Preserve local evidence and escalate; do not repair with SQL |

A failed probe must leave the previous profile revision unchanged. Verify that no new
`provider_capability_attestations`, activation audit fact, activation outbox event, or vector write was
created for the failed operation.

## Drift and embedding-space response

A model, endpoint, adapter, configuration, purpose, preprocessing, tokenizer, dimension, dtype,
normalization, similarity, instruction, or quantization change is not an in-place refresh. Freeze
affected writes, preserve the attestation and routing decision, create the required new profile and
embedding space under the applicable stories, reindex into a shadow generation, validate it, and only
then switch routing atomically.

Do not acknowledge drift by overwriting an evidence row or reusing the old vector index.

## Incident evidence

Preserve:

- AgentMemory release/build and migration heads;
- profile ID/version/status and configuration/manifest digests;
- operation and evidence IDs;
- adapter, endpoint, suite, canary, validation, and revision fingerprints;
- model revision, validated batch count, safe error code, and timestamps;
- redacted gateway/sidecar correlation identifiers; and
- relevant hash-chained audit and outbox identities.

Escalate immediately for schema-v2 evidence without its normalized attestation, content-address
mismatch, mutable-table trigger failure, endpoint/model drift, unauthorized activation, raw
credential/content leakage, or any vector write observed before activation.
