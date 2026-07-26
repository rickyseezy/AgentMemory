# PRO-009 provider containment runbook

This runbook is for a local AgentMemory installation using the optional remote-provider profile.
Default installations remain offline and do not run `provider-gateway`.

Never paste a provider key, payload, vector, permit, secret reference, vault document, raw provider
response, DNS answer, or Docker inspection output into a ticket, log, chat, or diagnostic bundle.
Use operation IDs, policy/profile versions, attestation IDs, safe outcome codes, and digests only.

## Expected runtime shape

The signed runtime inspection must show:

- `am_internal` is an internal bridge;
- `core`, Neo4j, local providers, and custom adapters have only `am_internal`;
- `provider-gateway` alone has `am_internal` and `am_egress`;
- the gateway publishes no host port and mounts no state, artifacts, database, project, or Docker
  socket;
- Core mounts `provider-core-egress` read-only at `/run/provider-egress`;
- the gateway mounts `provider-gateway-secrets` read-only at `/run/secrets`; and
- an operation-scoped custom adapter mounts `provider-adapter-egress` read-only only when its
  approved manifest requests mediated gateway access.

Treat any deviation as a containment incident. Disable remote provider execution through the
governed profile/policy control, preserve content-free audit evidence, and do not restart into an
unverified topology.

## Safe health checks

Use AgentMemory status/readiness and the provider administration UI/API. The gateway container health
check authenticates `POST /v1/health` locally and performs no provider request. Healthy means only
that the isolated process, protected client capability, strict internal HTTP boundary, and composed
encrypted vault are usable. It does not prove a vendor endpoint, model, credential, quota, or budget.

Do not expose port 8080, use `curl` with a capability, enter the gateway container, print environment
variables, copy `/run/secrets`, or run a manual provider request.

## Safe failure classes

| Symptom or safe code | Meaning | Action |
|---|---|---|
| `provider egress is denied` | Policy, taint, route, profile attestation, security epoch, residency, retention, quota, budget, or permit did not match | Confirm current profile and active policy versions. Do not broaden policy until the user explicitly approves the exact provider/destination/data declaration. |
| `provider gateway request invalid` | Internal envelope, path, body digest, method, header, size, or permit schema failed | Quarantine the caller/runtime revision and retain operation ID plus image/plan digest. Never retry malformed bytes blindly. |
| `provider gateway request denied` | Internal capability, signed permit, replay, DNS/address, redirect, or credential binding was denied | Rotate/reproject only through the credential-management flow if a legitimate binding changed. Investigate possible tamper or stale runtime. |
| `provider gateway unavailable` | Protected file, DNS, TLS, socket, vendor, audit sink, or gateway dependency failed safely | Keep work queued under its existing deadline/retry policy. Check local status and vendor health without exposing secrets. |
| `adapter_crash` / `provider adapter runtime failed` | The one-operation custom runtime failed or returned an invalid frame | Verify the signed adapter digest and conformance evidence. Ensure cleanup/orphan reconciliation completes before retry. |
| `cost_budget`, `request_rate`, `token_rate`, or replay denial | Independent gateway accounting refused admission | Wait for the governed window or obtain explicit owner policy change. Never edit SQLite counters. |

All user-facing errors must remain content-free. An exception containing vendor response text, a
credential, content, path, address, or process output is itself a security incident.

## Credential rotation

Provider credentials are entered and rotated only through the local credential-management surface.
That surface must create a new authenticated encrypted vault and protected key artifacts, then ask the
launcher to reproject the exact remote secret set. Do not edit the projected Docker volume, Compose
YAML, `.env`, container environment, SQLite, or a vault JSON document manually.

After rotation:

1. confirm the protected source artifacts passed ownership, mode, link-count, size, HMAC, and
   AES-GCM validation;
2. reproject through the signed one-shot projector;
3. restart only the signed remote profile through the launcher;
4. wait for gateway health and Core runtime readiness;
5. run the governed provider probe/canary; and
6. confirm only content-free success facts were appended.

If projection or gateway composition fails, the previous protected source and last known-good runtime
remain the recovery anchor. Do not weaken file modes or bypass vault authentication.

## Policy or profile change

Publish a new immutable egress policy version; never update a historical policy. Every allowed route
must bind one exact active profile version, capability attestation, model revision, operation,
purpose, HTTPS hostname/port/path prefix, and region. Repository configuration may remove choices but
cannot add a provider, endpoint, credential, class, purpose, or retention/training permission.

Changing provider, model, output contract, endpoint, credential binding, or embedding semantics also
requires the applicable profile probe and embedding-generation migration. Do not reuse old vectors
or edit an active generation pointer.

For a new remote profile, preserve this exact activation order:

1. create the immutable draft profile;
2. add its credential to the encrypted gateway vault under
   `(profile_id, draft_configuration_digest)` and reproject the signed remote secret set;
3. publish a provisional egress route bound to the draft profile version, configuration digest,
   configured model, exact operation/purpose/path, destination, and credential reference;
4. run the governed fixed-canary probe through the signed `/v1/provider-operations/execute` gateway;
5. activate the profile only with the returned capability attestation;
6. rotate/reproject the vault entry so it is bound to
   `(profile_id, active_capability_attestation_id)`; and
7. publish the active operational route bound to that attestation and immutable model revision.

Never reuse the provisional route or draft credential binding for billable work. Never create an
unsigned probe route, send a policy/secret reference to the gateway, or invoke a vendor endpoint
directly from Core.

## Custom-adapter recovery

On launcher or adapter failure, startup must call orphan reconciliation with the currently authorized
immutable adapter plans before accepting new operations. Reconciliation:

1. lists only containers with AgentMemory managed, custom-provider-adapter, and exact plan-digest
   labels;
2. bounds and validates every full lowercase container ID;
3. re-inspects the exact ID and verifies managed, kind, plan, and operation labels;
4. force-removes only that proven-owned container; and
5. lists again and requires the authorized orphan set to be empty.

Unknown, unlabeled, ownership-drifted, or excessive containers are not deleted. Keep the provider
runtime disabled and escalate with content-free IDs/digests. Never run a broad Docker prune.

## Containment incident procedure

1. Disable new remote dispatch through governed policy/profile controls.
2. Preserve immutable SQLite permit/decision/runtime facts and the append-only gateway telemetry
   file; do not copy secret volumes.
3. Record installation/release/generation IDs, operation IDs, policy/profile/attestation versions,
   image/plan digests, safe failure codes, and timestamps.
4. Verify the signed topology and container labels against the active release.
5. Rotate the internal capability, permit key, vault keys, and affected provider credential through
   the credential-management flow when compromise is possible.
6. Rebuild and reproject from protected source artifacts; never repair a projected volume in place.
7. Re-run offline containment, adversarial DNS/redirect, telemetry scan, sandbox cleanup, and
   controlled provider certification before re-enabling remote dispatch.

If sensitive material reached logs, telemetry, diagnostics, an unauthorized address, or a custom
adapter outside its operation, treat it as a zero-tolerance release blocker.

## Qualification checklist

Before release, retain:

- Python unit/property/contract/integration/security/migration/privacy/resilience results;
- Linux Go race tests, package and changed-code coverage at or above 80%, vet/static analysis, and
  custom-adapter cleanup/orphan tests;
- dedicated gateway image build, non-root identity, SBOM, provenance, signature, vulnerability scan,
  and immutable digest;
- rendered default and remote Compose policy evidence;
- packet-capture proof that the default profile is offline and only the gateway egresses in the
  remote profile;
- telemetry scans with secret/content/vector canaries;
- controlled live-provider certification using isolated short-lived credentials and budgets; and
- 24-hour default-offline plus allowlisted-gateway soak results.

Any skipped containment cell, failed cleanup, stale evidence, unpinned image, missing mutation result,
or unresolved high/critical finding blocks release.
