# ADR-008: Provider sidecar protocol, trust, sandbox, and gateway-only egress

- Status: Accepted
- Decision owners: Provider Platform Owner and Security Owner
- Consulted owners: Runtime/Installer, Governance, Retrieval, Release Engineering
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before protocol-major, sandbox, trust-root, or egress changes
- Supersedes: None
- Related requirements: PRD Section 11; Technical Requirements Sections 2.2, 5.6, 6, 11.8, and 11.12 SEC-004/SEC-006

## Context

AgentMemory must support built-in and user-authored embedding/reranking providers in any language,
without importing vendor/model runtimes into core or granting a custom adapter filesystem, secret,
Docker, or unrestricted network access. Default semantic operation must work entirely offline.

## Decision

### Protocol

Provider Protocol v1 is JSON-RPC 2.0 with strict versioned JSON Schemas. Required capability-specific
methods are `GetManifest`, `ValidateConfiguration`, `Probe`, `Health`, optional `ListModels`,
`EmbedDocuments`, `EmbedQueries`, `Rerank`, `EstimateCost`, `Cancel`, and `Shutdown`. An embed-only
adapter is not forced to implement rerank; unsupported capability is explicit.

Two transports are certified:

- length-prefixed stdio for conformance, approved operation-scoped processes, and SDK integration: one
  unsigned 32-bit big-endian byte length followed by exactly one UTF-8 JSON object; maximum frame is
  8 MiB and trailing/concatenated/duplicate-key input fails;
- authenticated container-internal HTTP for persistent release/custom sidecars: HTTP/1.1 or HTTP/2 on
  the named internal network, per-adapter mTLS identity, and an opaque operation-scoped 256-bit
  capability supplied through a protected file—not argv, environment, URL, or logs.

There is no inbound Internet provider endpoint and no arbitrary remote adapter transport. Protocol
negotiation chooses one common major/minor; unsupported major blocks activation.

Every request contains protocol/operation/profile IDs, purpose, ordered content IDs, classification,
deadline, idempotency key, trace context, and operation-specific bounded content. Every response echoes
operation and ordered IDs, resolved model/revision evidence, dimension, usage, and typed per-item or
operation errors. Content count/order mismatch is fatal before any write. Diagnostics are a separate
redacted channel and cannot appear in result fields.

Default request limits are 8 MiB protocol frame, 100 items, and the lower of adapter-attested and
profile limits for bytes/tokens/items; providers may only reduce them. Deadlines/cancellation propagate.
Adapters cannot request an interactive credential or policy change during an operation.

### Manifest, trust, and activation

A custom manifest declares adapter/protocol versions, digest-pinned OCI image, signature/SBOM/
provenance, supported operations/purposes/modalities/dimensions/dtypes/normalization/similarity,
query/document behavior, model/tokenizer revisions, batching/limits/cancellation, local/remote and data
handling, configuration JSON Schema, requested mounts/network, and resource bounds.

Install verifies ADR-016 release/trust rules, license/vulnerability policy, protocol range, and that
permissions fit the closed sandbox. Explicit owner trust binds exact image digest, manifest digest,
permissions, endpoint class, and expiry. Claimed capability is not active until deterministic live
probe verifies count/order, dimension, finite values, dtype/norm, purpose behavior, limits,
cancellation/deadline, rerank semantics, and model pin/drift canary. Any configuration/image/model
change invalidates attestation.

### Sidecar sandbox

Services are generated only from the signed closed Compose template. Arbitrary Compose fragments are
never merged. Each adapter runs as fixed non-root, read-only rootfs, all capabilities dropped,
no-new-privileges/default seccomp, bounded CPU/memory/PIDs/time, size-limited tmpfs, no inherited
environment, and no host listener. It receives no project/home/database/CAS/Docker socket/other secret
mount. Operation data is minimum, mounted/sent only for that operation, and removed afterward.

Local providers attach only to `am_internal`, have no host port/default route, and receive pinned model
artifacts installed/verified before runtime. Default BOM is Qwen3-Embedding-0.6B (1024 dimensions),
Qwen3-Reranker-0.6B, and Qwen3-4B-GGUF Q4_K_M local extraction with exact digests/templates/runtimes.
Runtime containers never download models. Extraction is always local.

In-process custom adapters exist only in an unmistakable unsafe development installation namespace
that cannot open production data; they are never a release feature.

### Gateway-only remote embedding/reranking

Default Compose has no egress network. Owner activation of `remote-providers` creates `am_egress` and
dual-homes only `provider-gateway`. Core/custom adapter sends an authenticated operation envelope over
`am_internal`; the gateway independently reauthorizes Brain/project, provider/profile, exact HTTPS
scheme/host/port/region/model/purpose/classification/retention/budget and resolves `SecretRef` itself.
Credential values never return to core/adapter.

For each connection the gateway resolves DNS and rejects loopback, metadata, link-local, multicast,
and unapproved private/address ranges; pins the approved resolved set for that connection; verifies TLS
1.2 minimum/TLS 1.3 where available; disallows redirect by default and fully reauthorizes any explicitly
supported redirect; enforces SNI/Host/destination agreement, body/time/rate bounds, and no proxy bypass.
It supports only provider embedding/reranking operations, not arbitrary CONNECT, URL fetch, extraction,
telemetry, analytics, model download, webhook, or license traffic.

Egress authorization runs immediately before socket acquisition. `restricted`, `local_only`, private,
or secret-tainted data is unconditionally denied and its payload buffer destroyed. Batches are
homogeneous by Brain, classification, profile, purpose, retention, and policy. Repository policy can
only narrow.

### Failure behavior

Provider errors normalize to authentication, permission, invalid configuration, unsupported
capability, missing model, oversized input, rate limit, quota, timeout, cancellation, transient
upstream, malformed response, dimension mismatch, model drift, privacy denial, and adapter crash.
Only typed retryable errors retry, maximum three attempts within deadline with full jitter. Embedding
fallback requires an attested equivalent endpoint for the same space. Otherwise work stays durably
queued. Reranking may skip/use approved alternative and reports fallback. Exact/lexical/graph retrieval
continues with explicit degradation.

## Security and privacy impact

Protocol validation, content minimization, sandboxing, gateway isolation, independent authorization,
and credential brokering assume adapter/provider compromise. No content, credential, raw vector, path,
or repository name appears in telemetry. Embeddings inherit source policy. A compromised Docker daemon
or approved model/runtime image remains a host-level residual risk.

## Compatibility, migration, and rollback

Additive methods/fields negotiate within v1; breaking framing/meaning creates v2 and a parallel client
through the support window. Adapter upgrade creates a new attestation and, when semantic fields change,
a new embedding space/generation. Rollback selects the exact prior signed image/config/attestation and
compatible generation. Permission expansion always requires fresh owner approval.

## Rejected alternatives

- In-process vendor/custom SDKs: dependency and compromise blast radius in core.
- Arbitrary HTTP endpoint/custom Compose: bypasses package trust and sandbox policy.
- Direct adapter/core Internet route: bypasses destination and credential enforcement.
- Credentials in environment/Compose: leak through inspect/diagnostics/process state.
- Remote extraction: product requires local extraction and default offline behavior.
- Trusting manifest capability claims: cannot detect malformed/drifting output.
- Fallback to a different model in one index: corrupts embedding semantics.

## Consequences

Custom adapters must package an OCI service and pass conformance/trust/probe. Gateway and mTLS add
local complexity, but provider neutrality no longer expands core dependencies or egress authority.

## Verification

- Reference adapters in Python and another language pass the same protocol suite.
- Frame/schema fuzzing, count/order/dimension/NaN/Infinity/cancellation/model-drift adversarial stubs.
- Signature/digest/SBOM/provenance/license/vulnerability/permission tampering blocks launch.
- Sandbox escape tests cover mounts, secrets, socket, host listener, capabilities, OOM/PID/hang, and
  cleanup.
- Packet tests cover direct socket, IPv4/IPv6, DNS rebinding, CNAME/IP drift, redirect, alternate port,
  metadata/link-local/private targets, proxy/QUIC bypass, and exact allowed endpoint success.
- Default-offline 24-hour soak and extraction/model-download egress canaries.
- Retry/equivalence/circuit/idempotency/billing/degraded-recall decision tables.
