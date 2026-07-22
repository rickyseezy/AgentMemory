# Custom provider adapter SDK contract (protocol v1)

An adapter is an OCI image plus a strict `provider-adapter-manifest.v1` document. The image reference and every evidence object are SHA-256 pinned. Installation fails before Docker starts when the signature, trust root, OCI descriptor, CycloneDX or SPDX subject, SLSA provenance, license policy, vulnerability policy, protocol range, permission request, or resource limit fails.

## Operations

Protocol v1 defines `get_manifest`, `validate_configuration`, `probe`, `health`, `list_models`, `embed_documents`, `embed_queries`, `rerank`, `estimate_cost`, `cancel`, and `shutdown`. Manifest, validation, probe, health, cancel, and shutdown are mandatory. At least one embedding or reranking operation is mandatory.

Each request is JSON-RPC 2.0 and includes `protocol_version`, `operation_id`, `profile_id`, `purpose`, ordered unique `content_ids`, `classification`, absolute microsecond deadline, `idempotency_key`, W3C `traceparent`, and a method-specific `payload`. The JSON object is strict: duplicate names, unknown fields, batches, notifications, unbounded arrays, oversized messages, invalid IDs, and protocol-major mismatches are rejected.

Each response echoes the JSON-RPC/operation ID, ordered content IDs and item results, vector dimension, usage, and immutable model revision. Vectors must match the declared dimension and contain only finite float32 values. Errors use the closed codes `invalid_request`, `unauthorized`, `unsupported`, `deadline_exceeded`, `cancelled`, `rate_limited`, `unavailable`, or `internal`; messages are bounded and must not contain credentials or authorization material.

## Framing and transport

Framed stdio uses a four-byte unsigned big-endian payload length followed by one UTF-8 JSON object, with an 8 MiB maximum. A persistent stream may carry consecutive frames. Authenticated HTTP carries the identical schema over the installation's internal network and must authenticate every operation; it cannot publish a host port. Diagnostics are separate from protocol output and must be redacted.

## Container contract

The launcher generates Compose JSON from its closed template. Adapter packages cannot provide Compose keys. The service runs as `65532:65532`, with a read-only root filesystem, `/tmp` no-exec tmpfs, all Linux capabilities dropped, no-new-privileges, init enabled, and hard CPU, memory, PID, scratch, and operation-time limits. It receives no project/database/host/Docker-socket mounts, no host port, no host network, and no arbitrary secret. It joins only the installation-scoped `am_internal` network. Remote provider traffic goes through the authenticated provider gateway; direct egress is impossible.

Reference implementations live in `conformance/provider-adapters/python-reference` and `conformance/provider-adapters/go-reference`. The Python OCI base is multi-architecture and digest-pinned. The Go image is `scratch` and contains only the statically built adapter.

## Conformance

Before activation, the launcher negotiates protocol v1 and certifies manifest identity, image digest, declared operations, health, ordered results, cancellation, and shutdown. Activation persists the attestation only after the live checks pass. A failed start, crash, hang, malformed response, policy denial, or journal failure triggers bounded service cleanup and never enters the canonical active registry.
