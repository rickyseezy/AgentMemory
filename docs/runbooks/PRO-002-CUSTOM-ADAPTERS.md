# PRO-002 custom adapter operations

## Install

Use only a publisher package whose manifest validates against `contracts/jsonschema/provider-adapter-manifest.v1.schema.json`. Installation requires owner or administrator authority. The setup flow acquires the OCI descriptor and evidence into the immutable local artifact store, verifies all digests and offline trust evidence, applies local sandbox ceilings, renders the closed Compose service, starts it with pull/build disabled, runs live conformance, and atomically records activation.

Never edit Compose to install an adapter. Raw Compose documents, Docker flags, environment maps, mounts, ports, network names, and secret paths are not accepted by the install application.

## Diagnose

Safe failure classes are `verification`, `policy`, `runtime`, `conformance`, `conflict`, and `storage`. Adapter stderr and provider responses are not returned directly. Correlate redacted diagnostics by operation ID and attestation digest. Do not paste provider credentials into a manifest or diagnostic bundle.

For runtime failure, verify the installation-scoped internal network exists and the digest-pinned image is present in the verified local artifact set. For conformance failure, run the same signed adapter through the conformance suite and check protocol framing, protocol major 1, ordered content IDs, dimensions, finite numeric values, cancellation, health, and shutdown. A failed installation must have no row in `provider_adapters`; its temporary service must be absent.

## Contain and recover

If an active adapter crashes or is suspected compromised, quarantine it in the canonical registry and remove only its digest-derived `custom-provider-*` service. Never run project-wide `compose down`, prune, or volume deletion. The adapter has no project/database/socket mount and cannot corrupt SQLite transactions; pending provider work remains retryable outside the core transaction.

After a launcher interruption, reconcile the immutable `provider_adapter_installations` journal with managed container labels. Remove an orphan only when its project name, service name, and plan-digest label all match canonical installation state. Re-run supply-chain and live conformance checks before reactivation.

## Release verification

A release is blocked unless both reference adapters pass the black-box contract, framing fuzz tests pass, the closed Compose renderer rejects forbidden keys, signature/evidence tamper tests pass, cleanup is verified after partial startup and conformance/storage failure, the relational migration constraints pass, linters/type checks pass, and changed-code coverage is at least 80%.
