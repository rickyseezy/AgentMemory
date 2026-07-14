# ADR-017: Compose topology, launcher sessions, resources, upgrades, and uninstall

- Status: Accepted
- Decision owners: Architecture Owner and Runtime/Installer Owner
- Consulted owners: Security, Operations, Core, Provider Platform, Agent Adapters
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before any service, mount, network, port, generation, or uninstall-policy change
- Supersedes: None
- Related requirements: PRD Sections 3, 15, and 16; Technical Requirements Sections 1.1-1.4, 2.2, 2.2.2, 4.1, 7, 11.1 PF-001/PF-005, 11.12 SEC-004/SEC-006, and 11.13 OPS-001/OPS-005/OPS-007

## Context

AgentMemory is a single-user, single-machine product whose only production deployment is Docker
Compose. It must start automatically from any agent directory, keep the persistent core away from
host source trees, remain offline by default, permit tightly governed provider egress, preserve data
across upgrades, and remove only resources it can prove it owns.

## Decision

### 1. Fixed deployment topology

One installation owns one Compose project. The persistent services are `core`, `neo4j`,
`local-embedding`, `local-reranker`, and `local-extractor`. Optional signed profiles may add
`provider-gateway`, approved `local-provider-*` containers, and `otel-collector`. `migrate`, `backup`,
and `restore` are one-shot operation containers. An `mcp-session` is created directly by the launcher
for one agent connection and is never part of the persistent service set.

No release profile may add another canonical database, broker, cache service, object store, hosted
control plane, native AgentMemory daemon, or public MCP service. The closed service inventory and
every image digest are bound by ADR-016's signed release manifest.

### 2. Networks and exposure

- `agentmemory_<iid>_internal` is an internal user-defined bridge. Core, Neo4j, MCP sessions, local
  providers, and observability attach only to it and have no default Internet route.
- Core publishes its API/UI only as `127.0.0.1:<port>:9411` and, where certified, the equivalent
  `::1` mapping. Default port is 9411; a collision produces one persisted alternate selected by
  binding an OS-assigned loopback port, never a non-loopback fallback.
- Neo4j and provider services use internal `expose` only. No other service declares `ports`.
- `agentmemory_<iid>_egress` does not exist by default. Enabling the owner-approved
  `remote-providers` profile creates it and dual-homes only `provider-gateway`. The gateway accepts
  authenticated embedding/reranking operation envelopes; it is not a CONNECT proxy. Core and custom
  adapters do not receive direct egress or provider credential values.
- No container joins Docker's default bridge or uses host network/PID/IPC. No container receives the
  Docker socket/pipe.

### 3. Persistent resources and naming

The physical project name is `agentmemory_<iid>`, where `<iid>` is the 32 lowercase hexadecimal
digits of the installation UUID. User, repository, project, path, and display text never enter a
Docker name.

Required resources are:

| Purpose | Name |
|---|---|
| canonical SQLite state | `agentmemory_<iid>_state_<gen>` |
| encrypted CAS | `agentmemory_<iid>_artifacts_<gen>` |
| Neo4j projection | `agentmemory_<iid>_neo4j_<gen>` |
| audit/deletion journal | `agentmemory_<iid>_journal` |
| model cache | `agentmemory_<iid>_models` |
| local telemetry | `agentmemory_<iid>_telemetry` |
| internal network | `agentmemory_<iid>_internal` |
| optional egress network | `agentmemory_<iid>_egress` |

`<gen>` is the 32 lowercase hexadecimal digits of a UUIDv7 data-generation ID. Every resource has
the exact labels `io.agentmemory.installation`, `io.agentmemory.release`,
`io.agentmemory.generation`, `io.agentmemory.purpose`, and `io.agentmemory.managed=true`.

The launcher records Docker object IDs, expected labels, creation operation, and ownership in an
HMAC-authenticated signed resource inventory immediately after each creation. A mutation requires
both inventory membership and exact installation label match. A name match alone is never authority.

Persistent data uses local Docker named volumes on the selected local engine. NFS, SMB, synchronized
folders, project binds, and volumes concurrently opened by another installation are rejected. Only
core opens active SQLite. One-shot migration/backup/restore may open a targeted generation only after
exclusive maintenance and stopped-core verification.

### 4. Container baseline

Every service uses `image@sha256:digest`, a fixed non-root UID/GID, read-only root filesystem,
`cap_drop: [ALL]`, `no-new-privileges`, default seccomp, bounded PIDs/CPU/memory, size-limited tmpfs
scratch, read-only configuration/secret mounts, a finite stop grace period, and a real health check.
Persistent services use `restart: unless-stopped`; one-shots use `restart: "no"`; MCP sessions use
automatic removal. Privileged mode, added capabilities, unapproved devices, writable source/config/
secret binds, broad home mounts, and mutable image tags are invalid.

Core readiness requires healthy Neo4j and local default providers plus migration head, SQLite
integrity, key access, audit append, deletion guard, lease recovery, and the write/index/recall probe.
Container `running` state is not readiness.

### 5. Signed rendering and policy validation

Compose is rendered only from the immutable signed base model plus closed, schema-validated profile
values. A profile may select an approved service/profile and bounded resources; it cannot introduce a
service, image, mount, port, capability, network, command, environment secret, or Compose extension.

Before every `up`, `run`, repair, or upgrade, the launcher renders `docker compose config`, parses it
as data, and enforces the closed policy. The rendered output must be safe for diagnostics because it
contains SecretRefs/protected file paths, never secret values. Static validation is followed by
runtime inspection of image digests, mounts, networks, users, capabilities, security options,
resources, labels, and published addresses.

### 6. Startup lock and active pointers

All install, start, repair, upgrade, restore activation, and uninstall operations acquire one
machine-global cross-process installation lock. The lock is owner/machine bound, has a bounded lease
with process-liveness validation, and cannot be stolen solely because time elapsed. Read-only status
may proceed concurrently from authenticated journal snapshots; mutations are serialized.

The owner-only host inventory stores an HMAC-authenticated tuple:

`installation_id, active_release_digest, active_data_generation, selected_runtime_endpoint,
resource_inventory_version, security_epoch`.

Core mirrors it when available. Disagreement fails closed. Pointer change uses durable temp write,
file/directory flush, atomic replace, and post-write verification; SQLite's mirrored pointer changes in
the governed upgrade/activation transaction. Recovery reconciles only through the journaled operation,
never by newest filename or running-container inference.

### 7. Per-agent MCP session

`StartMcpSessionApplication`:

1. acquires the startup lock;
2. validates the selected runtime is local, compatible, and not cloud/offload/remote;
3. starts and probes that exact endpoint and the exact active Compose release;
4. resolves logical and real current paths without a shell;
5. obtains host device/Git identity and a UUIDv7 session ID;
6. mints an opaque 256-bit session credential with a 12-hour maximum and 30-second heartbeat;
7. runs the exact manifest-bound `mcp-session` image; and
8. attaches launcher stdin/stdout to MCP stdio and diagnostics only to stderr.

The sole source mount uses Docker long mount syntax with separately encoded argv fields:

`type=bind,source=<existing canonical current directory>,target=/workspace,readonly,bind-propagation=rprivate`.

The container has no TTY, writable layer, parent/sibling mount, Git metadata expansion, database/
provider credential, host listener, or Docker socket. Recursive read-only is required where supported;
nested writable mounts are detected and refused/excluded elsewhere. Worktree identity metadata may be
signed on the host when `.git` lies outside the mount, but the mount is not widened.

The bridge streams only changed, privacy-authorized relative content to core while the mount exists.
It never opens SQLite or Neo4j. EOF/cancellation/signal triggers a bounded checkpoint, accurate
completed/interrupted event, credential revocation, and container removal. A lease marks the session
interrupted after 120 seconds without heartbeat.

### 8. Upgrade generations and rollback

Upgrade order is fixed: lock, prevent new sessions, drain/interrupt, verify target release, verify
space and recovery point, acquire exact digests, allocate target generation when required, migrate in
one-shot maintenance, start target Compose, run full probes, atomically change active pointers, retain
the prior generation.

The last known-good state/CAS/graph generation is never overwritten or deleted by upgrade. Failed
upgrade returns to the previous signed release if its schema remains readable; otherwise it restores
the verified pre-upgrade archive into a new generation. Blind database downgrade is prohibited.
Provider egress remains disabled during migration, restore, and recovery.

### 9. Scoped uninstall

Default uninstall is keep-data. It removes only inventoried, label-matching AgentMemory containers and
networks and preserves volumes, configuration, credentials, backups, runtime, and reinstall metadata.

Purge is a distinct journaled operation requiring exact installation/Brain confirmation. It stops
sessions, processes tracked provider deletion, removes only inventoried label-matching volumes and
owner-bound files, destroys the installation encryption root, and reports partial remote deletion.
Image deletion is separately selected. Global prune and prefix-based deletion are prohibited.

Docker/WSL/virtualization/package repositories/groups/global settings are preserved regardless of
ownership. Runtime removal is a second operation governed by ADR-018 and is allowed only after
ownership proof, exhaustive unrelated-dependency scan, and separate impact confirmation. Uncertainty
preserves the runtime.

## Security and privacy impact

The persistent core never sees a host source mount. Per-session access is least privilege and
read-only. Network default-deny, exact loopback publishing, closed rendering, immutable images,
resource labels plus inventory, session credentials, and no Docker socket limit lateral movement.
Resource names and telemetry contain no user path/project text. Host paths exist only in the
owner-protected launcher operation and Docker mount request; they are not logged or exported.

A compromised Docker daemon or privileged host can bypass these controls and remains an explicit
residual risk.

## Compatibility, migration, and rollback

Compose schema/profile changes are versioned and bound by the release manifest. During the supported
window, the launcher retains readers for the previous inventory/pointer version and migrates it
forward under the operation lock. Unknown security-relevant fields fail closed. Resource renaming is
performed by creating a new generation and migrating/restoring; existing volumes are never renamed
or adopted by name.

Rollback uses the exact prior release and preserved compatible generation. Removing a service or
profile requires an expand/migrate/contract release, export/cleanup plan, and conformance update.

## Rejected alternatives

- Persistent core source-tree mounts: violate least privilege and cross-project isolation.
- One persistent MCP container: cannot isolate directory/session credentials.
- Docker socket inside core: turns a core compromise into host runtime control.
- Host networking or published Neo4j/provider ports: expands the local attack surface.
- A direct external network on core/custom adapters: bypasses provider egress policy.
- Bind-mounted persistent databases: weakens portability and SQLite durability assumptions.
- Resource cleanup by name prefix: can destroy unrelated user resources.
- In-place upgrade of the only data generation: removes a verifiable rollback boundary.
- Native AgentMemory daemon or hosted control plane: violates the sole deployment model.

## Consequences

Session startup creates a container and requires robust runtime probes. Upgrades consume temporary
extra disk, and strict profile validation limits ad-hoc customization. In exchange, source access,
egress, lifecycle ownership, rollback, and uninstall are mechanically testable.

## Verification

- Render and inspect every supported profile/platform/architecture; reject every forbidden Compose
  field and unknown service/resource.
- Scan from LAN, IPv4/IPv6 loopback, and an unrelated container; only authenticated API/UI loopback
  is reachable.
- Packet-capture the default workflow for 24 hours and prove zero AgentMemory runtime egress.
- Inspect user, rootfs, capabilities, seccomp, mounts, networks, limits, labels, health, and image
  digests for each running container.
- Race concurrent install/start/repair/upgrade/uninstall and prove one mutation owner.
- Fuzz paths and Docker inspect/config input; test spaces, Unicode, metacharacters, symlinks,
  junctions, worktrees, UNC/drive paths, nested mounts, and remote contexts.
- Prove read-only workspace, parent/sibling/socket/secret denial, stdout purity, lease cleanup, and
  cross-session isolation.
- Kill every startup/upgrade/uninstall boundary and verify journal resume and exact resource set.
- Test keep-data reinstall, purge, label/inventory mismatch, unrelated resources, failed upgrade,
  pointer atomicity, generation rollback, and runtime-removal separation.
