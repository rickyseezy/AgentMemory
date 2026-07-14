# ADR-006: Project, repository, checkout, and device identity fingerprints

- Status: Accepted
- Decision owners: Identity Context Owner and Security Owner
- Consulted owners: Indexing, Agent Adapters, Retrieval, Launcher
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before changing a fingerprint or path/device source
- Supersedes: None
- Related requirements: PRD Section 5; Technical Requirements Sections 2.4, 4.2, and 11.2

## Context

A path moves, a repository has clones/worktrees/forks, monorepos contain multiple projects, and
non-Git directories may have no stable external identity. Treating directory text or similar content
as identity causes false merges and cross-project leakage. Fingerprints must also avoid exposing raw
host paths/remotes in graph, telemetry, or provider payloads.

## Decision

### Separate identities

`Project`, `Repository`, and `Checkout` always have separate UUIDv7 IDs.

- Project is a logical product/work scope and may link many repositories or share a monorepo.
- Repository is one source-history lineage/fork identity.
- Checkout is one local clone/directory/Git worktree on one device.
- Path is a mutable encrypted checkout alias and current-resolution hint only.

Resolution order is fixed: explicit manifest UUID, known repository plus project mapping, known
checkout alias, then non-versioned real-path fallback. Ambiguity returns candidates and requires user
confirmation; it never merges automatically.

### Canonical encoding and privacy

Fingerprint inputs are RFC 8785 canonical JSON, UTF-8 NFC where specified, and SHA-256. When an input
could reveal a path, remote, machine value, or repository identity, the stored lookup is
`HMAC-SHA-256(IdentityIndexKey, canonical_input)`. The key is installation-scoped under ADR-010.
User-visible raw paths/remotes are stored only as encrypted authorized aliases, never in Neo4j,
metrics, logs, cache keys, or provider requests.

Every fingerprint record declares algorithm version and input evidence. Changing algorithm creates a
new fingerprint alias; it never rewrites entity UUIDs.

### Explicit project manifest

`.agentmemory/project.json` may declare schema version, immutable project UUID, display name,
component roots, and repository links. It contains no credential, grant, egress policy, or authority.
The resolver validates file ownership/location, strict schema, UUID, and repository-relative component
paths. A copied manifest in incompatible repository evidence creates an identity conflict, not an
automatic merge. Project creation/manifest adoption is audited.

### Git repository fingerprint

The Git observer reads through typed argv APIs with no shell and records:

- object format and sorted full root commit object IDs reachable from the observed repository;
- normalized primary remote identity when present;
- repository common-directory/worktree metadata and submodule/fork evidence; and
- current HEAD/branch/working state as checkout/revision context, not repository identity.

Remote normalization strips credentials, query, fragment, default port, trailing slash, and `.git`;
normalizes scheme aliases (scp-style SSH and SSH URI), lowercase DNS host, and preserves path case.
The normalized value is HMACed before lookup.

`GitRepositoryFingerprintV1` is HMAC over object format, sorted root IDs, and normalized primary remote
fingerprint. A known exact match resolves the Repository across ordinary clones and moved checkouts.
A different remote with shared roots is a distinct fork candidate and is never auto-merged. A remote
change is added as a new evidence-backed alias only after continuity with the already known checkout/
history is established. Root-only similarity without a remote is a repository candidate requiring
explicit confirmation unless an existing checkout/file-identity alias proves continuity.

This deliberately favors false separation over false merge. Confirmed clone/fork links remain
evidence-backed graph assertions and do not collapse Repository IDs.

### Checkout/worktree identity

`CheckoutFingerprintV1` is HMAC over Repository UUID, device UUID, filesystem volume identity,
canonical real path, and Git worktree ID/common-dir-relative worktree identity where present. Logical
and real path are both retained as encrypted aliases to explain symlinks/junctions; identity uses the
real path and device/volume. Worktrees share Repository ID but have distinct Checkout IDs and branch/
working-tree state.

Moves on the same device are recognized from Repository identity plus stable filesystem file ID/inode
and prior alias when available; the new path becomes an alias and the Checkout UUID persists. A clone
creates a new Checkout linked to the same Repository. Case folding follows the observed filesystem,
not a universal lowercase rule.

### Device identity

At installation, `DeviceIdentityPort` reads the stable OS machine identifier through native APIs
(macOS hardware platform UUID, Windows MachineGuid protected by OS access, Linux machine-id) and the
installation UUID. It derives `DeviceFingerprintV1 = HMAC-SHA-256(DeviceIdentityKey,
os_identifier || installation_id)`. The Device entity receives a UUIDv7 and the installation maps the
stable fingerprint to that ID. Raw OS identifiers are never persisted. If a stable identifier is
unavailable or changes, the device becomes `UnverifiedChanged`; automatic checkout merge stops until
owner confirmation. Virtual/clone image duplicates are detected by the installation UUID and
owner-bound key, so two installations do not share a device identity accidentally.

### Non-Git directories

An explicit manifest is the only portable non-Git identity. Without one,
`NonGitCheckoutFingerprintV1` is HMAC over device UUID, filesystem volume identity, and real path.
It is intentionally local and path-sensitive. Moving such a directory resolves through file ID/prior
alias when possible; otherwise it creates an ambiguous candidate and asks for owner confirmation.
Directory name or content-tree similarity alone never merges non-Git projects.

### Complex layouts

Nested repositories and submodules remain separate Repository entities with evidence-backed
`CONTAINS_REPOSITORY`/`SUBMODULE_OF`. Monorepo components/projects link to one Repository with bounded
root paths. Fork, clone, and project-use relations remain explicit assertions with correction history.
The launcher may supply signed host-computed Git identity when worktree metadata lies outside the
read-only MCP mount; it reports partial coverage and does not widen the mount.

## Security and privacy impact

HMACed lookups and encrypted aliases prevent raw path/remote/machine identifiers from becoming graph,
telemetry, or provider data. Identity evidence does not grant authorization; Brain/project grants are
resolved separately. False merge risk is treated as a cross-scope security risk, so ambiguity fails
separate. A privileged host can spoof repository/device inputs and remains a residual risk.

## Compatibility, migration, and rollback

Fingerprint algorithms are versioned records. A migration computes V2 aliases alongside V1, compares
resolution on the identity corpus, records conflicts, and activates V2 only after owner-safe
validation; entity UUIDs remain stable. The previous resolver remains for the supported window and
rollback pointer can select it. Raw aliases are never recreated from HMACs; encrypted alias migration
requires key access.

## Rejected alternatives

- Canonical path as Project/Repository ID: moves/clones/worktrees break it.
- Directory name or content hash: unrelated/forked trees collide and content changes constantly.
- Remote URL alone: remotes move and forks/clones need history evidence.
- Root commits alone: forks share ancestry and would be falsely merged.
- Global machine identifier persisted raw: privacy and cloned-image collision risk.
- Auto-merging ambiguous candidates: can leak or corrupt cross-project history.

## Consequences

Some non-Git moves and remote-less Git clones require confirmation, and false separation can occur.
That is repairable by linking; a false identity merge is far harder and unsafe. Multiple aliases add
storage but preserve history.

## Verification

- Golden fingerprint vectors and normalization fixtures for HTTPS/SSH/scp remotes, Unicode, case,
  credentials, ports, and `.git` suffix.
- Move, clone, fork, remote change, worktree, submodule, nested repo, monorepo, symlink/junction,
  case-insensitive, volume/device-change, Windows drive/UNC, and long-path matrices.
- Prove identical names/content and shared roots with different remotes do not auto-merge.
- Non-Git manifest/fallback/move ambiguity tests and copied-manifest conflicts.
- Privacy scans prove raw paths/remotes/machine IDs never reach graph/log/metric/provider output.
- Resolver property/fuzz tests and V1-to-V2 shadow migration/rollback tests.
