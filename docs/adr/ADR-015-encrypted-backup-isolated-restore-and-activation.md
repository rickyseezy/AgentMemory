# ADR-015: Encrypted backup, deletion continuity, isolated restore, and activation

- Status: Accepted
- Decision owners: Operations Owner and Data Protection Owner
- Consulted owners: Persistence, Graph, Governance, Audit, Runtime/Installer
- Decision date: 2026-07-13
- Review date: 2026-10-13 and after every quarterly restore drill or archive-format change
- Supersedes: None
- Related requirements: PRD Section 16.4; Technical Requirements Sections 7.4, 11.13 OPS-004/OPS-005, and 14.1

## Context

Local machine/disk loss requires a portable recovery point, while SQLite, CAS, Neo4j projection,
outbox/jobs, audit, and deletion journal must agree at known watermarks. Restoring in place or serving
before applying later tombstones can expose deleted data. Backups must remain encrypted when copied to
removable media and verifiable without a hosted service.

## Decision

### Recovery objectives and schedule

The local reference profile has machine/disk backup RPO 24 hours and restore RTO 4 hours for up to one
million searchable units/ten million relationships on reference hardware. Default scheduled retention
is daily 35 days, weekly 13 weeks, and monthly 12 months where policy permits. Full automated isolated
restore drills run at least quarterly. A backup does not count toward RPO until archive verification and
at least one compatible restore drill policy says it is verified.

Destination is an owner-selected local or removable filesystem only. Network/cloud paths are rejected.
The scheduler reports unavailable destinations and never silently redirects to Docker data root.

### Portable key wrapping

Every archive has a random 256-bit Backup DEK. Payload entries use ADR-010 AES-256-GCM envelopes and
independent nonces. The Backup DEK has:

- an installation-local wrapper under current IRK for routine local restore; and
- a mandatory portable recovery wrapper before the backup can count toward machine-loss RPO.

The portable wrapper is either an owner-provided public key from an approved algorithm/profile or a
recovery passphrase-derived key using Argon2id (256 MiB memory, 3 iterations, parallelism 2, random
16-byte salt) followed by AES-256-GCM wrapping. Parameters and algorithm IDs are stored; the passphrase/
private key is never stored. The separately retained recovery descriptor also pins the source
installation ID and backup-signing public-key fingerprint; a public encryption key alone is not an
authenticity anchor. The accessible UI guides creation/testing and warns that losing both installation
keys and portable recovery material makes the archive unrecoverable. A machine-local-only archive is
labeled unverified for machine-loss recovery.

Archive manifest is signed by the installation audit/backup signing key; its public key and audit
checkpoint binding are inside the authenticated recovery metadata and must match the separately pinned
recovery descriptor (or the existing installation trust record for a same-machine restore). Portable
AEAD authentication plus that pinned signature/checkpoint verification detects archive and signer
substitution without a hosted service.

### Consistent backup operation

`StartBackupCommand` acquires maintenance lock, prevents new governed mutations, drains in-flight
commands, and records:

- SQLite committed event/domain/outbox/inbox/job/migration watermark and active schema/generation;
- CAS manifest root/count/bytes/key versions at that watermark;
- audit sequence/checkpoint and latest signed deletion-journal head;
- grant/policy/security epochs;
- active/rollback graph, text, vector, provider-space generations; and
- release/BOM/Compose/migration compatibility.

It then uses SQLite online backup API and validates the copy, snapshots immutable encrypted CAS and
configuration containing SecretRefs but no values, copies audit/deletion checkpoints, and either
performs a coordinated Neo4j Community dump or includes a complete signed rebuild plan from canonical
watermark. Provider egress is not used. New post-maintenance work resumes only after the committed
watermark and operation state are durable; backup may continue packaging immutable snapshots.

Every entry has fixed type, digest, encrypted/plain lengths, key ID, source watermark, count, and
classification in `BackupManifestV1`. The one-file `.ambak` format is ZIP64 with fixed normalized
manifest-defined entry names, store/no compression for already encrypted payload, no symlink/device/
absolute/`..` entries, and strict duplicate rejection. Consumers never extract paths directly; they
stream validated entries into operation-owned targets.

Archive is written to an owner-only temporary sibling, flushed, read-back verified (signature, every
AEAD/digest/count/watermark), then atomically renamed and parent directory flushed. The signed final
manifest/completion record is the only completion marker. Partial archives are retained only as
AgentMemory-owned resumable chunks or safely removed; they are never listed as backups.

### Restore isolation

`RestoreBrainCommand`:

1. acquires launcher/maintenance lock and creates a distinct restore operation/Compose project plus
   new labelled state/CAS/Neo4j generations;
2. never attaches `am_egress` and denies all provider calls/model downloads;
3. authenticates recovery wrapper, backup signature/checkpoint, fixed entry schema, every AEAD/digest/
   length, release/schema/BOM compatibility, and archive completion;
4. restores canonical state to the new generation and applies the newest trusted local signed
   deletion/access-revocation journal before any API/query starts;
5. restores Neo4j dump only if compatible or rebuilds graph/text/vectors solely from included
   canonical source and recorded model artifacts/results—never a remote provider;
6. runs SQLite integrity/FK/migration, counts/hashes/watermarks, audit chain, graph assertion/edge/vector
   generation, Brain isolation, grant, deletion non-resurrection, provider-disabled, and golden-recall
   validation; and
7. presents validation evidence to the local Owner for explicit activation.

Restore API/UI binds no normal product listener until validation; the setup surface exposes only
operation status. In-place overwrite and mounting an archive database as active are prohibited.

### Deletion-journal continuity

Archive records deletion head sequence/hash at capture. Activation requires a signed deletion head at
least as new as both archive head and the installation's declared latest head for affected scopes. If
the backup predates deletion, the newer journal is applied first. Missing, forked, corrupted, or older
proof fails closed. Restore never chooses the archive's older grants/security epoch over a newer local
revocation.

### Activation and rollback

After Owner approval, launcher and core atomically CAS the active release/data-generation pointer from
the expected current tuple to the verified restore tuple, then start exact signed services and rerun
readiness. Prior active generation remains unchanged and rollback-ready. Provider routes remain
disabled until a separate owner reauthorization/probe after activation. Failed activation restores
the prior pointer; it never overwrites either generation.

### Retention and deletion

Retention removes only inventoried completed archives after policy/hold evaluation and audit. A
deletion requiring faster backup erasure destroys the applicable per-backup/Brain recovery wrapper
within 24 hours when key granularity permits and updates signed inventory; otherwise archive expires by
retention and the pending status remains visible. The deletion ledger itself retains no content and is
included in later backups.

## Security and privacy impact

Archives contain sensitive canonical state and are always application-encrypted. Secret values are
excluded by schema/scan. Portable recovery material is an owner responsibility exposed clearly in UI;
the project cannot recover a lost secret because there is no hosted service. Restore remains offline
and isolated, preventing tampered/stale data from reaching providers or normal recall.

## Compatibility, migration, and rollback

Archive/manifest/envelope versions are explicit. Restore supports every product version in ADR-016's
window and tests signed intermediate migration for older supported archives. Unknown required/security
fields block. Archive migration stages into isolated generation and never rewrites the source archive.
Rollback is pointer-based to prior generation or a new restore attempt.

## Rejected alternatives

- Copying live SQLite/WAL/volumes: no consistent watermark.
- Unencrypted tar/volume snapshot: unsafe on removable media.
- Encryption only with machine IRK: unusable after machine loss/migration.
- Storing passphrase/recovery private key in archive: defeats encryption.
- In-place restore: destroys rollback and may expose partial/deleted data.
- Restoring projections before canonical/deletion state: resurrection risk.
- Provider re-embedding during restore: violates offline/isolation and may drift.
- Treating a created archive as verified without read-back/restore drill.

## Consequences

Machine-loss recovery requires the owner to retain portable recovery material, and restore needs extra
disk/time for isolated generations. Maintenance briefly blocks governed mutations. These costs provide
testable RPO/RTO, portability, and deletion safety.

## Verification

- Backup under ingestion, maintenance boundary, and kill/disk-full/permission/removable-disconnect at
  every phase; no partial is complete.
- Corrupt/missing/swapped/duplicate/path-traversal entry, wrong key/passphrase, altered signature/
  checkpoint/manifest/watermark, and secret canary tests.
- Restore from every supported version into egress-disabled distinct project/generations with packet
  capture and no provider calls.
- Older backup plus newer deletion/revocation, missing/forked head, and non-resurrection tests.
- Graph dump and canonical rebuild paths, incompatible schema/BOM, active-pointer CAS/race/failure, and
  rollback tests.
- Scheduled retention, legal hold, cryptographic erasure, destination absence, 24-hour RPO, 4-hour RTO,
  and quarterly drill evidence.
