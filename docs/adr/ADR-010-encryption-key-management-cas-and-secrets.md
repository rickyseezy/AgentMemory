# ADR-010: Encryption envelope, key management, CAS, disk encryption, and secrets

- Status: Accepted
- Decision owners: Security Owner and Data Protection Owner
- Consulted owners: Runtime/Installer, Persistence, Backup/Restore, Provider Platform
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before algorithm, key source, envelope, CAS, or secret-delivery changes
- Supersedes: None
- Related requirements: PRD Section 15; Technical Requirements Sections 4.7, 6.4, 11.12 SEC-002, and 11.13 OPS-004

## Context

Large payloads, private data, provider credentials, installation/session credentials, and backups need
protection on a local machine. Searchable SQLite/Neo4j/vector data cannot remain application-encrypted
while queried, so application envelopes and host full-disk encryption solve different threats. Compose
file/env/argv delivery would spread secrets into diagnostics and process metadata.

## Decision

### Cryptographic baseline

Production uses reviewed libraries, never custom primitives. Payload and key wrapping use AES-256-GCM
with random 96-bit nonces and 128-bit tags. A platform without a certified constant-time AES-GCM
implementation may use ChaCha20-Poly1305 through a specification revision and new envelope algorithm
ID; it may not silently substitute. SHA-256, HMAC-SHA-256, HKDF-SHA-256, and Ed25519 signatures are
used only through approved libraries for their named purposes.

All random keys/tokens are 256 bits from the OS CSPRNG. Nonce reuse under one key is prohibited; random
nonce generation plus per-object random DEKs makes collision tests/monitoring possible. Authentication
failure is `AM_INTEGRITY_VIOLATION`; plaintext is never returned.

### Key hierarchy

- Installation Root Key (`IRK`): random 256 bits, non-exportable where the OS facility permits, stored
  separately from data volumes. It wraps installation-purpose keys and per-Brain key-encryption keys.
- Identity/locator/journal/audit keys: independent keys derived from or wrapped by IRK with distinct
  versioned purpose labels. A key is never reused across encryption, HMAC, identity, or signing.
- Brain Key-Encryption Key (`BKEK`): random 256 bits per Brain, wrapped by current IRK and stored only as
  authenticated ciphertext plus key IDs.
- Object Data-Encryption Key (`DEK`): random 256 bits per CAS object/revision, encrypts payload and is
  wrapped by that Brain's BKEK.
- Backup DEK/recovery wrappers: independent per archive and governed by ADR-015; backup keys never reuse
  Brain object keys.

Wrapped-key records include envelope version, algorithm, installation/Brain/purpose, wrapping and data
key IDs, created/rotated time, nonce, ciphertext, and RFC 8785 AAD hash. Key bytes never enter SQLite,
Neo4j, graph/vector records, image layers, or logs.

### Host key materialization

The launcher resolves IRK/bootstrap keys from:

- macOS Keychain bound to the invoking user and device;
- Windows Credential Manager with DPAPI user/machine protection;
- Linux Secret Service when available; otherwise an owner-only `0600` regular file with owner-only
  parent directories on a verified local, non-symlink, host-encrypted filesystem.

Platform adapters verify UID/SID owner, ACL/mode, file type, parent traversal, no reparse/symlink,
machine binding, and secret-store status. Unsafe ownership/mode or unavailable required key fails
closed. Secret bytes are materialized only for the exact component/purpose, in bounded locked memory
where supported or an owner/service-readable temporary file on local storage, then best-effort
zeroized/unlinked after use.

### Envelope format

`AMENVELOPEv1` consists of a fixed magic/version/algorithm header, canonical metadata length and bytes,
wrapped DEK record, payload nonce, ciphertext length, ciphertext, and tag. Canonical metadata includes
Brain ID, opaque object ID, original plaintext SHA-256, byte length, media type, classification,
retention policy, key IDs, and schema version. The entire header/metadata is AEAD additional
authenticated data. Readers enforce length limits, reject duplicate/unknown required fields, verify tag
before release, then verify plaintext length and SHA-256.

### CAS layout and behavior

Canonical content hash is SHA-256 of original authorized bytes. Physical key is
`HMAC-SHA-256(BrainLocatorKey, content_sha256)`. Its lowercase hex forms:

`objects/v1/<brain-token>/<hex[0:2]>/<hex[2:4]>/<hex[4:]>.amb`,

where `brain-token` is the first 32 lowercase hex characters of an HMAC over Brain UUID. No raw path,
user text, repository name, or content digest appears in the layout.

Writes use exclusive temp create in the target directory, encrypt/flush, atomic no-follow rename, and
parent-directory flush. CAS is write-once by logical Brain/content digest. Existing object is accepted
only after envelope/tag/plaintext-digest metadata agrees; different content/ciphertext binding is an
integrity incident. Reads check tombstone/authorization before filesystem access and verify envelope.
Logs contain opaque object ID and length only.

### Searchable volume encryption requirement

SQLite, Neo4j, full-text, vector, model cache containing derived sensitive data, and telemetry volumes
reside only on local host storage covered by an attested active full-disk encryption chain: FileVault
on macOS, BitLocker/device encryption on Windows, or LUKS/dm-crypt (or catalog-approved equivalent) on
Linux. The probe validates that Docker's data root/VM disk actually rests on the encrypted device, not
merely that another volume is encrypted.

Readiness for a persistent Brain is blocked when this cannot be attested. The setup UI reports one
plain-language native/administrator action; AgentMemory does not weaken policy or claim application
blob encryption protects searchable plaintext. A future explicit low-sensitivity mode requires a PRD/
specification revision and is not created here.

### SecretRef and resolution

Configuration contains only typed opaque `SecretRef` with provider, purpose, owner component, and key
version. `SecretResolver` authorizes caller component/purpose at resolution time, obtains exact value,
and returns a bounded-lifetime handle. Cache default is zero; an adapter may cache up to five minutes
only when required, keyed by version and invalidated synchronously on rotation/revocation.

Secrets are prohibited in Compose YAML/interpolation, `.env`, environment, argv, labels, image layers,
status/errors, logs/traces/metrics, database/graph/vector records, exports, diagnostics, and backups.
Compose receives owner/service-readable protected files mounted read-only only into the consuming
service. Provider credentials resolve inside gateway, never core/custom adapter.

### Rotation and destruction

IRK rotation creates a new version, rewraps BKEKs and purpose keys resumably, verifies every new wrap,
then retires old IRK only after no live reference and a verified recovery point. BKEK rotation creates
a new key for new objects and resumably rewraps object DEKs; payload need not be re-encrypted. Object
DEK compromise/revocation re-encrypts affected objects into new immutable envelope revisions.

Cryptographic Brain/installation purge destroys all applicable wrapping keys only after tombstone and
resource inventory commit; non-content deletion/audit receipts remain. Backup erasure follows
ADR-011/ADR-015 and cannot claim deletion while a usable wrapper remains.

## Security and privacy impact

Envelope encryption protects CAS/backups against volume/archive theft; FDE protects searchable stores
and Docker VM/data root at rest. Purpose-separated keys limit cross-use. It does not protect an unlocked
host, root, Docker daemon, or running core with keys available. Filenames leak only bounded object
count/size/timing, not path/content digest.

## Compatibility, migration, and rollback

Envelope/algorithm/key versions are explicit. Readers support formats in ADR-016's window. A format
upgrade writes a new immutable envelope revision and verifies before pointer change; old stays for
rollback until deletion/retention permits removal. Key rotation is resumable and rollback retains old
wrappers until every new wrapper verifies. A downgrade never uses an algorithm/key version it cannot
authenticate.

## Rejected alternatives

- Custom crypto or deterministic AES-GCM nonce: unsafe.
- One installation key for every Brain/object/purpose: excessive blast radius and nonce/cross-use risk.
- Plain content hash/path as CAS key: leaks equality/path semantics.
- Secrets in env/Compose: exposed by inspect, crash, and diagnostics.
- Application encryption of searchable columns: incompatible with required search/graph behavior.
- Application envelopes without FDE: leaves SQLite/Neo4j/vector plaintext at rest.
- FDE without object/backup envelopes: removable archives/CAS lose Brain/key granularity.

## Consequences

Readiness depends on platform disk-encryption attestation, and key recovery/rotation adds operational
work. Per-object envelope metadata/storage is larger. The result has explicit deletion, backup, and
cross-Brain key boundaries.

## Verification

- Cryptographic known-answer/envelope parser/property tests, nonce uniqueness monitoring, tamper at
  every byte/length/AAD/wrapped-key field, and wrong Brain/key tests.
- CAS no-follow/ACL/atomicity/crash/concurrency/content-collision and path privacy tests on all OSes.
- Keychain/DPAPI/Secret Service/Linux fallback ownership, unsafe mode, machine/user mismatch, rotation,
  revocation, and interruption tests.
- FileVault/BitLocker/LUKS positive, unencrypted Docker data root, external/network volume, and unknown
  attestation readiness tests.
- Repository/Compose/env/argv/image/log/trace/metric/status/export/diagnostic/backup secret canaries.
- BKEK/IRK rotation and cryptographic deletion prove old wrappers cannot decrypt.
