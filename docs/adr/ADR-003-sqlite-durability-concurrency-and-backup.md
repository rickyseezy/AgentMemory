# ADR-003: Packaged SQLite durability, writer ownership, jobs, and online backup

- Status: Accepted
- Decision owners: Data Persistence Owner and Operations Owner
- Consulted owners: Ingestion, Audit, Backup/Restore, Security
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before SQLite, filesystem, checkpoint, pool, or backup changes
- Supersedes: None
- Related requirements: Technical Requirements Sections 2.1, 4.2-4.4, 7.2-7.4, and 11.4 ING-001/ING-004

## Context

SQLite is the canonical acknowledgement boundary on user-owned machines. Durability depends on the
packaged library, pragmas, one writer owner, filesystem/volume semantics, WAL handling, queue leasing,
and use of the online backup API rather than copying live files.

## Decision

### Packaged engine and storage

Core ships and loads SQLite 3.53.3 or the exact newer version named by the release BOM. Startup checks
`sqlite_version()` and an allowlisted compile-option manifest; an OS SQLite or unexpected library is
rejected. SQLite and WAL live together in the installation-labelled local Docker named state volume.
NFS/SMB/network/synchronized/project bind storage is unsupported and blocks readiness.

Exactly one persistent core process opens an active database. Within it, one `WriteCoordinator` owns
one long-lived write connection and serializes write UoWs through a bounded priority queue. Separate
read-only connections may serve bounded queries under WAL snapshots; they cannot execute write SQL or
change pragmas. MCP, sidecars, Neo4j, and UI never mount/open the volume.

### Verified connection policy

Every connection sets and reads back:

- `journal_mode=WAL`;
- `synchronous=FULL`;
- `foreign_keys=ON`;
- `busy_timeout=5000` milliseconds;
- `secure_delete=ON` when compiled/supported;
- `locking_mode=NORMAL`;
- `temp_store=MEMORY`; and
- `trusted_schema=OFF` for application connections where packaged extension behavior permits it.

The writer sets `wal_autocheckpoint=1000` pages. Automatic checkpoints are passive and must not block
interactive work indefinitely. A `TRUNCATE` checkpoint is permitted only in exclusive maintenance
after the backup/job watermark and active readers are verified; WAL bytes are never removed merely to
meet a size target. The application does not load arbitrary SQLite extensions.

Startup also verifies file owner/mode through the volume/container policy, local capacity, encryption
key access, migration head, `PRAGMA integrity_check`, foreign-key integrity, and recovery of expired
leases. A failed required check keeps governed mutation/readiness disabled.

### Transaction and acknowledgement policy

Ordinary UoWs are explicit and short. Commands requiring serialization—policy/grant changes,
generation cutover, procedure promotion, installation pointer, and job leasing—use `BEGIN IMMEDIATE`.
All writes use aggregate CAS/unique constraints. Busy or version conflicts map to typed retry/conflict;
last-write-wins is forbidden.

AgentEvent ACK follows only successful return from COMMIT on the FULL-synchronous writer transaction
that includes event, artifact reference, outbox, and required audit state. No response buffering,
Neo4j write, or in-memory queue can move the ACK boundary earlier. Disk-full/fsync/I/O failure returns
no ACK and transitions capacity/integrity state safely.

### Queue leasing

Ready jobs are selected in stable priority, `next_attempt_at`, and UUID order. Claim uses
`BEGIN IMMEDIATE`, sets a random worker lease owner and 60-second `lease_until`, then commits before
work. Heartbeat extends at 20 seconds only for the same owner/attempt. Completion verifies ownership
and writes result/inbox/next-outbox/audit in one UoW. Lease expiry never rewinds history; it creates a
new attempt. Cancellation changes state only at a declared safe boundary.

At 80% state-volume utilization, pause/throttle background indexing, migration, and evaluation. At
95%, reject new durable capture before false ACK with `AM_CAPACITY_EXHAUSTED`; existing acknowledged
work remains intact. Capacity calculations include database, WAL, CAS reserve, migration, and backup
headroom.

### Online backup

Backup enters application maintenance, blocks new governed mutations, drains or records job/outbox
watermarks, and uses SQLite's online backup API from a committed snapshot into a new file. It never
copies a live database/WAL pair with filesystem reads. The copy must pass `integrity_check`, foreign-key
check, schema/migration head, row-count/hash/watermark comparison, and archive manifest binding before
it is marked complete.

The backup adapter may open the active database through the core-owned connection or a coordinated
read connection. A standalone one-shot tool opens a generation only after core is stopped/exclusive
maintenance is proven. Restore writes a new isolated generation and never opens archive SQLite as the
active database. Activation is governed by ADR-015.

### Corruption and recovery

WAL recovery after ordinary crash is delegated to the packaged SQLite engine and then verified.
Checksum/integrity failure enters read-only recovery; automated repair never drops rows, recreates
canonical state from Neo4j, or edits WAL bytes. Recovery requires a verified backup or an explicitly
supported SQLite recovery procedure that writes a new shadow database and passes full canonical
validation before owner activation.

## Security and privacy impact

One writer owner prevents confused concurrent access. Foreign keys, constraints, trusted-schema-off,
no extensions, prepared statements, file/volume isolation, and encrypted artifact references reduce
tamper/injection risk. SQLite searchable data still depends on host full-disk encryption under
ADR-010. Backups are envelope-encrypted before leaving operation storage.

## Compatibility, migration, and rollback

SQLite upgrades are exact BOM changes with format/compile-option, migration, replay, backup/restore,
performance, and previous-release tests. SQL schema changes use Alembic expand/migrate/contract and
closed lowercase CHECK values. A target migration never overwrites the last-known-good generation when
backward read is uncertain. Rollback uses prior compatible binaries/generation or verified archive,
never an unsupported SQLite downgrade.

## Rejected alternatives

- Host SQLite: version/compile/fsync behavior is not controlled.
- Multiple writer processes or direct bridge access: breaks ownership and backup guarantees.
- `synchronous=NORMAL/OFF`: violates acknowledged-event durability.
- Rollback journal mode: weakens reader concurrency and operational profile.
- Live file/WAL copying: cannot establish a consistent recovery point.
- Network/project bind storage: SQLite WAL durability/locking is not certified there.
- An external queue database/broker: unnecessary additional canonical state.

## Consequences

Write throughput is bounded by one durable writer and FULL commits. This matches a single-user local
product and makes the durability promise auditable. Expensive work stays outside write transactions.

## Verification

- Assert library version/compile options and every pragma on startup and in integration tests.
- Kill/power-fault at begin/write/commit/ACK/checkpoint and verify zero acknowledged loss.
- Test disk full, I/O/fsync failure, busy timeout, CAS conflicts, concurrent readers/writers, and WAL
  growth/checkpoint policy.
- Lease property tests cover expiry, heartbeat, duplicate worker, retry, cancellation, and DLQ.
- Online backup under concurrent ingestion validates snapshot watermark and recovery; ordinary live
  copy is detected as an invalid test fixture.
- Reject NFS/SMB/synchronized/project storage and second-process writers.
- Restore into a new generation and run deletion/audit/Brain-isolation/golden-recall checks.
