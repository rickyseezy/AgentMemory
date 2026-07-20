# ADP-005 local spool recovery runbook

This runbook is for support and release engineering. Normal users install the AgentMemory MCP/host
adapter and take no recovery action: the launcher creates protected state, starts the local Docker Core,
and supervises the spool worker automatically.

## Normal behavior

| Condition | Capture result | Local action | Recovery action |
|---|---|---|---|
| Core healthy | `accepted` / `duplicate` | No spool write | None |
| Core stopped/restarting | `deferred` | Encrypted event committed locally | Worker retries automatically |
| Spool at configured bound | `spool_full` | No eviction and no false ACK | Restore Core; investigate retained non-durable items |
| Spool/key unavailable | `spool_unavailable` | No plaintext fallback | Repair protected installation state |
| Event invalid before capture | `invalid` | Nothing persisted | Correct the producing adapter |

The worker is silent during normal retry and drain. Docker restarts and upgrades do not require a manual
replay command.

## Launcher-owned configuration

The installer writes one owner-only JSON file and two distinct owner-only 32-byte secrets: the Core API
capability and spool-encryption key. The document supplies only:

- fixed loopback Core endpoint;
- protected credential and spool-key file paths;
- protected spool database path;
- finite record/byte and batch bounds;
- lease/upload timeouts; and
- finite retry/idle/fairness policy.

The upload timeout must be shorter than the recovery lease. Configuration, secret, and database paths
must never be provided through MCP input, project files, the current directory, or environment-variable
overrides. Do not reuse the Core installation root key as the spool key.

## Content-free health triage

1. Confirm the installed launcher and adapter package are the active signed release.
2. Confirm the local Core readiness endpoint is healthy on its installation-bound loopback port.
3. Confirm exactly one launcher-supervised `agentmemory-spool-worker` is running. A second instance is
   safe but should report `busy` internally until the finite lease is available.
4. Confirm the spool directory is owner-private, the database is a regular `0600` file, and both secret
   files satisfy the protected-file policy. Do not print or copy their contents.
5. Allow one retry interval after Core readiness. Pending count should decrease in bounded batches.
6. If count does not decrease, inspect only content-free result categories. Never dump canonical event
   bytes, SQLite ciphertext, bearer credentials, or key material into support logs.

## Result handling

- `accepted`: Core durably committed this item. The worker may advance its per-key watermark and erase
  local ciphertext.
- `duplicate`: Core proved the same canonical item was already committed. It has the same deletion
  authority as accepted.
- `retryable`: dependency or whole-request failure did not prove durability. Retain and retry.
- `rejected`: schema/scope/capability authorization failed. Retain; repair the adapter registration or
  installation authority before retrying.
- `conflict`: immutable event identity/order was reused for different content. Retain; quarantine the
  producing adapter release and investigate without deleting evidence.

A later accepted item never bypasses an earlier non-durable item under the same ordering key. Independent
ordering keys can progress.

## Safe restart and upgrade

1. Stop the affected host adapter/worker through the launcher so SIGTERM can release the lease.
2. Upgrade or restart the local Core through the signed launcher workflow. Do not edit generated Compose
   files or start an alternate container on the bound port.
3. Start the installed adapter. The worker reopens the same protected spool, recovers an expired crash
   lease if necessary, and resumes from persisted per-key watermarks.
4. Verify Core readiness and eventual pending-count reduction. Occurrence timestamps must remain the
   original canonical values; ingestion timestamps and clock skew are expected to reflect Core commit.

An abrupt worker kill is safe. Unacknowledged ciphertext remains, and the next worker recovers after the
finite lease expires. A Core crash before commit yields no durable item result; a retry is idempotent. A
Core crash after commit yields `duplicate` on retry and safely authorizes deletion.

## Key and corruption incidents

- Never replace or delete the spool key while pending records exist. A wrong key or modified
  nonce/ciphertext/AAD fails closed and cannot be treated as an empty spool.
- Never loosen directory/database permissions to make recovery proceed.
- Preserve the protected installation directory for forensic handling. Do not upload it to a hosted
  service.
- If an ACK transaction is interrupted, restart normally. Atomic SQLite commit leaves either the old
  ciphertext/watermark or the new watermark with ciphertext removed.
- Only accepted/duplicate item evidence can erase data. There is no force-delete recovery switch.

When retention must be overridden for privacy or legal reasons, use the product's explicit deletion and
audit workflow once implemented; do not manipulate the spool database manually.
