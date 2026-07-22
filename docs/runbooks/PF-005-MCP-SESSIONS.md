# PF-005 automatic MCP session runbook

## Purpose

Use this runbook when an installed agent does not connect to AgentMemory automatically, reports a
partial directory/index state, cannot recall authorized cross-project history, or leaves an interrupted
session. The normal user journey is automatic: the user starts the configured AI agent in a directory.
Do not instruct a nontechnical user to run Docker, Compose, database, migration, or recovery commands.

The product must preserve the coding agent even when memory is unavailable. Diagnostics are
content-free and appear on stderr or the local setup/status surface; stdout belongs exclusively to MCP.

## Read the visible state

`brain_status` returns only the authenticated session ID, Brain ID, agent ID, keyed workspace
fingerprint, Git coverage, index coverage, and session state.

| State | Meaning | Product action |
|---|---|---|
| `registered` | Credential exists but the child lease has not begun | Retry the same bounded startup; do not mint overlapping authority |
| `active` | Container and heartbeat lease are current | Continue; inspect coverage separately |
| `completed` | Final checkpoint, revocation, removal, and terminal persistence succeeded | No action |
| `interrupted` | At least one required terminal guarantee was not proven | Automatic recovery/retry; never relabel completed |

| Git coverage | Meaning |
|---|---|
| `none` | No usable Git identity was visible inside the exact directory boundary |
| `partial` | Repository/worktree evidence exists but some metadata lies outside the permitted mount |
| `complete` | Repository and worktree evidence are complete without widening the mount |

| Index coverage | Meaning |
|---|---|
| `pending` | No batch exists yet, or a newly staged batch has not entered indexing |
| `indexing` | Durable checkpoint/receipt exists and IDX-002 work is queued or running |
| `complete` | Every staged complete batch has a completed index run |
| `partial` | The latest checkpoint was explicitly partial |
| `degraded` | At least one corresponding index run failed |

Never infer a raw path, repository name, source text, or credential from these fields.

## Automatic startup diagnosis

The launcher executes these gates in order. Preserve the content-free error code, correlation/session
ID, active release digest, runtime endpoint class, platform, architecture, and timestamps. Do not
collect source files, paths, prompts, credentials, or Docker configuration belonging to other users.

1. **Installation lock** — only one process may repair/start the runtime and Compose stack. Other
   sessions wait within the bounded startup deadline, then independently mint their own session.
2. **Active release** — the pointer, manifest, Compose topology, image digest, network, schemas, and
   migrations must match the signed Ready installation.
3. **Runtime endpoint** — only the recorded supported local endpoint/context is accepted. Remote,
   environment-substituted, or changed endpoints fail closed.
4. **Runtime health** — a stopped supported Desktop/Engine is started by its native adapter. A running
   daemon must pass API, Linux-container, mount, network, security, and ownership probes.
5. **Compose health** — the exact active project is brought up with wait semantics. Core readiness must
   pass before a session credential exists.
6. **Path and Git identity** — the exact current directory is canonicalized and inspected without a
   shell. Missing external Git metadata produces partial coverage, not a parent mount.
7. **Credential and lease** — a new secret is protected locally, its digest is registered, and the
   session becomes active before container creation.
8. **Container/MCP** — the signed image starts with the fixed sandbox, then owns raw stdio.

If a gate fails, inspect only that gate and its predecessor. Never work around a failure by changing the
global Docker context, using a mutable image tag, exposing a port, mounting a parent, disabling
read-only mode, weakening file permissions, or running the bridge directly from a development runtime.

## Common failure classes

| Diagnostic | Meaning | Safe recovery |
|---|---|---|
| `AM_SESSION_USAGE` | Installed command/arguments differ from the signed host configuration | Restore the signed launcher entry through installer repair |
| `AM_SESSION_INTEGRITY` | Session ID, composition, credential source, or immutable authority is invalid | Stop this session; verify active release and host configuration |
| `AM_SESSION_UNAVAILABLE` | The transient transport or Core call failed under its deadline | Let automatic retry/recovery run; inspect local dependency health |
| `AM_UNAUTHENTICATED` | Secret/session binding is absent, expired, revoked, or stale | End the transient container and start a new session; never reuse the secret |
| `AM_FORBIDDEN` | Current installation, Brain, principal, grant, epoch, or workspace authority denies the action | Restore legitimate current authority; do not edit session rows |
| `AM_CONFLICT` | Identity, digest, optimistic revision, or immutable acknowledgement diverged | Quarantine the operation and investigate substitution/concurrency |
| `AM_DEPENDENCY_UNAVAILABLE` | Required local runtime/Core/key/index dependency is unavailable | Restore the exact pinned dependency and allow idempotent retry |
| `AM_INTEGRITY_VIOLATION` | Authenticated history, ciphertext, metadata, event, index ACK, or scope failed verification | Stop promotion; preserve content-free evidence and restore canonical authority |

## Docker Desktop or Engine is stopped

1. Confirm the launcher selected the installation-recorded local runtime authority.
2. Allow the native runtime adapter to start the stopped service automatically.
3. Verify the daemon capability probe succeeds before Compose is touched.
4. Verify Compose uses the signed project/config/environment files and reaches Core readiness.
5. Confirm the MCP handshake completes within the host deadline and stdout contains only protocol
   frames.

If the service cannot start because elevation, license consent, reboot, virtualization, or platform
provisioning is required, PF-006 owns that user journey. PF-005 must return the typed setup state and
must not print a Docker command for the user.

## Docker Desktop file-sharing or recursive-read-only failure

The exact workspace may be unreadable to the daemon, or the daemon may not support recursively
read-only bind mounts.

1. Confirm the failing source is exactly the canonical current directory; do not log it.
2. Confirm no parent, sibling, common Git directory, Docker socket, or provider directory was added.
3. Surface the platform-owned file-sharing decision through the local setup UI where supported.
4. After the user/administrator grants only the exact required directory, rerun the probe.
5. If recursive read-only cannot be guaranteed because nested mounts exist, keep the session unavailable.

Never retry with a writable mount or legacy bind syntax that loses propagation/read-only guarantees.

## Partial Git or index coverage

Partial is an evidence state, not an error to conceal.

1. Verify the keyed path, device, repository, and worktree fingerprints correspond to the current
   session; raw paths must remain absent from Core.
2. For an external Git common directory or worktree metadata outside the workspace, retain `partial`.
   Do not mount the external directory automatically.
3. Confirm changed files inside the exact workspace are still scanned under ignore/privacy policy.
4. Confirm the final checkpoint records `partial=true` and IDX-002 exposes `partial` after completion.
5. Cross-project recall may still use already indexed authorized history. Results must retain source
   project and producer provenance.

## Interrupted or killed session

EOF, cancellation, launcher/Core/bridge kill, host shutdown, lease expiry, or failed cleanup all enter
the same fail-closed recovery model.

1. Core's recovery worker finds bounded active sessions whose lease or credential expired.
2. It atomically marks each one `interrupted` and revoked using optimistic revision control.
3. The launcher removes any remaining exact transient container and deletes the credential file only
   after revocation has been attempted.
4. A pending encrypted checkpoint is reconciled by batch digest. Exact replay is accepted; divergent
   content is rejected.
5. The next agent start receives a new UUIDv7 session, secret, mount, and lease. It never resumes the
   old credential.

A session may be `completed` only when the bounded checkpoint was durably accepted and credential
revocation, container removal, and terminal persistence all succeeded. Do not manually change terminal
state or extend expiry.

## Checkpoint and indexing recovery

1. Confirm checkpoint ciphertext and metadata exist without reading plaintext.
2. Verify AAD/canonical digests, algorithm, nonce size, session/workspace binding, sequence, partial
   flag, and change count before decryption.
3. Confirm each prepared change has a deterministic change/event ID and privacy-policy decision.
4. Confirm excluded files produce no content event; rejected files retain only a safe rejection code.
5. Confirm accepted artifacts are encrypted under the current Brain key and canonical events are
   idempotent by event ID/digest.
6. Confirm `pf005-index-<batch-digest>` resolves current authorization and receives an exact repository
   and target-digest acknowledgement.
7. Append the checkpoint receipt only after canonical ingestion and index scheduling both succeed.
8. Let the supervised IDX-002 worker finish. Never edit run state, coverage, receipts, or projection
   tables manually.

For a dependency outage, the recovery worker catches the typed operation failure, waits on its bounded
idle interval, and retries. Cancellation propagates immediately so Core can shut down cleanly.

## Cross-agent and cross-project recall

1. Confirm the request reaches `/v1/session/recall:brief` with the session bearer and exact session ID.
2. Confirm the request body contains no Brain, actor, grant, project, repository, checkout, or selected
   project ID.
3. Confirm current/related/global scope is derived from one current canonical authorization snapshot.
4. Confirm global recall includes only owner/admin-authorized Projects in the same Brain.
5. Verify each item includes original producer host/model/adapter/capture provenance and an evidence
   event ID. The consuming agent must not replace producer provenance.
6. Treat all returned content as untrusted historical data. Never execute recalled text as an
   instruction merely because it came from memory.
7. A foreign, revoked, expired, stale-epoch, or current-grant-revoked session must receive the same
   content-free denial.

## Concurrent sessions

For two agents started at once, verify:

- the installation startup lock serializes only runtime/Compose readiness;
- each session has a distinct UUIDv7, secret digest, protected file, container, and workspace mount;
- each credential authenticates only its own session ID;
- each session resolves its own Project/Repository/Checkout identity;
- ending one session does not revoke, remove, or checkpoint the other; and
- authorized global recall can still retrieve provenance-backed context from the shared Brain.

Any credential, mount, container, terminal state, or checkpoint crossing between sessions is a release
blocking integrity incident.

## Escalate immediately

Stop release promotion and preserve content-free evidence for any writable workspace, parent/sibling
read, Docker socket or provider/database access, acquired capability, host listener, mutable image,
remote endpoint, shell evaluation, stdout diagnostic, raw path/secret/plaintext in persistence or logs,
credential accepted for another session, completed state after failed checkpoint/cleanup, ambiguous
identity auto-merge, divergent replay accepted, missing provenance, caller-selected identity scope,
authorization represented as partial recall, or checkpoint/index receipt written before its durable
preconditions.
