# PF-004 safe-degradation runbook

## Purpose

Use this runbook when recall reports unavailable channels, capture reports a degraded status, or the
local recovery queue is not draining. Degradation is an explicit product state, not permission to
disable authorization, integrity, deletion, encryption, or bounded-capacity controls.

## Read the evidence

Recall returns one status and UTC freshness watermark per configured channel:

| Status | Meaning | Immediate action |
|---|---|---|
| `available` | The channel completed under its deadline | Use the result and inspect freshness normally |
| `unavailable` | Its adapter returned a typed dependency failure | Check only that dependency |
| `timed_out` | A started call exceeded the smaller channel/caller deadline | Check latency and local resource pressure |
| `circuit_open` | Calls are suppressed until the half-open interval | Restore dependency health and wait for one probe |

Capture returns `deferred` only after the encrypted spool commit. `spool_full`, `spool_unavailable`, or
`deadline_exceeded` means capture durability was not confirmed and must be surfaced as a nonblocking
diagnostic. Never infer success from the absence of an exception.

## Dependency diagnosis

1. Preserve the request correlation ID, channel outcomes, freshness values, current release digest,
   and content-free logs. Do not collect prompts, queries, code, vectors, memory text, credentials, or
   raw provider responses.
2. Check Core readiness and the exact failing local container/provider health probe.
3. For `neo4j`, verify the pinned Neo4j container and schema head without changing graph data.
4. For `embedding`, `reranking`, or `extraction`, verify the selected immutable provider/model profile,
   resource availability, and its bounded capability probe. Do not silently switch providers or
   embedding spaces.
5. For `noncanonical_worker`, inspect its supervised process and queue lag. Do not edit queue rows.
6. For a canonical-ledger failure, treat exact recall and direct capture as unavailable. Confirm that
   the host reports `deferred` before assuming the event is protected.

After repair, the first eligible request becomes the sole half-open probe. A successful probe closes
the circuit. If it fails, the circuit reopens for the configured interval. Restarting Core resets the
process-local circuit registry but does not change canonical data or queued capture.

## Capture queue diagnosis

1. Confirm the spool database, key, and parent directory are owned by the invoking user and are not
   symlinks. Do not copy the key or database into an incident ticket.
2. Inspect only content-free queue count/byte metrics and the recovery worker status.
3. For `spool_full`, free unrelated disk space or restore Core. Do not delete queued rows and do not
   raise configured bounds beyond the certified local resource profile.
4. For `spool_unavailable`, correct permissions, key access, or filesystem health. Never recreate the
   key for a nonempty spool; doing so makes queued ciphertext unrecoverable.
5. For `deadline_exceeded`, inspect filesystem latency and resource saturation. A background atomic
   write may have completed after the host returned, so identify the event by ID and allow normal
   idempotent recovery; do not enqueue a modified payload under the same ID.

## Recovery verification

The supervised worker recovers automatically; the user should not need a terminal command.

1. Confirm only one worker owns the renewable recovery lease.
2. Confirm batches stay within configured item/byte limits and upload timeout remains below lease time.
3. Verify pending count decreases only after Core returns `accepted` or `duplicate` with complete time
   evidence.
4. Confirm a retry of an already committed event returns `duplicate`, advances the same ordering-key
   watermark, and leaves one effective canonical event.
5. Confirm later events for an ordering key remain queued behind a retryable earlier event; independent
   ordering keys may continue.
6. When the queue reaches zero, verify recall/channel freshness catches up through normal projection
   workers. Never patch freshness fields or derived stores manually.

## Escalate immediately

Stop release promotion and preserve evidence for any authorization failure represented as partial
success, canonical-integrity failure represented as degradation, missing channel outcome, freshness
without a UTC watermark, duplicate effective canonical event, spool plaintext, authentication-tag
failure, foreign/missing upload response identity, non-prefix acknowledgement, or `deferred` result
returned before a durable spool commit.
