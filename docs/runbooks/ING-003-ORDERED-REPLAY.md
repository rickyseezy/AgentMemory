# ING-003 causal ordering and replay runbook

## Normal live behavior

For a sequenced ordering key, `completed` means every earlier sequence was applied or an explicit gap
was declared after the configured 60-second timeout. Temporary `causal_order_busy` and
`causal_gap_wait` retries are normal and must not be cleared manually. The first observation fixes the
blocking event's timeout; retries do not extend it.

An outbox/inbox pair in `replay_required` means the event arrived behind an already advanced
watermark. Its canonical event remains intact, but it was deliberately excluded from live projection
state. Treat this as repair work, not as successful ingestion and not as a retryable transport error.

## Start a selected-range replay

Use the authenticated local Core API or the packaged client. Choose:

- one active actor/grant with access to the exact Brain;
- `canonical-event-projection-v1`;
- a new UUIDv7 operation ID and a separate new UUIDv7 projection generation;
- the immutable reducer code fingerprint from the installed signed release; and
- the narrowest inclusive time/event range that contains the causal chain being investigated.

Send the operation ID unchanged as `Idempotency-Key`. An uncertain HTTP response is retried with the
same header and byte-identical body. Do not create a new generation merely because the first response
timed out.

The accepted response is content-free and reports `queued`. Creation has already captured the exact
source event-ID snapshot; newly ingested events cannot enter that run.

## Interpret replay states

- `queued`: durable immutable selection exists and awaits the local worker.
- `building`: the worker owns a bounded lease and is appending only shadow history/state.
- `validating`: the complete shadow state is being compared with equivalent live history.
- `ready`: shadow and live generation digests match; selected replay-required evidence is resolved.
- `superseded`: the deterministic shadow differs from live; no live state was activated and repair
  evidence remains pending.
- `partial`: the cursor is retained, the lease is released, and `failure_code` identifies a bounded
  authorization, dependency, integrity, or internal failure class.

`ready` proves deterministic reproduction. It does not authorize manual pointer changes.
`superseded` commonly confirms that a late event would change history; use the governed PF-002 full
projection rebuild workflow to construct, validate, and atomically activate a complete replacement
generation.

## Diagnose a waiting or declared gap

Through packaged diagnostics, correlate only content-free identifiers and inspect:

1. the Brain/projection/ordering-key watermark and current applied sequence;
2. any exact key lease owner/event/sequence/until;
3. the blocking event's missing `from_sequence`/`to_sequence`, first detection, and timeout;
4. the source outbox/inbox state and its retry time/error code; and
5. canonical presence of the missing predecessor sequence.

Before timeout, allow the consumer to retry. If the predecessor exists but is stuck, diagnose its own
outbox/inbox/lease state. After timeout, the blocker will be recorded as a declared gap and can
advance. Any predecessor that arrives later is retained as replay-required evidence.

Do not infer sequence from timestamps or event IDs. Only the canonical ordering key and sequence are
causal authority.

## Diagnose `partial`

- `authorization_revoked`: verify principal, Brain, grant identity, `valid_from`, and `valid_to`.
  Restore access only through the normal authorization workflow, then let the same run resume.
- `dependency_unavailable`: preserve the complete state volume, check SQLite/storage health, and
  restore the supported dependency before retry.
- `integrity_violation`: stop the affected replay worker, preserve state and audit evidence, run
  packaged SQLite/foreign-key/audit/migration diagnostics, and investigate immutable source,
  recorded provider evidence, cursor, or digest divergence.
- `internal_error`: collect content-free local diagnostics and release/version metadata; do not expose
  event or provider contents in an issue report.

An expired building/validation lease is recovered automatically at startup. The durable processed
count and unique source ordinals ensure resume starts after the last committed shadow append.

## Recorded model/provider evidence

If a reducer depends on nondeterministic work, confirm the event has one projection-specific recorded
operation binding and that the referenced provider operation is completed, belongs to the same Brain
and profile, uses an immutable model revision, and has identical result digest/reference. Replay must
never be made to pass by changing the binding, calling a newer model, or copying another Brain's
result.

## Prohibited recovery actions

Never:

- edit watermarks, sequences, gaps, source ordinals, cursors, digests, leases, or replay states with
  SQL;
- force a late event through the live projection consumer;
- delete a gap or replay-required row to make monitoring green;
- change an event schema version or canonical hash during replay;
- invoke a current provider/model to replace missing historical operation evidence;
- merge shadow records into live tables or activate a partial selected range manually;
- reuse a projection generation for a different range, Brain, fingerprint, or actor/grant;
- delete ordering/replay evidence to force migration downgrade; or
- copy only the SQLite main file without its supported state-volume/backup procedure.

These actions destroy causal evidence and can make an incorrect projection appear deterministic.

## Verification after recovery

Recovery is complete only when:

- SQLite integrity, foreign keys, migration head, audit chain, and FULL/WAL policy pass;
- each ordered key has at most one exact active lease and its watermark digest matches its latest live
  history record;
- every declared gap retains its immutable range/times and each late event retains replay-required
  evidence until a governed repair resolves it;
- the replay source count equals its immutable source snapshot and committed shadow ordinals are
  contiguous from one through processed count;
- a resumed run creates no duplicate shadow history;
- every recorded nondeterministic input matches a completed same-Brain provider result/version;
- `ready` has equal shadow/live digests, while `superseded` has unequal digests and did not change live
  state; and
- an identical replay request returns the existing generation while conflicting identity reuse is
  rejected.
