# ID-002 Checkout continuity runbook

## Purpose

Use this runbook when a moved checkout is not recognized, a clone/worktree was merged incorrectly,
an observation returns `AM_CONFLICT`, or Checkout history cannot be appended. Do not edit Checkout,
event, or observation rows manually. Historical observations and canonical events are immutable.

## Safe diagnosis

1. Record the content-free correlation/operation ID, time, agent adapter version, OS family, and Core
   release. Do not collect raw paths, remote URLs, repository contents, credentials, or prompts.
2. Confirm Core readiness reports relational head `0004_id002_checkout_observation` and a passing
   SQLite integrity result.
3. Confirm the session bridge sent a verified Device plus non-null logical path, real path,
   filesystem-object, Repository, common-directory, worktree, HEAD, and dirty fingerprints. Compare
   only keyed digests and UUIDs.
4. Confirm the exact principal and grant are active for the Brain. A 403 is an authorization issue,
   not evidence that the Checkout is missing.
5. For `AM_CONFLICT`, count continuity candidates by Checkout UUID. More than one is a protected
   ambiguity. Preserve the evidence and escalate for an explicit future identity-correction command;
   never select a row manually.
6. For a stale version conflict, resolve the current Checkout again, observe current Git/device
   evidence, and retry with a new operation ID and the returned version. Reusing the same operation ID
   returns the original result and must not be used for a different observation.

## Expected behavior

- Moving a directory on the same verified filesystem preserves the filesystem-object and Git
  worktree fingerprints, retains Checkout ID, increments version, and emits `CheckoutMoved`.
- A symlink alias with the same resolved path retains Checkout ID and emits `CheckoutObserved`.
- A clone has new filesystem/common-directory/worktree evidence and receives a new Checkout ID even
  when Repository history matches.
- A linked worktree shares Repository and common Git-directory evidence but has a distinct worktree,
  path, branch/HEAD/dirty snapshot, and Checkout ID.
- A remote-only or revision-only change preserves Checkout ID and emits `CheckoutObserved`.

## Recovery

- Dependency failure: restore the local filesystem/Git/SQLite dependency, verify readiness, then
  retry the exact command only when its observation is unchanged. Otherwise use a new operation ID.
- Stale writer: re-resolve and retry from the current version. Never bypass the version predicate.
- Ambiguous continuity: stop automatic adoption and retain separate Checkout identities. Await an
  authorized correction workflow; SQL edits are unsupported.
- Damaged database or missing canonical history: stop Core and use the governed backup/restore and
  integrity procedures. Do not reconstruct observations from the mutable Checkout snapshot.
- Migration rollback: downgrade is safe only when no ID-002 canonical events exist. Once events
  exist, keep the newer binary/schema or restore a pre-ID-002 backup. The deliberate downgrade
  refusal prevents silent provenance loss.

## Verification after recovery

Submit a new path-free observation and verify one event and one immutable observation were appended,
the Checkout version advanced exactly once, retry returns the same result, no raw path/remote appears
in logs or responses, and the full readiness probe remains green.
