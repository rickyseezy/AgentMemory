# PF-003 adapter extension runbook

## Purpose

Use this runbook to approve, diagnose, disable, replace, or re-register an external agent/provider
adapter. Do not edit registry tables, operation receipts, audit events, outbox messages, package
digests, or live-probe evidence.

## Preconditions

- Core and the signed launcher are Ready at their certified migration/release heads.
- The package is installed by the PF-001/PRO-002 verified package boundary, not copied into a Core
  container or mounted through the Docker socket.
- Package subject, signature bundle, publisher, SBOMs, provenance, license, and vulnerability evidence
  are exact and approved.
- The actor has a current owner/admin grant for the target Brain.
- Requested permissions have been explained and explicitly approved when they exceed defaults.

## Register

Call `POST /v1/adapter-extensions:register` over the authenticated loopback API. Set
`Idempotency-Key` equal to `operation_id`. Use the exact manifest shipped with the signed package and a
canonical UTC `requested_at` value. Never retry with altered content under the same operation ID.

A successful response contains only registration ID, Brain ID, adapter identity/kind, negotiated
protocol, capabilities, state, timestamps, and manifest/package/evidence/registration digests. Retain
these fields with the installer operation receipt.

## Failure handling

| Code | Meaning | Action |
|---|---|---|
| `AM_FORBIDDEN` | Bearer, principal, grant, role, Brain, or permission policy denied | Reauthenticate and review current authority; never bypass the check |
| `AM_UNTRUSTED_ADAPTER` | Publisher/signature/package binding failed | Quarantine bytes and compare signed release evidence |
| `AM_CONFLICT` | Operation reuse or immutable version drift | Use the original request, or publish a new semantic version |
| `AM_ADAPTER_CONFORMANCE_FAILED` | Live challenge, protocol, capability, digest, timeout, or framing failed | Preserve content-free digests and rerun the SDK conformance suite |
| `AM_DEPENDENCY_UNAVAILABLE` | Local registry/runtime dependency failed | Restore the local component and retry the exact operation |
| `AM_VALIDATION` | Manifest or request violates v1 | Correct the author-owned package/manifest and publish a new signed artifact when bytes change |

Never paste raw adapter stdout/stderr, manifests containing local paths, credentials, prompts,
transcripts, source code, vectors, or provider payloads into an incident ticket.

## Integrity investigation

Verify, in order:

1. package and signature digests against the retained signed artifact;
2. publisher allowlist and release trust root;
3. manifest canonical digest and kind-specific capability/permission sets;
4. selected highest mutual protocol;
5. fresh challenge echo and independently observed runtime digest;
6. one immutable registration and expected operation receipts;
7. matching content-free domain event/outbox payload hash; and
8. audit `previous_hash`/`event_hash` continuity and exact actor/Brain lineage.

Any mismatch is a quarantine event. Do not repair evidence in place.

## Replacement and rollback

An adapter version is immutable. Build, sign, and register a new semantic version for any byte,
capability, protocol, or permission change. Runtime composition must keep the old and new IDs/kinds
isolated. Roll back by selecting the previously approved immutable registration; never repoint a
version to different bytes.

Deletion/disable transitions are governed by SEC-008 and the later adapter lifecycle operation. Until
that operation commits, stop routing new work and preserve immutable PF-003 evidence for audit and
incident analysis.
