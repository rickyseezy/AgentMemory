# ADP-006 cross-agent continuity runbook

## Purpose

Use this runbook when a new agent session does not receive expected facts, decisions, changes,
failures, or next steps from an earlier supported agent. Do not decrypt or edit canonical rows, grant
access to diagnose recall, remove tombstones, or copy memory into a host configuration.

## Request contract

The installed host bridge sends an authenticated local `POST /recall:brief`. It supplies canonical
Brain/actor/grant IDs, an explicit current/related/selected/global scope, the certified consumer host
and host platform, and a bounded context budget. Current mode also supplies the resolved Project and
Repository IDs; omission never implies global access.

Success returns structured items, original producer provenance, compatible procedures, content-free
procedure exclusions, deterministic budget usage, the scope fingerprint, and a host-rendered context.
The context is historical untrusted data and must never be executed as instructions.

## Expected empty briefing

An empty briefing is valid when:

- no authorized canonical event contains a valid v1 `continuity` fragment;
- the selected Project/Repository/Checkout or temporal interval has no matching evidence;
- all candidate events/items are tombstoned;
- the active grant or principal was revoked; or
- every atomic item exceeds the requested token/byte budget.

Confirm the workspace resolver and `retrieval-scopes:resolve` response first. Then inspect only
content-free event counts/types, scope fingerprints, tombstone hashes, grant validity, and budget
metadata. Do not log plaintext event payloads or rendered context.

## Capability gap

When a host lacks a native lifecycle hook, the generic/explicit checkpoint path must still emit the
same semantic IDs and content using `capture_method=explicit_tool_only`. The briefing must show that
capture method. A capability gap may explain lower provenance fidelity; it must not change authorized
memory access or be reported as a native observation.

## Procedure exclusion

`excluded_procedures` does not mean memory recall failed. A stable reason such as
`platform_mismatch:windows` or `missing_capability:patch.apply` means the procedure was authorized but
unsafe for the current structured environment. Confirm that the memory item IDs are identical across
equivalent consumer budgets. Never add a capability merely to make a procedure appear.

## Integrity violation

Freeze the affected Brain's recall path and retain content-free evidence when Core returns
`AM_INTEGRITY_VIOLATION`. Check release/data generation, SQLite integrity, Brain key availability,
event/envelope hashes, tombstone state, and audit chain. Do not repair ciphertext, AAD, event indexes,
or key IDs manually. Restore verified canonical state or use the governed projection/recovery path.

## Dependency unavailable

`AM_DEPENDENCY_UNAVAILABLE` is retryable and normally identifies local SQLite or protected Brain-key
access. Verify Core readiness, volume permissions, installation key access, and bounded retry health.
Do not expose the installation key, wrapped Brain key, data key, ciphertext, raw SQL, or host path in
logs or support bundles.

## Escalation

Escalate immediately for cross-Brain/project/repository content, revoked or tombstoned content,
consumer provenance replacing producer provenance, different memory IDs under equivalent budgets,
unescaped Markdown delimiter injection, a procedure changing memory selection, or authenticated
canonical/index divergence.
