# ADP-003 adapter capability runbook

Use this runbook to register an agent adapter version, observe permission changes, inspect effective
telemetry, and diagnose a rejected event. All requests use the owner-protected local launcher
credential over the loopback Core endpoint. Never place the credential, raw prompts, source content,
paths, or host diagnostics in a capability manifest.

## Register a version

1. Verify the adapter binary and calculate its lowercase SHA-256.
2. Build a complete matrix with one entry for every capability in the current contract.
3. Mark only directly delivered signals `native`; use `inferred` only for documented observable
   derivation and `explicit_tool_only` only when the agent must call a public tool.
4. Mark unavailable signals `unsupported`. Use the command's `permission_denied` list only when a
   declared observable signal is currently blocked by host/user permission.
5. Send `POST /v1/agent-adapters:register` with the same unique operation ID in the
   `Idempotency-Key` header and body.
6. Retain the returned manifest digest with the adapter release. Do not reuse the semantic version if
   any declared evidence changes.

Successful first registration returns `registered`. An exact network retry returns `duplicate`; a
new operation with identical effective state returns `unchanged`. `AM_CONFLICT` means either the
adapter version or operation ID was reused with different input. Allocate a new adapter semantic
version or correct the caller; never edit database rows.

## Observe permission loss or restoration

Send the complete current matrix to
`POST /v1/agent-adapters/{adapter_id}/versions/{adapter_version}:observe`. Bind the exact adapter
binary and manifest digests returned at registration. A permission loss changes only affected
observable entries to `permission_denied`; restoration changes them back to their declared method.

The response returns revision `N+1`, disposition `observed`, and one warning per transition. The
affected event families fail admission while permission is denied. Do not compensate by relabeling
the event as inferred or by emitting an empty/negative observation.

## Inspect operator-visible status

Use `GET /v1/agent-adapters/capabilities` for all active versions or the version-specific capability
route for one adapter. The `warning_limit` query parameter is bounded from 0 through 100. Confirm:

- the adapter binary and manifest digests match the installed release;
- all capabilities are present exactly once;
- supported families have observable required evidence;
- the current revision reflects the most recent permission probe;
- breaking/degraded warnings are understood before relying on affected sessions.

The response is safe for local diagnostics because it contains status metadata only. It still
requires authentication and must not be published with other installation metadata.

## Diagnose rejected capture

| Result | Check | Safe action |
|---|---|---|
| `AM_VALIDATION` | malformed/partial matrix, bad digest/token/version, or mismatched idempotency header | regenerate the complete canonical request |
| `AM_CONFLICT` | immutable version changed, operation ID reused, or observation binds another manifest | use the exact registered identity or release a new adapter version |
| `AM_FORBIDDEN` | local capability credential or event evidence is unauthorized | renew the scoped launcher/session credential; do not widen permissions |
| `AM_NOT_FOUND` | queried adapter version is not registered | complete verified registration before capture |
| `AM_DEPENDENCY_UNAVAILABLE` | canonical SQLite transaction/read is unavailable | retry with the same operation ID after Core recovery |

For an event admission failure, compare its adapter ID/version/binary digest, manifest digest, event
family, and capture method with the version-specific display. If the required capability is
`unsupported` or `permission_denied`, the rejection is correct.

## Recovery and rollback

- Repeat an interrupted command with the identical operation ID and body. Do not generate a new ID
  until the prior outcome is known.
- Restore a lost permission by probing the host and appending a new complete observation.
- Roll back an adapter binary by installing its prior semantic version and using that version's exact
  manifest; never mutate the newer declaration.
- Do not downgrade migration `0008` after any capability command or capability-bound event. The
  migration intentionally refuses evidence loss.
- If relational integrity validation reports malformed manifest evidence, stop affected capture,
  preserve the database, and collect only protected diagnostic metadata for repair. Do not recreate
  or guess declarations from host names.
