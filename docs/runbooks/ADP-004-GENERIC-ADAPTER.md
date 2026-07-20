# ADP-004 generic adapter runbook

This runbook is for launcher/integration authors and operators diagnosing a hookless-host session.
Normal installation writes the protected context automatically; users must not be asked to build it,
register the adapter, or invoke Docker.

## Protected context

The launcher writes one regular, owner-only (`0600`) JSON file with exactly these fields:

```json
{
  "endpoint": "http://127.0.0.1:8765",
  "credential_file": "/protected/session/credential",
  "brain_id": "UUIDv7",
  "principal_id": "UUIDv7",
  "project_id": "UUIDv7",
  "repository_id": "UUIDv7",
  "checkout_id": null,
  "branch_name": "main",
  "commit_sha": "40-or-64-lowercase-hex",
  "session_id": "UUIDv7",
  "task_id": "UUIDv7-or-null",
  "correlation_id": "UUIDv7-or-null",
  "ordering_key": "UUIDv7-or-null",
  "classification": "local_only",
  "retention_policy_id": "default",
  "adapter_version": "1.0.0",
  "adapter_digest": "signed-release-sha256",
  "redaction_patterns": []
}
```

The credential file is a separate owner-only regular file containing exactly 32 random bytes. The
context file contains no credential value. Neither file may be a symlink or hard link. The launcher
removes both after the session lease ends.

## Operations

The executable automatically registers the exact generic manifest before every operation.

Wrap an agent process while preserving live stdio:

```text
agentmemory-generic --config <protected-context> wrap --cwd <workspace> -- <agent> <args...>
```

Import an existing transcript using an explicit format and encoding:

```text
agentmemory-generic --config <protected-context> import-transcript \
  --format json_lines --encoding utf-8 <transcript-file>
```

Record a checkpoint from an owner-only summary file:

```text
agentmemory-generic --config <protected-context> checkpoint \
  --checkpoint-id <client-generated-UUIDv7> --summary-file <protected-summary>
```

Serve only the explicit checkpoint MCP tool over stdio:

```text
agentmemory-generic --config <protected-context> mcp
```

Diagnostics go to stderr. MCP mode reserves stdout exclusively for newline-delimited JSON-RPC.
Generate a new UUIDv7 when the checkpoint first occurs and reuse that exact ID and summary for every
retry. The ID's embedded UTC millisecond is the durable checkpoint occurrence time.

## Transcript source contract

Select exactly one format: `plain_text`, `json_lines`, or `json_array`. Structured records have this
shape; unknown properties are ignored except prohibited hidden-reasoning properties, which reject the
record recursively:

```json
{"role":"user|assistant|tool|system|unknown","content":"text","timestamp":"UTC RFC3339"}
```

Select exactly one encoding: `utf-8`, `utf-8-sig`, `utf-16-le`, or `utf-16-be`. BOM encodings require
the matching BOM; plain UTF-8 rejects any BOM. An abrupt source uses `--completion abrupt` and retains
the final unterminated line when it is valid.

## Privacy policy

Create `.agentmemoryignore` in the workspace to add exclusion globs. Blank lines and `#` comments are
ignored. Rules are additive; `!` negation is rejected. Private defaults cannot be overridden.

Never put a credential into the context JSON, command line, checkpoint ID, filename, or adapter
diagnostic. Sensitive checkpoint/transcript content belongs only in the transcript or protected
summary input so the redactor runs before canonical event creation.

## Expected outcomes

- Accepted events return `accepted`; exact replay returns `duplicate`.
- A normal child returns its exit status after all capture acknowledgements commit.
- Timeout returns exit code 124 and records the process/session as `abrupt`.
- Invalid configuration returns exit code 2 and a type-only stderr diagnostic.
- A stopped/unavailable Core fails the operation without writing plaintext fallback state. ADP-005
  adds the bounded encrypted offline spool/reconciliation path.

## Triage

1. Confirm the context and credential are regular owner-only files with one link.
2. Confirm the endpoint is HTTP loopback and has no path, user info, query, or fragment.
3. Query the ADP-003 capability API for exact adapter version/digest/manifest status.
4. Check whether a required capability is `permission_denied`; do not retry until permission is
   restored and observed.
5. For an import failure, verify the explicit format, matching BOM/encoding, record size, UTC
   timestamps, and absence of prohibited hidden-reasoning fields.
6. For missing file evidence, inspect only exclusion counts and policy rules; do not log excluded
   paths or content.
7. For Git absence, verify the selected directory is within the intended repository. Never widen the
   workspace mount to find a parent repository.
8. For MCP failure, replay initialize → initialized → tools/list with protocol `2025-11-25`; verify
   every stdout line is one JSON-RPC object and diagnostics are on stderr.

Do not edit SQLite rows, capability manifests, event IDs, transcript offsets, or encrypted envelopes
to recover. Correct the protected configuration/source and retry; the canonical idempotency boundary
handles exact replay.
