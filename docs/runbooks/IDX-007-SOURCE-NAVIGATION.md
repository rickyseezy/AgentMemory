# IDX-007 source navigation runbook

## Purpose

Use this runbook when an AgentMemory code result cannot open its supporting revision, reports a
checkout mismatch, has no current-worktree mapping, or is rejected by authorization or content
policy. Never substitute a current line manually for immutable evidence.

## Normal resolution

1. Keep the `evidence_id` returned with the code-search or graph result.
2. Resolve `GET /v1/indexing/source-evidence/{evidence_id}` with the exact Brain, actor, grant,
   Project, and Repository scope.
3. Treat `immutable_revision_uri`, `content_digest`, `file_revision_id`, and `span` as one
   inseparable citation.
4. Inspect `checkout_resolution`, `checkout_mismatch`, `checkout_commit_id`, and `checkout_dirty`.
5. Open `current_mapping` only when it is present. The host UI/CLI must call the explicit local
   resolver with the returned immutable URI, relative path, and current digest.
6. If no current mapping exists, open the historical commit/blob through the trusted workspace Git
   adapter. Do not redirect the citation to current lines.

## Resolution states

| State | Meaning | Operator action |
|---|---|---|
| `exact` | Clean checkout commit, file digest, path, and span equal the evidence | Safe to open the current mapping |
| `different_mapped` | Checkout differs, but one unique exact fragment mapping was proved | Show the mismatch, then offer the mapped current span and immutable revision separately |
| `different_unmapped` | Checkout exists but no unique mapping is provable | Open the immutable revision or restore/fetch the historical blob |
| `unavailable` | No current candidate is available | Verify the configured ephemeral repository mount and Git availability |

## `dependency_unavailable`

Confirm that the ephemeral workspace boundary has the exact Repository ID and canonical root, the
fixed Git executable exists, the commit object is present locally, and the file is below the bounded
size limit. Fetching a missing commit is a separate explicit local Git operation; IDX-007 never
performs network access. If the historical blob is absent, an exact current full-file hash can still
verify the evidence. Otherwise preserve the immutable citation and report it unavailable.

## Checkout mismatch or no mapping

- A different HEAD commit always sets mismatch.
- Any staged, unstaged, or untracked change sets mismatch, even when the cited file is unchanged.
- Git-proven rename/copy plus a unique exact fragment can produce a mapping.
- Repeated snippets or multiple matching rename candidates intentionally produce no mapping.
- Line and column values are UTF-8 byte columns. Do not convert them to Unicode code-point columns
  before handing them to an editor adapter that expects bytes.

For a dirty, unstaged delete plus an untracked replacement, stage the rename or commit it if the user
intends that VCS relationship. IDX-007 does not scan unrelated untracked files and guess that one is
a rename.

## `conflict`

A conflict means persisted evidence and trusted bytes disagree, candidate checkout metadata is
internally inconsistent, or an explicit local-open request replayed different URI/path/digest
coordinates. Preserve the evidence and repository. Check:

1. the indexed `file_revision_id`, content digest, byte length, and parser coordinates;
2. the Git object at the exact commit and relative path;
3. whether repository objects were rewritten or corrupted;
4. whether an adapter supplied candidates from more than one checkout;
5. whether the file changed between source-link display and explicit open.

Run repository integrity checks and a governed IDX-002 reindex if canonical local history changed.
Do not edit SQLite evidence rows or force an open.

## `forbidden` or missing evidence

Re-resolve the current grant and verify Brain/Project/Repository membership. Check whether IDX-006
invalidated the path after a policy change. A later final content-include decision plus completed
reindex is required before derivatives become visible again. Do not bypass policy by using Git
directly through an AgentMemory adapter.

## Path safety incident

If a local open is refused:

- verify the mapped path is canonical repository-relative POSIX form;
- reject `..`, absolute paths, backslashes, NUL, and symlinked files or parent directories;
- verify the configured root is the trusted ephemeral mount, not request data;
- compare the current file SHA-256 with the mapping digest.

Treat an unexpected escape/symlink attempt as hostile repository input. Retain only stable error
codes and content-free IDs; do not log the absolute path or file content.

## Privacy rules

- Never log source bytes, snippets, Git stderr, absolute roots, or editor command lines.
- Never send source navigation content to an embedding or remote provider.
- Keep historical/current bytes ephemeral and bounded.
- Reapply IDX-006 path and content policy before every historical or worktree read.
- Never persist the transient absolute path returned to a local UI/CLI open action.
