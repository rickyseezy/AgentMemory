# Dependency review: go-toml v2.4.3

Status: approved for PF-001 Codex configuration parsing on 2026-07-14.

## Identity and immutability

- Module: `github.com/pelletier/go-toml/v2`
- Version: `v2.4.3`, the latest stable release at review time
- Immutable tag commit: `071a36c2a57244f2e70369bfc69889fda2a1f60f`
- Go module checksum: `h1:GTRvJQutkOSftxIFD5xw9aepkYNuPWmVJpffdDPYVpY=`
- Go module-file checksum: `h1:2gIqNv+qfxSVS7cM2xJQKtLSTLUE9V8t9Stt+h56mCY=`
- Downloaded module ZIP SHA-256: `bc0de16d4942df8503be13bde0447e0b7ce1694f3bb1b840f485ce839f8974cf`
- Downloaded `go.mod` SHA-256: `72b2ddd20583039d110a50147c63fd1e419a5c4acc1ba8f28881f1df4486abae`

The Git tag and Go module origin resolve to the commit above. The module is
pinned in `go.mod`, and its public checksum-database values are recorded in
`go.sum`.

## Provenance, compatibility, and licence

- Upstream release: <https://github.com/pelletier/go-toml/releases/tag/v2.4.3>
- Upstream source: <https://github.com/pelletier/go-toml/tree/v2.4.3>
- Licence: MIT
- Upstream minimum Go version: 1.21
- AgentMemory Go version: 1.26.5

The stable `toml` package follows semantic versioning. AgentMemory does not
import the separately documented `unstable` parser API.

## Approved surface and controls

Production code may import only `github.com/pelletier/go-toml/v2` and only for
bounded in-memory decoding of an already owner-scoped Codex `config.toml`.
It must not use the unstable AST parser, filesystem helpers, encoders, command
tools, or Docker image.

The AgentMemory adapter independently:

1. limits documents to one MiB and requires valid UTF-8;
2. rejects malformed, duplicate, and contradictory TOML;
3. treats an existing unowned `mcp_servers.agentmemory` table as ambiguous;
4. preserves every unrelated user byte instead of re-encoding the document;
5. replaces only an exact EOF ownership block whose digest matches the durable
   prior receipt;
6. parses the complete result again before publication; and
7. verifies the exact command, arguments, required flag, installation ID,
   entry ID, and signed-launcher digest after publication.

Any version change, import of the unstable package, document-size increase, or
relaxation of duplicate/ownership checks requires a new dependency review.
