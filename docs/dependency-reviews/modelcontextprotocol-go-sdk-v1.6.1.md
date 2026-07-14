# Dependency review: Model Context Protocol Go SDK v1.6.1

Status: approved for the PF-001 stdio bootstrap MCP adapter on 2026-07-14.

## Identity and immutability

- Module: `github.com/modelcontextprotocol/go-sdk`
- Version: `v1.6.1`
- Immutable tag commit: `d454bbaf06a342aee5336df3370321d9cdec2478`
- Go module checksum: `h1:0zOSupjKUxPKSocPT1Wtago+mUHU2/uZ4xSOY0FGReU=`
- Go module-file checksum: `h1:kzm3kzFL1/+AziGOE0nUs3gvPoNxMCvkxokMkuFapXQ=`
- Downloaded module ZIP SHA-256: `42d2f3dd1c889e7591675c83eae6ccb29a4a3ae9560dd5767869467bbb03ca85`
- Downloaded `go.mod` SHA-256: `77385a63f6339a0bac57b6aeeb28958f378980b011a075a821127d1b9d42f549`

The Git tag and Go module origin resolve to the commit above. The dependency
is pinned directly in `go.mod`; its public checksum-database values are
recorded in `go.sum`.

## Provenance, compatibility, and licence

- Upstream release: <https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.6.1>
- Upstream source: <https://github.com/modelcontextprotocol/go-sdk/tree/v1.6.1>
- Maintainer: the official Model Context Protocol organization, in
  collaboration with Google
- Licence: transition notice covering Apache-2.0 and unrelicensed MIT
  contributions; the shipped `LICENSE` is retained in release notices
- Upstream minimum Go version: 1.25
- AgentMemory Go version: 1.26.5
- Supported MCP revisions include 2025-06-18, the PF-001 baseline

## Approved surface and controls

Production code may import only `github.com/modelcontextprotocol/go-sdk/mcp`
for the local stdio server, in-memory protocol conformance tests, typed tool
registration, and list-changed notifications. PF-001 does not enable SDK HTTP,
OAuth, sampling, elicitation, filesystem, or remote-server facilities.

The AgentMemory adapter independently:

1. exposes exactly the three pre-Ready tools required by the product contract;
2. accepts an empty closed input object for each tool and rejects unknown input;
3. takes all state from operation/plan-bound application ports;
4. writes protocol frames only through `StdioTransport` and diagnostics only to
   stable stderr codes;
5. validates the complete Ready surface before replacing bootstrap tools;
6. advertises and emits tool/resource list changes during the in-session
   handoff; and
7. proves initialize, list, call, cancellation, malformed input, handoff, and
   list-changed behavior through an SDK client/server in-memory transport test.

Any SDK version change, use of another SDK package, HTTP transport, remote
listener, new client capability, or weakening of the closed bootstrap surface
requires a new dependency review and MCP conformance campaign.
