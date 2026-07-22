# Public agent and provider adapter SDK v1

PF-003 is the common extension contract for new AI-agent hosts and new model providers. Adapter code
runs outside AgentMemory Core. Authors may use any language or runtime that can implement the strict
manifest and probe protocol.

## Choose one adapter kind

An `agent` adapter observes a host and submits canonical AgentEvents through `AgentAdapterPort`. It
must declare `agent.event.capture`; it may additionally declare session resume or explicit checkpoint
support. A `provider` adapter implements the framed provider sidecar protocol behind
`ProviderAdapterPort`. It must declare `provider.embed`; reranking and extraction are optional.

Never combine agent and provider capabilities or permissions in one manifest. Publish two separately
signed packages when one project supplies both.

## Authoritative contract files

- JSON Schema: `contracts/jsonschema/adapter-extension-manifest.v1.schema.json`
- Python package: `sdk/python` (`agentmemory-adapter-sdk==1.0.0`)
- Go package: `github.com/rickyseezy/AgentMemory/sdk/go/adapter`
- External Go agent example: `conformance/agent-adapters/go-reference`
- OCI provider examples: `conformance/provider-adapters/python-reference` and `go-reference`

The SDK packages are dependency-free and contain no Core domain types. Do not import
`agentmemory.*` internals from an adapter.

## Manifest rules

Use a semantic version that identifies immutable bytes. `package_digest` is the lowercase SHA-256 of
the executable or OCI subject. `signature_digest` identifies the exact detached signature/bundle.
`signer_identity` must match an installation-approved publisher. Protocol ranges are inclusive and
Core selects the highest mutually supported version.

Arrays must be sorted lexicographically and contain no duplicate. Request only permissions that are
actually required. Default policy permits canonical event writes for agents and provider execution
for providers; transcript, workspace metadata, or gateway access requires explicit user/admin policy.

## Live probe framing

The reference executable reads one four-byte big-endian unsigned length followed by canonical UTF-8
JSON. The maximum request is 64 KiB. It validates the complete request, then writes one identically
framed response. The response must echo the challenge, manifest digest, package digest, negotiated
protocol, and complete capability array, with `schema_version: 1` and `status: "passed"`.

Do not log probe bodies, package paths, credentials, environment variables, prompts, source content,
or raw exceptions. Exit nonzero or return a closed protocol error when validation fails.

## Registration sequence

1. Build reproducibly and calculate the package digest.
2. Produce the release-policy signature, CycloneDX/SPDX SBOMs, provenance, license, and vulnerability
   evidence required by PF-001/PRO-002.
3. Validate the manifest against the JSON Schema and the language SDK.
4. Run the reference conformance tests, including malformed, duplicate, unknown, oversized,
   cancellation, and timeout cases.
5. Install through the signed AgentMemory launcher/package boundary.
6. Send the authenticated registration command with matching `Idempotency-Key` and `operation_id`.
7. Treat the returned manifest, evidence, package, and registration digests as the activation receipt.

Registration never grants undeclared access and never loads adapter code into Core. A failed trust,
permission, negotiation, or live-probe gate leaves no active registry entry.
