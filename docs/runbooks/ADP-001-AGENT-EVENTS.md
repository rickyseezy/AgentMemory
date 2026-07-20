# ADP-001 AgentEvent adapter-author runbook

## Purpose

Use this runbook to implement or diagnose an AgentMemory host adapter. Do not add host-name branches
to ingestion, identity, memory, graph, retrieval, or learning domain code. Host-specific parsing ends
at a `NativeEventTranslator`; all outputs use the public AgentEvent contract.

## Implement an adapter

1. Identify only host activity that is actually observable. Never capture hidden reasoning or infer a
   lifecycle signal that the host does not expose.
2. Define the exact supported family and evidence-capability sets for one immutable adapter version.
   Construct `AdapterCapabilityManifest` with the signed adapter binary digest. A version's
   manifest must never change in place.
3. Before the first send, allocate one UUIDv7 event ID and UUIDv7 ordering stream key, assign the next
   unsigned sequence, canonicalize/redact the payload, calculate its SHA-256, and durably retain the
   complete typed native observation. Retry must reuse these values and exact bytes.
4. Set unavailable optional task, turn, subagent, checkout, branch, and commit fields to null. Set an
   unavailable model ID to `unknown`. Do not borrow IDs from another lifecycle entity.
5. Translate through `NativeEventTranslator`, serialize through `AgentEventEnvelopeV1`, and validate
   the exact serialized bytes with `parse_agent_event_json` before enqueue.
6. Run the public contract, family-fixture, fuzz, retry, ordering, privacy, and cross-adapter
   conformance tests. Regenerate the schema only when the approved immutable contract changes.

## Payload rules

- Inline payload is canonical UTF-8 JSON and at most 65,536 bytes. Use sorted keys, compact separators,
  preserved Unicode, and finite JSON numbers.
- Reject duplicate keys and prohibited reasoning/scratchpad fields before spooling.
- Encrypt larger authorized content into CAS first. Set `dataref` to
  `cas://sha256/<content_sha256>`, exact plaintext byte size, and the same top-level content hash.
- Set exactly one of `data` or `dataref`. Never log either content, the rejected value, a repository
  path, prompt, or credential.

## Time and ordering

- Serialize occurrence time as aware UTC RFC 3339 with exactly six fractional digits and `Z`.
- Preserve delayed/offline occurrence time. Core assigns a separate ingestion time and records skew.
- A producer stream owns one opaque UUIDv7 ordering key and monotonic unsigned 64-bit sequence from 1.
  Independent streams never share a key to manufacture global order.
- Correlation groups the operation. Causation names only a directly observable predecessor. Do not
  claim model or hidden causal reasoning.

## Diagnose rejection

Use only the returned safe field/code pairs:

| Field/code class | Corrective action |
|---|---|
| UUID, token, SemVer, digest | Correct the producer serializer or immutable adapter build metadata |
| `content_sha256` mismatch | Quarantine the spool record; compare retained bytes without logging them |
| noncanonical/duplicate/non-finite JSON | Fix canonical serialization before retrying with the same ID only if bytes never reached Core |
| schema/type mismatch | Select the exact immutable schema for the event major |
| missing/unauthorized capability | Correct the manifest/version; do not fabricate the signal |
| future clock skew | Repair the host clock; preserve the original quarantined observation |
| identity authorization | Re-establish the authenticated session/workspace mapping; never overwrite claimed IDs to bypass resolution |

An ID retried with different content is an integrity incident handled by ADP-002. Preserve the native
spool record, event ID, safe hashes, adapter/version/digest, manifest digest, ordering coordinates, and
daemon audit reference. Never manually insert an event or edit a manifest/hash to force acceptance.

## Contract verification

Run:

```shell
uv run pytest tests/ingestion
uv run python tools/export_agent_event_schema.py --check
uv run lint-imports
uv run ruff check src/agentmemory/ingestion tests/ingestion
uv run mypy src/agentmemory/ingestion tests/ingestion
uv run pyright src/agentmemory/ingestion tests/ingestion
```

Release certification additionally runs the repository-wide coverage, mutation, security, lock,
OpenAPI, package-build, Go, UI, Docker, and supported-host gates. Local success does not authorize a
new adapter package or schema version for release.
