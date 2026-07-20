# MEM-002 provenance and temporal explanation runbook

## Normal explanation

Use `GET /memories/{memory_id}` with the exact `brain_id`, `actor_id`, `grant_id`, `valid_at`, and
`recorded_at`. Both instants must be canonical UTC with six fractional digits, for example
`2026-07-21T10:00:00.000000Z`. The response is historical metadata plus an `effective` evaluation;
an inactive time does not mean the record is corrupt.

Treat time ranges as half-open:

- `from <= instant` is effective at the start;
- `instant < to` is effective before a finite end; and
- `instant == to` is not effective.

An absent target and a target outside the current grant both return `AM_NOT_FOUND`. Do not change
this behavior to help diagnosis because it prevents cross-scope existence disclosure.

Agents installed through the launcher use the equivalent read-only `memory_explain` MCP tool with
the same six named arguments. The launcher exposes it only after authenticated Core readiness,
rechecks readiness for every invocation, and forwards the request solely to the configured local
loopback Core. A missing tool means the connected launcher/Core release does not implement MEM-002;
do not replace it with filesystem, database, Cypher, or arbitrary HTTP access.

## Verify canonical provenance

For an authorized incident, inspect only metadata first:

```sql
SELECT m.id,m.brain_id,m.status,m.valid_from,m.valid_to,m.recorded_from,m.recorded_to,
       hex(m.content_hash) AS content_sha256,r.provenance_json,r.schema_version
FROM memories m
JOIN memory_revisions r ON r.memory_id=m.id AND r.revision=m.current_revision
WHERE m.id=:memory_id;
```

Do not update `provenance_json`; migration `0016` installs a trigger that rejects it. Compare a
suspect database with a coherent backup and preserve SQLite, installation/Brain keys, audit events,
and canonical encrypted AgentEvents together.

## Evidence states

| State | Meaning | Operator action |
|---|---|---|
| `available` | Canonical AgentEvent and task lineage metadata authenticate the stored link | Follow the resource only through an independently authorized evidence query. |
| `purged` | An authoritative `agent_event` deletion tombstone excludes the source | Do not restore from projection/cache; retain the content-free ID and digest explanation. |
| `missing` | The evidence link remains but canonical event or lineage metadata is absent | Quarantine the data copy, run integrity and backup comparison, and repair from trusted canonical evidence. |

Never convert `missing` to `purged`, fabricate an event type/time, delete an evidence link to make
the query pass, or expose plaintext from a backup through the explanation endpoint.

## Projection verification

`MemoryProjected` is the replay source for Neo4j, not proof that a particular graph generation is
active. Verify its relational source before rebuilding:

```sql
SELECT event_id,projection_type,stable_id,target_type,
       hex(target_id_hash),hex(payload_hash),hex(source_digest),schema_version
FROM domain_events
WHERE aggregate_type='memory' AND aggregate_id=:memory_id;
```

Expected values are `projection_type=graph`, `stable_id=:memory_id`, `target_type=memory`, and schema
version `2`. Payload JSON and event JSON must be byte-identical. Use the PF-002 projection rebuild
command to create and validate a shadow graph generation; never patch Neo4j directly.

## Failure response

- `AM_VALIDATION`: correct UUIDv7 or canonical UTC query input; do not coerce local time.
- `AM_NOT_FOUND`: verify the caller's principal/grant/Brain without probing other scopes.
- `AM_DEPENDENCY_UNAVAILABLE`: restore SQLite availability and retry the idempotent read.
- `AM_INTEGRITY_VIOLATION`: stop explanation traffic for the affected data copy, preserve evidence,
  run SQLite integrity and foreign-key checks, and compare provenance, consolidation, evidence, and
  projection hashes with a trusted backup.

MCP callers receive a deliberately generic unavailable/invalid-tool error rather than these Core
details. Correlate it locally with Core health and audit records; never widen MCP error text to
include credentials, protected paths, raw authorization failures, or database diagnostics.

## Backup, upgrade, and rollback

Back up SQLite, encrypted event/CAS data, keys, and release metadata as one coherent set. Upgrade
`0016` validates legacy provenance before rewriting it; a failure is evidence of incompatible or
divergent state and must not be bypassed. Downgrade refuses while memory revisions exist. Restore a
coherent pre-upgrade backup or deploy a forward repair that preserves provenance and projection
hashes.
