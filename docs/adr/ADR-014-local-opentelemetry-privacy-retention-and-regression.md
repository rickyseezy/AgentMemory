# ADR-014: Local OpenTelemetry privacy, retention, and regression calculations

- Status: Accepted
- Decision owners: Observability Owner and Security Owner
- Consulted owners: Operations, Evaluation, Performance, Every runtime role
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before exporter, attribute, sampling, retention, or regression changes
- Supersedes: None
- Related requirements: PRD Sections 15-17; Technical Requirements Sections 7, 8, 11.13 OPS-002/OPS-003, and 14

## Context

AgentMemory needs local diagnosis and release SLO gates without call-home telemetry or content leakage.
Unbounded identifiers destroy metric usability and can reveal user data. Performance release decisions
must use reproducible comparisons rather than anecdotal p95 values.

## Decision

### Local-only telemetry topology

All processes emit OpenTelemetry-compatible metrics/traces and structured JSON logs to the bounded
local sink. The optional `otel-collector` is on `am_internal`, has no external network route, and has no
exporter enabled by product configuration. OTLP receivers are internal or authenticated loopback only.
Remote exporters, analytics, crash upload, vendor telemetry, and call-home endpoints are absent from
release schemas and rejected by Compose policy.

Audit events/checkpoints are not telemetry and follow their longer governance retention. Diagnostics
export is an explicit authenticated command that allowlists fields, scans content/secrets, encrypts the
bundle, and is audited.

### Common signal contract

Logs are UTF-8 JSON with timestamp, severity, component/runtime role, release/data generation, safe
event name/outcome/error code, trace/span/correlation/operation IDs where applicable, and bounded safe
dimensions. Traces propagate through API/MCP, SQL outbox/jobs, provider protocol, and graph work; new
async roots link to origin span rather than copying payload. Metrics are recorded at application
acknowledgement, retrieval, deletion, provider, learning, migration, backup, and recovery boundaries—not
only HTTP middleware.

No signal contains prompt, query text, code, content, raw/normalized host path, repository/project/user
name, URL with query, credential/SecretRef value, vector, provider payload, SQL/Cypher, stack local,
hidden reasoning, archive name, or arbitrary exception string. External errors map to safe code and
approved bounded fields before recording.

Brain/project context in local logs/traces uses
`telemetry_pseudonym = first_16_hex(HMAC-SHA-256(TelemetryKeyVersion, UUID))`. The key is separate under
ADR-010 and rotates with security epoch; metrics never use this pseudonym as a label. Diagnostics can
map a pseudonym only through an authorized local query.

### Metric cardinality policy

Metric attributes are a closed registry reviewed in source. Allowed examples are component, operation
class, outcome/error code, channel, provider adapter/profile class (not instance ID), purpose,
classification class, state, retry bucket, platform/architecture, release/generation cohort, and
bounded size/latency bucket.

Forbidden metric labels include UUID/event/session/task/operation/trace/span IDs, Brain/project/
repository/checkout principal or provider instance, model/request ID, path/name, query/content hash,
port, exception message, and any user text. A startup registry validator and test fixture cap each enum;
unknown label keys/values are dropped with a local safe telemetry-policy counter, never dynamically
created.

Required metrics are the technical-specification list for ingestion/outbox/jobs/indexing/retrieval/
providers/stores/auth/deletion/learning/migration plus launcher setup phase duration/failure/reboot. They
report queued/degraded work rather than measuring only successful requests.

### Sampling and retention defaults

Metrics and SLI boundary events are unsampled. Traces retain 100% of security/admin/deletion/audit-
adjacent, setup/upgrade/restore, failed, integrity, and SLO-synthetic operations. Normal successful
ingestion/retrieval/indexing internal spans use deterministic 10% sampling by trace ID; their boundary
metrics remain complete. Logs retain WARN+ and security/admin operation summaries; DEBUG is disabled in
release and explicit temporary diagnostic mode expires after one hour.

Local storage uses first-hit eviction by age or encrypted volume quota:

| Signal | Default age | Default maximum |
|---|---:|---:|
| structured application/launcher logs | 7 days | 1 GiB |
| traces | 7 days | 2 GiB |
| metric series/rollups | 30 days | 1 GiB |
| temporary diagnostic-mode detail | 1 hour | 256 MiB |

Security alerts and signed evaluation/benchmark reports are canonical audit/operation artifacts, not
extended by telemetry retention. At quota, oldest eligible data is removed; telemetry pressure never
deletes canonical events or blocks ACK. Users can purge telemetry; deletion manifest removes target-
linkable pseudonyms/traces when required.

### SLI calculation

Latency uses monotonic clocks within a process and explicit linked stage timestamps across processes.
Percentiles use complete boundary histogram/distribution records, not sampled traces. Every SLI cohort
binds exact release/data generation, hardware profile, corpus/workload version, warm/cold state,
concurrency, provider/model, and degraded/maintenance status.

Maintenance may be excluded only when the operation explicitly entered signed/audited maintenance
before measurement. Errors, timeouts, queued work, fallback/degraded channels, and cold starts are not
silently excluded. Clock gaps/reset split a measurement window and are reported.

### Performance regression policy

Candidate and baseline run on identical dedicated hardware profile, OS/runtime/BOM except the intended
change, corpus, seed set, warmup, concurrency, and network policy. Run at least five independent trials
after one discarded warmup. Retain per-request/interval aggregates and report median of trial p50/p95/
p99 plus 95% stratified bootstrap confidence intervals (10,000 deterministic resamples with recorded
seed).

For a lower-is-better SLI, `regression = (candidate - baseline) / baseline`. Release blocks when:

- any absolute SLO/RPO/RTO/zero-tolerance limit fails in any required qualified trial;
- median p95 regression exceeds 10% and the 95% confidence interval excludes zero;
- error/timeout/abstention-harm rate increases by more than 0.5 percentage points and its interval
  excludes zero; or
- peak memory, steady disk growth per searchable unit, or CPU-seconds per fixed workload regresses more
  than 15% and its interval excludes zero.

For higher-is-better quality/throughput metrics the signs reverse. Small baselines use an absolute
predeclared floor to avoid division artifacts. Multiple primary SLI comparisons use Holm-Bonferroni at
family alpha 0.05. A signed benchmark plan predeclares metrics, direction, floors, and cohorts before
results. Regression-budget failure freezes release/upgrade recommendation; only a new passing artifact
or approved specification change can clear it. Zero-tolerance has no waiver.

## Security and privacy impact

Local-only topology and closed attributes prevent telemetry becoming egress or a shadow content store.
Pseudonyms remain sensitive local metadata and rotate. Content-free traces cannot fully diagnose all
model cases; explicit authorized diagnostics fetches canonical evidence separately. Root/local host
owner can read local telemetry, an accepted threat boundary.

## Compatibility, migration, and rollback

Metric/log/span names and attribute registries are versioned. Additive bounded fields are compatible;
renames dual-emit for one supported release and dashboards accept both. Retention/sampling change is a
policy version and cannot retroactively recover discarded data. Rollback selects prior collector/
dashboard policy and keeps safe newer records until normal expiry.

## Rejected alternatives

- Remote SaaS telemetry/call home: violates local-only product.
- User/path/UUID metric labels: cardinality/privacy failure.
- Raw exception/prompt/provider payload logs: content/secret leak.
- Sampling boundary metrics: corrupts SLO calculations.
- Comparing one p95 run or unlike machines/corpora: non-reproducible regression claim.
- Excluding errors/degraded/queued work: hides user-visible failure.
- Treating audit as short-retention logs: loses governed evidence.

## Consequences

Some debugging requires explicit evidence access rather than logs. Local telemetry consumes bounded
disk and benchmark gates take multiple trials. Signals remain privacy-safe and release calculations are
reproducible.

## Verification

- Static attribute registry and adversarial content/secret/path/vector/exception canary scans across
  logs, spans, metrics, diagnostics, and setup failures.
- Cardinality tests with one million unique operations show bounded metric series.
- Packet capture proves no telemetry exporter/DNS/TCP/UDP egress in default and remote-provider modes.
- Retention/quota/rotation/purge tests prove canonical state is unaffected.
- End-to-end trace linkage across outbox/jobs/provider with no payload.
- Golden percentile/bootstrap/Holm-Bonferroni/regression math, clock-gap, maintenance, degraded, and
  low-baseline fixtures.
- Candidate deliberately violating each threshold freezes signed release decision.
