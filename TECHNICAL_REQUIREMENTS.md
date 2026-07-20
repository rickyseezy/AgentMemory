# AgentMemory Technical Requirements and Delivery Specification

| Field | Value |
|---|---|
| Product | AgentMemory |
| Document status | Normative implementation contract |
| Product scope | Complete production product; no MVP or prototype release |
| Product requirements authority | [PRD.md](PRD.md) |
| Technical authority | This document |
| Baseline date | 2026-07-13 |
| Minimum quality gate | Python/TypeScript: 80% line and branch globally/per package; Go launcher: 80% statement per package plus complete branch decision tables and mutation gate |
| Architecture | Clean Architecture with domain-driven bounded contexts and explicit ports/adapters |

## 0. How to use this specification

### 0.1 Normative language

The words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, and MAY are normative:

- MUST or SHALL is a release-blocking requirement.
- SHOULD is required unless an Architecture Decision Record, or ADR, documents why the exception produces a safer or simpler result and receives architecture-owner approval.
- MAY is an allowed implementation choice, not unfinished product scope.

This document and the PRD form one product specification. The PRD defines externally observable behavior and product outcomes. This document defines implementation boundaries, technology choices, verification, and story-level delivery contracts. If they conflict, security and privacy invariants take precedence; the conflict must then be resolved in both documents before implementation proceeds.

AgentMemory has no MVP track. Work may be sequenced behind disabled release flags, but a production release is not complete until every required story in this specification is implemented, tested, documented, operable, and accepted.

On a certified computer, installing AgentMemory in an AI agent is the only product installation action. Docker Engine/Desktop, Compose, WSL2 or rootless prerequisites, runtime services, images, models, networks, and volumes are managed transitive dependencies that AgentMemory discovers, provisions, configures, starts, verifies, and repairs. No successful supported path may require a Docker account, terminal command, configuration-file edit, Docker context choice, manual service start, or Docker knowledge. Only an informed third-party-terms decision, OS-native privilege approval, user-approved restart, or organization-administrator authorization may require human action; the product cannot bypass a refusal, device policy, unsupported hardware, or firmware-disabled virtualization.

### 0.2 Required delivery evidence

Every pull request implementing a story MUST include:

1. The story ID in the pull request and test names.
2. A short Red-Green-Refactor record identifying the first failing test, the minimal passing change, and the refactor.
3. Unit and story-specific tests listed in the story contract.
4. Updated machine-readable schemas, generated clients, migrations, documentation, metrics, and runbooks when affected.
5. Coverage evidence showing that global and per-package line and branch thresholds remain satisfied.
6. Security, privacy, authorization, egress, retention, and deletion impact declarations.
7. Compatibility and rollback evidence for persisted or public-contract changes.

A developer MUST NOT close a story by implementing only its happy path. “Works locally,” manual verification without automated tests, disabled tests, or coverage obtained through assertion-free execution are not acceptance evidence.

### 0.3 Decision precedence

When two requirements appear to compete, implement in this order:

1. Brain isolation, local-principal authorization, deletion, privacy, and controlled-learning invariants.
2. Durability, correctness, provenance, temporal truth, and auditability.
3. Public compatibility and operability.
4. Latency and throughput SLOs.
5. Developer convenience.

No layer may weaken a higher-priority invariant to meet a lower-priority objective.

## 1. Architecture

### 1.1 System style

AgentMemory MUST use Clean Architecture implemented as a modular monolith inside one persistent `agentmemory-core` container, with Neo4j in a second persistent container and MCP/provider adapters in constrained local containers. This is a deliberate choice:

- A modular monolith gives SQLite exactly one owning service and keeps transactions, contracts, installation, backup, and debugging simple.
- Independently supervised logical worker roles and bounded subprocess pools isolate CPU-, memory-, and model-heavy jobs without adding a distributed queue or fleet of services to a single-user product.
- Ephemeral MCP bridges give each agent session the minimum source-tree access it needs without mounting the user's home directory into the persistent core.
- Clean ports preserve testability and provider/agent extensibility; they are not a pretext for hosted microservices.

The release Compose project MUST NOT add another canonical database, broker, cache server, object store, or AgentMemory service. A local provider sidecar or optional local observability sidecar requires a bounded capability, threat model, resource profile, health contract, and rollback. A package MUST NOT become a service merely to mirror its code boundary.

~~~mermaid
flowchart TB
    subgraph Host["Host integration boundary"]
      Launcher["Signed installer/MCP launcher"]
      Hooks["Agent host hooks"]
    end
    subgraph Bridge["Ephemeral MCP bridge container"]
      MCP["stdio MCP and workspace scanner"]
    end
    subgraph Core["Persistent AgentMemory core container"]
      HTTP["Loopback API and UI"]
      Workers["Supervised worker roles"]
      subgraph Application["Application layer"]
        Commands["Command handlers"]
        Queries["Query handlers"]
        Policies["Authorization and policy orchestration"]
      end
      subgraph Domain["Domain layer"]
        Aggregates["Aggregates and value objects"]
        Services["Pure domain services"]
        Events["Domain events"]
        Ports["Repository and provider ports"]
      end
      SQL[("SQLite WAL, jobs, and outbox")]
      Blob["Encrypted local CAS"]
    end
    Graph[("Local Neo4j Community")]
    Providers["Local provider sidecars"]
    Gateway["Optional provider egress gateway"]
    Launcher --> MCP
    Hooks --> HTTP
    MCP --> Application
    HTTP --> Application
    Workers --> Application
    Application --> Domain
    SQL --> Ports
    Blob --> Ports
    Graph --> Ports
    Providers --> Ports
    Gateway -. "approved embedding/reranking HTTPS only" .-> Remote["Configured provider endpoint"]
    Providers --> Gateway
    Core --> Gateway
~~~

Dependencies point inward. Domain code knows no framework. Infrastructure implements domain/application ports. The composition root is the only place that selects concrete adapters.

### 1.2 Required bounded contexts

The following bounded contexts are REQUIRED. Each owns its domain model and exposes a versioned public application API. A context MUST NOT import another context’s internal entities, database models, or repositories.

| Context | Owns | Public operations |
|---|---|---|
| identity | Brain, Project, Repository, Checkout, aliases and links | resolve, link, unlink, move, authorize scope |
| ingestion | AgentEvent ledger, outbox/inbox, jobs, replay, DLQ | append, acknowledge, schedule, replay, quarantine |
| sessions | Session, Turn, Task, TaskContract, checkpoints | start, checkpoint, complete, summarize |
| memory | Memory aggregates, corrections, consolidation, lifecycle | extract, merge, correct, pin, archive, expire, forget |
| graph | assertions, evidence, temporal graph projection, integrity | assert, contradict, invalidate, traverse, explain |
| indexing | source snapshots, files, symbols, contracts, topology | scan, diff, parse, project, invalidate |
| providers | adapter manifests, profiles, routes, embedding spaces | register, probe, route, embed, rerank, migrate |
| retrieval | query understanding, candidate channels, fusion, context | recall, timeline, graph query, briefing, explain |
| learning | outcomes, mistake candidates, lessons, procedures, rollout | detect, evaluate, review, promote, canary, rollback |
| governance | principals, grants, classification, retention, egress | authorize, classify, redact, hold, delete |
| audit | tamper-evident security and administrative history | append, verify, search, export |

Cross-context commands MUST use a public port. Cross-context facts MUST travel as immutable integration events. Synchronous calls are allowed inside the modular monolith through interfaces, but circular dependencies are forbidden.

### 1.3 Process topology

The production installation contains these runtime roles:

| Runtime role | Placement | Responsibility and isolation |
|---|---|---|
| host bootstrapper/launcher | signed static host binary plus accessible agent-host/launcher-served local setup surface | runtime discovery/provisioning/repair ownership, install/upgrade/uninstall, Docker health/start, reboot resume, MCP bootstrap/status and stdio attachment, loopback hook delivery, and bounded encrypted capture spool; no Brain/domain decisions |
| mcp-bridge | one ephemeral container per agent session | MCP translation, current-workspace identity/scan/streaming, and session lifecycle; the workspace is mounted read-only and the bridge never opens a database |
| core API/UI | persistent core process | loopback HTTP, health, command/query dispatch, static UI, local outbox pump, and application composition |
| ingestion role | supervised core task | validation, redaction, ordering, event persistence, and projection scheduling |
| indexing role | supervised core task plus bounded subprocess pool | stored-artifact parsing, SCIP import, topology inference, and incremental invalidation |
| memory role | supervised core task | local extraction, deduplication, consolidation, and contradiction processing |
| provider role | supervised core task | batching, policy, optional gateway calls, output validation, and vector writes |
| retrieval role | core query task | exact/full-text/vector/graph retrieval, fusion, and explanation |
| learning/evaluation roles | supervised core tasks and sandboxed subprocesses | outcomes, candidates, replay, holdouts, promotion, and rollback |
| maintenance role | supervised core task | retention, deletion, repair, migrations, backup coordination, and local telemetry retention |
| Neo4j | persistent separate container | rebuildable graph/full-text/vector projection; it owns no canonical events |
| local provider | optional constrained sidecar | local embedding/reranking/extraction runtime, normally with no egress |
| egress gateway | optional constrained sidecar | sole external route for explicitly approved embedding/reranking HTTPS destinations |

Each logical core role MUST retain independent cancellation, health, concurrency, queue, retry, and memory/CPU budget. An unhandled optional-role failure is contained, reported, and restarted with backoff; it MUST NOT terminate event intake, loopback health, or the host agent. CPU-heavy parsers and local model execution MUST NOT run on the API event loop.

### 1.4 Clean Architecture layers

Every Python bounded-context package MUST have these directories:

~~~text
src/agentmemory/<context>/
  domain/
    entities.py
    value_objects.py
    events.py
    errors.py
    services.py
    ports.py
  application/
    commands/
    queries/
    dto.py
    policies.py
  adapters/
    inbound/
    outbound/
  infrastructure/
    persistence/
    configuration/
  bootstrap.py
~~~

Rules:

- domain MAY import only the Python standard library and shared kernel value types.
- application MAY import domain and shared contracts. It MUST NOT import FastAPI, MCP, SQLAlchemy, Neo4j, Docker clients, provider SDKs, or filesystem implementations.
- adapters translate protocols and persistence representations. They MUST NOT contain domain decisions.
- infrastructure constructs clients, pools, transaction managers, configuration, and concrete repositories.
- bootstrap.py is the composition root. Constructor injection occurs there.
- shared kernel is limited to UUID/time primitives, result/error contracts, pagination, classification, and event metadata. Business entities do not belong in shared kernel.

Import Linter MUST enforce these rules in CI with layers, independence, forbidden-import, and acyclic-sibling contracts. A blanket ignored import is prohibited.

The Go host launcher follows the same dependency direction with no duplicated Brain domain:

~~~text
apps/launcher/
  cmd/agentmemory/              # composition root only
  internal/domain/              # install/session/upgrade operation state and value objects
  internal/application/         # use cases and capability-specific ports
  internal/adapters/
    runtimecatalog/             # signed platform/runtime prerequisite manifest
    runtimediscovery/           # trusted local endpoint/context/workload discovery
    runtimeprovision/           # macOS, Windows, and Linux provisioning adapters
    artifactacquisition/        # resumable allowlisted host artifact download
    artifacttrust/              # notarization, Authenticode, package/signature checks
    consent/                    # exact terms/install-plan consent receipts
    privilege/                  # plan-bound native one-shot elevation
    reboot/                     # one-use per-user continuation
    servicemanager/             # Docker Desktop/systemd lifecycle and probes
    setupui/                    # accessible native progress and decisions
    dockercli/                  # argv-only Docker/Compose process adapter
    filesystem/                 # atomic journal/config/secret files
    agentconfig/                # one adapter per supported host
    platform/                   # path, OS identity, keychain, process, lock
    coreapi/                    # authenticated loopback client
  internal/contracts/           # generated/versioned DTOs only
~~~

Launcher domain/application code imports only the Go standard-library value packages and its own inward layer. It MUST NOT import Docker clients, `os/exec`, filesystem/network/keychain implementations, native privilege APIs, vendor installers, or agent-host adapters. The launcher owns runtime/install/resource/session orchestration only; project identity truth, authorization, memory, graph, provider, learning, and retrieval rules remain in core application/domain packages. Every host/runtime/Docker/filesystem action is behind a narrow interface and uses typed operations and argv/data, never a command shell.

### 1.5 Domain model rules

- Aggregates enforce invariants and emit domain events. Setters that allow invalid intermediate state are forbidden.
- Entity identity uses UUIDv7. Equality is identity-based, never database object identity.
- Value objects are immutable, validated at construction, and compare by value.
- Value objects use frozen, slotted standard-library dataclasses; aggregates use plain typed Python classes. Domain objects MUST NOT subclass Pydantic, SQLAlchemy, Neo4j, or framework base classes.
- Pydantic models are boundary/application DTOs. SQLAlchemy persistence records are separate adapter models and explicit mappers translate them to/from domain aggregates.
- Domain services are pure unless their required side effects are expressed through ports.
- Domain events are past-tense immutable records. They carry event ID, aggregate ID/version, occurred_at, actor, Brain scope, correlation ID, causation ID, and schema version.
- External or model-generated content is always an untrusted candidate. It becomes authoritative only through the application use case that verifies schema, authorization, evidence, temporal scope, and policy.
- Naive datetimes are forbidden. Time is UTC and serialized as RFC 3339 with microsecond precision. Tests use an injected Clock port.
- Floating point is forbidden for currency and persisted confidence calculations. Cost uses Decimal plus ISO currency; confidence stores bounded decimal values with documented precision.

### 1.6 Command/query separation

AgentMemory MUST use logical CQRS:

- A command changes state, names an intent, returns an ID/status DTO, and executes inside one Unit of Work.
- A query never mutates canonical state and returns an immutable read DTO.
- HTTP GET, MCP read tools, UI reads, and CLI read commands MUST call query handlers.
- Workers call command handlers; they MUST NOT call repository adapters directly.
- Query services MAY use optimized Neo4j or SQL read models, but those projections must be rebuildable and report generation/freshness.

Each command input contains:

- command_id for idempotency;
- actor and authenticated principal;
- Brain and narrower scope;
- expected aggregate version when concurrency matters;
- correlation and causation IDs;
- request time and deadline.

Command handlers execute in this order:

1. Validate boundary DTO.
2. Resolve authenticated actor and authorize action/scope.
3. Load aggregate through repository.
4. Apply domain behavior.
5. Persist aggregates, outbox events, deletion tombstones, and required audit facts atomically where they share a store.
6. Commit Unit of Work.
7. Return result; asynchronous side effects occur from outbox events.

### 1.7 Repository pattern and Unit of Work

Repositories are mandatory and aggregate-oriented. GenericRepository, BaseRepository with table-shaped CRUD, Active Record, and direct ORM leakage are prohibited.

Repository ports live in domain or application and use domain types. Representative contracts:

~~~python
class MemoryRepository(Protocol):
    async def get(self, memory_id: MemoryId, scope: AuthorizedScope) -> Memory | None: ...
    async def find_merge_candidates(
        self, fingerprint: ContentFingerprint, scope: AuthorizedScope
    ) -> tuple[Memory, ...]: ...
    async def add(self, memory: Memory) -> None: ...
    async def save(self, memory: Memory, expected_version: int) -> None: ...

class UnitOfWork(Protocol):
    memories: MemoryRepository
    events: EventRepository
    outbox: OutboxRepository
    audit: AuditRepository
    async def __aenter__(self) -> Self: ...
    async def commit(self) -> None: ...
    async def rollback(self) -> None: ...
~~~

Rules:

- Repository methods express domain queries, not storage operations such as find_by_column.
- Repositories never commit. The Unit of Work owns the transaction.
- The SQLAlchemy session and Neo4j session never escape an adapter.
- A command that spans SQL canonical state and Neo4j projection MUST commit canonical state plus an outbox request in SQL first; a worker then idempotently updates Neo4j. Distributed dual writes are forbidden.
- Neo4j projection repositories use explicit parameterized Cypher stored in versioned query modules. String concatenation of user values, labels, properties, or predicates is forbidden.
- Dynamic index/label names are generated only from validated internal IDs using a closed naming function.
- Optimistic concurrency uses aggregate_version and compare-and-swap. Lost updates MUST produce Conflict, not last-write-wins.

### 1.8 SOLID requirements

| Principle | Enforceable rule |
|---|---|
| Single Responsibility | One class has one domain reason to change. Handlers orchestrate one use case; parsers parse; repositories persist; policies decide. |
| Open/Closed | New agent/provider adapters implement published ports and conformance suites without changing domain switch statements. |
| Liskov Substitution | Every implementation passes the same repository, provider, clock, blob, queue, and adapter contract tests. |
| Interface Segregation | Ports are capability-specific. An embed-only adapter is not forced to implement reranking; read repositories are separate from write repositories. |
| Dependency Inversion | Domain/application depend on protocols; infrastructure depends on and implements them. Concrete selection exists only in composition roots. |

Code review MUST reject service locators, ambient global clients, mutable singletons, inheritance used only for reuse, boolean parameters that create unrelated behaviors, and large interfaces with unused methods.

### 1.9 KISS and abstraction limits

KISS is mandatory:

- Use a direct function or small class until at least two stable implementations require an abstraction, except for boundaries that this specification explicitly mandates as ports.
- Prefer composition over inheritance.
- Prefer explicit orchestration over reflection, metaprogramming, decorators that hide transactions, or magic repository generation.
- Do not introduce a framework-specific domain base class.
- Do not build a custom workflow engine, ORM, queue, cryptographic primitive, policy language, or vector database.
- A function SHOULD remain below 40 logical lines and cyclomatic complexity 10. A class SHOULD remain below 300 logical lines. Exceeding either requires decomposition or a review note explaining why decomposition would reduce clarity.
- Public functions take no more than five independent parameters; group related values in validated value objects.
- Duplicate business logic is forbidden. Small duplicated translation code is preferable to a premature cross-context abstraction.

### 1.10 Dependency injection

- Constructor injection is mandatory.
- FastAPI Depends MAY resolve request-scoped objects at the inbound edge only. Domain and application code MUST NOT import or call Depends.
- Worker and CLI composition roots use the same provider container factories as the daemon.
- Test doubles are passed as constructors, never monkey-patched globals.
- Configuration is immutable after startup. Runtime configuration changes create versioned records and publish invalidation events.
- Startup fails closed for invalid security, store, migration, or encryption configuration. Optional providers fail into explicit degraded status.

### 1.11 Required ports and repository ownership

These are the minimum public ports. Teams may split an interface for Interface Segregation but may not merge unrelated ports into a generic data service.

| Context | Required ports/repositories |
|---|---|
| shared | Clock, IdGenerator, TransactionManager, EventPublisher, BlobStore, CryptoPort, SecretResolver |
| identity | BrainRepository, ProjectRepository, RepositoryIdentityRepository, CheckoutRepository, ProjectRepositoryLinkRepository, VcsIdentityPort, DeviceIdentityPort |
| ingestion | EventLedgerRepository, ArtifactRepository, OutboxRepository, InboxRepository, JobRepository, DeadLetterRepository, EventUpcaster, OfflineSpoolRepository |
| sessions | SessionRepository, TaskRepository, TaskContractRepository, TaskEvidenceQuery |
| memory | MemoryRepository, MemoryQueryRepository, MemoryCandidateExtractor, MemoryDedupCandidateQuery |
| graph | AssertionRepository, EvidenceRepository, ContradictionRepository, GraphProjectionWriter, AuthorizedGraphQuery, GraphIntegrityQuery |
| indexing | SourceSnapshotRepository, FileRevisionRepository, SymbolProjectionRepository, EvidenceLineageRepository, VcsRevisionPort, LanguagePluginPort, ArtifactParserPort |
| providers | ProviderAdapterRegistry, ProviderProfileRepository, ProviderRouteRepository, ProviderRuntimePort, EmbeddingSpaceRepository, IndexGenerationRepository, VectorWriteRepository |
| retrieval | ExactCandidateSource, LexicalCandidateSource, VectorCandidateSource, GraphCandidateSource, RerankerPort, TokenCounter, RecallTraceRepository |
| learning | LearningCandidateRepository, CausalHypothesisRepository, ProcedureRepository, EvaluationRepository, DeploymentRepository, EvaluationRunnerPort |
| governance | PrincipalRepository, ScopeGrantRepository, AuthorizationPolicy, ClassificationPolicy, EgressAuthorizationPort, RetentionRepository, DeletionRepository, DeletionPort |
| audit | AuditRepository, AuditCheckpointSigner, ImmutableCheckpointStore |
| operations | MigrationRepository, BackupPort, RestorePort, DiagnosticContributor, DependencyHealthPort, SliRecorder |
| host launcher | HostCapabilityProbe, ContainerRuntimeDetector, RuntimeReleaseCatalog, RuntimeArtifactFetcher, RuntimeArtifactVerifier, RuntimeConsentPort, PrivilegeBroker, RebootCoordinator, ContainerRuntimeInstaller, ContainerRuntimeController, RuntimeOwnershipRepository, AgentConfigAdapter |

Port rules:

- Read and write concerns are split when their consumers or representations differ.
- A repository returns domain aggregates; an optimized query port returns read DTOs.
- Query ports accept AuthorizedScope and bounded query objects, never arbitrary SQL/Cypher strings.
- Provider/parser/model ports return validated candidate DTOs, never mutate repositories.
- Infrastructure exceptions are translated to typed port errors before leaving the adapter.
- Test suites provide in-memory fakes for application tests and contract fixtures that every real adapter must pass.

### 1.12 UI architecture

The viewer is a separate TypeScript application with this dependency direction:

~~~text
app composition/routes
  -> feature presentation and application hooks
    -> feature domain/view models
      -> shared primitives
feature infrastructure -> generated API client
~~~

- features are brains, projects, search, sessions, memory, graph, indexing, providers, learning, governance, audit, and operations.
- A feature may import shared and generated contracts, never another feature’s internal modules. Cross-feature composition occurs in app routes or public feature entrypoints.
- Server state belongs to TanStack Query. Local state uses React state/reducer; a global client-state library requires an ADR and measured need.
- API DTOs are mapped to view models at the feature boundary. Components do not receive raw unknown API JSON.
- Route loaders/actions, hooks, and components contain presentation orchestration only; authorization, lifecycle, promotion, deletion, and provider policy remain server-side.
- Mutations use generated clients, AbortSignal, ETag, idempotency key, operation progress, and typed problem details.
- Error, loading, empty, partial/degraded, stale, forbidden, and conflict states are designed and tested for every data view.
- No dangerouslySetInnerHTML is allowed for recalled content. Markdown/code rendering uses an allowlist sanitizer, no raw HTML, safe links, and isolated syntax highlighting.
- Every feature has unit tests for view-model mapping/hooks, component behavior tests with MSW, accessibility tests, and a Playwright critical flow where it changes a user workflow.

## 2. Technology stack

### 2.1 Version policy

The versions below are the approved baseline on 2026-07-13. Exact patches and transitive dependencies MUST be committed in uv.lock and pnpm-lock.yaml and production images MUST be pinned by digest. Floating latest tags and unbounded dependencies are forbidden.

Patch updates MAY be automated after the full CI/security suite passes. Minor or major updates require a compatibility pull request, changelog review, migration/replay tests, performance comparison, SBOM diff, and rollback plan. Pre-release dependencies are forbidden in production.

The initial quality-tool BOM is Ruff 0.15.21, mypy 2.2.0, pytest 9.1.1, Coverage.py 7.15.1, Hypothesis 6.156.6, pip-audit 2.10.1, Bandit 1.9.4, Semgrep 1.169.0, and Trivy 0.70.0. Exact versions remain in the lockfile or tool image. A beta tool such as an OpenTelemetry instrumentation package is exact-pinned and cannot define a public contract.

| Area | Required technology and baseline | Why |
|---|---|---|
| backend runtime | CPython 3.14.6, standard GIL build; compatibility CI on 3.13 | current stable runtime; one production interpreter reduces ambiguity |
| host installer/launcher | Go 1.26.5, standard library plus narrowly reviewed locked modules | static cross-platform MCP command with no host runtime dependency or domain logic |
| bootstrap setup UI | minimal React 19.2.7/TypeScript 6.0.3/Vite 8.1.4 static application embedded into the signed launcher with Go `embed`; OS-native elevation/reboot dialogs | accessible visible installation without a host Node/browser extension/runtime dependency |
| Python workspace | uv and uv_build 0.11.28, universal uv.lock | fast, reproducible workspace with one reviewed lock |
| API | FastAPI 0.138.0 and Uvicorn 0.51.0 | typed ASGI, OpenAPI, streaming, mature testing |
| validation | Pydantic 2.13.4 and pydantic-settings 2.14.2, strict models | canonical boundary validation and JSON Schema; 2.14.2 contains the reviewed fix for the advisory affecting 2.14.1 |
| relational access | SQLAlchemy 2.0.51 and Alembic 1.18.5 with aiosqlite | explicit async SQLite transactions and versioned migrations |
| canonical ledger and work queue | packaged SQLite 3.53.3 or newer, WAL, `synchronous=FULL`, transactional outbox/inbox, leased jobs and DLQ | one zero-administration durable store owned by one local core service |
| graph | Neo4j 2026.06.0, Cypher 25 | temporal graph and in-index filtered SEARCH required for authorization |
| graph driver | official Neo4j Python Driver 6.2.0 async | supported Bolt, pooling, transactions, causal bookmarks |
| code parsing | py-tree-sitter 0.26.0, Tree-sitter CLI 0.26.11, SCIP 0.9.x, LSP 3.17 | incremental syntax coverage plus precise semantic data |
| artifact storage | application-encrypted content-addressed files in a local named volume | large artifacts outside graph/SQL without an object-store dependency |
| cache | in-process bounded LRU only | non-canonical acceleration without another stateful service |
| model transport | HTTPX async for built-ins; versioned provider sidecar protocol | cancellation, connection pooling, language-neutral extensibility |
| default offline models | Qwen3-Embedding-0.6B (1024 dimensions), Qwen3-Reranker-0.6B, Qwen3-4B-GGUF Q4_K_M extraction; exact upstream revisions/weight digests and serving images in release BOM | CPU-capable semantic indexing/reranking/local extraction with no API key or runtime download |
| MCP | official MCP Python SDK 1.28.1 and protocol 2025-11-25 until v2 is stable and certified | stdio through the session bridge; optional authenticated loopback HTTP only |
| CLI | Typer and Rich, using application ports | typed cross-platform operator interface |
| container runtime | installer-provisioned Docker Engine 29.6.1 or certified Docker Desktop equivalent; Docker Compose plugin 5.1.4 | current patched single-host runtime with no user preinstallation, health-gated orchestration, volumes, networks, and profiles |
| image trust | OCI images, Cosign/Sigstore verification, CycloneDX/SPDX SBOM, SLSA provenance | immutable offline-verifiable supply chain |
| telemetry | OpenTelemetry Python 1.43.0, contrib 0.64b0, optional local Collector 0.156.0, OTLP | local vendor-neutral traces/metrics and correlated safe logs; no call home |
| UI runtime | Node.js 24.18.0 LTS, React 19.2.7, TypeScript 6.0.3 | supported stable UI/runtime baseline |
| UI build | pnpm 11.12.0 workspace, Vite 8.1.4 | deterministic fast SPA build; SSR is unnecessary for an admin UI |
| UI server state | TanStack Query current locked major | caching, invalidation, cancellation, paginated server state |
| UI graph | Cytoscape.js behind a visualization port | filtered interactive graph with mature layouts |
| UI unit tests | Vitest 4.1.10, Testing Library, MSW | behavior-focused component and API tests |
| UI end-to-end | Playwright 1.61.1 and axe-core 4.11.4 across Chromium, Firefox, WebKit | cross-browser, accessible, traceable E2E |

The product MUST NOT use an agent framework as its core architecture. LLM/provider SDKs are outbound adapters only. LangChain, LlamaIndex, Neo4j GraphRAG, or vendor helpers MAY be used internally only behind ports, only when they reduce code, and only if conformance tests prove identical domain behavior.

Neo4j 2026.06 Community is selected instead of 5.26 LTS because Cypher 25 SEARCH with filterable non-vector properties is required to apply Brain/project/repository/classification filters inside vector candidate generation. The project MUST certify every monthly Community image before its predecessor leaves support and move to the first compatible 2026 LTS when available. Cypher queries explicitly target Cypher 25. A fallback that performs project authorization only after vector retrieval is prohibited.

### 2.2 Local Docker Compose topology

The only supported runtime is one single-host Docker Compose project. There is no hosted, cluster, remote-MCP, or native-daemon variant. The default release contains:

| Service/container | Lifetime | State and access | Networks and host exposure |
|---|---|---|---|
| `core` | persistent | owns SQLite/WAL, encrypted CAS, API/UI, scheduler, supervised roles; no source-tree mount | `am_internal`; API/UI published only on configured `127.0.0.1` and `::1` loopback ports |
| `neo4j` | persistent | owns only the graph projection volume; authenticated Bolt available to core only | `am_internal`; no host port |
| `mcp-session` | transient per agent connection | current resolved directory at `/workspace` read-only and one short-lived session credential; no database/provider credential | `am_internal`; MCP stdio only; automatic removal |
| `local-embedding`, `local-reranker`, `local-extractor` | required default set | pinned release-BOM Qwen weights; no project mount; CPU-capable, optional certified GPU override | `am_internal`; no host port and no external route |
| `local-provider-*` | optional profile | additional pinned local model weights/cache; no project mount; GPU only when explicitly selected | `am_internal`; no host port and no external route |
| `provider-gateway` | optional `remote-providers` profile | only service permitted to resolve remote provider credentials and open external connections | `am_internal` plus `am_egress`; no host port |
| `otel-collector` | optional local observability profile | local bounded telemetry volume and local-only receivers | `am_internal`; optional loopback UI only; no exporter by default |
| `migrate`, `backup`, `restore` | one-shot, launcher-targeted | exact operation-scoped volumes and local archive bind mount | `am_internal`; restore never joins `am_egress` |

`am_internal` MUST use an internal user-defined bridge network. `core`, Neo4j, MCP sessions, local providers, and observability MUST have no default Internet route. Enabling remote providers creates `am_egress` and dual-homes only `provider-gateway`; application and custom-adapter traffic reaches the gateway on `am_internal`. The gateway is an authenticated application proxy and credential broker, not an unrestricted CONNECT proxy: it accepts a validated embedding/reranking operation envelope, independently reauthorizes the destination, resolves/injects the exact provider credential after approval, removes credentials from all response/error/telemetry paths, and opens the HTTPS connection. Core, MCP, and custom adapters receive only SecretRefs and never provider credential values. No runtime egress is permitted for analytics, telemetry, crash reporting, licensing, arbitrary webhooks, extraction, or model downloads.

Bootstrapper downloads are separate, foreground setup operations bound to the signed runtime/product manifest and displayed plan. Network conformance therefore measures two explicit windows: setup may reach only approved vendor/package/image/model sources, while post-Ready AgentMemory-managed launcher/containers must satisfy the default-offline policy. Docker Desktop is an external runtime with separately disclosed vendor settings/network behavior; tests attribute traffic by process/container and must never classify unrelated Desktop traffic as AgentMemory provider egress.

The release Compose model MUST enforce for every service where supported:

- immutable digest-pinned image and fixed non-root UID/GID;
- `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`, default seccomp, bounded PIDs/CPU/memory, and tmpfs scratch with size/mode limits;
- read-only configuration and secret mounts, explicit health check, finite stop grace period, and `restart: unless-stopped` for persistent services;
- no privileged mode, host network/PID/IPC namespace, Docker socket, broad home/root bind, unapproved device, or writable source-tree mount.

Persistent data MUST use installation-labelled Docker named volumes on the same Docker host, never NFS/SMB/network storage and never a project-directory bind. Volume names include installation ID, purpose, and data-generation ID so an upgrade can preserve the last known-good generation. The persistent core is the only process that opens SQLite. The container writable layer is non-canonical and disposable.

The core image carries the reviewed CPython/SQLite build and rejects an older SQLite or unsupported compile options. SQLite is canonical for events, identity, configuration, grants, audit, deletion tombstones, domain snapshots/events, outbox/inbox, jobs, operations, and migrations. Neo4j, full-text records, vectors, briefings, and caches are rebuildable projections.

Secrets are `SecretRef` records. The launcher materializes random installation/key/provider material from the OS credential facility where supported or an owner-only local secret source, then mounts it read-only only into the consuming container. Compose secrets are treated as protected file mounts, not as a cloud secret manager. Production rejects plaintext secret values in YAML, `.env`, labels, process arguments, or environment variables.

Local embedding, reranking, and extraction adapters run out of process on `am_internal`; core never imports GPU frameworks. The default release MUST start and certify Qwen3-Embedding-0.6B at 1024 dimensions, Qwen3-Reranker-0.6B, and Qwen3-4B-GGUF Q4_K_M extraction, each bound to exact upstream revision, weight digest, tokenizer/template hash, runtime image digest, and resource profile in the BOM. These artifacts are pulled/loaded and verified by the installer, not downloaded by a runtime container. A BOM model change creates new embedding/index generations and passes provider/golden/privacy/performance gates. Remote execution is permitted only for explicitly approved embedding/reranking operations through the gateway. Extraction is always local.

#### 2.2.1 Installer and automatic MCP session lifecycle

The signed Go distribution has two roles in one verified binary: a full native bootstrapper used only for installation/repair/upgrade/uninstall and a minimal steady-state MCP launcher. The bootstrapper owns host dependency provisioning; it contains no Brain business rules. Installing the MCP is the complete product installation, and no Docker knowledge or preinstalled runtime may be assumed.

Every certified MCP package MUST contain the exact signed launcher and embedded setup assets for its declared platform/architecture plus the release trust roots; it cannot be a script that downloads and executes an unverified bootstrapper or requires a host language/package runtime. The agent host verifies the package signature where it supports that capability, and the launcher self-verifies its signed release binding before any download or elevation.

`InstallApplication` composes `EnsureContainerRuntimeApplication` before any Compose operation. It uses the typed ports `HostCapabilityProbe`, `ContainerRuntimeDetector`, `RuntimeReleaseCatalog`, `RuntimeArtifactFetcher`, `RuntimeArtifactVerifier`, `RuntimeConsentPort`, `PrivilegeBroker`, `RebootCoordinator`, `ContainerRuntimeInstaller`, `ContainerRuntimeController`, `RuntimeOwnershipRepository`, and `AgentConfigAdapter`. Platform code remains behind adapters; domain/application packages never branch on raw OS strings or invoke a shell.

The fsync-safe install journal implements this state machine:

~~~text
DetectHost -> DetectRuntime -> PlanRuntime -> AwaitRuntimeConsent
  -> AcquireRuntime -> VerifyRuntimeArtifact -> InstallPrerequisites
  -> InstallRuntime -> AwaitThirdPartyTerms -> StartRuntime
  -> VerifyRuntimeCapabilities -> AcquireAgentMemoryRelease
  -> VerifyAgentMemoryRelease -> PrepareLocalState -> StartCompose
  -> BootstrapBrain -> MergeAgentConfiguration -> VerifyProduct -> Ready

Any phase -> Cancelled | PausedForAdministrator | UnsupportedHost | RuntimeConflict | FailedRecoverable
InstallPrerequisites | InstallRuntime -> RebootPending -> ResumeVerified -> next recorded phase
~~~

Every transition stores operation ID, phase, attempt, input-plan digest, verified artifact digest, non-secret output facts, runtime ownership, compensation boundary, and next safe action using temp-file, fsync, rename, and parent-directory fsync. `Ready` is unreachable until every predecessor is verified. Re-entry resumes the first unverified transition; it never infers completion from a downloaded filename, installed executable, running process, or Docker CLI on `PATH` alone.

At operation creation the launcher generates a 256-bit `BootstrapOperationKey` in macOS Keychain, Windows Credential Manager/DPAPI, Linux Secret Service when available, or an owner-only `0600` local secret file on a verified local filesystem. It HMAC-chains the journal, plan, consent, privilege, ownership, and resume receipts stored below the platform user-config directory at `AgentMemory/bootstrap/<operation-id>/`; the key never enters a privileged helper or reboot entry. On Ready, an audit-safe operation summary is imported into core and the temporary key/receipts are retained for the signed-install evidence period or securely removed according to policy. A journal with an invalid chain, owner, machine binding, or sequence is `AM_INTEGRITY_VIOLATION` and cannot resume.

Before modification, `RuntimeInstallPlan` MUST contain the certified OS/architecture/runtime version and channel, existing local runtime/context/workload summary, exact official source URLs, publisher identities and digests, download and expanded sizes, required free-space reserve, packages/features/settings to change, privilege scope, third-party terms URL/version/digest, reboot probability, proxy mode, rollback limits, and ownership disposition. A visible agent-host or launcher-served local setup UI presents this in plain language with one recommended action. Docker Desktop consent links the official terms, discloses that some commercial/government use requires a paid subscription, and requires a non-preselected confirmation that the user has authority and entitlement; AgentMemory does not collect organization revenue/headcount or decide eligibility. Consent is bound to the plan and terms digests; any material plan or terms change invalidates it. AgentMemory never accepts third-party terms, claims license eligibility, captures an administrator password, bypasses UAC/Gatekeeper/PolicyKit/device management, changes firmware, disables endpoint protection, or adds a user to a root-equivalent group on the user's behalf.

Every artifact whose signed `expanded_bytes` is nonzero MUST also carry a closed expanded-target representation kind, the deterministic local Docker storage projection/identity, the source CAS digest and exact source size, the expected target digest, and a digest of that target-authority projection inside the signed release/install plan. The launcher MUST reject a plan that omits or does not understand any of these fields before writing target lifecycle state or mutating Docker. It MUST NOT infer archive, image, volume-tree, model, schema, or bundle semantics from a filename, media sniffing, source URL, or payload. Materialization, generation transfer, compensation, rollback, and uninstall MUST use an independently authenticated pending-state journal, reconcile only exact source/pool/receipt/target/owner observations, persist engine-measured bytes rather than planned or reserved estimates, and verify both the reservation and target identity absent before recording retirement. Contradictory or foreign state is an integrity failure and MUST NOT be repaired, adopted, relabelled, or deleted.

`SetupProgressPort` prefers a certified agent-host installation surface. Otherwise the launcher binds an ephemeral HTTP server to random IPv4/IPv6 loopback ports, serves only the static setup application embedded in its signed binary, and opens the system default browser automatically. The one-use 256-bit setup capability is placed in the URL fragment, removed with `history.replaceState` before any navigation, and sent only in an authorization header; the server validates exact loopback Host/Origin, anti-CSRF token, OS-user ownership, operation ID, rate/size limits, and expiry. Assets use no CDN, analytics, remote font, external script, or Internet request. Progress streams by authenticated SSE, decisions use idempotent POST commands bound to the plan digest, and the server exits on terminal state. The UI meets WCAG 2.2 AA, keyboard and screen-reader operation, reduced motion, 200% zoom, localized message keys, explicit download/disk/restart information, and never renders raw Docker errors. OS elevation and reboot confirmations remain native system dialogs. A platform/host without either a certified embedded host surface or an automatically openable local browser is not a one-click certified consumer installation target.

Runtime acquisition and installation rules are exact:

- **Existing runtime:** inspect the local endpoint through an explicitly addressed context/socket, Engine API, Compose plugin, architecture, bind-mount probe, network/volume probe, current workloads, and security mode. Reuse only a certified compatible local runtime. Do not change the user's global Docker context, proxy, registries, resource allocation, update channel, images, containers, networks, volumes, or settings. Start a compatible stopped runtime automatically. An incompatible runtime requires a new displayed remediation plan and approval; remote contexts and uncertified Docker-compatible products are rejected.
- **macOS:** fetch the architecture-correct certified Docker Desktop artifact only from the signed release catalog's official Docker host, verify TLS, release digest, Apple code-signing identity and notarization, mount/copy through argv-based OS APIs, and request only macOS-native authorization. Present the exact vendor terms through `RuntimeConsentPort`; only after an explicit receipt may the adapter invoke Docker's documented installer for the invoking user with its documented license-acceptance flag. If the certified vendor build still requires a first-run terms surface, launch and foreground it and observe rather than synthesize the user's decision. Launch Docker Desktop programmatically and wait for Engine plus Compose capability probes. No PATH edit, drag-and-drop, Docker onboarding choice, or settings navigation is delegated to the user.
- **Windows:** use the certified stable Docker Desktop all-users installer and WSL2 Linux containers. Verify the official installer digest and Authenticode chain with `WinVerifyTrust`; after an exact `RuntimeConsentPort` receipt, invoke its documented stable install mode and license-acceptance flag without a command shell through one UAC-approved fixed plan. Probe WSL version, Windows features, virtualization, edition/build, and firmware capability. Missing Microsoft-signed WSL components/features are installed through the same journaled native-elevation flow; if restart is required, checkpoint first and resume after sign-in. Add the invoking user to `docker-users` only if the certified WSL2 installation demonstrably requires it, after a separate root-equivalence warning and consent; otherwise do not. Launch Docker Desktop and observe any vendor-required residual terms decision before readiness. Per-user or ARM64 installers fail certification while their vendor status is pre-GA.
- **Linux:** support only distro/version/architecture tuples in the signed compatibility catalog. Configure Docker's official stable package repository using its signed repository metadata/key, install exact `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-buildx-plugin`, `docker-compose-plugin`, and `docker-ce-rootless-extras` versions through an argv-based `apt`/`dnf` adapter, and verify installed package signatures and versions. Never execute `curl | sh`, `get.docker.com`, a floating package version, or an unreviewed convenience script. Install rootless prerequisites, allocate subordinate IDs safely, invoke the packaged `dockerd-rootless-setuptool.sh` as the user, create the user service/context, and validate rootless security options. If certified rootless prerequisites cannot be established, return `AdministratorActionRequired`; do not silently enable a rootful daemon or add the user to `docker`.
- **Offline:** the bundle may contain a runtime installer only when redistribution rights permit and the same vendor/signature/digest checks pass. Otherwise the UI requests one separately supplied official vendor artifact, verifies it before execution, and continues automatically; it never accepts an arbitrary executable or tells the user to run it.

For a runtime installed by AgentMemory, `RuntimeConfigurationPort` selects the local Linux engine, keeps the daemon on a local socket with no TCP listener, disables Docker Offload/cloud execution and Kubernetes, avoids Docker account/sign-in and extension installation, disables usage analytics/crash upload and vendor automatic updates where documented controls permit, and applies the certified CPU/RAM/disk profile without exposing privileged ports. AgentMemory performs signed runtime update checks only as an explicit foreground maintenance operation. For a reused runtime, the launcher changes none of these global settings; it addresses a proven local engine endpoint explicitly and blocks if cloud/offload/remote execution, Windows-container mode, an exposed unauthenticated TCP daemon, or insufficient isolation makes local execution unverifiable. Any proposed remediation is a new consented plan and cannot interrupt unrelated workloads silently.

The `PrivilegeBroker` launches only an immutable, signed, plan-digest-bound executable/argument allowlist: macOS uses Authorization Services/the vendor installer authorization path, Windows uses `ShellExecuteEx` with `runas` and a verified helper, and certified graphical Linux uses Polkit/`pkexec` with a verified helper. It never opens a hidden terminal or invokes `sudo` interactively. The helper revalidates caller UID/SID, executable and plan hashes, artifact file descriptor/hash, nonce, expiry, IPC ACL, and closed typed operation before mutation. It passes no secret on argv/environment, inherits no untrusted working directory or library search path, writes an append-only result receipt, and exits immediately after the fixed privileged steps. All downloads and signature checks happen unprivileged before elevation. User denial transitions to `Cancelled`; policy/MDM denial or missing certified native prompt facility transitions to `PausedForAdministrator`; unsupported firmware/virtualization transitions to `UnsupportedHost`. Inbound adapters map them to the Section 5.8 error codes, never to a raw Docker error.

Before reboot/logout, `RebootCoordinator` writes the verified journal, creates an owner-only one-use continuation containing only launcher path/hash, operation ID, journal path/hash, expiry, and random non-secret nonce, and registers it with the platform's per-user login continuation facility. On launch it verifies binary/journal ownership and hashes, consumes the nonce atomically, resumes once, and removes the continuation on success, cancellation, expiry, or terminal failure. Credentials, provider keys, Docker tokens, and Brain data never appear in the continuation.

After runtime readiness, `InstallApplication` MUST:

1. verify OS/architecture, rootless/user access, disk/memory, host-at-rest encryption attestation, loopback port, proxy policy, and current-directory bind-mount support;
2. obtain a signed release manifest, digest-pinned images, and default local-model artifacts, or consume an offline bundle, then verify checksums, signature identity, provenance subject, SBOM association, model/weight digests and licenses, compatibility, vulnerability, and license policy before execution;
3. store the immutable Compose bundle under `~/.agentmemory/releases/<version>/`, create owner-only configuration/runtime/secret/backup directories, installation ID, keys, active-release pointer, and recovery metadata;
4. create labelled volumes and the internal network, run one-shot migrations, execute `docker compose up -d --wait`, and require Neo4j health before core readiness;
5. verify SQLite integrity/migration head, writable volumes, Neo4j schema compatibility, encryption keys, audit append, deletion guard, worker lease recovery, and a write/index/recall smoke test;
6. atomically back up and merge the selected host's MCP and supported hook configuration; repeated installation returns `AlreadyReady` without duplicate Brain/state, runtime installation, or unrelated configuration changes.

A certified host package invokes the bootstrapper during MCP installation when the host supports native post-install execution. Otherwise `agentmemory mcp --agent <host>` MUST complete the host's MCP initialization deadline first, expose `installation_status` and `installation_cancel` while the bootstrapper continues, return typed `NotReady` from other tools, and issue the protocol's tool/resource-list-changed notification when Ready. It never writes progress frames outside valid MCP stdout. The keyboard- and screen-reader-accessible agent-host/local setup surface and host diagnostics show phase, bytes, estimated remaining stages, consent/reboot request, automatic retry, cancellation, and one safe recovery action in plain language. Logs/stderr alone are insufficient. No screen may instruct the user to run Docker, Compose, WSL, package-manager, service-manager, or shell commands.

Host packages use a two-level, non-circular signed authority. The canonical release publication is signed first and binds every native installer and its evidence. Each platform-specific host package contains that exact publication, its offline Sigstore bundle, the exact publication-selected native installer or Linux DEB/RPM pair, their bound offline signature bundles, and one independently publisher-verified and Sigstore-verified `agentmemory-bootstrap` executable. A detached canonical host-package record then binds the completed archive digest/size, bootstrap digest, publication digest, publication-signature digest, host, OS, architecture, version, source commit, and source epoch; the archive and record are signed and qualified without changing package bytes. Immutable promotion MUST only copy this already-signed set and MUST NOT rebuild, rearchive, or sign it. Putting a record that contains an archive's digest inside that same archive is forbidden.

Claude packages MUST be deterministic `.mcpb` ZIP archives conforming to the pinned official MCPB v0.4 binary-server schema, with root `manifest.json`, `server.type=binary`, a root-confined `entry_point`, `${__dirname}` command, separate argv `mcp --agent claude`, and one exact `darwin`, `linux`, or `win32` compatibility cell. Gemini packages MUST contain a root `gemini-extension.json` conforming to the pinned Gemini extension contract, use `${extensionPath}${/}` rather than PATH or a working-directory guess, separate command/args, and invoke `mcp --agent gemini`; the distributed ZIP is a signed release transport that the certified marketplace/installer atomically expands to a local extension directory before invoking Gemini's local-path installation, never a ZIP path passed directly to Gemini CLI. The generic package uses `agentmemory.custom-agent-registration.v1`, relative root-confined command metadata, stdio, and exactly `mcp --agent custom`; the consuming host owns registration. Archives have sorted closed entries, fixed source timestamps, explicit `0755` bootstrap and `0644` data modes, no links/special entries, and byte-reproducible output. Certified cells are macOS Intel/Apple Silicon, Linux x86_64/ARM64, and Windows x86_64; another cell requires a signed compatibility change and full qualification.

Agent-adapter certification MUST prove the distribution channel can deliver and verify the platform launcher, execute it on install or first invocation, open the local setup surface and native consent/elevation controls, survive the host's MCP timeout policy, and reconnect after reboot. A marketplace that forbids native execution or required OS interaction fails certification; documentation cannot substitute for this capability.

The bootstrapper MUST NOT request a remote-provider credential. It reserves space before multi-gigabyte image/model acquisition, uses range-resumable content-addressed downloads with per-chunk and final digest validation, retains only verified complete artifacts across retry, and removes AgentMemory-owned partials on cancellation. It never deletes unrelated Docker data to make space. A proxy/PAC/TLS-interception/captive-portal failure is identified before elevation when possible and uses the OS credential flow without persisting proxy secrets.

`RuntimeOwnershipRecord` is created before the first runtime mutation and stores `ReusedExternal` or `ProvisionedByAgentMemory`, vendor/version/channel, endpoint/context, artifact digest/publisher, install plan/consent digests, components and settings created, pre-existing-state hashes, privilege receipts, reboot continuations, and last compatibility probe. At Ready it is atomically copied to the owner-only AgentMemory runtime directory, HMAC-protected by the installation key, and referenced from the core audit summary. Repair and upgrade may mutate only items recorded as AgentMemory-provisioned, except that starting a compatible stopped external runtime is allowed. Runtime upgrade that could affect unrelated workloads requires a new plan listing those workloads and explicit approval. Default uninstall never removes Docker. It may offer a separate runtime-removal action only for `ProvisionedByAgentMemory`, only after proving no non-AgentMemory container/image/volume/network/context depends on it, and only after a second impact-specific confirmation; uncertainty preserves the runtime.

Each host integration implements the same `AgentConfigAdapter` contract: `Detect`, `Read`, `Validate`, `PlanMerge`, `ApplyAtomic`, `VerifyInvocation`, and `RestoreBackup`. It uses the host's documented configuration format/API, preserves unknown fields and ordering/comments where the format permits, stores a content-hashed backup under the owner-only AgentMemory configuration backup directory, adds one stable AgentMemory-owned entry/marker, and refuses ambiguous duplicate ownership. Install never removes another MCP server or hook. Uninstall removes only the entry whose stored before/after hashes and ownership marker still match; a user-modified entry becomes a displayed conflict rather than an overwrite.

On `agentmemory mcp --agent <host>`, the launcher MUST acquire an installation startup lock, ensure the exact active Compose release is healthy, and start it only when necessary. It canonicalizes both logical and real current paths without shell interpolation, records host device/Git identity, creates a UUID session and short-lived scoped credential, and runs the exact digest-pinned `mcp-session` image without a TTY or writable layer. The only source mount is:

~~~text
type=bind,source=<canonical-current-directory>,target=/workspace,readonly
bind propagation: rprivate; source must already exist; no implicit parent mount
~~~

On supported Linux kernels the launcher requests recursive read-only behavior; otherwise it detects nested mounts and refuses or excludes them rather than allowing a writable submount. If a worktree's Git metadata lies outside the mount, the launcher supplies signed host-computed identity metadata and reports partial repository coverage; it never widens the mount silently.

The bridge writes MCP protocol frames only to stdout and diagnostics only to stderr. It calls core application contracts, never SQLite, Neo4j, or a provider. It hashes the workspace and streams only changed, policy-authorized relative paths/content to canonical ingestion while the mount exists, because persistent workers cannot reread the host source later. On cancellation, EOF, or signal it attempts a bounded checkpoint, records completed/interrupted accurately, revokes the credential, and removes the container. A heartbeat lease cleans abandoned sessions.

Host lifecycle hooks call the authenticated loopback core through the launcher and correlate to the MCP session; they do not `docker exec` into the bridge. If core is unavailable, the launcher writes only a bounded encrypted temporary spool and returns before the hook deadline. That spool is reconciled and erased after acknowledged ingestion; it is the only host-side data buffer and is not a second Brain store.

#### 2.2.2 Normative Compose resources and policy

The signed release manifest and generated Compose model use these logical resources. Physical names are derived only from a validated installation UUID, purpose, and generation; user/project text never enters a Docker resource name.

| Resource | Required name shape | Owner/mount policy | Lifecycle |
|---|---|---|---|
| canonical state | `agentmemory_<iid>_state_<gen>` | core `/var/lib/agentmemory/state` read-write; stopped-core migrate/backup/restore only | generation-pinned; never deleted by upgrade |
| encrypted CAS | `agentmemory_<iid>_artifacts_<gen>` | core read-write; stopped-core backup/restore only | generation-pinned with manifest deduplication |
| graph projection | `agentmemory_<iid>_neo4j_<gen>` | Neo4j read-write only; dump/restore helper while coordinated | rebuildable generation |
| audit/deletion journal | `agentmemory_<iid>_journal` | core append; verifier read; backup read | installation-stable, separately signed |
| model cache | `agentmemory_<iid>_models` | selected local-provider sidecar read/write; core no mount | retained across release changes; untrusted/rebuildable |
| local telemetry | `agentmemory_<iid>_telemetry` | core/optional collector only | bounded retention and user-purgeable |
| internal network | `agentmemory_<iid>_internal` | `internal: true`; attachable only for the launcher-created bridge using the exact network ID | installation-stable |
| egress network | `agentmemory_<iid>_egress` | absent by default; gateway only | created only after owner activates remote provider profile |

Every Docker resource carries exact labels `io.agentmemory.installation`, `io.agentmemory.release`, `io.agentmemory.generation`, `io.agentmemory.purpose`, and `io.agentmemory.managed=true`. Launcher inventory records Docker IDs after creation and verifies labels before mutation. Cleanup/uninstall requires both inventory membership and matching installation label.

The default Compose model MUST satisfy all of the following static and runtime assertions:

- `core` publishes `${AM_LOOPBACK_V4:-127.0.0.1}:${AM_PORT:-9411}:9411` and, only when the certified platform supports it, the equivalent `::1` mapping; no other service declares `ports`.
- `neo4j` uses `expose` only on the internal network, authenticates core with a dedicated secret, and does not enable Browser/telemetry/remote backup features.
- `core.depends_on` requires `neo4j`, `local-embedding`, `local-reranker`, and `local-extractor` to be `service_healthy`; readiness additionally waits for application migrations/schema/provider probes. Container-running state alone is insufficient.
- Persistent services use `restart: unless-stopped`; one-shot services use `restart: "no"`; the MCP session uses `--rm` outside the persistent Compose service set.
- Each service declares a health check that exercises its real dependency boundary without returning version, configuration, credential, path, Brain, or content data.
- Configuration uses immutable validated files. Secret values never pass through Compose interpolation; the rendered `docker compose config` output must be safe to attach to diagnostics.
- No service can join Docker's default bridge. The launcher supplies `--network none` to verification helpers and the explicit internal network to MCP/operation helpers.
- Resource limits are non-null. The release profile publishes minimum/recommended host resources and per-service memory/CPU/PID limits; local-model profiles add their model-specific CPU/GPU/RAM/disk requirement before activation.
- A rendered-profile policy engine rejects `privileged`, host namespaces, `network_mode: host`, Docker socket/pipe, unapproved devices, added capabilities, writable config/secret/source bind, non-loopback publish, mutable image tag, missing digest, external network on a non-gateway service, or unlabelled managed resource.

The Compose conformance suite renders every supported profile and override for both architectures, inspects running containers/networks/mounts/capabilities, scans from the LAN and an unrelated container, and captures packets during the full default workflow. A static declaration is not sufficient evidence of isolation.

### 2.3 Approved dependency direction

The core package graph is:

~~~text
apps -> bounded-context application APIs -> bounded-context domain
adapters -> public contracts and application APIs
infrastructure -> domain/application ports
contracts -> shared kernel only
domain -X-> framework, database, queue, network, filesystem, provider SDK
bounded-context internals -X-> another bounded-context internals
~~~

The UI consumes only the generated OpenAPI client and explicitly versioned SSE contracts. It MUST NOT duplicate backend domain rules; it may perform presentation validation for faster feedback.

### 2.4 Supported language, contract, and platform matrix

The complete production release MUST publish and test this minimum code-intelligence matrix:

| Tier | Languages | Required capability |
|---|---|---|
| precise | Python 3.10–3.14; JavaScript ES2020–ES2026; TypeScript 5–6; Java 17/21/25; Kotlin 1.9/2.x; Go 1.22–1.26; C#/.NET 8–10 | syntax plus cross-file definitions, references, calls, implementations, packages, and precise-source spans using SCIP/LSP/compiler evidence where available |
| structural | Rust 2021/2024; C11/C17/C23; C++17/20/23; Ruby 3.2–3.5; PHP 8.2–8.5; Swift 5.10/6.x; POSIX shell/Bash; PowerShell 7 | syntax, definitions, imports/includes, local calls, inheritance/implementation candidates, and exact spans; uncertain cross-file links remain inference-labeled |
| lexical fallback | every UTF-8 text language not above | file/chunk exact and full-text search only; no fabricated semantic symbols or call relationships |

Every grammar is pinned to an immutable commit/checksum and tested against its declared language versions. A parser upgrade changes the parser fingerprint and schedules affected reindexing. Unsupported syntax produces partial coverage metadata, never an authoritative absence.

Required contract/configuration parsers:

- OpenAPI 3.0 and 3.1, JSON Schema 2020-12, GraphQL SDL/operations, Protocol Buffers proto3/edition 2023, gRPC bindings, and AsyncAPI 2/3.
- package and lock formats for Python, npm/pnpm/yarn, Maven/Gradle, Go modules, Cargo, NuGet, Bundler, Composer, Swift Package Manager.
- Dockerfile/Compose, Kubernetes YAML and Helm-rendered manifests, Terraform HCL, GitHub Actions, GitLab CI, environment-name references, and common reverse-proxy/API-gateway configuration. Kubernetes/Helm/Terraform are indexed user-repository formats, not AgentMemory runtime targets.
- JSON, JSON5, YAML, TOML, XML, INI, and dotenv names; dotenv values are classified/secret-scanned and are not persisted by default.

Supported product platforms:

- macOS 15 and 26 on ARM64/x86_64: the signed native launcher automatically provisions a certified Docker Desktop release when absent, verifies its Apple publisher/notarization and release digest, drives the documented per-user installation/privilege flow, launches it, waits for the user's Docker terms decision, and verifies current-directory file sharing.
- Linux ARM64/x86_64 on the exact Ubuntu, Debian, Fedora, RHEL, and CentOS releases in the signed compatibility manifest: the launcher automatically configures Docker's official signed stable package repository, installs exact Docker Engine/CLI/containerd/rootless-extras/Buildx/Compose packages, and configures rootless Docker for the invoking user. A compatible existing local rootful daemon may be reused only after an explicit root-equivalence warning; the installer never silently adds a user to the `docker` group.
- Windows 11 x86_64: the signed native launcher automatically provisions the certified stable Docker Desktop all-users installer in WSL2/Linux-container mode when absent, verifies Authenticode publisher and release digest, provisions or updates the Microsoft-signed WSL2 prerequisite through native elevation when required, coordinates reboot/resume, launches Docker Desktop, and waits for the user's Docker terms decision. Docker Desktop per-user mode and Windows ARM64 remain uncertified while their vendor channel is Beta, Early Access, or otherwise pre-GA. The launcher translates drive and UNC paths through typed APIs and never constructs a shell command from a path.
- Runtime images: OCI Linux ARM64/x86_64 multi-architecture indexes with platform-specific immutable digests bound by the signed release manifest.
- Browsers: Vite 8 baseline widely available targets, never less than Chrome/Edge 111, Firefox 114, and Safari 16.4; the release test matrix uses the current Playwright Chromium, Firefox, and WebKit against loopback only.

Path identity is computed from the host logical/real path, device ID, repository fingerprint, and Git metadata, never from `/workspace`. The executable compatibility matrix MUST cover spaces, Unicode, quotes/metacharacters, symlinks/junctions, case-insensitive filesystems, worktrees, submodules, paths longer than common defaults, Windows drive/UNC paths, and Docker Desktop mount-permission failures. A remote Docker context/daemon is rejected because a bind mount targets the daemon host rather than the user's current machine.

Removing a cell from this matrix requires a documented deprecation window, usage evidence, export/migration path, and updated PRD/specification. Adding a cell requires parser/adapter fixtures, indexing precision metrics, incremental invalidation tests, and support ownership.

## 3. Repository organization

The repository MUST be a monorepo because schemas, adapters, server, SDK, UI, tests, deployment artifacts, and migrations must change atomically.

~~~text
agentmemory/
  apps/
    daemon/
    mcp_server/
    cli/
    worker/
    viewer/
    setup_ui/                # pre-container accessible bootstrap UI embedded in launcher
    launcher/
      cmd/agentmemory/
      internal/domain/
      internal/application/
      internal/adapters/
        runtimecatalog/
        runtimediscovery/
        runtimeprovision/
        artifactacquisition/
        artifacttrust/
        consent/
        privilege/
        reboot/
        servicemanager/
        setupui/
      internal/contracts/
      go.mod
      go.sum
  src/agentmemory/
    shared/
    identity/
    ingestion/
    sessions/
    memory/
    graph/
    indexing/
    providers/
    retrieval/
    learning/
    governance/
    audit/
  contracts/
    openapi/
    jsonschema/
    events/
    mcp/
    provider-protocol/
  adapters/
    agents/
      claude_code/
      codex/
      gemini_cli/
      cursor/
      generic/
    providers/
      openai/
      cohere/
      voyage/
      google/
      qwen/
      openai_compatible/
  sdk/
    python/
    typescript/
  migrations/
    relational/
    neo4j/
    projections/
  tests/
    contract/
    integration/
    end_to_end/
    security/
    privacy/
    migration/
    resilience/
    load/
  evals/
    golden/
    holdout/
    adversarial/
    provider_bakeoff/
  deploy/
    compose/
    installer/
      runtime_manifests/
      platform_helpers/
    offline_bundle/
    policies/
  docs/
    adr/
    architecture/
    api/
    adapters/
    operations/
    security/
    runbooks/
  pyproject.toml
  uv.lock
  pnpm-workspace.yaml
  pnpm-lock.yaml
~~~

Naming:

- Python modules and packages use snake_case; classes use PascalCase; commands are imperative; events are past tense.
- Tests mirror production paths and use test_<behavior>_<condition>_<outcome>.
- Every public schema has a stable schema ID and semantic version.
- Generated code lives in generated directories and is never hand-edited.
- Cypher is stored in named .cypher files or typed query modules and tested with EXPLAIN on representative data.

## 4. Data and persistence design

### 4.1 Canonical versus derived state

Canonical:

- owner-only host installation journal, signed Docker resource inventory, and active release/data-generation pointer for pre-core orchestration; SQLite mirrors these once available and startup reconciliation fails closed on disagreement;
- authorized raw AgentEvents and immutable event payload references;
- identity and scope mappings;
- user corrections, approvals, policies, grants, holds, and deletion tombstones;
- provider profile configuration without credentials;
- audit events and signed audit checkpoints.

Derived and rebuildable:

- memories and summaries generated from raw events;
- Neo4j nodes, assertions, evidence paths, materialized edges;
- code symbol and topology projections;
- full-text records and embeddings;
- retrieval caches, briefings, evaluation read models, metrics.

A projection write MUST store source event/artifact IDs, source content hashes, schema version, parser/extractor version, provider/embedding-space generation, and projection generation. Rebuild compares a deterministic projection digest excluding nondeterministic timestamps.

Relational memories, assertions, learning objects, and operation rows are operational aggregate/write-model snapshots. Their authoritative mutation history is the append-only domain_events stream plus explicit user/admin records and AgentEvents. A Unit of Work appends the next aggregate-version domain event, updates its snapshot, writes outbox and audit, and commits atomically. Rebuild can recreate snapshots and Neo4j from those streams; snapshot loss does not erase the decision history.

### 4.2 Relational schema

All tables include created_at, updated_at where mutable, schema_version, and brain_id where applicable. Primary keys are UUIDv7 unless the row is an append-only sequence. Foreign keys and explicit indexes are mandatory. Soft deletion is not a substitute for the deletion workflow. One SQLite database belongs to one local installation and may contain multiple explicitly isolated Brains.

Required tables:

| Table | Essential columns and constraints |
|---|---|
| installation_state | singleton_key fixed `local`, installation_id, owner_principal_id, active_release_digest, active_data_generation, security_epoch |
| brains | id, normalized_name unique, display_name, trust_class, status |
| principals | id, local_subject, type, status; unique local_subject/type |
| scope_grants | id, principal_id, role, brain_id, project_id nullable, repository_id nullable, valid_from/to; no scope outside Brain |
| projects | id, brain_id, name, manifest_key, status, version; unique brain/manifest_key |
| repositories | id, brain_id, vcs_type, root_fingerprint, primary_remote_fingerprint nullable, status |
| checkouts | id, repository_id, canonical_path_hash, device_id, worktree_id, branch, head_commit, last_seen_at |
| project_repositories | project_id, repository_id, relation_type; composite primary key |
| agent_sessions | id, brain_id, project_id, checkout_id, host, adapter_version, model, started_at, completed_at, status |
| tasks | id, session_id, parent_task_id, contract_json, status, result_json, version |
| agent_events | event_id, brain_id, ordering_key, sequence, occurred_at, ingested_at, type, payload_hash, payload_ref, classification, schema_version; unique event_id and unique ordering_key/sequence when sequence exists |
| domain_events | event_id, aggregate_type, aggregate_id, aggregate_version, brain_id, event_type, event_json, correlation_id, causation_id, occurred_at; unique aggregate_type/aggregate_id/aggregate_version |
| artifacts | id, brain_id, sha256, media_type, byte_length, encryption_key_ref, blob_uri, classification; unique brain/sha256 |
| memories | id, brain_id, memory_class, scope_json, status, current_revision, valid_from/to, recorded_from/to, confidence_json, retention_policy_id, aggregate_version |
| memory_revisions | id, memory_id, revision, content_hash, content_ref, provenance_json, created_by_event; unique memory_id/revision and memory_id/content_hash |
| assertions | id, brain_id, subject_ref, predicate, object_ref, status, scope_json, valid_from/to, recorded_from/to, confidence_json, aggregate_version |
| assertion_evidence | assertion_id, evidence_id, relation, evidence_group, added_by_event; composite primary key assertion_id/evidence_id/relation |
| contradictions | id, brain_id, left_assertion_id, right_assertion_id, conflict_type, status, resolution_ref, aggregate_version |
| source_snapshots | id, repository_id, checkout_id, commit_id, working_tree_digest, parser_policy_version, created_at |
| index_runs | id, brain_id, source_snapshot_id, state, plan_hash, parser_set_hash, cursor, coverage_json, started_at, completed_at |
| recall_traces | id, brain_id, principal_id, scope_hash, query_hash, policy_version, generation_refs, candidate_trace_ref, expires_at |
| learning_candidates | id, brain_id, task_id, candidate_key, taxonomy, status, risk, scope_json, evidence_summary_ref, aggregate_version; unique brain_id/candidate_key |
| causal_hypotheses | id, candidate_id, revision, status, content_hash, hypothesis_ref, aggregate_version |
| procedure_revisions | id, procedure_id, revision, content_hash, procedure_ref, risk, scope_json, expires_at; unique procedure_id/revision and content_hash |
| learning_reviews | id, target_type, target_id, target_hash, reviewer_id, decision, policy_version, reason_ref, expires_at |
| evaluations | id, procedure_revision_id, plan_hash, baseline_ref, result_ref, state, metrics_json, signed_report_ref |
| procedure_deployments | id, procedure_revision_id, state, cohort_policy_json, active_from/to, previous_deployment_id, aggregate_version |
| operations | id, brain_id, kind, state, request_hash, progress_json, result_ref, cancel_requested_at, aggregate_version |
| outbox_messages | id, source_event_id, aggregate_id, topic, key, payload, not_before, attempts, status; unique source_event_id/topic |
| inbox_receipts | consumer, message_id, result_hash, processed_at; composite primary key |
| jobs | id, brain_id, kind, idempotency_key, input_ref, state, priority, attempts, lease_owner, lease_until, next_attempt_at; unique kind/idempotency_key |
| dead_letters | id, job_id, error_code, safe_details, first_failed_at, last_failed_at, replay_count |
| provider_adapters | id, protocol_version, package_digest, signature, capabilities, status |
| provider_profiles | id, brain_id, adapter_id, model_id, endpoint_policy_ref, secret_ref, limits, status, version |
| provider_routes | id, brain_id, selector, purpose, profile_id, precedence, status; selectors validated against policy |
| embedding_spaces | id, immutable_fingerprint unique, model metadata, dimension, dtype, normalization, similarity, purpose, preprocessing, privacy class |
| index_generations | id, brain_id, space_id, corpus, state, neo4j_index_name, source_watermark, coverage, activated_at |
| migration_runs | id, type, from_version, to_version, state, cursor, checksum, started_at, completed_at |
| retention_policies | id, scope, classification, retain_for, legal_hold_behavior, version |
| deletion_tombstones | id, brain_id, target_type, target_id_hash, requested_by, effective_at, purge_state, restore_guard_version |
| audit_events | sequence, brain_id nullable only for installation-scoped action, actor_id, action, target_ref, before_hash, after_hash, previous_hash, event_hash, occurred_at |
| audit_checkpoints | id, sequence_from/to, merkle_root, signature, key_id, local_append_only_ref |

Payloads over 64 KiB MUST be stored in encrypted blob storage and referenced by digest. SQL JSON is allowed for versioned boundary data but MUST NOT replace relational keys used for authorization, status, ordering, retention, or operational queries.

Physical mappings are fixed:

- SQLite IDs and SHA-256 values use fixed-length BLOBs, timestamps use signed INTEGER UTC microseconds since Unix epoch, canonical JSON uses UTF-8 TEXT, and Decimal values use validated canonical decimal TEXT.
- Closed lifecycle values use lowercase text plus CHECK constraints instead of database-native enums so expand/contract migrations remain compatible with the supported previous local release during the maintenance transition.
- All user-visible text is UTF-8; equality/search normalization is explicit per field. Names retain original display form plus a separate normalized key when uniqueness is required.
- Nullable scope columns mean the explicitly documented installation-wide scope; an absent Brain key is never interpreted as permission to search every Brain.
- Foreign-key deletion defaults to RESTRICT. Cascades are used only for purely internal child rows and never as the user deletion workflow.

### 4.3 SQLite durability

The local adapter MUST set and verify:

- sqlite_version is 3.53.3 or newer and compile options meet the packaged support manifest;
- journal_mode=WAL;
- synchronous=FULL;
- foreign_keys=ON;
- busy_timeout at least 5 seconds;
- secure_delete=ON where supported;
- a bounded WAL checkpoint policy that never truncates an unbacked acknowledged transaction.

Acknowledgment is returned only after the transaction containing the event and outbox row commits and fsync semantics succeed. Startup runs integrity_check, migration-head verification, available-disk checks, encryption-key checks, and recovery of expired job leases.

### 4.4 SQLite concurrency, queue, and backup durability

- Only the persistent core service opens the canonical SQLite file during normal operation. MCP bridges, sidecars, UI, and Neo4j MUST call core use cases and MUST NOT mount or open the SQLite volume. A one-shot migration/backup/restore tool may open an explicitly targeted generation only after the core has stopped or entered the operation's exclusive maintenance state and the launcher has verified the lock/owner.
- Normal Unit of Work transactions are short and explicit. Contended policy changes, generation cutover, procedure promotion, installation-pointer changes, and job leasing use `BEGIN IMMEDIATE` plus aggregate-version compare-and-swap; a busy/optimistic conflict becomes a typed retry/conflict rather than last-write-wins.
- The transactional outbox poller selects ready rows in stable priority/time/ID order, atomically assigns a bounded lease, and commits before executing work. Completion writes inbox/idempotency receipt, job state, derived canonical records, next outbox messages, and audit records in one Unit of Work where applicable.
- Lease expiry permits another worker attempt. Consumers remain idempotent because `inbox_receipts`, operation IDs, content fingerprints, aggregate versions, and provider idempotency metadata are checked before side effects. Retry exhaustion creates a DLQ row and never discards the source event.
- The online backup adapter uses SQLite's backup API against a committed watermark, verifies `integrity_check` on the copy, and never copies a live database/WAL pair with ordinary filesystem reads. Restore never opens an archive database in the active data generation.
- SQLite and WAL files MUST live in one Docker-managed local named volume. Network filesystems, synchronized folders, project bind mounts, and concurrent access from another installation are rejected.

### 4.5 Neo4j graph schema

The one local Neo4j Community service uses one application database for every local Brain. Database selection is not an authorization mechanism: every node, relationship, index record, query predicate, cache key, and integrity check carries and enforces `brain_id`. A Brain-to-Brain link is represented only by a governed transfer/reference assertion and never removes either scope filter.

Every node carries id, brain_id, entity_type, schema_version, created_at, recorded_from, recorded_to nullable, and classification. Temporal assertions additionally carry valid_from, valid_to nullable, branch/commit scope, status, confidence components, and extractor metadata.

Required node labels:

- Brain, Project, Repository, Checkout, Branch, Commit;
- Agent, Session, Task, Turn, Event, Artifact;
- File, FileRevision, Symbol, SymbolRevision, Package, Service, Endpoint, Contract, Dependency, Environment;
- Memory, Decision, Constraint, Preference, Procedure, Lesson, Failure, Outcome;
- Assertion, Evidence, Contradiction, CausalHypothesis, Evaluation, ProcedureRevision, Deployment;
- EmbeddingSpace, IndexGeneration, VectorRecord.

All authoritative factual relationships are Assertion nodes:

~~~text
(subject)-[:SUBJECT_OF]->(assertion:Assertion)-[:OBJECT_OF]->(object)
(assertion)-[:SUPPORTED_BY]->(evidence:Evidence)
(assertion)-[:CONTRADICTED_BY]->(evidence)
(assertion)-[:INVALIDATED_BY]->(evidence)
~~~

Frequently traversed direct edges such as CALLS, IMPORTS, CONSUMES, IMPLEMENTS, DEPENDS_ON, PRODUCES, and DEPLOYED_AS are projections. Each carries assertion_id, brain_id, valid_from/to, branch/commit scope, and projection_generation. A projected edge without a resolvable active assertion is an integrity failure.

Required constraints include unique (brain_id, id) for every stable label and unique immutable_fingerprint for EmbeddingSpace. Graph writes use MERGE only on constrained stable keys. MERGE on mutable names, paths, text, or URLs is forbidden.

### 4.6 Graph authorization and vector isolation

Authorization occurs before search:

1. Governance resolves an AuthorizedScope containing an allowed Brain and explicit project/repository IDs.
2. Every exact, full-text, vector, and graph query receives this scope.
3. Neo4j Cypher 25 SEARCH indexes include brain_id, project_id, repository_id, classification, status, and generation_id as filterable non-vector properties.
4. SEARCH WHERE restricts candidates inside the index before ranking.
5. Returned records are checked again against AuthorizedScope before fusion and before every expansion.

An embedding-space generation has one dedicated VectorRecord label and one named vector index generated from the immutable generation UUID. The index defines exactly one dimension, similarity, dtype/quantization policy, purpose, and vector property. Mixing providers, model revisions, dimensions, preprocessing, instructions, or incompatible normalization in an index is prohibited.

Neo4j Community stores embeddings using the one certified representation selected for the locked release. VectorWriteRepository hides driver/storage details, and its conformance suite verifies dimension, finite values, score ordering, Brain filters, and generation isolation. Quantization is disabled for correctness baselines; enabling a supported quantization mode creates a new immutable generation and must pass the golden recall comparison.

Neo4j SEARCH is approximate. Retrieval MUST over-fetch within the already-authorized filter, record requested and returned k, and allow exact/lexical/graph channels to compensate. Raw similarity scores are meaningful only within one query/index and MUST NOT be compared across spaces.

### 4.7 Blob storage

- Blob keys are Brain-scoped and derived from HMAC-SHA-256 of content hash, not raw path or user text.
- Content is envelope-encrypted with a per-Brain data key protected by the installation key materialized from the OS credential facility or an owner-only local secret source.
- Metadata and payload classification are stored before the local write.
- A local CAS write is write-once by digest; overwriting different content at the same key is rejected.
- Reads verify ciphertext authentication and plaintext digest.
- Deletion creates the tombstone first, denies future reads immediately, then removes all versions/replicas according to provider capability.
- Logs contain blob IDs and lengths, never payloads or host paths.

### 4.8 Migrations

Relational migrations use Alembic. Neo4j migrations use ordered, checksummed Cypher migrations owned by AgentMemory. Projection migrations are versioned rebuild jobs.

Every migration MUST be:

- idempotent or protected by a checksummed applied-migration record;
- resumable with a durable cursor;
- forward-compatible with the previous application version during rolling deployment;
- tested from every supported prior version and on a production-scale anonymized snapshot;
- observable with state, rate, ETA, errors, and pause/resume;
- accompanied by roll-forward and rollback instructions.

Destructive change uses expand-migrate-contract:

1. Add new representation.
2. Deploy dual-read or read-old/write-both compatibility.
3. Backfill and validate checksums/counts.
4. Cut reads to new representation.
5. Observe through one release window.
6. Remove old representation only after backup and explicit approval.

### 4.9 Required state machines

Status fields are closed enums changed only by aggregate methods/commands. Repositories reject unknown transitions and optimistic-version conflicts.

| Aggregate | States and allowed forward transitions |
|---|---|
| EventProcessing | Accepted → Ordered → Projecting → Projected; any processing state → RetryScheduled → Projecting; exhausted/nonretryable → DeadLettered; replay creates a linked new processing run |
| Job | Queued → Leased → Succeeded; Leased → RetryScheduled → Queued; Leased/Queued → Cancelled when safe; Leased/RetryScheduled → DeadLettered |
| Memory | Candidate → Active or Rejected; Active → Disputed, Superseded, Archived, Expired, DeletionPending; Disputed → Active/Superseded/DeletionPending; Archived/Expired → Active only through explicit restore; any retained state → DeletionPending → Deleted |
| Assertion | Candidate → Active or Rejected; Active → Disputed, Stale, Superseded, Invalidated; Disputed → Active/Superseded/Invalidated; Stale → Active after new evidence or Invalidated |
| IndexGeneration | Planned → Creating → Populating → Validating → ShadowReady → Active; Active → RollbackReady → Retired; any pre-active state → Failed; Active/Retired may become DeletionPending → Deleted |
| ProviderProfile | Draft → Probing → Active; Probing → Rejected; Active → Degraded, Suspended, Rotating, Retired; Degraded/Rotating → Active after probe; Suspended → Probing |
| EmbeddingMigration | Planned → Building → Backfilling → DualWrite → CatchingUp → Validating → Shadowing → Ready → Active; active migration → RolledBack; nonterminal → Paused/Failed; Paused → prior state through stored resume_state |
| LearningCandidate | Observed → Diagnosing → ReviewReady → UnderEvaluation → Approved or Rejected/Disputed; Approved → Deployable; any nonterminal retained state → Merged/Superseded |
| ProcedureDeployment | Approved → Shadow → Canary → Active; Shadow/Canary/Active → Suspended; Suspended → Canary/Active only after review or → RolledBack/Revoked; any active state → Expired |
| Deletion | Requested → Tombstoned → Purging → Verifying → Completed; hold conflict → Held; Held → Tombstoned after release; any processing state → PartialFailure → Purging |
| Operation | Accepted → Running → Succeeded/Failed; Accepted/Running → Cancelling → Cancelled when supported; completed states are terminal |

Retry never rewinds domain state or edits attempt history; it creates another Attempt record. Failed, rejected, superseded, revoked, rolled-back, and deleted history remains queryable only when authorization/retention permit. Deleted content itself is not retained merely to preserve a state transition.

## 5. Public contracts

### 5.1 Contract rules

- OpenAPI 3.1 and JSON Schema 2020-12 are source-controlled artifacts.
- Pydantic models generate schemas; generated schemas are compared in CI and intentional changes require review.
- Public command/request models use Pydantic strict mode with extra=forbid; integration-event readers use extra=allow and preserve unknown fields for forward compatibility. Unknown enum values are retained as Unknown only when the schema explicitly defines that safe behavior; otherwise validation fails.
- IDs are opaque strings. Clients MUST NOT infer entity type or time from UUID encoding.
- UUIDs serialize lowercase with hyphens. Timestamps serialize UTC RFC 3339 with Z and microseconds. Enums serialize lower_snake_case. Missing and explicit null are different and schemas state which is allowed.
- Hash/signature inputs use RFC 8785 JSON Canonicalization Scheme for JSON metadata. Text fingerprints normalize Unicode to NFC and line endings only where the named fingerprint contract permits it; raw artifact SHA-256 always hashes original bytes.
- Pagination uses opaque cursor tokens bound to query, scope, sort, and expiry.
- Long-running operations return 202 with operation_id and expose status plus SSE progress.
- Errors use RFC 9457 problem details with type, title, status, safe detail, instance, code, correlation_id, retryable, and optional field_errors.
- Secrets, raw vectors, internal stack traces, Cypher, SQL, and policy internals never appear in public errors.

### 5.2 REST API

The base path is /v1. Required resource groups:

| Prefix | Operations |
|---|---|
| /events | batch append, status, replay authorization |
| /brains | create, inspect, export, delete, status |
| /projects | resolve, link, alias, retrieval scope, index |
| /sessions and /tasks | lifecycle, checkpoint, timeline, unresolved work |
| /memories | search, inspect, correct, pin, archive, forget |
| /graph | scoped path query, entity, assertion, evidence, history |
| /recall | recall, briefing, explain, feedback |
| /providers | adapters, profiles, probes, routes, budgets, health |
| /embedding-spaces | spaces, generations, migrations, cutover, rollback |
| /learning | candidates, reviews, evaluations, procedures, deployments |
| /governance | grants, classifications, retention, holds, deletion |
| /audit | authorized search, verification, export |
| /operations | jobs, DLQ, migrations, backup, restore, diagnostics |

Mutating endpoints require Idempotency-Key. The server stores principal, route, normalized request hash, result status/body hash, and expiry. Reusing a key with a different request returns 409. ETag/If-Match protects versioned administrative resources.

### 5.3 AgentEvent

AgentEvent uses a CloudEvents-compatible JSON envelope with:

- specversion, id, source, type, subject, time, datacontenttype;
- dataschema pointing to a versioned immutable schema;
- brain_id, project_id, repository_id, checkout_id;
- agent_host, adapter_id/version, model_id, session_id, task_id, turn_id;
- correlation_id, causation_id, ordering_key, sequence;
- classification, retention_policy_id, capture_capabilities;
- data or dataref, never both; content_sha256.

Batch append is atomic per event, not per batch. Each item returns accepted, duplicate, rejected, or deferred. A duplicate with the same ID and different hash is a security event and rejected.

### 5.4 Integration events and local job dispatch

Integration events are immutable CloudEvents-compatible records created in `outbox_messages` in the same SQLite transaction as their canonical source mutation. Their logical topic is:

~~~text
am.local.<brain>.<context>.<event-name>.v<major>
~~~

The local dispatcher converts ready outbox records into leased SQLite jobs; it does not publish to a broker. Delivery is at least once and effective processing is exactly once for the declared idempotency key. `message_id` equals integration-event ID; an `inbox_receipts` conflict with a different result hash is an integrity incident. Completion is acknowledged only after the consumer Unit of Work, inbox receipt, subsequent outbox records, and required audit state commit. Retry uses capped exponential backoff with full jitter; non-retryable schema, authorization, or invariant errors go directly to the local DLQ.

### 5.5 MCP

The MCP server is an inbound adapter over the same application use cases. It exposes the tools and resources listed in PRD Section 13.1.

Before product readiness, the host launcher runs a protocol-valid bootstrap MCP adapter with exactly `installation_status`, `installation_open_setup`, and `installation_cancel`. `installation_status` returns installation ID, state/phase, completed and total bytes when known, completed and total stages, plain-language message key plus localized arguments, interaction kind (`none|terms|elevation|restart|administrator`), automatic-retry time, cancellability, typed error, and whether Ready handoff is pending; it returns no path, credential, command, or raw Docker error. Other product tools return `AM_SETUP_INTERACTION_REQUIRED` or `AM_DEPENDENCY_UNAVAILABLE` with the same operation ID. On Ready the launcher atomically hands off to the session bridge and emits tool/resource-list change notifications without requiring the agent or user to reinstall the MCP.

- stdio through the ephemeral session bridge is required for every supported host.
- Optional Streamable HTTP binds only to loopback, uses the installation/session credential, validates Host and Origin, and passes the same conformance suite as stdio.
- Remote/shared MCP, OAuth configuration, a public listener, and non-loopback bind addresses are unsupported and rejected at configuration validation.
- MCP tool inputs and structured outputs are generated from canonical schemas.
- Tool cancellation propagates to query/provider ports.
- Long operations report progress and return operation IDs.
- MCP text content labels recalled repository/memory content as untrusted data.
- No MCP handler opens a database session or embeds content directly.

The stable MCP Python SDK v1 line is pinned until v2 reaches stable release and passes the full conformance/compatibility suite. Protocol upgrades are adapter changes, not domain rewrites.

### 5.6 Provider adapter protocol

Built-in and custom providers implement the same language-neutral protocol. The canonical interface includes:

- GetManifest
- ValidateConfiguration
- Probe
- Health
- ListModels when supported
- EmbedDocuments
- EmbedQueries
- Rerank
- EstimateCost
- Cancel
- Shutdown

Every request contains protocol version, operation ID, profile ID, purpose, content IDs, declared classification, deadline, idempotency key, and trace context. Every response echoes operation/content IDs and returns ordered results, dimensions, token/usage data, model-revision evidence, and typed errors.

Custom adapters run as local digest-pinned, unprivileged sidecar containers generated from a validated manifest. They use length-prefixed JSON-RPC 2.0 over stdio or authenticated container-internal HTTP. Arbitrary Compose fragments and inbound remote adapter endpoints are forbidden. The image digest, signature, SBOM, provenance, protocol, permissions, and capabilities are approved before launch. The runtime receives only operation-scoped input, a tmpfs scratch directory, bounded CPU/memory/PIDs/time, no inherited environment or unrelated secrets, and no filesystem access except explicit read-only mounts. A remote embedding/reranking adapter reaches its approved endpoint only through `provider-gateway`; extraction adapters receive no external route.

Probe MUST verify:

- exact output count and input order;
- stable declared dimension;
- finite numeric values and allowed dtype;
- normalization behavior;
- maximum items/tokens/bytes;
- cancellation/deadline behavior;
- query/document purpose support;
- rerank score/order semantics;
- stable model-revision pin or drift canary.

A failed probe prevents activation and index mutation.

### 5.7 Required operation map

M means Idempotency-Key is mandatory. Every path is under /v1, every operation is authenticated except liveness, and every resource operation authorizes the target scope. The OpenAPI operationId MUST equal the application use case name.

| Method/path | Application use case | Notes |
|---|---|---|
| POST /events:append | AppendAgentEventBatchCommand | M; per-item result; Adapter role |
| GET /events/{event_id} | GetEventStatusQuery | metadata/payload access separately authorized |
| POST /events/{event_id}:replay | ReplayEventCommand | M; Admin; writes shadow projection |
| POST /brains | CreateBrainCommand | M; local installation Owner |
| GET /brains/{brain_id} | GetBrainQuery | includes health/generations |
| POST /brains/{brain_id}:export | ExportBrainCommand | M; Owner; long operation |
| DELETE /brains/{brain_id} | RequestDeletionCommand | M; Owner; explicit confirmation token |
| POST /projects:resolve | ResolveWorkspaceQuery | body carries checkout observations |
| POST /projects | CreateProjectCommand | M |
| PATCH /projects/{project_id} | UpdateProjectCommand | M; If-Match |
| POST /projects/{project_id}/repositories | LinkProjectRepositoryCommand | M |
| DELETE /projects/{project_id}/repositories/{repository_id} | UnlinkProjectRepositoryCommand | M; preserves history |
| POST /projects/{project_id}/aliases | AddProjectAliasCommand | M |
| POST /sessions | StartSessionCommand | M |
| POST /sessions/{session_id}:complete | CompleteSessionCommand | M; If-Match |
| GET /sessions/{session_id}/timeline | GetSessionTimelineQuery | cursor pagination |
| POST /tasks | StartTaskCommand | M; includes TaskContract |
| POST /tasks/{task_id}/checkpoints | CheckpointTaskCommand | M |
| POST /tasks/{task_id}:complete | CompleteTaskCommand | M; outcome evidence |
| GET /tasks/{task_id} | GetTaskQuery | contract/outcome/history |
| POST /memories:search | SearchMemoriesQuery | POST avoids sensitive query in URL |
| GET /memories/{memory_id} | GetMemoryQuery | current plus allowed history |
| POST /memories/{memory_id}:correct | CorrectMemoryCommand | M; If-Match |
| POST /memories/{memory_id}:pin | PinMemoryCommand | M; If-Match |
| POST /memories/{memory_id}:archive | ArchiveMemoryCommand | M; If-Match |
| DELETE /memories/{memory_id} | ForgetMemoryCommand | M; deletion operation |
| POST /graph:query | GraphPathQuery | bounded graph query |
| GET /graph/entities/{entity_id} | GetGraphEntityQuery | no raw Cypher API |
| GET /graph/assertions/{assertion_id} | ExplainAssertionQuery | evidence/temporal history |
| POST /recall | RecallQuery | query body, scope, budget, disclosure |
| POST /recall:brief | StartSessionBriefingQuery | compact context |
| GET /recall/{trace_id}/explanation | ExplainRecallQuery | recorded trace |
| POST /recall/{trace_id}/feedback | RecordRecallFeedbackCommand | M |
| POST /indexing/runs | StartIndexRunCommand | M; long operation |
| GET /indexing/runs/{run_id} | GetIndexRunQuery | progress/coverage/failures |
| POST /indexing/runs/{run_id}:cancel | CancelIndexRunCommand | M |
| POST /providers/adapters | InstallProviderAdapterCommand | M; Admin/Owner |
| POST /providers/profiles | CreateProviderProfileCommand | M |
| POST /providers/profiles/{profile_id}:probe | ProbeProviderCommand | M |
| PATCH /providers/profiles/{profile_id} | UpdateProviderProfileCommand | M; If-Match |
| POST /providers/routes | CreateProviderRouteCommand | M; If-Match policy version |
| GET /providers/status | GetProviderStatusQuery | content-safe |
| POST /embedding-migrations | StartEmbeddingMigrationCommand | M; long operation |
| POST /embedding-migrations/{id}:pause | PauseEmbeddingMigrationCommand | M; state-checked |
| POST /embedding-migrations/{id}:resume | ResumeEmbeddingMigrationCommand | M |
| POST /embedding-migrations/{id}:cutover | ActivateIndexGenerationCommand | M; approval/If-Match |
| POST /embedding-migrations/{id}:rollback | RollbackIndexGenerationCommand | M |
| GET /learning/candidates | ListLearningCandidatesQuery | filter/cursor |
| GET /learning/candidates/{id} | GetLearningCandidateQuery | complete evidence read model |
| POST /learning/candidates/{id}/reviews | ReviewLearningCandidateCommand | M; exact revision |
| POST /learning/evaluations | StartProcedureEvaluationCommand | M; long operation |
| POST /learning/procedures/{id}:promote | RequestProcedurePromotionCommand | M; approval binding |
| POST /learning/procedures/{id}:deploy | DeployProcedureCommand | M; shadow/canary first |
| POST /learning/procedures/{id}:suspend | SuspendProcedureCommand | M; priority path |
| POST /learning/procedures/{id}:rollback | RollbackProcedureCommand | M; priority path |
| GET /learning/procedures/{id}/explanation | ExplainProcedureQuery | authorized lineage |
| POST /governance/grants | CreateScopeGrantCommand | M; Owner/Admin policy |
| DELETE /governance/grants/{grant_id} | RevokeScopeGrantCommand | M; synchronous cache invalidation |
| POST /governance/holds | CreateLegalHoldCommand | M; Owner |
| DELETE /governance/holds/{hold_id} | ReleaseLegalHoldCommand | M; Owner/two-person where configured |
| POST /governance/deletions | RequestDeletionCommand | M; long operation |
| GET /governance/deletions/{id} | GetDeletionStatusQuery | receipts/remaining stores |
| GET /audit/events | SearchAuditEventsQuery | Auditor; cursor |
| POST /audit:verify | VerifyAuditChainQuery | Auditor; long operation |
| POST /operations/backups | StartBackupCommand | M |
| POST /operations/restores | RestoreBrainCommand | M; isolated target |
| POST /operations/rebuilds | StartProjectionRebuildCommand | M |
| GET /operations/{operation_id} | GetOperationQuery | status/progress/result |
| POST /operations/{operation_id}:cancel | CancelOperationCommand | M; safe-state checks |
| POST /operations/diagnostics | DiagnosticBundleCommand | M; encrypted output |

No endpoint exposes arbitrary SQL, Cypher, filesystem path reads, provider HTTP calls, or prompt execution. Administrative batch endpoints cap item count/bytes and return individual results without partial authorization.

MCP maps exactly as follows:

| MCP tool/resource | Use case |
|---|---|
| memory_recall | RecallQuery |
| memory_checkpoint | CheckpointTaskCommand |
| memory_explain | ExplainRecallQuery or ExplainMemoryQuery by target type |
| memory_timeline | GetSessionTimelineQuery |
| memory_graph | GraphPathQuery |
| memory_correct | CorrectMemoryCommand |
| memory_forget | ForgetMemoryCommand |
| memory_index | StartIndexRunCommand |
| memory_status | GetBrainStatusQuery |
| memory_provider_status | GetProviderStatusQuery |
| memory_feedback | RecordRecallFeedbackCommand |
| learning_candidates | ListLearningCandidatesQuery |
| learning_review | ReviewLearningCandidateCommand |
| procedure_explain | ExplainProcedureQuery |
| procedure_deploy | DeployProcedureCommand |
| procedure_rollback | RollbackProcedureCommand |
| memory://project/{id}/brief | StartSessionBriefingQuery |

### 5.8 Canonical error taxonomy

| Code | HTTP | Retryable | Meaning |
|---|---:|---|---|
| AM_VALIDATION | 422 | no | strict input/schema validation failed |
| AM_UNAUTHENTICATED | 401 | no after reauth | authentication missing/invalid |
| AM_FORBIDDEN | 403 | no | action or scope denied |
| AM_NOT_FOUND | 404 | no | authorized resource absent; unauthorized existence is not disclosed |
| AM_CONFLICT | 409 | no until refresh | aggregate version/state conflict |
| AM_IDEMPOTENCY_CONFLICT | 409 | no | key reused with a different request hash |
| AM_RATE_LIMITED | 429 | yes | caller/profile budget; includes safe retry_after |
| AM_DEADLINE_EXCEEDED | 504 | caller may retry idempotently | deadline/cancellation boundary |
| AM_DEPENDENCY_UNAVAILABLE | 503 | yes | required dependency unavailable |
| AM_SCHEMA_UNSUPPORTED | 400 | no | contract major/version outside supported window |
| AM_EGRESS_DENIED | 403 | no | provider/region/purpose/classification policy denied |
| AM_LEGAL_HOLD | 409 | no until hold changes | destructive deletion blocked by hold |
| AM_VECTOR_INCOMPATIBLE | 409 | no | dimension/space/model/generation mismatch |
| AM_PROVIDER_RETRYABLE | 503 | yes | normalized transient provider failure |
| AM_PROVIDER_REJECTED | 422 | no | normalized permanent provider/config failure |
| AM_INTEGRITY_VIOLATION | 500 | no automatic retry | canonical/graph/audit invariant failed; alert |
| AM_CONTROLLED_SURFACE | 403 | no | prohibited autonomous policy/code/prompt/permission change |
| AM_CAPACITY_EXHAUSTED | 507 | after operator action | local durable capacity cannot accept safely |
| AM_SETUP_INTERACTION_REQUIRED | 409 | after recorded user action | exact terms, elevation, or restart decision is awaiting the local user |
| AM_SETUP_ADMIN_REQUIRED | 403 | after administrator policy change | device policy or missing authority blocks the signed install plan |
| AM_UNSUPPORTED_HOST | 400 | no | OS, architecture, virtualization, firmware, or resource profile is not certified |
| AM_REBOOT_REQUIRED | 409 | automatically after sign-in | a verified one-use continuation is registered for the journaled operation |
| AM_RUNTIME_CONFLICT | 409 | after approved remediation | an existing runtime/workload cannot be safely adopted or changed |

Partial/degraded recall is a successful response with degradation fields, not a hidden AM_DEPENDENCY_UNAVAILABLE. Internal exception classes map to this taxonomy once at each inbound adapter. Unknown exceptions map to AM_INTERNAL with correlation ID and no internal details; AM_INTERNAL is never declared retryable without operation-level idempotency.

## 6. Security, privacy, and governance

### 6.1 Threat model

A versioned threat model using STRIDE plus privacy-abuse cases is mandatory for:

- agent hooks and transcript imports;
- host launcher, loopback API/UI, MCP stdio, and ephemeral workspace mounts;
- provider and custom adapter execution;
- event replay and schema migration;
- full-text/vector search and graph expansion;
- learning detection, evaluation, approval, and rollout;
- UI/CLI administrative operations;
- backups, restores, exports, and deletion;
- Docker daemon/Compose networks, volumes, images, offline bundles, upgrades, and release supply chain;
- runtime discovery/download, vendor installers, package repositories, license presentation, privilege broker, WSL/rootless prerequisites, service start, reboot continuation, repair, ownership tracking, and runtime uninstall.

The model MUST include malicious repository/memory/event input, hostile local web origins and DNS rebinding, other unprivileged host users/containers, compromised custom adapters, provider compromise/MITM, SSRF/redirect/DNS attacks, secret exfiltration, backup theft/tamper, image/dependency/update compromise, runtime-catalog rollback, malicious PATH/context/socket, installer publisher substitution, privilege-plan/IPC/nonce/TOCTOU attack, license-confusion or forged consent, resume-task hijack/replay, partial vendor installation, unrelated-workload destruction, rollback/downgrade, disk/resource exhaustion, crash/power loss/corruption, and deletion resurrection. Trust boundaries include host client to bootstrap MCP, setup UI to user, launcher to official artifact source/package repository, launcher to OS trust verifier, unprivileged launcher to privilege broker, installer to service manager/reboot continuation, host client to loopback API/MCP, browser to UI, bridge workspace mount, Docker internal/egress networks, core to SQLite/CAS/Neo4j, adapter sandbox, gateway to provider, volume to backup, and CI to signed runtime/image manifest.

A privileged host/root user, compromised Docker daemon, or access to an already-unlocked physical host is a documented residual risk. AgentMemory MUST NOT claim to protect data from a fully compromised local machine.

It is reviewed for every material architecture change and at least quarterly. Threats have owner, mitigation, verification test, residual risk, and review date.

### 6.2 Authentication and authorization

Authentication is local only. Installation bootstrap binds one owner-controlled OS account to a random installation identity and credential with at least 256 bits of entropy. The credential source is owner-readable only, never appears in a URL or browser localStorage, and rotates without data loss. Each MCP bridge receives a short-lived session credential bound to installation, agent host, Brain/project request scope, process/session ID, and expiry; revocation is checked before every request.

Loopback HTTP accepts only configured localhost Host values, validates Origin on browser requests, requires anti-CSRF protection on mutations, applies request size/rate/deadline limits, and emits restrictive CSP/frame/referrer headers. An unauthenticated health endpoint may expose only alive/not-alive with no version, dependency, path, or data details. Internal gateway/sidecar requests use separate least-privilege installation credentials. Non-loopback listeners and remote identity providers are not implemented.

Roles:

- Owner: Brain lifecycle, grants, export/delete, provider policy.
- Admin: configuration, adapters, indexing, retention without owner-only destruction.
- Editor: checkpoint, correct, review approved learning scopes.
- Reader: authorized recall and explanation.
- Auditor: read-only audit and governance evidence.
- Adapter: append only permitted AgentEvents for its assigned scope.
- Worker: consume specific job classes and write only named projections.

Authorization is deny-by-default and evaluates local principal, action, resource type/ID, Brain, project/repository, classification, purpose, agent capability, and time. It occurs before candidate generation, cache lookup, search, graph expansion, mutation, export, and audit access. Scope IDs are mandatory query parameters in repositories; a query without AuthorizedScope cannot compile through the public adapter API.

Cross-Brain leakage through results, counts, timing, errors, cache keys, telemetry, embeddings, jobs, or provider batches has zero tolerance.

### 6.3 Data classification and taint

Classes in ascending restriction:

1. public
2. internal
3. confidential
4. restricted
5. local_only

Derived data inherits the maximum classification of all inputs unless an approved deterministic redaction demonstrably removes the sensitive component. This rule covers chunks, summaries, memories, assertions, embeddings, evaluation fixtures, caches, logs, exports, and backups.

`restricted`, `local_only`, private-block, and detected-secret content is unconditionally non-egress. No installation, Brain, project, repository, provider, or adapter setting can override this invariant. Provider batches are homogeneous by Brain, classification, provider profile, purpose, and retention policy.

Before canonical persistence and before each egress, the pipeline applies:

1. path and private-block exclusion;
2. content size/type policy;
3. secret scanning;
4. PII/classification rules;
5. deterministic redaction/tokenization;
6. minimal payload construction plus destination/provider/region/purpose authorization;
7. audit of the decision without content.

Repository configuration may further restrict egress but may not add credentials/endpoints or weaken Brain policy.

### 6.4 Encryption and secrets

- Remote provider HTTPS requires verified certificates and TLS 1.3 where available, with TLS 1.2 as the minimum; release code contains no insecure-verification path. Loopback HTTP is permitted only with the installation credential and the browser controls above. Internal Neo4j/provider links authenticate independently and use installation-local TLS where the certified image/runtime supports it.
- Sensitive blobs and every backup use application envelope encryption. Searchable SQLite/Neo4j/vector volumes require verified host full-disk encryption because these local databases must process searchable plaintext/derived values; readiness produces a blocking policy error for restricted/local_only capture when host encryption cannot be attested.
- AEAD uses an approved library and AES-256-GCM or ChaCha20-Poly1305. Custom cryptography is forbidden.
- Per-Brain data-encryption keys and per-backup data keys are protected by a versioned installation key stored separately from ciphertext. Rotation is resumable, old keys remain only through verified rewrap, and key material never enters SQLite, Neo4j, logs, images, or provider containers.
- Configuration stores secret references only. The SecretResolver materializes credentials at call time only for the exact consuming component, caches for a bounded TTL where unavoidable, zeroizes/releases best-effort on rotation, and supports revocation.
- Secret values are prohibited from Compose YAML, `.env`, labels, process arguments/environment, image layers/history, database/graph/vector records, status/errors, logs/traces/metrics, exports, diagnostics, and backups. Host secret sources are owner-only; startup fails closed on unsafe ownership/mode.
- Diagnostic bundles, exceptions, metrics attributes, traces, and audit details are scanned for secrets before release.

### 6.5 Prompt injection and memory poisoning

Retrieved content is data, never instruction. Context output wraps it in explicit untrusted delimiters with source/classification. It cannot change system/developer prompts, tool permissions, approval policy, egress, retention, provider routing, evaluators, adapters, security controls, or executable code.

Model-generated facts and causal diagnoses start as candidates. Promotion requires evidence and policy outside the model. The model that produced a candidate cannot be the only validator. Repository content cannot approve, broaden, or deploy its own learned procedure.

### 6.6 Audit

Security and administrative events append to `audit_events`. `event_hash` is SHA-256 over canonical event bytes plus `previous_hash`. Periodic ranges form a Merkle root signed by the installation signing key supplied through SecretResolver and copied to a separate append-only local audit/deletion-journal path included in encrypted backups.

Audit captures actor, authenticated subject, action, scope, target reference, policy/rule version, request/correlation ID, before/after hashes, outcome, reason code, IP/device metadata where lawful, and timestamp. It MUST NOT contain raw prompts, code, secrets, vectors, or hidden reasoning.

Verifier jobs continuously validate chain continuity and checkpoint signatures. A mismatch raises a local critical alert and makes governed mutations read-only until triage. This is tamper-evident against accidental or unprivileged modification; it is not claimed immutable against a privileged host owner who can delete both data and keys.

### 6.7 Deletion

Deletion is a saga with an immediate deny phase:

1. Authorize request and check legal hold.
2. Commit a deletion tombstone and audit event.
3. All reads, searches, replay, exports, and jobs exclude the target immediately.
4. Traverse the dependency manifest to find graph, text, vector, blob, cache, queue, learning, evaluation, export, and provider descendants.
5. Purge each store idempotently and record a non-content receipt.
6. Verify absence using targeted queries and sampling.
7. Mark complete only when required stores acknowledge; unsupported remote deletion is surfaced, not hidden.

Backup restore applies the deletion ledger before making restored data queryable. Deleted content cannot be reconstructed from replay. Legal hold blocks destructive purge but still obeys access revocation.

## 7. Observability, reliability, and operations

### 7.1 Telemetry

All processes emit OpenTelemetry traces and metrics to the bounded local telemetry sink or optional local Collector. Python logs use structured JSON and carry trace_id, span_id, correlation_id, operation_id, safe Brain pseudonyms, component, version, and outcome. AgentMemory configures no remote exporter and performs no call home.

Required metrics:

- ingestion acknowledgment latency, failures, duplicate/conflict rate;
- outbox/job depth and age, expired leases, retries, DLQ;
- index queue depth, file/task freshness, parser coverage/failures;
- retrieval latency by channel, authorized candidate counts, fusion/rerank, abstention;
- evidence/citation correctness samples and stale-result feedback;
- provider requests, tokens, bytes, latency, errors, circuits, cost, budgets, drift;
- Neo4j pool and SQLite lock/WAL/checkpoint/query latency;
- authorization denials and Brain-isolation canaries;
- deletion queue/age/completion and restore guards;
- learning candidate/promotion/canary/adverse/rollback;
- migration/backfill/cutover state and coverage.

Metric labels MUST be bounded. User text, paths, repository names, prompts, code, vectors, secrets, and high-cardinality IDs are forbidden attributes.

### 7.2 SLOs

At minimum:

| SLI | Objective |
|---|---|
| acknowledged event durability | zero loss after SQLite FULL commit across supported process/container/Docker/host restart; host/disk loss bounded by latest verified backup |
| bootstrap MCP initialization | p95 below 2 s and below every certified host timeout |
| visible setup progress freshness | p95 below 2 s while a phase is active; no silent wait longer than 30 s without a stated reason/retry |
| local hook enqueue | p95 below 50 ms |
| warm local recall | p95 below 2 s on published profile |
| index freshness | p95 below 30 s while dependencies healthy |
| deletion exclusion | immediate after tombstone commit |
| cross-Brain authorization correctness | 100%; zero-error budget |
| audit append success | 100% for governed mutation; mutation fails closed otherwise |

Recall latency, indexing throughput, disk growth, backup RPO, restore RTO, purge completion, and rollback SLOs are published for the local reference hardware/corpus. Other hardware is reported by measured profiles, never an availability promise. Regression-budget exhaustion freezes risky local releases until recovery.

### 7.3 Resilience

- Every outbound call has a timeout, cancellation, bounded retry, and circuit breaker.
- Retries occur only for typed retryable errors and use exponential backoff with full jitter.
- Provider retries honor Retry-After and do not exceed the caller deadline.
- Bulkheads separate interactive recall, ingestion, indexing, migration, and evaluation capacity.
- At 80% data-volume utilization, warn and throttle/pause low-priority indexing, evaluation, and migration. At 95%, reject/defer before accepting data that cannot commit durably. Acknowledged canonical events are never discarded.
- Process shutdown stops intake, drains in-flight commands to deadline, extends or releases leases, flushes telemetry, and closes pools.
- Supported recovery classes are interrupted runtime download/trust verification/elevation/package installation, partial Docker Desktop/Engine or WSL/rootless setup, license/elevation denial, pending logout/reboot and resume, Docker service start/repair, launcher/core/worker/container restart, Docker daemon or host reboot/power loss, SQLite lock/WAL recovery, Neo4j outage/corrupt projection, local-model crash/OOM, remote-provider/DNS/network outage, disk soft/hard pressure, corrupt backup, and failed runtime/product upgrade. The product makes no regional, leader-election, cluster-HA, or automatic failover promise.
- Neo4j/provider failure leaves canonical work queued and preserves healthy retrieval channels with explicit degradation. A corrupt Neo4j projection is discarded and rebuilt from canonical SQLite/CAS inputs or restored; canonical SQLite corruption requires a verified backup recovery.
- Chaos tests kill components before/after every runtime-provisioning journal transition and at receive, SQLite commit, ACK, lease, provider send/response, graph/vector write, audit append, and deletion commit. Runtime recovery verifies machine/user/manifest/plan/artifact/journal/ownership/nonce consistency and preserves unrelated software/workloads; product recovery verifies SQLite integrity, event/outbox/inbox/job watermarks, graph/assertions, vector generations, authorization, audit, and deletion guards.

### 7.4 Backup and restore

Backup destination is a user-selected local/removable filesystem path only. `StartBackupCommand` enters maintenance mode, prevents new governed mutations, drains or records job/outbox watermarks, takes a SQLite online backup, snapshots the encrypted CAS/configuration without secret values/audit checkpoints/latest deletion journal, and obtains either a compatible Neo4j Community dump or a complete signed graph-rebuild plan. One signed manifest binds every item's digest, encryption key ID, schema/BOM version, source watermark, count, and capture time. A partial archive is never marked complete.

Restore:

1. Creates a new isolated Compose project and data-generation volumes; in-place overwrite is forbidden.
2. Starts without `am_egress` and verifies signature, AEAD, every digest, and compatible release/schema versions.
3. Restores canonical state and applies the newest signed deletion-journal head and access revocations before any query is served.
4. Restores or rebuilds projections without issuing provider calls.
5. Runs SQLite integrity, counts/hashes/watermarks, audit chain, graph/assertion/vector-generation integrity, Brain-isolation, deletion non-resurrection, and golden-recall tests.
6. Requires explicit local-owner activation; provider routes remain disabled until separately reauthorized.

A recovery point older than a later deletion cannot activate without a signed deletion-journal head at least as new as the installation's declared head. Missing or unverifiable proof fails closed for affected scopes. Automated full restore drills run at least quarterly on the reference corpus. A backup that has not passed a restore drill is not a verified backup.

## 8. Engineering quality and TDD

### 8.1 Mandatory TDD workflow

Every story and defect follows Red-Green-Refactor:

1. Red: write the smallest behavioral test that fails for the intended reason. Commit/CI evidence must show the failure or the PR description must capture its command and failure.
2. Green: implement the minimum domain/application behavior to pass.
3. Refactor: remove duplication, improve names/boundaries, and rerun all affected tests.
4. Expand: add boundary, failure, authorization, idempotency, concurrency, and property cases required by the story.

Tests are specifications. Mock-call-count tests are insufficient unless the call itself is the contract. Prefer assertions on returned value, state transition, emitted domain event, persisted observable state, or external protocol.

### 8.2 Test pyramid and required tools

| Level | Purpose | Required tooling |
|---|---|---|
| domain unit | aggregates, value objects, policies, rank math, state machines | pytest 9.x |
| property/state machine | idempotency, temporal ranges, retries, vector validation, deletion | Hypothesis 6.x |
| application unit | command/query orchestration with in-memory ports | pytest, typed fakes |
| launcher unit/property | install/session/upgrade/uninstall state machines, path/resource policies, journal recovery | Go `testing`, fuzz tests, typed fakes, race detector |
| repository contract | identical documented behavior for SQLite/Neo4j/local-CAS adapters and in-memory fakes | pytest parameterized suites |
| protocol contract | OpenAPI, MCP, events, agent/provider adapter conformance | Schemathesis where applicable plus custom harness |
| integration | real packaged SQLite, Neo4j Community, local CAS, Compose networks/gateway, provider stubs | Testcontainers or the rendered pinned Compose services |
| end-to-end | host adapter to recall/UI/learning/deletion | pytest and Playwright |
| nonfunctional | load, soak, chaos, migration, backup/restore | k6/Locust, fault harness, deployment tests |
| security | auth matrix, injection, egress, secrets, supply chain | dedicated adversarial suites and scanners |

Unit tests MUST NOT start containers or use network. Integration tests MUST use real supported stores, not mocks of their drivers. Paid providers never run in pull-request CI; deterministic adversarial provider stubs do. A controlled nightly job MAY run live provider certification using isolated credentials/budgets.

### 8.3 Coverage gates

Coverage.py branch measurement is mandatory for Python; Vitest V8 coverage is mandatory for TypeScript. Go's standard coverage profile measures statements rather than branches, so the launcher uses per-package statement coverage plus mandatory explicit decision tables, fuzzing, race testing, and mutation testing for branch quality.

Blocking thresholds:

- at least 80% line and 80% branch coverage globally across Python/TypeScript production code;
- at least 80% line and 80% branch in every first-party Python package and UI package;
- at least 80% line and branch coverage on changed production code;
- at least 80% Go statement coverage in every launcher package and 80% statement coverage on changed launcher production code;
- complete Go decision-table coverage for installation phases, host/platform validation, path/mount construction, Compose policy, signature policy, agent-config merge, upgrade compensation, resource inventory, and uninstall choices;
- complete decision-table tests for authorization, Brain filters, deletion, egress, approval, rollback, audit integrity, migration cutover, and embedding-space validation.

Generated code, migrations that are exercised through migration tests, vendored grammars, and type-only declaration files may be excluded by reviewed explicit paths. Blanket pragma exclusions are prohibited. New exclusions require security/quality owner approval and a reason.

### 8.4 Mutation and test quality

Mutation testing runs on changed domain/security code in pull requests and on the full critical suite nightly:

- minimum mutation score 80% for domain/security/policy/deletion/learning-promotion code;
- minimum mutation score 80% for launcher install/path/mount/signature/upgrade/uninstall policy packages;
- minimum 70% for all other eligible business code;
- equivalent surviving mutants are documented with reviewer approval.

Tests MUST be deterministic, isolated, order-independent, parallel-safe, and repeatable with a recorded seed. Time, UUIDs, random, network, and provider output use injected ports. Retry tests use a fake clock, never real sleeps.

A flaky test may be quarantined only with an owner, issue, risk assessment, expiry no longer than seven days, and release-manager approval. Zero-tolerance tests cannot be quarantined.

### 8.5 Linting, formatting, typing, and architecture

Python blocking checks:

- Ruff format --check.
- Ruff check with the exact pinned rule registry set to ALL, excluding only documented formatter conflicts and narrow file-specific test/migration rules shown below.
- Ruff preview rules are introduced only through reviewed dependency-update PRs.
- mypy strict across src, apps, adapters, and tests; Pydantic plugin where supported.
- Import Linter contracts for layer direction, context independence, and cycles.
- interrogate or equivalent public-API documentation check.
- codespell and markdownlint for documentation.

Ruff ignores are limited to formatter conflicts and narrowly documented compatibility cases. Blanket noqa is forbidden. Each noqa lists rule code and reason. RUF100 detects unused suppressions. Security S rules may not be globally ignored.

Type rules:

- Any is forbidden in domain/application and permitted at an untyped external boundary only until immediately validated.
- type: ignore requires exact error code and explanation.
- cast is allowed only after a runtime invariant or boundary check.
- public APIs and all functions have explicit parameter and return types.
- Mapping/Sequence are preferred at read-only interfaces; mutable concrete types only where mutation is part of the contract.

TypeScript blocking checks:

- tsc --noEmit with strict, noUncheckedIndexedAccess, exactOptionalPropertyTypes, noImplicitOverride, noFallthroughCasesInSwitch, useUnknownInCatchVariables.
- ESLint flat config with @typescript-eslint strictTypeChecked and stylisticTypeChecked, React Hooks, JSX accessibility, import, security, and TanStack Query plugins.
- Prettier check.
- No explicit any; unknown must be narrowed.
- Exhaustive discriminated-union checks.
- dependency-cruiser or equivalent enforces feature/layer boundaries and cycles.

Go launcher blocking checks:

- `gofmt` and `goimports` produce no diff; `go mod tidy -diff` and `go mod verify` pass.
- `go vet`, `staticcheck`, `govulncheck`, and a pinned `golangci-lint` strict configuration pass with zero warnings. The enabled set includes errcheck, errorlint, exhaustive, forbidigo, gocritic, gosec, govet, ineffassign, nilerr, noctx, prealloc, revive, staticcheck, unconvert, unparam, unused, and whitespace; an exact path-scoped exclusion requires code, reason, owner, and expiry.
- `go test -race -shuffle=on -count=1 ./apps/launcher/...` passes on every supported OS, and fuzz seeds for paths, manifests, journals, agent config, and Docker inspect output run in PR CI plus time-bounded fuzzing nightly.
- `go-arch-lint` or an equivalent pinned import-graph check enforces launcher Clean Architecture and forbids application/domain imports of `os/exec`, Docker SDK/CLI adapters, filesystem mutation, HTTP, or agent-config implementations.
- Direct `exec.Command("sh", "-c", ...)`, `cmd.exe /C`, PowerShell command strings, string-built Docker arguments, `unsafe`, unbounded goroutines, ignored errors, ambient mutable globals, and logging of argv/environment are prohibited by static/custom checks.

No warning baseline may grow. CI runs with warnings treated as errors.

### 8.6 Coding standards

- UTF-8, LF, final newline, 100-character Python line length; Go is always `gofmt`-formatted.
- Public API docstrings explain contract, invariants, errors, authorization, and side effects; they do not restate code.
- Exceptions are typed. Bare except and exception swallowing are forbidden.
- Domain errors map once at inbound adapters to problem details/MCP errors/CLI exit codes.
- Logging uses structured fields and lazy formatting; print is forbidden outside CLI presentation.
- Async code never performs blocking filesystem/network/CPU work on the event loop. Parsers and CPU-heavy work run in bounded processes.
- Database calls are bounded and paginated; unbounded MATCH, SELECT, list-all APIs, and full-Brain visualization are forbidden.
- Every external call has an operation ID, deadline, size limit, and cancellation path.
- TODO/FIXME requires an issue ID and cannot mark a correctness or security gap in released code.

### 8.7 Normative tool configuration

The root pyproject.toml MUST contain settings equivalent to the following. A change that weakens them requires quality and security approval.

~~~toml
[tool.ruff]
target-version = "py314"
line-length = 100
src = ["src", "apps", "adapters", "sdk/python"]
extend-exclude = ["**/generated/**", "**/vendor/**"]

[tool.ruff.format]
quote-style = "double"
indent-style = "space"
line-ending = "lf"
docstring-code-format = true

[tool.ruff.lint]
select = ["ALL"]
ignore = [
  "COM812", "ISC001",
  "W191", "E111", "E114", "E117",
  "D203", "D206", "D300",
  "Q000", "Q001", "Q002", "Q003",
]

[tool.ruff.lint.per-file-ignores]
"tests/**/*.py" = [
  "ANN", "ARG001", "D", "INP001", "PLR2004", "S101", "SLF001",
]
"migrations/**/*.py" = ["ANN", "D", "INP001"]
"apps/cli/**/*.py" = ["T201"]

[tool.ruff.lint.flake8-annotations]
allow-star-arg-any = false
suppress-dummy-args = false

[tool.ruff.lint.flake8-pytest-style]
fixture-parentheses = false
mark-parentheses = false
parametrize-names-type = "tuple"

[tool.mypy]
python_version = "3.14"
strict = true
warn_unreachable = true
warn_unused_configs = true
show_error_codes = true
pretty = true
plugins = ["pydantic.mypy"]
exclude = ["(^|/)generated/", "(^|/)vendor/"]
enable_error_code = [
  "explicit-override",
  "mutable-override",
  "possibly-undefined",
  "redundant-expr",
  "truthy-bool",
]

[tool.pytest.ini_options]
minversion = "9.1"
addopts = ["--strict-config", "--strict-markers", "-ra"]
asyncio_mode = "strict"
xfail_strict = true
filterwarnings = ["error"]
markers = [
  "contract: public/repository contract suite",
  "integration: real supported infrastructure",
  "e2e: complete user workflow",
  "security: authorization or adversarial security",
  "privacy: classification, egress, retention, or deletion",
  "migration: schema/projection upgrade and rollback",
  "resilience: fault, retry, backup, restore, or chaos",
  "load: performance or soak suite",
  "live_provider: controlled paid-provider certification",
]

[tool.coverage.run]
branch = true
parallel = true
source = ["src/agentmemory", "apps", "adapters"]
omit = ["**/generated/**", "**/vendor/**"]

[tool.coverage.report]
fail_under = 80
show_missing = true
skip_covered = false
precision = 2
exclude_also = [
  "if TYPE_CHECKING:",
]
~~~

The only globally ignored Ruff rules are formatter conflicts documented by Ruff. Per-file ignores MUST stay limited to the paths/rules above unless a reviewed amendment names the exact file, rule, reason, owner, and expiry. Tests retain all security/static rules except S101 because assertions are their purpose.

The UI tsconfig.json MUST enable strict, noUncheckedIndexedAccess, exactOptionalPropertyTypes, noImplicitOverride, noFallthroughCasesInSwitch, noImplicitReturns, noPropertyAccessFromIndexSignature, useUnknownInCatchVariables, forceConsistentCasingInFileNames, isolatedModules, and verbatimModuleSyntax. skipLibCheck is false in the contract/type job.

ESLint flat configuration MUST extend eslint:recommended, typescript-eslint strictTypeChecked and stylisticTypeChecked, React Hooks recommended, jsx-a11y strict/recommended, import, security, and TanStack Query recommended rules. It MUST reject explicit any, floating promises, unsafe assignment/member access/return, nonexhaustive switches, unhandled promises, unstable query keys, and dependency cycles. Test-only exceptions are path-scoped and documented.

The canonical local/CI commands are:

~~~text
uv lock --check
uv sync --frozen --all-packages --all-groups
uv run ruff format --check .
uv run ruff check .
uv run mypy src apps adapters tests
uv run lint-imports
uv run pytest tests/unit tests/property tests/contract --cov --cov-branch
uv run coverage json -o build/coverage.json
uv run python tools/check_package_coverage.py build/coverage.json --line 80 --branch 80 --changed 80
go mod tidy -diff
go mod verify
gofmt -l apps/launcher
goimports -l apps/launcher
go vet ./apps/launcher/...
staticcheck ./apps/launcher/...
govulncheck ./apps/launcher/...
golangci-lint run ./apps/launcher/...
go-arch-lint check
go test -race -shuffle=on -count=1 -covermode=atomic -coverprofile=build/go-cover.out ./apps/launcher/...
go run ./tools/check_go_coverage --profile build/go-cover.out --package 80 --changed 80
pnpm install --frozen-lockfile
pnpm exec tsc --noEmit
pnpm exec eslint . --max-warnings 0
pnpm exec prettier --check .
pnpm exec vitest run --coverage
pnpm exec playwright test
~~~

`tools/check_package_coverage.py` and `tools/check_go_coverage` are required first-party CI utilities with their own tests. They MUST fail when a package is below its language threshold, changed code is below 80%, coverage data is missing, or a production file is omitted unexpectedly. Python mutation tests use mutmut, TypeScript mutation tests use Stryker, and launcher mutation tests use a pinned Go mutation runner on changed eligible packages and scheduled full critical packages. Their thresholds are those in Section 8.4.

## 9. CI/CD and supply chain

### 9.1 Pull-request pipeline

Required jobs, all blocking:

1. repository policy, generated-file drift, schema compatibility;
2. Ruff format/lint, mypy strict, Import Linter, docs lint;
3. TypeScript typecheck, ESLint, formatting, UI boundary checks;
4. Python and UI unit/property tests with coverage gates;
5. repository/protocol/adapter contract tests;
6. packaged SQLite/Neo4j/local-CAS/Compose-network/provider-gateway integration tests;
7. focused end-to-end tests;
8. migration upgrade/downgrade/interrupt/resume tests;
9. authorization, Brain isolation, injection, egress, deletion, audit tests;
10. SAST, secret scan, dependency vulnerability/license scan;
11. Dockerfile, rendered-Compose, OCI image, offline-bundle, container-runtime catalog/artifact publisher, privilege-plan, reboot-continuation, and runtime-ownership policy scans;
12. changed-critical-code mutation tests;
13. build packages/images, generate CycloneDX SBOM and provenance;
14. sign ephemeral artifacts and verify install smoke tests on Linux.

Jobs fail on skipped required tests, unknown pytest markers, warnings, uncommitted generated changes, vulnerable disallowed licenses, or unpinned CI actions/images.

### 9.2 Main/nightly/release pipelines

Main adds the full multi-agent E2E matrix and publishes immutable candidate artifacts.

Nightly adds:

- complete mutation suite;
- live built-in provider conformance within budget;
- full parser/language matrix;
- load and index-freshness regression;
- chaos boundary matrix;
- backup/restore and deletion non-resurrection;
- golden retrieval/learning evaluation;
- dependency drift and drift-canary probes.

Release adds:

- pristine supported OS/architecture machines with Docker/Compose/WSL absent plus compatible-existing-runtime and stopped-runtime matrices; every certified cell begins from a stock image and uses only the end-user MCP action, native consent/elevation, and optional reboot;
- rendered Compose validation for default, local-model, remote-provider, observability, backup, restore, and offline-bundle profiles;
- maintenance-mode upgrade and rollback from every supported version;
- production-scale local migration rehearsal without overwriting the last known-good data generation;
- 24-hour egress-disabled soak for the release candidate and a separate allowlisted provider-gateway soak;
- SLO, security, privacy, accessibility, and zero-tolerance sign-off;
- signed SBOM, SLSA provenance, checksums, launchers, runtime prerequisite manifest, approved publisher/key allowlist, offline redistribution evidence, offline bundle, Compose lock, and multi-architecture images;
- fresh no-runtime install, terms accept/decline, elevation/MDM denial, WSL/rootless provisioning, reboot resume, concurrent bootstrap MCP, interrupted install, automatic MCP start, failed-runtime/product-upgrade recovery, keep-data reinstall, purge-uninstall, and separate managed-runtime-removal verification.
- the exact `contracts/pf001/support-matrix-v1.json` clean-host campaign, independently signed by the approved external Ed25519 certification authority with no waiver or skipped/reused snapshot, verified per cell and as a complete canonical bundle on GitHub-hosted runners, and retained unchanged as a qualified release object.

### 9.3 Branch and release policy

- Protected main; no direct push.
- CODEOWNERS approval for security, contracts, migrations, graph schema, provider protocol, learning promotion, deployment, and deletion.
- Required review by a different engineer; security owner for controlled surfaces.
- CI has no deployment-cloud credentials. Live provider certification and release signing use isolated short-lived credentials or hardware-backed signing identities; long-lived repository secrets are prohibited.
- Dependencies, CI actions, base images, Compose includes, and release tools are digest-pinned.
- The same signed launcher/image/bundle digests tested by release qualification are published; rebuild-on-promotion is prohibited.
- Critical exploitable vulnerability, secret leak, unsigned artifact, zero-tolerance failure, or unresolved data-loss defect blocks release without waiver.

## 10. Definition of Done

A story is Done only when all are true:

- Every acceptance criterion passes as an automated executable test.
- Mandatory TDD evidence exists and the regression test precedes or accompanies behavior.
- Unit, property, contract, integration, E2E, security, migration, resilience, and performance tests required by the story pass.
- Global, per-package, changed-code, and mutation thresholds pass.
- Lint, format, strict types, architecture contracts, schemas, docs, security, license, secret, Dockerfile/Compose, offline-bundle, and image checks pass.
- Domain behavior is in domain/application; adapters only translate; repositories/UoW are used; SOLID and KISS rules pass review.
- Authorization, Brain scope, privacy classification, egress, retention, deletion, and audit are implemented and tested.
- API/MCP/event/provider schemas and generated clients are updated and compatibility is proven.
- Migration, backfill, rollback, restore, and replay behavior is implemented when persisted data changes.
- Required logs, metrics, traces, dashboards, alerts, runbooks, and diagnostics are present and privacy-reviewed.
- Performance is measured against the story SLO; no unbounded query or high-cardinality telemetry is introduced.
- ADRs explain material choices; public/operator documentation is complete.
- Immutable artifacts, SBOM, provenance, signatures, and vulnerability evidence are produced.
- No unresolved critical/high defect, zero-tolerance failure, unowned flaky test, or expired waiver remains.

The story-level sections below add requirements; they never relax this global Definition of Done.

## 11. User stories and implementation contracts

### 11.0 Story rules

Every story below is required product scope. All stories inherit Sections 0–10 and the PRD zero-tolerance gates. Acceptance criteria use Given/When/Then and MUST become executable acceptance tests named with the story ID. “Technical approach” is normative, including named use cases, ports, repositories, events, state transitions, security checks, and failure behavior. “Mandatory tests” is the minimum story-specific suite, not a replacement for the global test requirements.

For every command story, implement the application command and handler, domain behavior, repository/UoW changes, outbox integration event, audit behavior, API/MCP/CLI translation where exposed, and read model. For every query story, implement authorization before candidate access, a query handler, stable DTO, pagination/budget behavior, explainability fields, and telemetry.

For a pre-core host-launcher operation such as install, automatic MCP start, offline bundle load, generation switch, or purge uninstall, the Go launcher application/use case, fsync-safe host operation journal, typed ports/adapters, signed resource inventory, and core-side governed command/audit once core is available are the equivalent implementation contract. Such a story MUST NOT manufacture an SQLite Unit of Work before SQLite exists, and it MUST still provide Red-Green-Refactor evidence and all listed unit/property/fuzz/integration/E2E/security/recovery tests.

### 11.1 Epic PF — Platform foundation

#### PF-001 — Install the complete local Brain from one MCP installation

**User story:** As a nontechnical agent user, I can install AgentMemory once from my agent and receive a fully initialized local Brain without knowing about or preinstalling Docker or any other runtime.

**Acceptance criteria**

- Given a pristine supported machine without Docker, Compose, Python, Node, Java, Neo4j, or a model runtime, when the user selects the AgentMemory MCP installation and approves only applicable native license/elevation/reboot prompts, then the installer provisions and validates the certified local container runtime and the signed AgentMemory stack reaches Ready without a terminal command, Docker setting, website visit, or technical choice.
- Given the same install request or an install interrupted by process kill, network loss, daemon failure, power loss, logout, or reboot, it resumes from verified journal steps, creates no duplicate runtime, Brain, schema object, key, volume, network, or agent entry, preserves unrelated host/agent configuration, and reports `AlreadyReady` when complete.
- Given no external provider credential and default egress-disabled topology, the pinned local embedding, reranking, and extraction providers pass live probes and the install smoke test demonstrates semantic index/recall without a runtime network request.
- Given unsupported hardware/OS/virtualization, managed-device denial, declined consent, an incompatible or remote Docker context, unavailable current-directory mount, insufficient disk/memory, occupied loopback port, unsafe secret permissions, invalid runtime/image/model signature/provenance/SBOM, incompatible migration, or failed smoke test, readiness remains false, the failure is typed and explained in plain language, no partial stack serves product requests, and pre-existing software/data/configuration remains intact.
- Given an offline installation bundle containing an authorized redistributable runtime artifact or a separately supplied official runtime installer, the same publisher, signature, checksum, SBOM, provenance, compatibility, migration, and smoke-test gates pass with no network access.

**Technical approach**

- Implement the host bootstrapper `InstallApplication` as a resumable saga with an owner-only, fsync-safe `InstallJournal` written atomically by temp-file, fsync, rename, and parent-directory fsync. Host integration code is layered into launcher domain/application/platform/runtime/agent-config adapters and contains no Brain business rules.
- Required Ensure steps are VerifyHost, EnsureContainerRuntime (PF-006), VerifyRelease, ReserveSpace, EnsureDirectories, EnsureKeys, EnsureComposeBundle, EnsureNetworkAndVolumes, RunMigrations, EnsureCoreAndGraph, BootstrapLocalBrain, MergeAgentConfiguration, VerifyReadiness, and CommitActiveRelease. Each step stores input/output digest and compensating action.
- The launcher invokes Docker through an argv-based process port, never a shell string. It neither mounts nor exposes the Docker socket to a container. The immutable release manifest binds launcher, platform image digests, Compose lock/config, schemas, migrations, verifier, SBOMs, provenance, and signatures.
- Bootstrap secrets are generated locally with a CSPRNG and passed only by SecretRef/protected file mount. The initial owner binds to the invoking OS identity plus installation credential. Provider credentials are absent.
- Compose startup uses `depends_on.condition: service_healthy` and `docker compose up -d --wait`. Liveness is separate from readiness; readiness requires SQLite integrity/migration head, writable volumes, graph schema/driver compatibility, key access, audit append, deletion guard, expired-lease recovery, and an end-to-end write/index/recall probe.
- Agent configuration mutation is parse/validate/backup/merge/validate/atomic-replace. Unsupported formats produce a safe preview and host-specific automatic adapter failure, never an instruction to edit the file manually and never an overwrite. The installed command is the signed launcher, not `python`, `node`, or a mutable image tag.
- Native release certification MUST use the executable support matrix, report/evidence schemas, exact evidence-path derivation, independent Ed25519 signature, seven-day freshness limit, immutable campaign release, hosted per-cell reverification, and 117-object copy-only promotion defined by `docs/implementation/PF-001-NATIVE-CERTIFICATION.md`. CI MUST reject wrong publication/matrix/trust digests, skipped or failed trials, waivers, stale times, snapshot reuse, missing/extra/linked/oversized attachments, noncanonical JSON/ZIP, self-hosted provenance substituted for the hosted verification layer, and promotion without the exact certification ZIP.
- Implement the path-neutral custom-host boundary as the versioned `agentmemory.custom-agent-registration.v1` contract. A custom host or its plugin/marketplace installer owns registration and MUST invoke the absolute release-verified launcher directly, without a shell or mutable `PATH` lookup, using exactly `mcp --agent custom` and the active project directory as the working directory. `MergeAgentConfiguration` MUST derive a deterministic length-prefixed binding over contract ID, installation ID, entry ID, custom host mode, absolute launcher path, launcher SHA-256, and exact argv; execute the same bounded MCP `initialize`, `notifications/initialized`, and `tools/list` verification used by certified hosts; and journal `verify_custom` only after the expected AgentMemory identity, supported protocol revision, and bootstrap tool surface are proven. The binding locator under the owner-only AgentMemory state root is an authenticated plan namespace only and MUST NOT be passed to a host-configuration store. Custom mode MUST NOT discover, parse, read, write, back up, restore, or remove any host-owned configuration, and MUST reject a supplied managed-entry digest. Handshake failure remains recoverable and NotReady, exposes no raw process or secret material, and triggers no configuration compensation.

**Mandatory tests:** TDD unit/state-machine/property tests; kill after every Ensure/journal/config-write step; pristine no-runtime/repeated/offline/reboot-resume install; first-MCP deadline and installation-status mode; deterministic MCPB/Gemini/generic archive reproduction; official manifest-schema validation; wrong publication/bootstrap/native-object/signature/host/cell substitution; archive path/link/mode/timestamp attacks; native package payload byte-equivalence to the retained release bundle; promotion-without-rebuild proof; novice usability; local-model semantic smoke with packet capture; wrong runtime/image/weight signer/digest/SBOM/provenance/license; unsupported/remote Docker; stopped daemon; low disk/memory; port collision; unsafe permissions; Compose health failure; exact seven-cell macOS Tahoe/Ubuntu 24.04/Fedora 44/Windows 11 25H2 campaign with 54–58 no-skip trials per cell; physical-capacity reservation on APFS/ext4/XFS/NTFS; independent-signature substitution; stale campaign; snapshot reuse; missing/foreign evidence; noncanonical ZIP; hosted-attestation self-hosted rejection; 117-object qualification/promotion; agent-config preservation; custom-host exact argv/CWD/stdout/cancellation/concurrency/no-store-call conformance; zero-preinstalled-runtime assertion.

**Why:** A signed resumable installer turns “install the MCP” into the complete product setup while preserving a recoverable local system boundary.

#### PF-002 — Rebuild all derived state

**Implementation record:** [`docs/implementation/PF-002.md`](docs/implementation/PF-002.md) and
[`docs/runbooks/PF-002-PROJECTION-REBUILD.md`](docs/runbooks/PF-002-PROJECTION-REBUILD.md).

**User story:** As an operator, I can rebuild graph, memory, search, code, and vector projections from canonical events and authorized artifacts.

**Acceptance criteria**

- Given intact canonical events/artifacts and empty projections, when RebuildProjection runs with pinned versions, then stable entity IDs, assertions, text records, and vectors reproduce the expected projection digest without duplicate effective state.
- Given deletion tombstones or revoked access, rebuild never recreates or exposes deleted/revoked content.
- Given a missing artifact or unavailable provider, the run records a partial typed result and resumable cursor; it does not fabricate content.

**Technical approach**

- Implement StartProjectionRebuildCommand and ProjectionRebuilder port with one generation per projection type.
- Read canonical data by immutable watermark; write to a shadow generation; compare counts, lineage, integrity, and golden queries; atomically activate only after validation.
- Idempotency key is projection_type + Brain + source watermark + implementation fingerprint.
- Store application build, schema, parser, extractor, provider, and embedding-space versions in RebuildManifest.

**Mandatory tests:** deterministic replay; deletion non-resurrection; shadow/activation concurrency; interrupted resume; old/new generation isolation; provider outage; production-size benchmark.

**Why:** Shadow generations make repair verifiable and rollbackable without corrupting the active Brain.

#### PF-003 — Extend the platform without core changes

**User story:** As an adapter author, I can add a new agent host or model provider through public contracts.

**Acceptance criteria**

- Given an external adapter that implements the supported protocol and passes conformance, when registered and approved, then it operates without modifying identity, memory, graph, indexing, retrieval, governance, or learning packages.
- An unsupported protocol/capability or untrusted package is rejected before execution.

**Technical approach**

- Publish versioned agent and provider SDK contracts plus reference adapters outside core context internals.
- Register AdapterManifest through RegisterAdapterCommand; verify protocol range, package digest, signature, requested permissions, and capability probe.
- Route adapters through AgentAdapterPort or ProviderAdapterPort selected by the composition/runtime registry; domain code never switches on vendor names.

**Mandatory tests:** external reference adapter built in another language; conformance; signature/digest tampering; version negotiation; Liskov substitution across built-ins.

**Why:** Stable ports and conformance preserve agent/provider neutrality and Open/Closed compliance.

#### PF-004 — Degrade safely during dependency failure

**User story:** As a developer, my coding agent remains usable when AgentMemory components or providers fail.

**Acceptance criteria**

- Given Neo4j, embedding, reranking, extraction, or a noncanonical worker is down, event capture remains durable and available retrieval channels return with degraded_channels and freshness.
- Given the canonical ledger is unavailable, the adapter buffers locally within limits, reports capture degradation, and never blocks the host beyond its hook deadline.
- Recovery drains queued work idempotently without duplicate effective state.

**Technical approach**

- Implement DependencyHealthRegistry, circuit breakers, channel-specific deadlines, bulkheads, and a DegradationPolicy domain service.
- RecallQuery executes independent channels under structured concurrency; failure of one returns a typed channel outcome rather than failing the whole query unless authorization/canonical integrity fails.
- Agent hooks use a bounded local spool with encrypted records and high-watermark admission policy.

**Mandatory tests:** dependency fault matrix; deadline/cancellation; disk pressure; circuit half-open; catch-up; no duplicate billing; host continuation E2E.

**Why:** Explicit partial results preserve utility without concealing missing evidence.

#### PF-005 — Start an isolated MCP session automatically from any directory

**User story:** As a developer, starting a configured agent in a directory automatically connects that directory to my local Brain without a separate service or indexing command.

**Acceptance criteria**

- Given a healthy installation or a stopped Docker Desktop/Engine and Compose stack, when the agent opens the installed MCP command, then one cross-process startup lock starts and probes the recorded local runtime, ensures the exact active Compose release is healthy, and returns MCP stdio without racing concurrent agents or requiring user action.
- Given current directory `D`, the session container can read `D` and observe later changes but cannot write it, read an unmounted parent/sibling, access a Docker socket/provider credential/database, acquire a capability, or open a host listener. No parent is mounted implicitly.
- Given spaces, Unicode, shell metacharacters, symlinks, case-insensitive paths, a worktree whose Git directory lies outside `D`, or Windows drive/UNC syntax, identity remains host-correct and command injection is impossible; partial Git/index coverage is reported instead of silently widening access.
- Given cancellation, stdin EOF, launcher/core/bridge kill, or host shutdown, the session is completed only if the bounded checkpoint succeeds; otherwise it is marked interrupted, its credential expires/revokes, the transient container is removed, and restart is safe.
- Given two concurrent agents in different directories, each receives a distinct mount/session credential and project identity while authorized cross-project recall still uses the shared local Brain.

**Technical approach**

- Implement `StartMcpSessionApplication` in the Go launcher with ContainerRuntimeController, RuntimeOwnershipRepository, DockerProcessPort, InstallationLockPort, PathIdentityPort, GitIdentityPort, SessionCredentialPort, and ChildProcessPort. Address only the recorded endpoint/context, start and capability-probe it before Compose, use argv arrays and Docker `--mount` long syntax, and never interpolate the path into a shell.
- Canonicalize logical and real paths, assert the source exists on the Docker daemon host, reject remote Docker contexts, and record host path/device/Git fingerprints. Set bind mount `target=/workspace`, `readonly`, `rprivate`, and recursive read-only where supported; detect/refuse writable nested mounts otherwise.
- Mint a random short-lived credential scoped to one session/agent and mount only its protected file. Launch the exact active `mcp-session` image with `--rm`, no TTY, read-only rootfs, dropped capabilities, no-new-privileges, tmpfs scratch, resource/PID limits, and only `am_internal`.
- MCP stdout is reserved for protocol frames and diagnostics use stderr. The bridge calls core contracts only. `WorkspaceScanner` applies ignore/privacy policy, hashes relative paths, and streams only changed authorized content before the mount disappears; persistent workers parse stored canonical artifacts and never require a source mount.
- Heartbeat/session leases make abrupt loss observable. Host hooks call the authenticated loopback API through the launcher and use the same correlation/session ID; they never `docker exec` into the bridge. The bounded encrypted host spool is reconciled by event ID/order and deleted after ACK.

**Mandatory tests:** startup-lock race; Docker Desktop closed/rootless service stopped/daemon unhealthy/Compose stopped; exact endpoint and mount inspection; read/write/parent/sibling/socket/secret/capability denial; recursive-mount behavior; malicious path corpus; Docker Desktop sharing error; worktree/submodule identity; concurrent sessions; stdout purity; EOF/signal/kill at every lifecycle boundary; credential expiry/revocation; changed-file streaming and privacy exclusions; cross-agent recall E2E.

**Why:** A transient least-privilege bridge makes directory-aware automatic memory possible without giving the persistent Brain broad host filesystem access.

#### PF-006 — Provision the local container runtime without Docker knowledge

**User story:** As a user unfamiliar with Docker, I can install AgentMemory through my AI agent while the product securely installs and operates its container runtime for me.

**Acceptance criteria**

- Given a pristine certified macOS, Windows, or Linux host without Docker or Compose, when MCP installation begins, then a plain-language plan is shown and the platform runtime is acquired, verified, installed, started, and capability-tested automatically after only the exact third-party-license, OS-elevation, and reboot decisions the platform requires.
- Given a compatible stopped or running local Docker installation, it is addressed explicitly and reused without changing the global context, proxy, registry, resources, update channel, or unrelated image/container/network/volume; no runtime package is downloaded or reinstalled.
- Given Windows lacks a supported WSL2 prerequisite, the Microsoft-signed prerequisite is installed through the native privilege flow, existing WSL distributions remain unchanged, a one-use continuation is registered before an approved reboot, and the same installation resumes exactly once after sign-in.
- Given the user declines terms/elevation, a device policy denies installation, virtualization is firmware-disabled, the OS is unsupported, or the runtime conflicts with unrelated workloads, the operation becomes `Cancelled`, `PausedForAdministrator`, or `UnsupportedHost` before product readiness, preserves existing software/configuration, and offers one plain-language safe action rather than a command or documentation detour.
- Given a runtime artifact, repository, publisher signature, package signature, terms digest, plan digest, privilege nonce, or resume journal is missing, stale, replayed, redirected, rolled back, or tampered, execution fails closed before the affected side effect and produces a privacy-safe diagnostic receipt.
- Given process/power/network failure at any acquisition, verification, elevation, prerequisite, vendor-installer, reboot-marker, service-start, or probe transition, retry resumes from the first unverified transition, revalidates artifacts/state, and produces exactly one ownership record and runtime installation.
- Given uninstall, Docker/WSL and all non-AgentMemory resources remain by default. Runtime removal is offered separately only when ownership proves AgentMemory provisioned it and an exhaustive dependency scan proves it unused by anything else.

**Technical approach**

- Implement `EnsureContainerRuntimeApplication` using the state machine and ports in Section 2.2.1. `RuntimePrerequisiteManifest` is signed with the release and binds supported OS range/architecture, exact runtime/Compose versions, official URL allowlist, size/digest, native publisher/key identity, closed installer argument template, prerequisite operations, reboot exit codes, health/mount/network/volume probes, terms ID/version/URL/digest, redistribution permission, rollback strategy, support expiry, and anti-rollback sequence.
- `RuntimeInstallPlanPolicy` deterministically chooses `AdoptCompatible`, `StartCompatible`, `InstallCertified`, `RepairManaged`, or `Block`. It cannot choose from a binary name or version string alone; discovery verifies local endpoint, signed/package-owned executable, Engine API, Compose capability, Linux-image execution, read-only bind, named volume, internal network, loopback publish, security mode, and unrelated workloads.
- Implement `DarwinRuntimeProvisioner`, `WindowsRuntimeProvisioner`, and `LinuxRuntimeProvisioner` exactly as Section 2.2.1 prescribes. Privileged actions are closed typed operations such as `InstallVerifiedPackage`, `EnableWSLFeature`, `ConfigureSubordinateIds`, and `EnableUserService`; no generic command, script, URL, or environment map crosses `PrivilegeBroker`.
- `SetupProgressPort` drives the accessible agent-host/launcher-served local setup surface and structured MCP status. `LicenseConsentPort` stores a receipt only for the exact terms and plan digests with accept/decline time and OS principal; it never records an employer-size answer as fact or accepts terms automatically. Changed terms require new consent.
- Persist `RuntimeOwnershipRecord` and before/after hashes before product provisioning. Compensation deletes only verified AgentMemory-owned partial downloads/continuations/settings. It never uninstalls, downgrades, resets, or garbage-collects a pre-existing runtime or unrelated Docker data.

**Mandatory tests:** TDD domain/state-machine/property/fuzz tests; pristine supported OS VM matrix; no-Docker novice journey; exact license accept/decline/re-consent; UAC/macOS authorization/polkit denial; WSL absent/outdated/reboot/power-loss; macOS publisher/notarization; Windows Authenticode; Linux repository/GPG/package/rootless/subuid/systemd/SELinux; MITM/redirect/captive portal/proxy/partial resume; malicious PATH/context/endpoint; conflicting runtime and unrelated workloads; privilege-plan/nonce/IPC/TOCTOU attacks; setup-loopback Host/Origin/CSRF/capability/replay/browser-history/no-remote-asset tests; kill after every phase; concurrent first starts; MCP deadline/stdout purity/Ready handoff; existing/managed runtime uninstall; offline redistribution matrix; WCAG/accessibility/localization.

**Why:** Docker is an internal implementation dependency. Automating its safe lifecycle makes “install the MCP” true for ordinary users without hiding legal consent, weakening the host, or risking unrelated local workloads.

### 11.2 Epic ID — Brain, project, and repository identity

#### ID-001 — Resolve stable project identity

**User story:** As a developer, opening a directory resolves the correct Brain, Project, Repository, and Checkout.

**Acceptance criteria**

- Given an explicit manifest, known checkout, Git repository, or non-Git directory, resolution follows manifest → checkout registry → repository fingerprint → approved heuristic precedence and returns an explanation.
- Given ambiguous candidates, the system returns AmbiguousIdentity with candidates and never silently merges them.
- Paths alone never become durable repository identity.

**Technical approach**

- Implement ResolveWorkspaceQuery using ManifestReader, CheckoutRepository, VcsIdentityPort, DeviceIdentityPort, and IdentityResolutionPolicy.
- Repository fingerprint combines VCS type, canonical history/root commit, configured stable repository ID, and normalized approved remote fingerprints; credentials/query strings are removed before hashing.
- Checkout identity includes device and worktree identity; canonical path hash is location evidence only.

**Mandatory tests:** precedence table; Git/non-Git; same-name directories; remote normalization; path move; missing metadata; ambiguous fork; authorization.

**Why:** Stable layered identity prevents both memory fragmentation and accidental project merging.

#### ID-002 — Preserve identity across moves, clones, and worktrees

**Implementation record:** [`docs/implementation/ID-002.md`](docs/implementation/ID-002.md) and
[`docs/runbooks/ID-002-CHECKOUT-CONTINUITY.md`](docs/runbooks/ID-002-CHECKOUT-CONTINUITY.md).

**User story:** As a developer, moving, cloning, symlinking, or opening a worktree does not lose history.

**Acceptance criteria**

- A moved checkout retains Checkout identity when device/worktree evidence matches and records a new path observation.
- A clone shares Repository history but has a new Checkout.
- Git worktrees share Repository and commit history while keeping branch, HEAD, path, and dirty state distinct.

**Technical approach**

- Implement ObserveCheckoutCommand with optimistic Checkout aggregate versioning and CheckoutMoved/CheckoutObserved events.
- VcsIdentityPort returns repository fingerprint, common Git dir, worktree ID, branch, HEAD, remotes, and dirty digest.
- Historical path observations are append-only and never rewrite event provenance.

**Mandatory tests:** move/symlink/case sensitivity; clone; worktrees; branch divergence; remote change; concurrent observations; Windows/WSL path fixtures.

**Why:** Repository and checkout are different concepts and require different lifecycles.

#### ID-003 — Model complex repository layouts

**Implementation record:** [`docs/implementation/ID-003.md`](docs/implementation/ID-003.md) and
[`docs/runbooks/ID-003-REPOSITORY-TOPOLOGY.md`](docs/runbooks/ID-003-REPOSITORY-TOPOLOGY.md).

**User story:** As a developer, monorepos, nested repositories, forks, submodules, and non-Git workspaces are represented accurately.

**Acceptance criteria**

- Nested repositories and submodules remain separate Repository entities connected by evidence-backed relationships.
- Monorepo logical projects may share a Repository without sharing all project scope.
- A fork is not merged solely because remotes or file content resemble another repository.

**Technical approach**

- Implement DiscoverRepositoryTopologyQuery and ConfirmRepositoryLinkCommand.
- Parser emits candidate CONTAINS_REPOSITORY, SUBMODULE_OF, FORK_OF, and PROJECT_USES_REPOSITORY assertions; inferred links remain candidate until deterministic VCS evidence or confirmation.
- ProjectRepositoryLink is an aggregate with relation type, validity, evidence, and user correction history.

**Mandatory tests:** topology fixture corpus; nested .git; bare repositories; submodules; forks; monorepo packages; unrelated identical trees; corrections.

**Why:** Explicit topology avoids irreversible identity guesses in real-world layouts.

#### ID-004 — Select and enforce retrieval scope

**Implementation record:** [`docs/implementation/ID-004.md`](docs/implementation/ID-004.md) and
[`docs/runbooks/ID-004-RETRIEVAL-SCOPE.md`](docs/runbooks/ID-004-RETRIEVAL-SCOPE.md).

**User story:** As a user, I can recall from current, related, selected, or global authorized projects.

**Acceptance criteria**

- Current scope returns only the active project/repository/checkout as requested.
- Related scope includes only graph-supported, authorized related projects and boosts the current project.
- Selected/global scopes require explicit IDs/permission and expose included scopes in the response.

**Technical approach**

- Implement ResolveRetrievalScopeQuery returning immutable AuthorizedScope and ScopeExplanation.
- Related-project expansion starts from active evidence-backed project edges, uses bounded depth/cost, then intersects authorization grants before any search.
- Cache key includes principal grant version, scope fingerprint, policy version, and query mode.

**Mandatory tests:** full role/scope matrix; revoked grant cache invalidation; related-cycle bounds; empty/ambiguous scope; cross-Brain rejection.

**Why:** Scope resolution before retrieval is the primary defense against cross-project leakage.

### 11.3 Epic ADP — Agent adapters

#### ADP-001 — Emit canonical AgentEvents

**Implementation record:** [`docs/implementation/ADP-001.md`](docs/implementation/ADP-001.md) and
[`docs/runbooks/ADP-001-AGENT-EVENTS.md`](docs/runbooks/ADP-001-AGENT-EVENTS.md).

**User story:** As an adapter author, I can translate native host activity into the canonical versioned event contract.

**Acceptance criteria**

- Every supported event contains required identity, timestamps, provenance, causation/order, classification, retention, and payload hash/reference.
- Invalid events are rejected with field-level errors before persistence; unknown optional host data remains explicit unknown, not fabricated.

**Technical approach**

- Each adapter implements NativeEventTranslator and AdapterCapabilityDescriptor.
- Generated schema types validate at the adapter and daemon boundary. The daemon recalculates payload hash and distrusts adapter-supplied scope until identity resolution.
- Event IDs are adapter-generated UUIDv7 and stable across retries.

**Mandatory tests:** one fixture per canonical event family; schema fuzzing; time/skew; hash mismatch; missing capability; cross-adapter equivalence.

**Why:** One strict envelope allows every host to feed the same domain pipeline safely.

#### ADP-002 — Capture without slowing the host

**Implementation record:** [`docs/implementation/ADP-002.md`](docs/implementation/ADP-002.md) and
[`docs/runbooks/ADP-002-DURABLE-CAPTURE.md`](docs/runbooks/ADP-002-DURABLE-CAPTURE.md).

**User story:** As a developer, AgentMemory hooks do not materially delay my coding agent.

**Acceptance criteria**

- Healthy local append p95 is below 50 ms on the published profile.
- A hook performs validation, redaction, encryption, and durable enqueue only; it never parses code, calls a model, embeds, or traverses Neo4j inline.
- Hook timeout returns control to the host with a safe capture status.

**Technical approach**

- Implement AppendAgentEventCommand on a minimal local IPC endpoint and batch connection reuse.
- Commit event and outbox in one SQLite transaction before ACK.
- Adapter spool is bounded and encrypted; it batches uploads but preserves individual IDs/order.

**Mandatory tests:** latency benchmark; process kill immediately after ACK; forbidden outbound-call spy; cold start; concurrent hooks; timeout.

**Why:** Fast durable capture separates user interaction latency from expensive enrichment.

#### ADP-003 — Declare host capabilities honestly

**User story:** As an operator, I can see exactly which lifecycle signals an adapter observes.

**Acceptance criteria**

- Capability status distinguishes native, inferred, explicit-tool-only, unsupported, and permission-denied.
- Downstream logic never assumes an unsupported signal exists.
- Capability changes create a versioned observation and compatibility warning.

**Technical approach**

- AdapterCapabilityManifest is immutable per adapter version and validated by RegisterAgentAdapterCommand.
- Each event records capture method and capability-manifest digest.
- Query and learning policies use EvidenceAvailability, not host-name conditionals.

**Mandatory tests:** partial-host matrices; permission loss; version change; fabricated signal rejection; UI/API display.

**Why:** Missing data is materially different from a negative observation.

#### ADP-004 — Support hosts without lifecycle hooks

**User story:** As a developer, I can use AgentMemory with an agent that exposes no native lifecycle API.

**Acceptance criteria**

- The generic integration captures observable process/transcript, filesystem/Git changes, and explicit checkpoints.
- It labels unavailable prompt/turn/tool provenance unknown and does not infer hidden reasoning.
- Reimporting the same transcript is idempotent.

**Technical approach**

- Build a shell/process wrapper, TranscriptImporter, GitObserver, FileObserver, and MCP checkpoint tools behind AgentAdapterPort.
- Transcript chunks use source digest plus stable offsets for IDs; sensitive input is redacted before persistence.
- Observers correlate by time/session but emit candidate causal links, never authoritative causation.

**Mandatory tests:** wrapper E2E; transcript formats/encodings; duplicate import; abrupt termination; ignored/private files; unknown provenance.

**Why:** A generic observable integration expands coverage without pretending unavailable telemetry exists.

#### ADP-005 — Buffer and reconcile activity during local service interruption

**User story:** As a developer, my captured session survives a stopped, restarting, upgrading, or temporarily unavailable local core.

**Acceptance criteria**

- Events persist in the launcher's bounded encrypted ordered spool and upload after local core recovery.
- Original occurrence time is preserved, ingestion time is separate, duplicates are removed, and clock skew is recorded.
- Concurrent recovery respects backpressure and never reorders one ordering key.

**Technical approach**

- Implement OfflineSpoolRepository and ReconcileSpoolCommand with per-ordering-key sequence and acknowledged watermark.
- Upload uses bounded batches and per-item results; only accepted/duplicate items are deleted locally.
- ClockSkew value object records server-observed delta without rewriting occurred_at.

**Mandatory tests:** stopped-core restart; partial batch failure; duplicate/conflicting IDs; clock jumps; concurrent recovery; spool capacity; spool key/permission; post-ACK erasure.

**Why:** Durable reconciliation preserves local capture across container lifecycle events without requiring a hosted service.

#### ADP-006 — Provide cross-agent continuity

**User story:** As a developer, work captured in one certified agent is recalled correctly in another.

**Acceptance criteria**

- Equivalent task facts, decisions, changes, failures, and next steps are returned across Claude Code, Codex, Gemini CLI, Cursor-compatible, and generic adapters.
- Original host/model/adapter provenance remains visible but does not silo authorized retrieval.

**Technical approach**

- Maintain one cross-host conformance scenario corpus mapped to canonical events.
- Build StartSessionBriefingQuery independent of host; host adapters translate only delivery format and context budget.
- Host-specific procedure applicability is filtered separately from memory access.

**Mandatory tests:** all producer/consumer host pairs; capability gaps; provenance; budget equivalence; incompatible procedure exclusion.

**Why:** Cross-agent recall is the defining outcome of an agent-neutral product.

### 11.4 Epic ING — Durable ingestion and processing

#### ING-001 — Never lose acknowledged events

**User story:** As a user, an acknowledged event survives supported process or machine failure.

**Acceptance criteria**

- After ACK, immediate process kill/restart preserves the event and eventual terminal projection.
- Before commit, no ACK is returned and client retry is safe.
- Corrupt or unreadable records fail closed and trigger repair alert.

**Technical approach**

- AppendEventHandler writes AgentEvent, Artifact reference, and outbox row in one Unit of Work.
- ACK follows the canonical SQLite FULL-synchronous transaction commit; no other runtime store defines the acknowledgment boundary.
- Startup scans unprocessed events/outbox and expired leases.

**Mandatory tests:** kill at begin/write/commit/ACK; disk-full/fsync error; database restart; checksum corruption; recovery.

**Why:** The acknowledgement boundary is the product’s durability promise.

#### ING-002 — Make at-least-once delivery idempotent

**User story:** As an operator, retries do not duplicate memories, graph facts, provider charges, or audit outcomes.

**Acceptance criteria**

- Concurrent repeats produce one effective event and one effective side effect per idempotency key.
- Same ID with different content is rejected and audited as conflict.

**Technical approach**

- Unique keys exist at event, command, inbox, job, provider-operation, and projection levels.
- Every consumer begins by claiming InboxReceipt and finishes receipt plus side-effect outbox atomically.
- Provider result cache keys include content hash, profile/model revision, purpose, preprocessing, and privacy class.

**Mandatory tests:** concurrent duplicate storm; consumer crash before/after commit/ACK; conflicting hash; duplicate billing stub; projection uniqueness.

**Why:** Exactly-once infrastructure claims do not remove application-level duplication risks.

#### ING-003 — Preserve ordering and deterministic replay

**User story:** As an operator, I can replay selected event ranges with causally correct results.

**Acceptance criteria**

- Events sharing an ordering key apply by sequence; late events wait or create a documented gap after timeout.
- Replay yields the same deterministic projection digest as live processing.
- Nondeterministic reductions reference recorded operation result/version rather than silently calling a current model.

**Technical approach**

- Maintain per-ordering-key watermark and gap table.
- Projection handlers are pure event + prior state + recorded artifact functions.
- ReplayRun targets Brain, event/time range, projection generation, and code fingerprint and always writes shadow state first.

**Mandatory tests:** reorder/property sequences; missing/late events; concurrent keys; replay of old schemas; deterministic digest.

**Why:** Explicit ordering makes history repairable and explainable.

#### ING-004 — Handle backpressure and dead letters

**User story:** As an operator, overload and poison jobs remain visible and recoverable.

**Acceptance criteria**

- At soft limits, low-priority background work slows while interactive/capture capacity is reserved.
- At hard storage limits, new unacknowledgeable capture fails fast with capacity error; existing acknowledged events remain intact.
- Nonretryable/exhausted work enters DLQ with safe diagnostics and can be replayed after correction.

**Technical approach**

- JobScheduler uses separate priority queues, quotas, leases, and admission thresholds.
- RetryPolicy maps typed error codes to none/bounded/backoff.
- ReplayDeadLetterCommand requires authorization, creates a new attempt linked to the original, and never edits history.

**Mandatory tests:** queue/disk limits; fairness; poison job; DLQ authorization; replay; recovery; alert thresholds.

**Why:** Controlled backpressure protects canonical durability and interactive responsiveness.

#### ING-005 — Sanitize before persistence or egress

**User story:** As a privacy administrator, excluded or secret content never enters durable storage or a provider request.

**Acceptance criteria**

- Ignore rules, private blocks, secret/PII classification, and egress policy execute before canonical payload write and remote invocation.
- Redaction output is deterministic and retains an audit-safe rule/version record.
- Malformed/encoded attacks cannot bypass inspection.

**Technical approach**

- CapturePolicyPipeline is an application service with ordered Exclusion, Decode, Classification, SecretScan, Redaction, EgressDecision stages.
- Raw pre-redaction bytes exist only in bounded memory and are zeroed/released where feasible.
- Store sanitized payload or encrypted local-only artifact according to policy.

**Mandatory tests:** ignore precedence; path traversal; binary/encoding/archive bombs; secret corpus; provider egress spy; rule-version replay.

**Why:** Post-persistence redaction is too late for privacy and breach prevention.

#### ING-006 — Evolve event schemas safely

**User story:** As an operator, upgrades retain older sessions and reject unsupported data safely.

**Acceptance criteria**

- Supported old events migrate deterministically to the current internal representation.
- Unknown additive fields survive round-trip; unsafe breaking versions are quarantined.
- Interrupted migration resumes and reports progress.

**Technical approach**

- Maintain a registry of one-step EventUpcaster functions; never leap versions with one opaque transform.
- Persist original event bytes/schema and create a derived upcast view; immutable canonical history is not overwritten.
- Contract compatibility CI verifies every advertised producer/consumer version.

**Mandatory tests:** golden bytes per version; upcast chains; unknown fields; unsupported major; interruption; replay equivalence.

**Why:** Immutable originals plus explicit upcasters preserve audit and future recovery.

### 11.5 Epic MEM — Memory lifecycle

#### MEM-001 — Consolidate useful long-term memory

**User story:** As a developer, the Brain retains useful decisions, constraints, procedures, preferences, lessons, episodes, and unresolved work rather than every raw event.

**Acceptance criteria**

- Completed/checkpointed tasks produce only schema-valid useful memory candidates with source evidence.
- Promotion applies class-specific thresholds and never treats unsupported model text as fact.
- Raw events remain separate and reconstructable.

**Technical approach**

- ConsolidateTaskCommand loads a bounded TaskEvidenceBundle, calls ExtractMemoryCandidatesPort, validates structured output, then applies MemoryPromotionPolicy.
- Memory aggregate records class, scope, confidence dimensions, temporal validity, extractor/model version, content hash, and evidence IDs.
- One idempotency key per task + evidence watermark + extractor fingerprint.

**Mandatory tests:** golden extraction corpus; unsupported claim; malformed model output; deterministic extractor stub; idempotency; policy thresholds.

**Why:** A candidate/policy boundary gains useful compression without granting a model write authority.

#### MEM-002 — Preserve provenance and temporal metadata

**User story:** As a user, I can see who or what created a memory and when it was valid.

**Acceptance criteria**

- Every memory exposes stable ID, scope, lifecycle status, valid/recorded time, actor/agent, extractor/model, hashes, retention, and resolvable evidence.
- Missing mandatory provenance prevents activation.

**Technical approach**

- MemoryProvenance is an immutable value object required by Memory.create.
- MemoryRepository persists aggregate metadata canonically and emits MemoryProjected for Neo4j.
- ExplainMemoryQuery joins only authorized evidence and reports missing/purged evidence explicitly.

**Mandatory tests:** creation invariants; repository round-trip; temporal boundaries; purged evidence; authorization; schema migration.

**Why:** Provenance and bitemporal state make memory trustworthy rather than merely searchable.

#### MEM-003 — Deduplicate without losing evidence

**User story:** As a user, repeated sessions do not flood recall with paraphrases.

**Acceptance criteria**

- Exact equivalent memories merge under one active identity and retain every independent evidence link.
- Semantic candidates merge only when class, subject, scope, temporal validity, polarity, and policy are compatible.
- False-merge and contradiction cases stay separate.

**Technical approach**

- DeduplicateMemoriesCommand uses exact canonical fingerprint first, then semantic candidate retrieval, then deterministic CompatibilityPolicy.
- Merge is a Memory aggregate operation creating MemoryMerged and redirect lineage; source IDs remain historically resolvable.
- Semantic similarity alone cannot authorize merge.

**Mandatory tests:** exact/property normalization; paraphrase golden corpus; opposite polarity; different scopes/times; concurrent merge; lineage.

**Why:** Deterministic compatibility protects against destructive semantic over-merging.

#### MEM-004 — Correct, dispute, and supersede memory

**User story:** As a user, I can correct false or outdated knowledge while retaining explainable history.

**Acceptance criteria**

- An authorized explicit correction governs current recall at its declared scope.
- The previous memory becomes disputed/superseded with time and link; it is not silently overwritten.
- Concurrent corrections return a conflict or visible dispute according to policy.

**Technical approach**

- CorrectMemoryCommand requires expected version, correction reason, scope, and optional evidence.
- Memory.correct emits MemoryCorrected; graph creates a new assertion and SUPERSEDES/CONTRADICTS edge.
- PrecedencePolicy prioritizes explicit authorized user statements but never broadens their scope.

**Mandatory tests:** role/scope authorization; version conflict; narrower/broader correction; contradiction; historical query; audit.

**Why:** Versioned correction preserves temporal truth and user control.

#### MEM-005 — Pin, expire, archive, and forget memory

**User story:** As a user, I control whether and how memory participates in recall.

**Acceptance criteria**

- Pinning changes ranking only within authorized scope and cannot bypass temporal/permission filters.
- Expired/archived items leave ordinary recall but remain available to permitted historical queries.
- Forget immediately excludes the target and starts the deletion saga.

**Technical approach**

- Implement PinMemoryCommand, ArchiveMemoryCommand, SetMemoryExpiryCommand, and ForgetMemoryCommand as separate handlers.
- Lifecycle transitions are enforced by Memory state machine; direct status writes are prohibited.
- Scheduler emits MemoryExpired using injected Clock; Forget delegates to governance deletion after tombstone commit.

**Mandatory tests:** state-transition table; clock boundary; ranking; authorization; deletion cascade/non-resurrection; audit.

**Why:** Separate explicit commands keep retention semantics understandable and testable.

#### MEM-006 — Restore unresolved-work continuity

**User story:** As a developer, a new session starts with useful prior work from any supported agent.

**Acceptance criteria**

- A bounded briefing includes recent decisions, changes, validations, failures, blockers, and unresolved next steps with freshness/evidence.
- Stale or branch-incompatible work is labeled or excluded.
- The briefing respects configured token and item budgets.

**Technical approach**

- StartSessionBriefingQuery composes TaskReadRepository, MemoryQueryRepository, CodeRevisionQuery, and RetrievalPipeline.
- Allocate budget by fixed priority: safety/constraints, unresolved work, decisions, failures, changes; deduplicate and truncate at semantic item boundaries.
- Emit ContextInjected event containing selected IDs/ranks/budget, never copied hidden reasoning.

**Mandatory tests:** cross-agent scenario; branch mismatch; token accounting; empty/no-answer; stale facts; authorization; deterministic selection.

**Why:** A structured bounded briefing provides continuity without overwhelming the active context.

### 11.6 Epic GRA — Neo4j graph and evidence

#### GRA-001 — Enforce the Brain-scoped graph schema

**User story:** As a platform engineer, graph records remain uniquely identified, temporally valid, and Brain-safe.

**Acceptance criteria**

- A node or relationship missing required brain_id/stable identity/schema fields is rejected.
- Concurrent projection of the same entity produces one effective node/version.
- A query cannot address a Brain outside AuthorizedScope, including through dynamic labels or paths.

**Technical approach**

- GraphSchemaMigration creates composite uniqueness/type/existence constraints before writers activate.
- Neo4jGraphRepository accepts AuthorizedScope at construction per operation and prepends closed, parameterized scope predicates to every query template.
- Stable graph IDs derive from canonical entity UUIDs; revision IDs derive from entity + content/commit/version fingerprint.

**Mandatory tests:** constraint integration; concurrent MERGE; scope-query static scan; malicious IDs; cross-Brain canary; migration upgrade.

**Why:** Database constraints and mandatory scope parameters make graph integrity structural, not conventional.

#### GRA-002 — Represent facts as evidence-backed assertions

**User story:** As a user, every authoritative factual relationship can be traced to evidence.

**Acceptance criteria**

- A proposed subject–predicate–object claim without explicit user authority or resolvable evidence remains Candidate.
- An active Assertion records subject/object, predicate, scope, valid/recorded time, confidence components, extractor, and evidence.
- Removing or revoking all supporting evidence disputes/invalidates the assertion.

**Technical approach**

- ProposeAssertionCommand validates predicate registry and creates AssertionCandidate.
- ActivateAssertionCommand calls EvidencePolicy, AuthorizationPolicy, TemporalPolicy, and Assertion aggregate transition, then emits AssertionActivated.
- EvidenceRepository resolves immutable source spans/artifacts/events; it never accepts an unverified URL/string as evidence.

**Mandatory tests:** evidence gate; explicit user statement; invalid predicate; inaccessible/deleted evidence; confidence boundaries; activation idempotency.

**Why:** Assertion nodes separate a claim’s authority and history from convenient graph edges.

#### GRA-003 — Materialize traversable relationships

**User story:** As a retriever, I can traverse common relationships efficiently without losing their authority.

**Acceptance criteria**

- Active assertions for supported predicates create direct edges carrying assertion_id and temporal/scope metadata.
- Invalidating or superseding the assertion updates only affected projected edges.
- An orphan projected edge is detected and excluded from retrieval.

**Technical approach**

- AssertionActivated integration events invoke MaterializeAssertionEdgeCommand in a projection worker.
- PredicateRegistry maps a closed predicate enum to a closed relationship type; user text cannot become a relationship name.
- Integrity worker performs reverse checks edge → assertion and assertion → expected edge and quarantines mismatches.

**Mandatory tests:** every predicate mapping; activation/invalidation race; branch scope; orphan injection; repair; traversal explanation.

**Why:** Denormalized edges deliver graph performance while the assertion remains the source of truth.

#### GRA-004 — Query bitemporal and branch-aware truth

**User story:** As a developer, I can distinguish what is true now from what was true at a commit, branch, or recorded time.

**Acceptance criteria**

- Valid-time, recorded-time, branch, and commit filters return the corresponding assertion revision.
- A change on one branch stales only facts whose evidence lineage intersects that branch/revision.
- Historical queries never relabel stale knowledge as current.

**Technical approach**

- TemporalScope value object requires as_of_valid, as_of_recorded, branch/commit, or explicit Current.
- Graph query templates apply half-open intervals valid_from <= t < valid_to and recorded_from <= t < recorded_to.
- Code evidence uses revision reachability supplied by VcsRevisionPort; branch names alone are insufficient after force-push.

**Mandatory tests:** interval boundaries; retroactive correction; branch divergence/merge/force-push; unaffected branch; historical explanation.

**Why:** Bitemporal plus revision reachability models both reality time and knowledge-recording time.

#### GRA-005 — Surface contradictions and uncertainty

**User story:** As a user, conflicting evidence appears as a dispute rather than a silently chosen fact.

**Acceptance criteria**

- Conflicting assertions with no decisive precedence are linked as Disputed and both appear with evidence.
- Retrieval qualifies or abstains; rank confidence does not erase contradiction.
- A later resolution preserves the dispute history and records the resolving authority/evidence.

**Technical approach**

- DetectContradictionsCommand runs deterministic predicate-specific incompatibility rules followed by optional candidate extraction.
- Contradiction aggregate links assertion IDs, conflict dimension, evidence, state, and resolution.
- Retrieval applies ContradictionPolicy after candidate fusion and before response synthesis.

**Mandatory tests:** predicate conflict table; non-conflicting time ranges; polarity; user resolution; unresolved abstention; model-only false conflict.

**Why:** Contradiction is domain state and must not be hidden inside a ranking score.

#### GRA-006 — Migrate and repair graph integrity

**User story:** As an operator, I can evolve and repair graph projections safely.

**Acceptance criteria**

- Interrupted graph migrations resume from a durable cursor and never duplicate effective state.
- Integrity checks find unsupported assertions, orphan vectors/edges, invalid temporal ranges, scope mismatches, and stale generations.
- Repair writes a shadow change or quarantines; it does not silently delete canonical history.

**Technical approach**

- GraphMigrationRun stores migration checksum, Brain, batch cursor, counts, and state in SQLite.
- ValidateGraphIntegrityQuery produces findings; RepairGraphFindingCommand uses finding-type-specific handlers and audit.
- Destructive repair requires explicit approval and verified canonical rebuild path.

**Mandatory tests:** interruption at each batch; schema compatibility; injected corruption types; repair idempotency; large-graph performance.

**Why:** Graph projections are repairable only when migration state and lineage live outside the graph being repaired.

### 11.7 Epic IDX — Code and architecture indexing

#### IDX-001 — Index semantic code entities

**User story:** As a developer, I can find modules, packages, symbols, definitions, references, calls, inheritance, and implementations.

**Acceptance criteria**

- Supported source files produce File/FileRevision and Symbol/SymbolRevision records with exact byte/line spans and parser versions.
- Precise SCIP/compiler data supersedes compatible syntactic candidates without deleting their provenance.
- Parse failure affects only the file/language and remains visible.

**Technical approach**

- IndexRepositorySnapshotCommand creates immutable SourceSnapshot from repository/commit/working digest.
- LanguagePluginPort performs Detect, Parse, ExtractSymbols, ExtractReferences; grammar commits and query-pack hashes are pinned.
- ImportScipCommand maps SCIP stable symbol identities and documents data source/priority.

**Mandatory tests:** fixture per supported language/version; Unicode/CRLF spans; syntax error/recovery; Tree-sitter versus SCIP; parser crash isolation.

**Why:** Versioned source revisions and tiered precision support both universal coverage and exact navigation.

#### IDX-002 — Incrementally index changed content

**User story:** As an operator, large repositories stay fresh without full rescans.

**Acceptance criteria**

- A one-file change reparses/re-embeds only changed semantic units and reverse-dependent topology facts.
- Unchanged content hash + parser/extractor fingerprint is reused.
- Rename preserves lineage; deletion invalidates dependent current assertions.

**Technical approach**

- Compute VCS diff plus content hashes; use IndexPlan domain service to produce Add/Modify/Rename/Delete/Reuse operations.
- Cache key includes blob hash, language plugin version, grammar/query pack, extraction config, and privacy policy version.
- Projection events include affected entity/evidence IDs for bounded invalidation.

**Mandatory tests:** property diff plan; rename/copy/delete; generated file policy; parser upgrade forcing rebuild; worktree dirty changes; p95 freshness.

**Why:** Content-addressed incremental plans are deterministic and scale with changes, not repository size.

#### IDX-003 — Preserve code history and invalidate stale facts

**User story:** As a developer, code-derived knowledge remains correct for its commit and branch.

**Acceptance criteria**

- Changed/deleted evidence stales dependent assertions only in affected revision ancestry.
- Historical source revisions remain queryable while authorized/retained.
- Reintroduction of identical content creates a new revision context, not false continuous validity.

**Technical approach**

- EvidenceLineageRepository maintains source revision → evidence → assertion reverse dependencies.
- ProcessSourceRevisionCommand closes affected valid intervals and schedules re-extraction.
- CommitGraphPort answers ancestry/merge-base using pinned repository state; persist answer watermark for replay.

**Mandatory tests:** branch/merge/revert/cherry-pick/force-push; deletion/reintroduction; reverse invalidation; historical query; race with recall.

**Why:** Lineage-driven invalidation prevents global staleness from a local branch edit.

#### IDX-004 — Connect API consumers across projects

**User story:** As an architect, I can ask which frontend or service consumes an API and receive the correct path with evidence.

**Acceptance criteria**

- A client call/SDK reference, contract, server route, service ownership, and project linkage form an explainable consumer path.
- REST, GraphQL, gRPC, and generated clients are supported where parsers exist.
- Ambiguous base URLs, dynamic routing, or multiple endpoints return qualified candidates.

**Technical approach**

- API topology plugins emit EndpointCandidate, ClientCallCandidate, ContractBindingCandidate, and ServiceOwnershipCandidate.
- LinkApiTopologyCommand applies deterministic matching: canonical contract operation ID > generated-client symbol > configured service/base URL > heuristic path.
- Each CONSUMES assertion references exact client and server evidence plus matching rule/version.

**Mandatory tests:** cross-repository golden systems; route parameters; environment base URLs; gateway/proxy; generated SDK; false-match/adversarial strings; removal staleness.

**Why:** Decomposed evidence and ranked deterministic rules make topology answers explainable instead of guessed.

#### IDX-005 — Index dependencies, messaging, and infrastructure

**User story:** As an architect, I can understand build and runtime topology beyond source calls.

**Acceptance criteria**

- Manifests/locks, containers, Kubernetes, Terraform, CI, environment refs, queues/events, and schemas produce evidence-backed dependencies/deployments.
- Secrets and raw environment values are never persisted.
- Conflicting environment/topology observations are temporal assertions, not overwritten fields.

**Technical approach**

- ArtifactParserPort plugins own one format and return a common TopologyCandidate schema.
- Deterministic parsers precede optional model extraction; unknown constructs remain raw authorized evidence only.
- Environment references are normalized names plus secret-reference classification, never values.

**Mandatory tests:** fixture matrix by artifact/version; lockfile resolution; templating/overlays; secret redaction; conflicting environments; malformed files.

**Why:** Format-specific parsers provide precision while a common candidate schema keeps graph projection uniform.

#### IDX-006 — Apply content indexing policy

**User story:** As an administrator, I control generated, vendored, binary, oversized, encrypted, ignored, and private content.

**Acceptance criteria**

- Brain policy > repository .agentmemoryignore > private blocks > .gitignore/default policy precedence is deterministic.
- Excluded content is neither parsed, persisted, embedded, nor sent remotely.
- Policy changes schedule bounded reindex/deletion of newly excluded derivatives.

**Technical approach**

- IndexContentPolicy evaluates normalized repository-relative paths before opening content, then media/size/content classifications after bounded read.
- Store PolicyDecision with rule ID/version and source hash.
- PolicyChanged event computes affected content and invokes projection deletion/rebuild through the deletion/invalidation pipeline.

**Mandatory tests:** precedence; negation/globs/symlinks/path traversal; binary/large/encrypted; policy tightening/loosening; egress spy.

**Why:** One policy decision point prevents parsers/providers from inconsistently handling sensitive files.

#### IDX-007 — Navigate to exact supporting code

**User story:** As a developer, I can open the exact revision and span supporting a code-derived result.

**Acceptance criteria**

- Evidence includes repository, commit/snapshot, file, symbol, byte and line range, content hash, parser version.
- If the checkout differs, the response states the mismatch and may offer the historical blob; it never points at unrelated current lines.

**Technical approach**

- ResolveSourceEvidenceQuery verifies evidence hash against checkout or content-addressed artifact.
- SourceLink DTO has immutable revision link and optional current-worktree mapping computed by rename/diff service.
- UI/CLI open actions require explicit local path resolution and block path escape.

**Mandatory tests:** rename/move/line shifts; Unicode; stale checkout; missing blob; path traversal; access revocation.

**Why:** Revision-bound links preserve citation correctness as source files evolve.

### 11.8 Epic PRO — Embedding and reranking provider platform

#### PRO-001 — Configure certified built-in providers

**User story:** As an administrator, I can configure OpenAI, Cohere, Voyage, Google, Qwen/local, and OpenAI-compatible providers through one model.

**Acceptance criteria**

- A profile activates only after manifest validation and live probe; a remote profile additionally requires explicit owner egress approval, gateway destination policy, credential reference, provider retention/training declaration, quota, and budget.
- Model IDs are explicit and immutable for an embedding space; mutable aliases cannot silently change an active generation.
- Built-ins pass the same conformance suite.

**Technical approach**

- CreateProviderProfileCommand stores adapter ID, model ID, endpoint policy reference, secret reference, limits, and purposes; never secret values.
- ProbeProviderCommand runs protocol probe and records capability evidence/model revision.
- Built-ins are separate adapter packages implementing ProviderAdapterPort; provider-specific errors map to canonical error codes.

**Mandatory tests:** built-in conformance; invalid secret safe error; mutable alias drift; local runtime; OpenAI-compatible deviations; serialization excludes credentials.

**Why:** A single profile lifecycle prevents vendor code from entering routing, indexing, or retrieval.

#### PRO-002 — Install a language-neutral custom adapter

**User story:** As a provider author, I can add embedding/reranking from any language without core changes.

**Acceptance criteria**

- A signed/digest-pinned adapter with supported protocol can validate, probe, health-check, embed, rerank, cancel, and stop.
- Excess permissions, invalid signature, incompatible protocol, or failed conformance prevents activation.
- Adapter crash cannot crash the daemon.

**Technical approach**

- InstallProviderAdapterCommand verifies OCI image digest/signature/trust root, protocol range, SBOM/provenance/license/vulnerability policy, and requested sandbox permissions. It generates a service only from the closed signed Compose template; user-supplied Compose keys are never merged.
- The host launcher's `ProviderInstallApplication` calls `InstallProviderAdapterCommand` for domain/policy validation, receives an immutable `AdapterDeploymentPlan`, generates a service from the closed template, starts it through Compose, and returns the live probe attestation. Core never invokes Docker. The sidecar has read-only rootfs, tmpfs scratch, CPU/memory/PID/time limits, no project/database/Docker-socket/other-secret mount, and only the approved internal network. A remote embedding/reranking adapter receives gateway access, never a direct external route.
- Protocol client enforces message size, deadline, operation IDs, strict schemas, authentication, and framing; adapter diagnostics use a separate redacted channel. Crash/restart state remains outside the core transaction and cannot corrupt SQLite.

**Mandatory tests:** reference OCI adapters in Python and another language; framing fuzz; crash/hang/OOM/PID limit; signature/digest/SBOM/provenance; arbitrary Compose injection; filesystem/secret/socket/network escape; inbound listener; protocol negotiation; cleanup.

**Why:** Container and protocol isolation make custom extensibility portable through Docker and compatible with least privilege.

#### PRO-003 — Validate provider capabilities with a live probe

**User story:** As an administrator, I cannot activate a provider based on untrusted manifest claims.

**Acceptance criteria**

- Wrong dimension/count/order, NaN/Infinity, invalid dtype, malformed response, missing cancellation, or false purpose support rejects activation before any vector write.
- Probe results are bound to adapter digest, endpoint, model revision, and configuration hash.

**Technical approach**

- ProviderProbeSuite uses known ordered canaries for document/query embedding and reranking.
- VectorValidator performs exact length/dimension, finite-number, allowed range/type, norm policy, and content-ID order checks.
- CapabilityAttestation is immutable; configuration change invalidates it.

**Mandatory tests:** adversarial stub for every failure; reordered duplicate inputs; zero/huge vectors; timeouts; attestation invalidation.

**Why:** Runtime evidence is the only reliable protection from incorrect or drifting adapters.

#### PRO-004 — Isolate immutable embedding spaces

**User story:** As a retriever, only semantically compatible vectors share an index.

**Acceptance criteria**

- Any provider/model revision, tokenizer, preprocessing, dimension, dtype, normalization, similarity, purpose, instruction, or quantization change creates a new space fingerprint/generation.
- Vectors are never padded, truncated, projected, or silently reused.
- A write whose result disagrees with the space contract is rejected atomically.

**Technical approach**

- EmbeddingSpace.create hashes canonical normalized metadata into immutable_fingerprint.
- EnsureIndexGenerationCommand creates a dedicated generated VectorRecord label/index with exact dimension/similarity and filter properties.
- VectorWriteRepository verifies space/generation/content hash and uses one transaction per validated batch.

**Mandatory tests:** fingerprint property tests; every metadata delta; mixed-space rejection; dimension error; index name injection; concurrent creation.

**Why:** Immutable space identity is required for meaningful similarity and safe migration.

#### PRO-005 — Route providers by workload and policy

**User story:** As an administrator, I can route code, memory, document, query, rerank, language, privacy, and workload purposes independently.

**Acceptance criteria**

- The most specific enabled route matching Brain/project/corpus/language/classification/purpose/workload wins.
- No route can weaken egress/residency or use a profile without compatible capability.
- Repository config can restrict but not broaden routing.

**Technical approach**

- ProviderRoutingPolicy evaluates a documented precedence tuple and returns RouteDecision with rule/profile/version/reason.
- CreateProviderRouteCommand statically validates overlapping routes and policy lattice; unresolved equal precedence is rejected.
- Route cache key includes policy/grant/profile versions and invalidates on change.

**Mandatory tests:** exhaustive precedence decision table; ambiguous overlap; classification/region denial; capability mismatch; cache invalidation.

**Why:** A deterministic routing policy keeps cost/privacy choices reviewable and reproducible.

#### PRO-006 — Batch and schedule provider work safely

**User story:** As an operator, provider work respects latency, quota, cost, fairness, and priority.

**Acceptance criteria**

- Only items with identical Brain, classification, profile, space, purpose, provider retention policy, preprocessing, and deadline class batch together.
- Provider item/token/byte/rate/concurrency limits are respected; splitting preserves order and IDs.
- Interactive queries are isolated from backfill and evaluation workloads.

**Technical approach**

- ProviderScheduler owns queues per workload/profile and uses weighted fair scheduling plus token-bucket rate limits.
- BatchPlanner is a pure function over item metadata and limits; payload construction occurs after final egress authorization.
- Every batch has operation ID and child item results; partial failures retry only retryable items.

**Mandatory tests:** Hypothesis batch invariants; exact limits; fairness/starvation; cancellation; partial response; rate-limit hints; cost budget.

**Why:** Central batching improves efficiency without mixing privacy or semantic contracts.

#### PRO-007 — Retry, use equivalent fallback, and degrade correctly

**User story:** As a developer, transient provider failure does not corrupt indexes or stop all recall.

**Acceptance criteria**

- Retryable errors use bounded jittered retry within deadline; nonretryable errors fail immediately.
- Fallback occurs only to an endpoint proven equivalent for the same immutable space; otherwise work queues.
- Recall continues through available exact/lexical/graph channels and discloses the missing channel.

**Technical approach**

- Canonical ProviderError taxonomy drives RetryPolicy and CircuitBreaker.
- EquivalentEndpointSet is part of ProviderProfile attestation and requires identical model revision/output contract.
- Provider operation idempotency plus result cache prevents duplicate writes/charges.

**Mandatory tests:** full error matrix; Retry-After; timeout budget; circuit states; unsafe fallback rejection; duplicate billing; degraded recall.

**Why:** Semantic provider fallback is stricter than a network retry because a different model creates incompatible vectors.

#### PRO-008 — Migrate embedding generations under live ingestion

**User story:** As an administrator, I can change embedding provider/model without downtime or index contamination.

**Acceptance criteria**

- Migration creates/builds a shadow generation, backfills from a consistent watermark, dual-writes, catches up, validates, shadow-reads, atomically cuts over, and retains rollback.
- Crash/restart resumes every state idempotently.
- Quality/privacy/coverage/latency regression blocks cutover.

**Technical approach**

- EmbeddingMigration aggregate states: Planned, Building, Backfilling, DualWrite, CatchingUp, Validating, Shadowing, Ready, Active, RolledBack, Failed.
- Backfill reads canonical content, never old vectors. GenerationActivation uses serializable transaction/lease and publishes cache invalidation.
- Old generation remains read-only through configured rollback window, then is deleted through a governed operation.

**Mandatory tests:** every state transition/interruption; continuous ingestion; watermark race; shadow quality threshold; atomic cutover; rollback; deletion.

**Why:** A persisted state machine makes a long live migration observable and reversible.

#### PRO-009 — Contain provider data and runtimes

**User story:** As a security administrator, sensitive content reaches only authorized providers and custom runtimes.

**Acceptance criteria**

- `local_only`, `restricted`, private-block, secret-bearing, or disallowed-region content is denied before network socket acquisition and is never eligible for an override.
- Custom adapters receive only the content and resources authorized for one operation.
- Telemetry never contains content, secret, raw vector, or credential.

**Technical approach**

- EgressAuthorizationPort is called immediately before gateway invocation with immutable content taint, Brain/project, exact destination, region, model, purpose, profile attestation, retention declaration, policy version, quota, and budget.
- AdapterSupervisor creates per-operation tmpfs scratch and input, mounts no provider credential/project/database/Docker socket, and removes the container/scratch on completion.
- The default internal Compose network has no external route. Only `provider-gateway` is dual-homed and independently enforces exact HTTPS scheme/hostname/port/resolved-address, redirect reauthorization, TLS verification, size/time/rate limits, and authenticated operation type.

**Mandatory tests:** network interception; DNS/redirect bypass; mixed-class batch; sandbox filesystem; telemetry scan; offline mode.

**Why:** Defense in depth assumes provider and custom adapter code may be faulty or malicious.

#### PRO-010 — Observe provider health, cost, and drift

**User story:** As an operator, I can diagnose providers and detect silent model changes.

**Acceptance criteria**

- Status shows health, circuits, queues, retries/DLQ, usage, latency, safe errors, budgets, active/rollback generation, and pin state.
- Drift canary mismatch suspends new writes for the affected generation and requires a new space/migration.
- Budget exhaustion applies configured queue/degrade behavior, not silent overrun.

**Technical approach**

- ProviderTelemetryRecorder consumes canonical operation outcomes and PricingSnapshot version.
- Scheduled DriftProbe compares canary vector fingerprints/norm/distance ordering with tolerance; it never logs vectors.
- BudgetPolicy reserves estimated cost before dispatch and reconciles actual usage after response.

**Mandatory tests:** drift simulation; pricing version; budget race; metric cardinality/privacy; health aggregation; alert/runbook.

**Why:** Operational visibility and drift detection prevent silent semantic corruption and uncontrolled spend.

### 11.9 Epic RET — Retrieval and context delivery

#### RET-001 — Resolve authorization and context before search

**User story:** As an authorized caller, I receive results only from a valid requested scope.

**Acceptance criteria**

- Identity, Brain, project/repository/checkout, branch/commit/time, and grants resolve before any exact, full-text, vector, cache, or graph candidate access.
- Every graph expansion rechecks scope/classification.
- A revoked grant invalidates caches and prevents recall immediately after grant-version commit.

**Technical approach**

- RecallQueryHandler first invokes ResolveRetrievalScopeQuery and produces AuthorizedRetrievalContext.
- CandidateSourcePort methods require this context as a nonoptional parameter.
- Query cache keys include principal/grant/policy/scope/generation versions; GovernanceChanged events evict affected keys.

**Mandatory tests:** complete role/scope matrix; cache revocation; timing/count side channels; malicious cursor; graph path crossing denied project.

**Why:** Filtering after retrieval can already expose data through rank, timing, or graph traversal.

#### RET-002 — Retrieve through independent channels

**User story:** As a developer, exact technical identifiers and conceptual questions both return useful candidates.

**Acceptance criteria**

- Exact lookup, lexical full-text, applicable vector spaces, temporal filtering, graph expansion, and optional reranking run independently when eligible.
- Failure/unavailability of one channel does not erase results from healthy channels.
- Query analysis never invents scope or authority.

**Technical approach**

- QueryAnalyzer produces normalized terms, identifier/path/endpoint candidates, intent, requested time, and expansion budget using deterministic rules first.
- Structured concurrency calls ExactCandidateSource, LexicalCandidateSource, VectorCandidateSource, and GraphCandidateSource under per-channel deadlines.
- Candidate DTO preserves channel rank, source/generation, evidence IDs, temporal state, and authorized scope.

**Mandatory tests:** channel golden cases; analyzer fuzz; timeouts/cancellation; multilingual identifiers; outage matrix; empty channel.

**Why:** Independent candidate sources allow hybrid recall and graceful degradation without score coupling.

#### RET-003 — Fuse incompatible result channels

**User story:** As a user, results from multiple search systems are combined fairly and reproducibly.

**Acceptance criteria**

- Rank lists use reciprocal-rank fusion or a versioned calibrated method; raw scores from different channels/spaces are never directly compared.
- Duplicate entities merge while retaining contributing ranks/evidence.
- Fusion configuration/version appears in explanation.

**Technical approach**

- RankFusionService is a pure domain service operating on RankedCandidateList.
- Default weighted reciprocal-rank fusion uses documented constants versioned in RetrievalPolicy; scope/currentness/evidence boosts are bounded after fusion.
- Optional reranking receives an authorized bounded candidate set and cannot introduce a new candidate.

**Mandatory tests:** permutation/rank invariants; scale-adversarial raw scores; duplicates; ties; missing channels; policy version replay.

**Why:** Rank-based fusion is robust to incompatible provider score scales.

#### RET-004 — Retrieve temporally correct cross-project paths

**User story:** As an architect, I can ask relational questions across projects at the current or historical state.

**Acceptance criteria**

- Only authorized paths valid for requested time/branch/commit rank as current.
- History-only/stale edges are labeled and cannot support an unqualified current answer.
- Traversal obeys maximum depth, node, time, and token budgets.

**Technical approach**

- GraphPathQuery accepts AuthorizedScope, TemporalScope, predicate allowlist, start candidates, max_depth, max_paths, and cost budget.
- Cypher templates apply scope/status/validity within each pattern, not after path production.
- PathRanker scores evidence quality, path length, temporal currentness, and project relevance and returns Assertion IDs per hop.

**Mandatory tests:** cross-project topology golden set; stale edge; mixed-time path; cycles; denied intermediate node; traversal budget.

**Why:** Each hop must be both authorized and temporally valid for an explainable topology answer.

#### RET-005 — Deliver progressive disclosure within budget

**User story:** As an agent host, I receive sufficient memory without crowding out the active task.

**Acceptance criteria**

- Brief, standard, timeline, subgraph, and full-evidence levels return increasing detail without changing factual identity.
- Responses remain within exact token/item/byte budgets and truncate only at item boundaries.
- Deduplication and diversity prevent one session/project from monopolizing context.

**Technical approach**

- ContextBudget value object is mandatory; TokenCounter is provider/model-aware but uses conservative fallback.
- ContextAssembler selects atomic ContextItems, allocates category/project quotas, applies maximal marginal relevance or deterministic diversity, then renders.
- Full source content is fetched lazily only at evidence level and reauthorized.

**Mandatory tests:** property budget never exceeded; disclosure monotonicity; diversity; Unicode/tokenizer fallback; lazy evidence auth; deterministic output.

**Why:** Explicit budgets turn context management into testable selection rather than prompt truncation.

#### RET-006 — Explain results and abstain

**User story:** As a user, I can verify why a result was returned and receive unknown when evidence is insufficient.

**Acceptance criteria**

- Explanation includes identity/status/scope, temporal validity, channels/ranks, graph path, embedding generation, and supporting/contradicting evidence.
- Explanation reconstructs recorded decisions without hidden chain-of-thought.
- Insufficient or contradictory evidence yields Unknown or qualified candidates, never fabricated certainty.

**Technical approach**

- ExplainRecallQuery takes immutable RecallTrace ID recorded during retrieval.
- RecallTrace stores candidate/rank IDs and configuration hashes, not content or private reasoning.
- AnswerSupportPolicy requires predicate-specific minimum evidence/currentness and contradiction handling before Answer DTO may be Certain.

**Mandatory tests:** citation/path correctness; deleted/inaccessible evidence; trace replay; no-answer corpus; contradiction; no hidden prompt/log content.

**Why:** A recorded retrieval trace provides reproducible explanation without exposing model internals.

#### RET-007 — Treat context as untrusted and disclose degradation

**User story:** As an agent host, recalled data cannot grant authority and missing channels are visible.

**Acceptance criteria**

- Stored prompt injection is delimited/labeled and cannot modify system/tool/policy behavior.
- Response reports unavailable, timed-out, stale, or fallback channels and freshness watermarks.
- Context contains no credential/raw secret after rendering.

**Technical approach**

- ContextRenderer uses typed data sections and escaping per host format; it never concatenates recalled text into trusted instruction templates.
- DegradationSummary is a first-class response field populated from channel outcomes.
- Final OutputDlpScanner blocks or redacts accidental high-confidence secrets and records safe reason.

**Mandatory tests:** stored-injection adversarial corpus across hosts; delimiter escape; tool-permission invariance; outage disclosure; DLP scan.

**Why:** Host-neutral memory must be useful data while remaining outside the authority hierarchy.

### 11.10 Epic INT — MCP, API, SDK, CLI, and UI

#### INT-001 — Expose versioned MCP tools and resources

**User story:** As an AI agent, I can use all recall, checkpoint, explanation, correction, forgetting, indexing, provider, and governed-learning operations through MCP.

**Acceptance criteria**

- Each PRD MCP tool/resource maps to the same application use case and result/error schema as REST.
- stdio and optional authenticated loopback-only Streamable HTTP pass the same contract suite; non-loopback/remote MCP configuration is rejected.
- Cancellation, progress, authorization, scope, and evidence semantics are preserved.

**Technical approach**

- Generate MCP input/output models from contracts/mcp; handlers only authenticate, validate, call a mediator, and translate.
- MCP RequestContext maps principal, client, deadline, progress, correlation, and cancellation.
- Resources are query-only and use ETag/generation metadata where supported.

**Mandatory tests:** tool/resource contract snapshots; stdio/HTTP parity; auth audience/origin; cancellation/progress; malformed client; every tool authorization.

**Why:** Thin translation prevents MCP from becoming a second business-logic implementation.

#### INT-002 — Provide a stable authenticated service API

**User story:** As an integrator, I can operate every product domain programmatically.

**Acceptance criteria**

- All required resource groups support canonical auth, pagination/streaming, idempotency, optimistic concurrency, rate limits, and problem errors.
- OpenAPI changes obey compatibility policy and generated SDKs remain in sync.
- Long operations survive client disconnect and are cancellable when safe.

**Technical approach**

- FastAPI routers are organized by bounded context and inject authenticated RequestContext plus application mediator.
- Middleware order is request ID → size/deadline → authentication → rate limit → route authorization metadata → handler → safe logging.
- Operation aggregate tracks long-running state; SSE uses resumable event IDs and authorization on reconnect.

**Mandatory tests:** Schemathesis/schema fuzz; auth/role matrix; idempotency conflict; ETag; pagination cursor tamper; SSE reconnect/cancel; rate limit.

**Why:** One versioned API contract is the source for all non-host integrations and UI.

#### INT-003 — Supply semantically equivalent SDKs

**User story:** As an application developer, supported Python and TypeScript SDKs expose identical product semantics.

**Acceptance criteria**

- Identical requests preserve IDs, scope, evidence, status, retryability, pagination, and errors in each SDK.
- SDKs expose deadlines/cancellation and never retry non-idempotent calls without an idempotency key.
- Supported server/SDK compatibility window is enforced.

**Technical approach**

- Generate transport DTO/client core from OpenAPI, then add a small hand-written ergonomic layer with no domain reinterpretation.
- Maintain language-neutral golden request/response fixtures.
- SDK User-Agent includes SDK/version and protocol; compatibility handshake fails clearly outside window.

**Mandatory tests:** cross-language golden fixtures; cancellation; retry decision table; unknown fields; old/new server matrix; package install.

**Why:** Generated cores plus shared fixtures prevent language-specific semantic drift.

#### INT-004 — Operate the product from CLI

**User story:** As a local user or operator, I can perform every required administration workflow without the UI.

**Acceptance criteria**

- CLI covers PRD initialization, adapter/project/index/memory/learning/provider/migration/diagnostic/repair/backup/restore/export/service operations.
- Output has stable JSON mode and human mode; exit codes distinguish validation, auth, conflict, unavailable, partial, and internal failure.
- Destructive actions require interactive confirmation or explicit --yes plus operation scope; secrets never print.

**Technical approach**

- Typer commands call generated SDK/application facade, not repositories or shell database clients.
- CommandResultRenderer is the only formatting layer; JSON schema is versioned.
- Local service discovery uses protected installation metadata and verifies server identity.

**Mandatory tests:** command E2E; JSON snapshots; all exit codes; confirmation/noninteractive CI; Unicode paths; secret redaction; interrupted streams.

**Why:** API-backed CLI parity keeps operations scriptable without duplicating state logic.

#### INT-005 — Inspect and manage the Brain from the UI

**User story:** As a user, I can search, inspect evidence/timelines/maps, correct memory, review learning, and manage projects/providers/privacy in a production UI.

**Acceptance criteria**

- UI actions invoke the same API operations/audit as CLI and show validation, conflict, authorization, degraded, and long-running states.
- Concurrent edits use ETag and offer refresh/compare rather than overwrite.
- Sensitive values are never placed in URLs, browser logs, analytics, or persistent client cache.

**Technical approach**

- Organize React by feature with presentation, application hooks, and generated client boundary.
- TanStack Query owns server state; query keys include Brain/scope and authorization changes clear cache.
- Forms use schemas generated from OpenAPI where feasible; mutations invalidate explicit keys and display operation IDs.

**Mandatory tests:** Testing Library/MSW behaviors; UI/API parity; conflict; auth expiry; cache scope switch; secret scan; Playwright critical flows.

**Why:** Reusing the API and server-state library prevents a second domain/client cache implementation.

#### INT-006 — Make large graph views accessible

**User story:** As a user with accessibility needs or a large Brain, I can navigate graph information effectively.

**Acceptance criteria**

- Viewer queries a bounded subgraph; it never downloads/renders the entire Brain.
- Equivalent table/list path representation is keyboard and screen-reader accessible.
- WCAG 2.1 AA automated and manual critical-path checks pass.

**Technical approach**

- GraphViewQuery requires seed, predicates, depth, node/edge limits, time/scope and returns continuation.
- Cytoscape adapter renders the visual; semantic table/tree is the authoritative accessible representation.
- Layout runs in a worker; progressive expansion reauthorizes and cancels on scope change.

**Mandatory tests:** axe; keyboard/screen reader manual checklist; 10k-node bounded benchmark; cancellation; denied expansion; color/zoom.

**Why:** Query-driven views preserve performance and an equivalent semantic representation preserves accessibility.

#### INT-007 — Export and import without lock-in

**User story:** As a user, I can move authorized Brain data between deployments while retaining semantics and deletion protections.

**Acceptance criteria**

- Export includes canonical events/artifacts, identities, memories/assertions, temporal provenance, provider metadata, ACL/policy, audit proofs, and deletion ledger within scope.
- Secrets are excluded; content is encrypted and manifest-signed.
- Import detects identity collisions, verifies digests/signatures/schema, reapplies deletion guards, and never broadens grants.

**Technical approach**

- ExportBrainCommand produces a versioned manifest plus chunked content-addressed encrypted archive from a consistent watermark.
- ImportBrainCommand stages into isolated namespace, validates, maps IDs under explicit collision policy, runs integrity, and activates atomically.
- Cross-Brain import is treated as data transfer with classification/egress approval and preserves source provenance.

**Mandatory tests:** round trip; partial/corrupt/signature fail; old schema; collision choices; deleted data; ACL non-escalation; large streaming archive.

**Why:** A signed canonical format provides portability without weakening trust boundaries.

### 11.11 Epic LRN — Evidence-gated self-improvement

#### LRN-001 — Define observable task outcomes

**User story:** As a user, success or failure is judged against a visible, versioned task contract.

**Acceptance criteria**

- Explicit user acceptance criteria are preserved exactly as authoritative checks.
- Inferred checks/constraints are labeled inferred with extractor/evidence and remain editable.
- Contract changes create a new version and never retroactively alter prior outcome evaluation.

**Technical approach**

- CreateTaskContractCommand constructs TaskContract aggregate with goal, checks, constraints, scope, risk, required approvals, and provenance.
- Check types are deterministic command/test/artifact/state/manual, each with evaluator port and timeout.
- Task start binds contract version/hash; UpdateTaskContractCommand requires expected version and actor.

**Mandatory tests:** explicit versus inferred precedence; malformed model candidate; version conflict; risk propagation; evaluator contract; audit.

**Why:** Learning from outcomes is impossible unless expected outcomes are explicit and immutable per attempt.

#### LRN-002 — Detect possible mistakes without equating failure with fault

**User story:** As a user, meaningful failures propose learning while probes and external outages do not automatically become agent mistakes.

**Acceptance criteria**

- Failed tests, corrections, retries, reversions, incidents, and feedback may create one idempotent candidate with attribution/evidence.
- Intentional probes, cancelled work, and transient provider/network/infrastructure failures classify external/unknown unless evidence supports agent fault.
- Detection never activates a lesson or changes behavior.

**Technical approach**

- DetectLearningCandidateCommand consumes Attempt/Outcome events and applies MistakeAttributionPolicy with taxonomy from PRD Section 8.3.
- Candidate key is task + attempt lineage + failure signature + repair signature + detector version.
- Detector output contains observed facts, attribution probabilities/qualifiers, missing evidence, and alternative classes; it is not causal truth.

**Mandatory tests:** labeled detection corpus; false-positive probes/outages; duplicate event storm; cancellation; explicit correction; precision threshold.

**Why:** Separating failure observation from fault attribution prevents harmful self-reinforcement.

#### LRN-003 — Build evidence-independent causal hypotheses

**User story:** As a reviewer, I can distinguish observed failure from suspected cause and alternatives.

**Acceptance criteria**

- Each hypothesis states cause, mechanism, applicability, alternatives, confounders, supporting/contradicting evidence groups, and status.
- Copies/summaries derived from one source count as one evidence group.
- Model-generated diagnosis cannot validate itself.

**Technical approach**

- ProposeCausalHypothesesCommand accepts candidate and EvidenceLineageGraph, calls structured extractor, then validates schema/taint/lineage.
- EvidenceIndependencePolicy groups by root event/artifact/actor/model-run and detects circular support.
- CausalHypothesis aggregate transitions Candidate → Corroborated/Disputed/Rejected only through independent evidence commands.

**Mandatory tests:** lineage grouping; circular copies; correlated model runs; alternative hypotheses; contradiction; unsupported diagnosis; authorization.

**Why:** Independence at root lineage, not document count, prevents confidence inflation.

#### LRN-004 — Compile narrow structured lessons and procedures

**User story:** As a developer, proposed learning is actionable, bounded, testable, and reversible.

**Acceptance criteria**

- A procedure contains triggers, preconditions, ordered steps, postconditions, verification, prohibited shortcuts, exclusions, narrowest scope, risk, expiry, immutable hash/version, and rollback.
- Missing verification, rollback, or justified scope prevents review readiness.
- Procedure content is data/instruction for an agent task, never executable plugin code.

**Technical approach**

- CompileProcedureCandidateCommand maps corroborated hypotheses into ProcedureDraft through a structured candidate compiler.
- ProcedureSchemaValidator and ScopeMinimizationPolicy enforce required fields and prevent broader-than-evidence scope.
- Canonical serialization creates content_hash; edits create a new immutable ProcedureRevision.

**Mandatory tests:** schema/property tests; scope minimization; forbidden controlled-surface content; hash determinism; edit/new version; negative examples.

**Why:** Structured procedures can be evaluated and rolled back; free-form “lessons” cannot.

#### LRN-005 — Review candidates in a Learning Inbox

**User story:** As an authorized reviewer, I can understand and govern proposed learning.

**Acceptance criteria**

- Inbox shows expected/observed outcomes, evidence, hypotheses, contradictions, confidence dimensions, risk/scope, proposed procedure, validation, and history.
- Authorized actions include observe, edit-as-new-version, merge, approve, reject, dispute, suspend, revoke, and rollback according to state/role.
- Every action is optimistic-concurrency protected and audited.

**Technical approach**

- LearningCandidateQuery builds a read model from canonical candidate/revision/evaluation/deployment records.
- Separate command per action invokes LearningGovernancePolicy; UI has no direct status mutation.
- Review decision binds reviewer, role, exact revision hash, scope, policy version, reason, and expiry.

**Mandatory tests:** full role × state × action decision table; concurrent review; hash mismatch; UI/API/CLI parity; audit.

**Why:** Explicit commands and decision binding prevent ambiguous or stale approvals.

#### LRN-006 — Evaluate against baseline, holdouts, and counterexamples

**User story:** As a platform administrator, only demonstrated improvements can advance.

**Acceptance criteria**

- Evaluation compares baseline versus candidate on sandbox replay, deterministic checks, repeated stochastic runs, temporal hidden holdouts, unrelated tasks, negative transfer, privacy, auth, and safety.
- Acting agent cannot read hidden expected answers/evaluator internals.
- No improvement, regression, leakage, or unsafe action blocks promotion.

**Technical approach**

- StartProcedureEvaluationCommand creates immutable EvaluationPlan with dataset versions, seeds, models, environment, metrics, thresholds, and isolation profile.
- EvaluationRunnerPort executes separate sandbox workers with read-only fixtures and no production credentials/network except allowlisted mocks.
- EvaluationResult stores signed aggregate metrics plus per-case encrypted refs; PromotionPolicy consumes results, never model narrative.

**Mandatory tests:** sandbox escape; hidden holdout secrecy; baseline/candidate randomization; repeated-run statistics; negative transfer; privacy/auth regression.

**Why:** Independent controlled comparison is required to distinguish improvement from anecdote.

#### LRN-007 — Apply risk-based promotion and exact approval binding

**User story:** As an administrator, promotion authority and evidence match procedure risk.

**Acceptance criteria**

- Promotion evaluates evidence independence, efficacy, safety, negative transfer, scope, and risk against versioned policy.
- Approval binds exact content hash, parameters, environment, scope, expiry, evaluator set, and test results.
- Any material edit or expired/revoked evidence invalidates approval.

**Technical approach**

- RequestProcedurePromotionCommand calls PromotionPolicy decision table; high/critical risk requires named multi-party roles.
- Approval aggregate contains ApprovalBinding fingerprint computed from all controlled fields.
- EvidenceChanged/ProcedureRevised/PolicyChanged events invoke RevalidateApprovalCommand and suspend deployment on invalidation.

**Mandatory tests:** exhaustive policy table; multi-party separation; binding field mutation; expiry; revoked evidence; concurrent approvals; no self-approval.

**Why:** Content-addressed approval prevents a reviewed procedure from being swapped after review.

#### LRN-008 — Shadow, canary, suspend, and roll back procedures

**User story:** As an operator, new learned behavior is introduced gradually and harmful behavior stops quickly.

**Acceptance criteria**

- Approved versions deploy first in shadow, then bounded canary by user/project/agent/environment/application count.
- Adverse outcome suspends new exposure/application, invalidates queued contexts, and restores prior active revision within rollback SLO.
- Full deployment requires canary efficacy/safety thresholds and explicit policy transition.

**Technical approach**

- ProcedureDeployment aggregate state machine: Approved, Shadow, Canary, Active, Suspended, RolledBack, Revoked, Expired.
- SelectProcedureQuery uses deterministic cohort assignment and execution-time authorization/applicability.
- AdverseOutcomeObserved triggers SuspendProcedureCommand at highest-priority queue and CacheInvalidated event; rollback pointer update is atomic.

**Mandatory tests:** state transitions; deterministic cohorts; adverse race with queued work; kill switch; rollback; prior revision unavailable; SLO.

**Why:** Progressive delivery limits blast radius and makes learned behavior as governable as production software.

#### LRN-009 — Transfer learning across compatible agents

**User story:** As a developer, a verified lesson learned through one agent helps another only when applicability matches.

**Acceptance criteria**

- An active project-scoped procedure is retrievable by another host when task, tools, platform, language, versions, and permissions satisfy preconditions.
- Host-specific or incompatible workarounds are excluded with a reason.
- Cross-project/Brain expansion requires evidence/policy/approval for that scope.

**Technical approach**

- ProcedureApplicabilityPolicy matches structured EnvironmentFingerprint and TaskIntent, never host name alone.
- SelectProcedureQuery filters authorization/state/scope/risk first, applicability second, ranking third.
- Agent host adapter renders only supported step/tool semantics and cannot rewrite procedure content.

**Mandatory tests:** cross-host compatibility matrix; OS/tool/version mismatch; narrower scope; denied Brain; adapter rendering equivalence; negative transfer.

**Why:** Structured applicability enables safe cross-agent value without universalizing local hacks.

#### LRN-010 — Measure exposure, application, outcome, and efficacy separately

**User story:** As a reviewer, I can tell whether a procedure was seen, used, and independently helped.

**Acceptance criteria**

- Exposure, acknowledgment, applicability, application, verification outcome, and adverse outcome are separate immutable events.
- Repeated exposure alone does not raise confidence or efficacy.
- Outcome joins require causal/application linkage and independent validator where policy demands.

**Technical approach**

- Define ProcedureExposed, ProcedureAcknowledged, ProcedureApplied, ProcedureVerificationCompleted, and AdverseOutcomeObserved schemas.
- ComputeProcedureEfficacyQuery uses versioned statistical policy, deduplicates correlated attempts, and reports sample size/uncertainty.
- Promotion/monitoring consume metrics read model but preserve raw event lineage.

**Mandatory tests:** event ordering/absence; repeated exposure; correlated subagents; outcome without application; confidence intervals; delayed outcomes.

**Why:** Separating funnel stages prevents recall frequency from masquerading as successful learning.

#### LRN-011 — Explain learning and prohibit autonomous self-modification

**User story:** As a user, I can audit improvement while core controlled surfaces remain protected.

**Acceptance criteria**

- Explanation traces source events, evidence groups, hypotheses, evaluation, approval, revisions, canary, applications, outcomes, and rollback without chain-of-thought.
- Attempts to learn or deploy changes to model weights, system/developer prompts, permissions, policies, adapters, evaluators, provider configuration, security controls, or executable code are rejected and audited.

**Technical approach**

- ExplainProcedureQuery traverses immutable authorized IDs and returns decision facts/rationales recorded by policies/reviewers.
- ControlledSurfacePolicy validates candidate text/step targets and all deployment operations; enforcement is outside the model.
- Forbidden attempts produce ControlledSurfaceViolation with safe evidence and security metric.

**Mandatory tests:** explanation completeness; deleted evidence; every forbidden surface; obfuscated instruction; prompt injection; audit/redaction.

**Why:** Self-improvement is governed memory/procedure evolution, not autonomous system modification.

### 11.12 Epic SEC — Security, privacy, and governance

#### SEC-001 — Authorize every operation and candidate access

**User story:** As a local Brain owner, unauthorized data never becomes a result or intermediate candidate.

**Acceptance criteria**

- Exact, lexical, vector, graph, learning, explain, export, evaluation, cache, and mutation operations deny by default.
- Unauthorized resources do not leak through counts, errors, timing, paths, metrics, queues, or cache keys.
- Worker identities can perform only named projection/job actions.

**Technical approach**

- AuthorizationPolicy is a domain service fed by ScopeGrantRepository and immutable RequestContext.
- All repository/query ports require AuthorizedScope; architecture tests forbid raw query adapter use outside infrastructure.
- Required AuthorizedScope repository parameters, SQLite Brain predicates, Neo4j filtered SEARCH/expansion, Brain-scoped CAS keys, isolated provider batches, and capability-scoped worker/session credentials are defense-in-depth controls.

**Mandatory tests:** generated action × role × scope matrix; cross-Brain fuzz; counts/timing/error/cache side channels; stale grants; worker/session privilege; confused deputy.

**Why:** Multiple enforcement layers reduce the chance that one missed application check leaks a Brain.

#### SEC-002 — Encrypt data and protect credentials

**User story:** As a security administrator, sensitive records and provider credentials remain protected in transit, at rest, logs, and exports.

**Acceptance criteria**

- Network/store encryption and approved key sources are verified at readiness.
- Credentials exist only as references outside SecretResolver and never serialize into config/status/log/trace/graph/vector/export.
- Rotation occurs without restart/data loss where provider permits.

**Technical approach**

- CryptoPort and SecretResolver are narrow outbound ports; domain sees SecretRef only.
- Readiness probes TLS mode, encryption keys, file permissions, and secret-store access without revealing values.
- Rotation event invalidates client pools/caches and establishes new connections before retiring old.

**Mandatory tests:** serialization/log scans; TLS downgrade; file permissions; key/secret rotation; expired credential; backup/export.

**Why:** Secret references and centralized resolution make accidental propagation structurally difficult.

#### SEC-003 — Honor capture privacy and exclude hidden reasoning

**User story:** As a user, private content and hidden chain-of-thought are not captured.

**Acceptance criteria**

- Ignore/private/secret/PII policy applies before persistence.
- Adapters capture only observable host events, explicit messages/outputs, tool facts, and user feedback; host-internal reasoning fields are dropped.
- Privacy settings and capture capability are visible and auditable.

**Technical approach**

- Adapter conformance contains forbidden-field schemas and privacy fixtures.
- CapturePolicyPipeline marks field-level origin/classification and rejects prohibited source classes.
- Privacy status query reports rules/capabilities, not content.

**Mandatory tests:** every certified adapter; hidden-field fixtures; private blocks; encoding bypass; telemetry; configuration precedence.

**Why:** The platform needs outcomes and evidence, not private model reasoning.

#### SEC-004 — Enforce default-offline provider egress and residency policy

**User story:** As a local Brain owner, AgentMemory stays offline by default and eligible data reaches only the exact embedding/reranking destinations I approve.

**Acceptance criteria**

- The default Compose topology has no external route and AgentMemory-managed containers/post-Ready launcher operations produce no DNS/TCP/UDP packets over IPv4 or IPv6 during ingestion, extraction, indexing, recall, backup, restore, diagnostics, background update checks, telemetry, or adapter execution. Explicit foreground runtime/product acquisition is a separately consented setup window with its own source allowlist.
- Only explicitly enabled embedding/reranking operations may egress. Before activation the owner approves provider ID, exact HTTPS endpoint/region, model/revision, purposes, allowed classes, retention/training declaration, credential reference, quota, and budget.
- `restricted`, `local_only`, private, or secret-bearing data is never eligible. Repository configuration can only narrow an approved route.
- Provider redirects, DNS changes, alternate ports, metadata/link-local/loopback/unapproved private addresses, IPv6 bypass, direct sockets, and proxy bypass cannot escape the allowlist.
- Provider unavailability durably queues embedding work and skips/degrades reranking without blocking capture or healthy retrieval channels.

**Technical approach**

- `remote-providers` creates the default-deny `provider-gateway`; it alone attaches to `am_egress`. Gateway policy admits exact CONNECT/host/port rules, validates DNS/IP on every connection, disables or reauthorizes redirects, verifies TLS, applies byte/time/rate limits, and writes a content-free decision audit.
- EgressAuthorizationPort executes immediately before socket acquisition using immutable taint, Brain/project, provider, endpoint, region, model, purpose, retention declaration, and policy version. Denial destroys the operation payload buffer.
- Core, bridge, local provider, extraction, Neo4j, telemetry, and custom-adapter containers have no direct egress path. A custom remote embedding/reranking adapter talks to the gateway over `am_internal`; it cannot accept inbound remote traffic.
- RuntimeEndpointPolicy proves every AgentMemory container is created by the explicit local Linux engine endpoint and rejects Docker Offload/cloud, remote contexts/daemons, Windows-container mode, or an unauthenticated TCP daemon before any Brain volume or project mount is attached.
- The runtime egress operation allowlist contains no analytics, telemetry export, crash upload, license check, arbitrary webhook, remote extraction, or model download.

**Mandatory tests:** 24-hour default-profile process/container-attributed packet capture across DNS/TCP/UDP and IPv4/IPv6; Docker Offload/remote context/remote daemon/Windows-container/TCP-daemon rejection; explicit setup-window source allowlist; exact allowed endpoint success; second host/alternate port/CNAME-IP drift/redirect/DNS rebinding/metadata-link-local-private IP/direct socket/proxy/QUIC bypass; policy matrix; mixed-class batch; secret canary; repository weakening; provider outage/recovery; restored system stays offline until reauthorization.

**Why:** Policy plus network enforcement assumes routing/adapters can fail.

#### SEC-005 — Resist prompt injection and memory poisoning

**User story:** As a developer, malicious stored content cannot control an agent or promote false learning.

**Acceptance criteria**

- Repository/memory text requesting policy, permissions, self-promotion, or tool authority remains untrusted data.
- It cannot become an active assertion/procedure without independent evidence and governed approval.
- Provenance spoofing and circular evidence are rejected.

**Technical approach**

- Taint metadata follows content into chunks, memories, embeddings, and context.
- Output rendering separates untrusted data; EvidencePolicy and ControlledSurfacePolicy run outside all LLM calls.
- EvidenceLineageGraph verifies signed adapter origin, root event IDs, and hashes.

**Mandatory tests:** stored injection corpus; self-approval; fake citations; circular summaries; delimiter escape; cross-agent delivery.

**Why:** Memory persistence amplifies attacks, so authority and data must remain separate at every stage.

#### SEC-006 — Secure runtime installers, executable adapters, and upgrades

**User story:** As an administrator, only trusted, least-privileged code packages execute.

**Acceptance criteria**

- Missing/invalid native publisher/package signature, release/catalog digest, SBOM, protocol, terms receipt, license, vulnerability policy, closed privilege plan, or excessive permissions blocks runtime, product, or adapter install.
- Approved adapters run isolated and upgrades show permission/contract diff for approval.
- Rollback restores the previous signed package/config.

**Technical approach**

- PackageTrustPolicy verifies local Sigstore/Cosign signature bundle and immutable digest against pinned trust roots and transparency inclusion evidence without requiring online verification. RuntimeArtifactTrustPolicy additionally verifies the signed prerequisite catalog, URL allowlist, native notarization/Authenticode/package signature, exact publisher/key, anti-rollback sequence, platform, and plan-bound privilege receipt before execution.
- AdapterInstall aggregate stores package metadata and approved capability/permission set.
- Supervisor mounts read-only package, ephemeral scratch, resource limits, and network policy.

**Mandatory tests:** catalog/native-publisher/package/signature/digest/SBOM tamper; redirect/MITM/rollback; privilege plan/nonce/IPC replay; terms mismatch; permission escalation; vulnerable/disallowed license; sandbox escape; runtime/adapter/product upgrade and rollback.

**Why:** Extensible executable code is a supply-chain boundary, not ordinary configuration.

#### SEC-007 — Maintain tamper-evident audit history

**User story:** As an auditor, I can detect alteration and reconstruct governed actions.

**Acceptance criteria**

- Required actions append actor/scope/policy/before-after/outcome facts before success is returned.
- Chain/hash/signature verification detects insertion, deletion, reorder, or modification.
- Audit access/export is separately authorized and content-safe.

**Technical approach**

- AuditRepository participates in the same Unit of Work for governed SQL mutations; graph-only projections reference the canonical audit event.
- Hash-chain canonicalization is versioned; the local checkpoint signer creates Merkle roots in the separate append-only audit/deletion-journal path and encrypted backup.
- VerifyAuditChainQuery streams verification with bounded memory and signed result.

**Mandatory tests:** tamper types; transaction rollback; signer outage fail-closed; key rotation; authorized export; content/secret scan.

**Why:** Signed checkpoints make unprivileged or accidental history alteration detectable while documenting that a privileged host owner remains outside the protection boundary.

#### SEC-008 — Delete comprehensively and prevent resurrection

**User story:** As an authorized user, deleted data immediately stops influencing the Brain and is purged from every derivative.

**Acceptance criteria**

- Tombstone commit immediately excludes target from recall/search/replay/export/jobs.
- Graph, text, vectors, blobs, cache, queue, provider artifacts, learning descendants, and evaluation fixtures purge idempotently.
- Restore/rebuild/replay cannot recreate content; legal hold behavior is explicit.

**Technical approach**

- RequestDeletionCommand creates Deletion aggregate/tombstone and dependency manifest.
- Purge handlers implement one store-specific DeletionPort and issue signed non-content receipts.
- RestoreGuard applies tombstones before activation; projection builders check tombstone bloom/index plus authoritative lookup.

**Mandatory tests:** every target type/store; nested descendants; concurrent recall/job; provider unsupported deletion; legal hold; backup restore; replay.

**Why:** Immediate deny plus asynchronous verified purge reconciles user control with multiple local canonical/projection stores and optional provider artifacts.

#### SEC-009 — Govern cross-Brain transfer and controlled surfaces

**User story:** As an administrator, trust boundaries and core policy cannot be weakened by local config, learning, or transfer.

**Acceptance criteria**

- Cross-Brain export/import requires explicit source/destination authorization, classification/egress approval, redaction, and signed manifest.
- Imported grants/policies never broaden destination authority automatically.
- Learned/repository configuration cannot alter auth, privacy, retention, egress, approval, provider, evaluator, adapter, or security policy.

**Technical approach**

- TransferBrainDataCommand is a governed two-party operation with immutable TransferPlan and destination mapping.
- PolicyLattice computes effective policy as at least as restrictive when merging; conflicts block.
- ControlledSurfacePolicy applies to every configuration/procedure mutation path, not just learning.

**Mandatory tests:** source/destination role matrix; policy conflict; grant escalation; malicious archive; controlled surface variants; audit.

**Why:** Brain is a trust boundary, so moving knowledge is a security operation rather than a file copy.

### 11.13 Epic OPS — Local operations, reliability, and recovery

#### OPS-001 — Operate and uninstall the local Compose installation safely

**User story:** As a local owner, I can start, stop, restart, inspect, reinstall, or uninstall AgentMemory without operating Docker or touching unrelated local resources.

**Acceptance criteria**

- Signed launchers and multi-architecture images execute the same critical flows on the supported macOS, Linux, and Windows matrix whether the runtime was pre-existing or AgentMemory-provisioned; launcher start after sleep/reboot starts the selected local runtime when necessary, and start/stop/restart preserve all named-volume state.
- Every rendered profile publishes only the authenticated loopback API/UI, exposes no Neo4j/MCP/provider port, and gives only `provider-gateway` an optional external route.
- Start, repair, inspect, reinstall, upgrade, and uninstall are available through the agent-host integration or accessible launcher-served local setup surface; CLI commands are equivalent expert automation and are never the sole user path.
- `agentmemory uninstall --keep-data` is the default and removes only installation containers/networks while preserving labelled volumes, config, credentials, backups, and a tested reinstall path.
- `--purge` requires exact installation/Brain confirmation, handles tracked remote-provider artifacts, stops sessions, destroys the installation encryption root, and removes only installation-labelled volumes/secrets/config/backups. Image removal is a separate flag; global prune commands are forbidden.
- Default uninstall preserves Docker Desktop/Engine, WSL, virtualization features, package repositories, groups, and shared OS settings regardless of runtime ownership. A separate `RemoveManagedRuntime` operation is available only when `RuntimeOwnershipRecord` proves AgentMemory provisioned it and a complete scan finds no unrelated container, image, volume, network, context, Compose project, or active client; uncertainty refuses removal.
- Interrupted start/stop/uninstall resumes from an operation journal and reports every remaining resource.

**Technical approach**

- Implement launcher `StartInstallation`, `StopInstallation`, `RestartInstallation`, `InspectInstallation`, `UninstallInstallation`, and `RemoveManagedRuntime` applications through typed ContainerRuntimeController, DockerProcessPort, InstallationResourceInventoryPort, and RuntimeOwnershipRepository. Runtime removal requires its own plan digest and second impact-specific consent; it is never an implicit flag of product purge.
- `ComposeProfile` is validated against the signed release schema and policy before rendering. It may select local models, observability, or remote-provider gateway but cannot add images, mounts, ports, capabilities, networks, or services outside the signed manifest.
- Every resource carries installation/release/generation/purpose labels. Deletion enumerates and matches these labels plus the persisted resource inventory; it never infers targets from broad name prefixes alone.
- Graceful stop rejects new sessions, marks forced sessions interrupted, drains to the deadline, checkpoints leases/WAL, and stops in dependency order. Docker restart policy recovers services only after the local runtime is available; every MCP/launcher entry first starts and capability-probes the selected Docker Desktop/Engine endpoint without changing the global context.

**Mandatory tests:** runtime stopped/Desktop closed/start/stop/restart/reboot matrix; certified ARM/x86 manifests; pre-existing versus managed runtime ownership; rendered-profile policy; LAN/unrelated-container/IPv4/IPv6 scans; keep-data reinstall exact recovery; purge confirmation/cancel/interruption; unrelated labelled/unlabelled Docker/OS resources survive; managed-runtime removal consent/dependency refusal; remote-artifact partial failure; cryptographic erasure; no global prune or implicit runtime uninstall invocation.

**Why:** A label-scoped, journaled launcher makes Docker portability safe without turning uninstall into a destructive host cleanup tool.

#### OPS-002 — Meet local durability, latency, and freshness SLOs

**User story:** As a local user, product durability and performance are measurable and predictable on published hardware/corpus profiles.

**Acceptance criteria**

- Published local profiles meet acknowledgment durability, hook latency, warm recall, index freshness, disk-growth, backup, restore, and recovery objectives.
- SLI calculations identify active release/data generation/hardware/corpus, exclude only explicit maintenance, and never hide degraded channels or queued work.
- Regression-budget exhaustion blocks release/upgrade recommendation until corrected.

**Technical approach**

- Implement SliRecorder at application boundaries, not only HTTP middleware.
- Synthetic local monitors execute append → SQLite commit → projection → cross-agent recall plus Brain-isolation and deletion probes.
- RegressionBudgetPolicy integrates release qualification and produces auditable freeze/unfreeze decisions.

**Mandatory tests:** local hardware/corpus load profiles; SLI math; clock gaps; synthetic end-to-end; Brain canary; regression freeze; telemetry outage; degraded-channel visibility.

**Why:** Boundary-level SLIs measure user outcomes rather than infrastructure availability alone.

#### OPS-003 — Diagnose production behavior safely

**User story:** As an operator, I can locate failures without exposing user content.

**Acceptance criteria**

- Correlated logs/traces/metrics identify request, event, job, projection, provider, and result stage using safe IDs.
- Diagnostics bundle contains configuration hashes, versions, health, queues, indexes, migrations, resource data, and redacted recent errors, never content/secrets/vectors.
- Bundle generation and access are audited.

**Technical approach**

- DiagnosticBundleCommand gathers through DiagnosticContributor ports with a strict allowlist schema.
- DLP/secret scan executes before encryption; bundle is encrypted to operator-provided public key or protected local file.
- Trace context propagates through SQLite outbox/jobs and provider protocol; new roots link to the originating trace without content.

**Mandatory tests:** correlation E2E; secret/content seeded scan; unauthorized bundle; huge logs; unavailable contributor; decrypt/expiry.

**Why:** Allowlisted diagnostics are safer and more supportable than copying raw logs/databases.

#### OPS-004 — Create and restore verified local recovery points

**User story:** As a local owner, I can recover a Brain from a signed encrypted archive within the published local RPO/RTO.

**Acceptance criteria**

- Backup writes only to a user-selected local/removable path, contains no credential values, and binds SQLite, CAS, graph dump/rebuild plan, generations, grants, audit checkpoints, and deletion journal at compatible watermarks.
- Restore targets a new egress-disabled Compose project/data generation, validates signature/AEAD/digests/BOM/schema, applies the newest deletion journal, rebuilds/verifies projections, and remains isolated until acceptance checks and explicit activation pass.
- A recovery point older than a deletion cannot expose that content; missing or unverifiable latest deletion-journal proof fails closed.

**Technical approach**

- `StartBackupCommand` acquires the maintenance lock, blocks new governed mutations, records/drains job watermarks, invokes SQLite online backup, writes CAS/config-with-secret-refs/audit/deletion data, and runs a compatible Neo4j dump or records a complete rebuild manifest. A unique backup DEK encrypts before destination write; a final signed manifest is the only completion marker.
- `RestoreBrainCommand` creates new installation-labelled volumes/project, never overwrites an active/last-known-good generation, and cannot attach `am_egress`. It applies deletion/access revocations before opening query access and performs no provider calls.
- `RestoreValidation` runs archive crypto/integrity, SQLite `integrity_check`, count/hash/watermark, audit chain, graph/assertion/vector-generation, Brain isolation, deleted-data absence, and golden recall. Activation atomically changes the active-generation pointer after owner approval.

**Mandatory tests:** scheduled/manual full backup; concurrent-ingest maintenance boundary; kill every backup phase; corrupt/missing/swapped part; altered manifest; wrong/rotated key; disk full/permission; secret scan; restore from every supported version; old backup plus newer tombstone; missing journal; graph rebuild; incompatible BOM/schema; egress absence; reference RPO/RTO; quarterly drill.

**Why:** An isolated manifest-coordinated restore proves local recovery and deletion safety before the owner activates it.

#### OPS-005 — Upgrade and roll back without data loss

**User story:** As a local owner, I can upgrade signed Compose releases in a maintenance window and recover from failure without data loss.

**Acceptance criteria**

- Preflight validates release/image/launcher signatures, SBOM/provenance, compatibility, free space, verified backup, migration plan, active sessions, and dependency health.
- Upgrade drains or explicitly interrupts sessions, blocks new sessions/mutations, preserves all acknowledged events, and runs resumable checksummed migrations against a new data generation when backward readability is not guaranteed.
- The active release/data-generation pointer changes only after the new exact image digests pass readiness, integrity, deletion, MCP, provider-policy, and golden-recall probes.
- Failure selects the prior signed images when schema-compatible or restores the pre-upgrade archive into new volumes; it never blindly downgrades a database or overwrites the last-known-good generation.

**Technical approach**

- `UpgradePlan` records from/to BOM and digests, migration checksums, active sessions, maintenance state, backup, source/target data generations, probes, commit pointer, and compensation. The launcher journals host-side phases; `UpgradeOperation` mirrors governed application phases in SQLite.
- Exact order is lock → prevent sessions → drain/interrupt → verify release → verify backup/free space → pull/load digests → allocate generation if needed → one-shot resumable migration → start target Compose → run probes → atomically commit pointers → retain rollback generation.
- Expand/migrate/contract is used when it simplifies compatibility, but there is no mixed-version cluster. Provider egress is disabled throughout migration/restore and requires post-recovery authorization.

**Mandatory tests:** every supported prior version; interruption at every phase; active session drain/force; old/new generation isolation; invalid signature/SBOM/provenance; low disk; migration checksum mismatch; failed health/integrity/golden probe; image rollback; archive restore rollback; pointer atomicity; no acknowledged-event loss.

**Why:** A persisted maintenance transaction separates safe software rollback from unsafe in-place database downgrade.

#### OPS-006 — Plan capacity from repeatable benchmarks

**User story:** As an administrator, I can size compute, memory, storage, queues, graph, and provider budgets.

**Acceptance criteria**

- Published local hardware/corpus profiles cover small/large/polyglot/multilingual/highly connected repositories and concurrent agents.
- Results report ingestion, indexing, graph/vector size, recall latency, migration time, provider usage/cost, and local-model resources.
- Regression beyond approved threshold blocks release or requires capacity-note approval.

**Technical approach**

- Version benchmark corpora and harness configuration; generated corpora supplement but do not replace representative anonymized cases.
- BenchmarkResult includes hardware/software/BOM, warm/cold state, percentiles, errors, and raw artifact refs.
- Capacity model is derived from measured coefficients with confidence bounds and validated on holdout sizes.

**Mandatory tests:** harness reproducibility; clean/warm runs; scale curves; regression comparison; resource exhaustion.

**Why:** Published repeatable measurements turn deployment sizing into an engineering contract.

#### OPS-007 — Recover from setup, local component, storage, and provider incidents

**User story:** As a local owner, I can resume or repair installation/runtime, process/container, host, SQLite, graph, model, provider, disk, backup, and upgrade failures without diagnosing Docker.

**Acceptance criteria**

- Acknowledged canonical events survive supported process/container/Docker/host restarts; disk/machine loss is bounded by the latest verified local backup, and queued projections catch up idempotently.
- Available retrieval channels continue with explicit degradation.
- Repair/recovery ends with integrity verification and audited incident actions.
- Runtime setup recovery preserves consent boundaries, existing software and workloads, resumes only verified phases, and never exposes a partial AgentMemory endpoint.

**Technical approach**

- Define typed launcher RecoveryApplications for runtime artifact/download verification, elevation denial, package/vendor partial install, WSL/rootless prerequisite, reboot continuation, daemon start/repair, and ownership conflict, plus core RecoveryCommand/runbooks for worker restart, host reboot/power loss, SQLite busy/WAL/corruption, Neo4j outage/corrupt projection, local model OOM/crash, provider/DNS/network outage, disk 80/95/100%, corrupt backup, and failed upgrade; no generic “retry everything.”
- Compose restarts persistent services, durable leases expire safely, and inbox/idempotency keys suppress duplicate effective work. Neo4j projection loss rebuilds from SQLite/CAS; canonical SQLite corruption enters read-only recovery and requires a verified backup.
- Post-recovery verifier checks SQLite integrity, event/outbox/inbox/job watermarks, duplicate side effects, graph/assertions, vector generations, Brain authorization canary, audit chain, deletion queue/guard, and provider ambiguity/billing state.

**Mandatory tests:** kill/network/power-loss at every runtime-download/verification/elevation/prerequisite/vendor-install/reboot/service-probe transition and at receive/commit/ACK/lease/provider send-response/graph-vector/audit/deletion boundaries; partial runtime repair; consent/elevation/MDM block; malicious resume; existing-workload preservation; stale lease; retry storm; ambiguous provider completion; graph outage/corruption/rebuild; provider outage/catch-up; DNS loss; disk thresholds/full; WAL corruption; host reboot; OOM; graceful-stop timeout; failed runtime/product upgrade/restore game day.

**Why:** Failure-specific recovery avoids turning canonical replay into uncontrolled duplicate side effects.

### 11.14 Epic EVA — Evaluation and release quality

#### EVA-001 — Maintain a versioned retrieval and learning corpus

**User story:** As a quality engineer, I can measure product behavior against representative private cases.

**Acceptance criteria**

- Corpus covers continuity, rationale, exact code, topology, temporal truth, contradiction, abstention, multilingual/polyglot, learning, privacy, auth, deletion, and prompt injection.
- Training/development cases and hidden holdouts have separate access.
- Each case has provenance, expected evidence/path/answer class, scope, time, and review history.

**Technical approach**

- EvalCase schema and dataset manifest are immutable/content-addressed; revisions create new versions.
- Sensitive corpus is encrypted with evaluator-only grants and never sent to unapproved providers.
- Corpus balancing report tracks domains, languages, difficulty, no-answer, and adversarial categories.

**Mandatory tests:** schema; duplicate/leak detection; access isolation; manifest signature; expected-evidence validity; sampling reproducibility.

**Why:** A governed corpus is necessary for comparable retrieval/provider/learning decisions.

#### EVA-002 — Gate releases on calibrated metrics

**User story:** As a release manager, quality regressions cannot ship unnoticed.

**Acceptance criteria**

- Release evaluation computes PRD metrics with confidence intervals and compares approved thresholds/baseline.
- Any zero-tolerance result fails immediately; noncritical regression follows documented budget/approval policy.
- Metric implementation/version and raw case outcomes are reproducible.

**Technical approach**

- EvaluationMetricPort functions are pure/versioned and consume case outcomes.
- ReleaseQualityPolicy stores metric direction, absolute floor, relative regression, minimum sample, confidence method, and criticality.
- Signed EvaluationReport binds build digest, datasets, providers, configs, seeds, and results.

**Mandatory tests:** metric golden math; missing/duplicate cases; confidence boundaries; threshold table; tampered report; baseline comparison.

**Why:** Versioned thresholds and signed inputs prevent cherry-picked release claims.

#### EVA-003 — Certify agent adapters

**User story:** As an adapter author, I can prove lifecycle behavior is compatible before certification.

**Acceptance criteria**

- Schema, lifecycle/capabilities, ordering, cancellation, offline recovery, deduplication, redaction, failure isolation, context injection, signed native-bootstrapper delivery, first-MCP status mode, native setup launch, reboot reconnect, and Ready handoff pass.
- Certification binds exact adapter version/digest and supported host version range.
- Host changes outside the certified range suspend certification until retest.

**Technical approach**

- AgentHostSimulator drives canonical scenarios and observes adapter outputs/latency/spool behavior. HostChannelHarness begins with no AgentMemory and no Docker, enforces the host MCP deadline, exercises the native setup/reboot channel, and proves automatic tool-list activation.
- CertificationRecord stores conformance suite/dataset version, platform/host versions, result digest, and expiry.
- Runtime status exposes certified/uncertified/degraded without blocking explicitly allowed experimental adapters in isolated mode.

**Mandatory tests:** every built-in; marketplace/post-install and first-invocation paths; pristine no-runtime host; native execution prohibited; MCP timeout/stdout purity; consent UI; reboot reconnect; Ready handoff; host-version boundary; tampered launcher digest; capability gaps; latency; cross-host matrix.

**Why:** Certification converts “supports host X” into a reproducible compatibility claim.

#### EVA-004 — Certify and compare provider adapters fairly

**User story:** As an administrator, built-in and custom providers meet identical semantic/safety contracts and can be compared fairly.

**Acceptance criteria**

- Manifest/probe, purpose, dimension/order/numeric, batching, limits, cancellation, errors, privacy, drift, and isolation pass conformance.
- Bake-offs use the same authorized corpus, chunking, index coverage, retrieval pipeline, and scoring.
- Cost/latency/quality reports identify model revision and confidence; raw incompatible scores are not compared.

**Technical approach**

- ProviderConformanceHarness uses adversarial deterministic provider fixtures plus approved live run.
- ProviderBakeoffPlan freezes corpus, preprocessing, query set, fusion, k, reranking policy, and budget.
- Results create no active route/generation until separate administrative decision.

**Mandatory tests:** adversarial stubs; live built-ins nightly; fair-input digest; privacy route; cost reconciliation; repeatability.

**Why:** Fixed experimental conditions make provider choice evidence-based rather than marketing-based.

#### EVA-005 — Verify parsers, migrations, and platform compatibility

**User story:** As a release engineer, supported languages, stores, schemas, and environments remain compatible.

**Acceptance criteria**

- Every declared parser/language version passes symbol/relationship/incremental fixtures.
- Every supported upgrade path and API/MCP/event/SDK window passes.
- Every supported OS/architecture starts from pristine stock images both without Docker/Compose/WSL and with each compatible existing Docker/Desktop/Engine state, then installs and runs critical flows from applicable online and legally complete offline bundles.

**Technical approach**

- Maintain `contracts/pf001/support-matrix-v1.json` and its JSON Schema with owner/status/min/max versions, official stock-image/reset authority, filesystem, runtime-present/absent state, privilege/reboot expectations, vendor channel stability, offline redistribution status, agent-host set, and exact scenario/variant/evidence suite. Semantic validation in `tools/check_pf001_certification` is stricter than the interchange schema and is authoritative.
- CI generates required matrix jobs from the exact reviewed bytes; a declared supported cell or trial cannot be manually skipped. The signed report binds matrix, publication, source, distribution-manifest, release-trust, image, hardware, filesystem, unique snapshot, times, and every evidence digest/size.
- Removing support requires deprecation window, telemetry evidence, migration/export path, and major release where public.

**Mandatory tests:** generated matrix completeness; pristine no-runtime and existing-runtime cell; terms/elevation/reboot variants; pre-GA channel rejection; skip detection; old/new contracts; parser grammar digest; installation.

**Why:** A single executable support matrix prevents documentation and CI from diverging.

#### EVA-006 — Enforce zero-tolerance gates

**User story:** As a security owner, critical integrity violations can never be waived into a release.

**Acceptance criteria**

- Any cross-Brain leak, post-deletion recall, unsupported active fact, mixed vector space, secret telemetry, self-validated active procedure, or autonomous controlled-surface change fails release.
- Any non-loopback product listener, execution through Docker Offload/cloud or a remote daemon/context, Windows-container execution, direct Internet route from a core/local-model/bridge/custom-adapter service, packet attributable to an AgentMemory-managed container or post-Ready launcher operation in the default egress-disabled profile, unauthorized provider operation/destination, restricted/local-only/private/secret egress, unsigned or tag-only executable image/adapter/runtime installer, unverifiable SBOM/provenance/publisher, lost acknowledged event, duplicate effective mutation, or deletion resurrection after restore fails release.
- Only a new passing build can clear the failure; no manual override exists.
- Failure evidence is retained securely for incident analysis.

**Technical approach**

- ZeroToleranceSuite is a separate required CI/release environment with protected configuration and security CODEOWNER.
- Release controller consumes signed suite result and has no waiver code path.
- Findings create security incident records and block artifact promotion digest.

**Mandatory tests:** intentionally vulnerable fixtures proving every semantic, listener, route, packet, egress, secret, image, provenance, durability, duplication, and restore detector; result tampering; skipped job; stale result/build digest; incident redaction.

**Why:** Removing the override path makes the product’s hardest safety promises enforceable.

#### EVA-007 — Validate resilience under realistic scale and faults

**User story:** As an operator, a release is proven under sustained load, failure, migration, replay, backup, and rollback.

**Acceptance criteria**

- Load/soak/chaos/live migration/local-job replay/backup restore/recovery/rollback meet SLO/RPO/RTO and integrity.
- No duplicate effective state, privacy leak, unbounded resource growth, or undeleted residue occurs.
- Results bind the exact release artifact and environment.

**Technical approach**

- ResiliencePlan specifies workload/fault timeline, invariants, thresholds, cleanup, and seed.
- FaultController injects failures at named architecture boundaries while invariant monitors run continuously.
- Post-run audit compares canonical/projection watermarks, duplicates, graph integrity, vector space, Brain canaries, network/volume/container cleanup, and resource leaks.

**Mandatory tests:** 24-hour release soak; boundary kill matrix; degraded provider; disk/network partitions; live generation cutover; restore/rollback.

**Why:** Correctness during faults cannot be inferred from unit coverage or a short happy-path run.

## 12. Story traceability

| PRD area | Primary stories |
|---|---|
| Product principles and architecture | PF-001–PF-006, SEC-001–SEC-009, OPS-001–OPS-007 |
| Agent integration | PF-005–PF-006, ADP-001–ADP-006, INT-001–INT-004, EVA-003 |
| Brain/project/repository identity | ID-001–ID-004 |
| Durable ingestion | ING-001–ING-006 |
| Memory system | MEM-001–MEM-006 |
| Evidence-gated self-improvement | LRN-001–LRN-011 |
| Neo4j knowledge graph | GRA-001–GRA-006 |
| Code and architecture indexing | IDX-001–IDX-007 |
| Provider platform | PRO-001–PRO-010, EVA-004 |
| Retrieval and context delivery | RET-001–RET-007 |
| Interfaces and management UX | INT-001–INT-007 |
| Security/privacy/governance | SEC-001–SEC-009, EVA-006 |
| Deployment and operations | PF-001, PF-006, OPS-001–OPS-007, EVA-007 |
| Evaluation and quality | EVA-001–EVA-007 |

There are 99 required stories: 6 PF, 4 ID, 6 ADP, 6 ING, 6 MEM, 6 GRA, 7 IDX, 10 PRO, 7 RET, 7 INT, 11 LRN, 9 SEC, 7 OPS, and 7 EVA. A backlog tool may split a story into implementation tasks, but it MUST preserve the parent acceptance and technical contract. New product behavior requires a new story or an explicit revision to an existing story; it cannot hide in a technical task.

## 13. Required ADRs before implementation begins

The following ADRs record the chosen implementation, not reopen product scope:

1. ADR-001 — Clean Architecture boundaries, bounded contexts, and Import Linter contracts.
2. ADR-002 — Canonical SQL state, Neo4j projection ownership, and outbox/inbox consistency.
3. ADR-003 — Packaged SQLite durability, single-writer ownership, local outbox/job leasing, online backup, and volume constraints.
4. ADR-004 — Neo4j Community 2026/Cypher 25 support cadence, multi-Brain record scoping in one local database, and filtered vector authorization.
5. ADR-005 — AgentEvent/event versioning and ordering semantics.
6. ADR-006 — Identity fingerprints for Git/non-Git, clones, forks, worktrees, and device identity.
7. ADR-007 — Embedding-space fingerprint, generated index naming, and migration state machine.
8. ADR-008 — Local provider sidecar protocol, signature trust roots, sandbox controls, and gateway-only remote embedding/reranking egress.
9. ADR-009 — Local OS-owner/installation/session identity, role/scope authorization, loopback/browser controls, and SQLite/Neo4j defense in depth.
10. ADR-010 — Local encryption envelope, host key materialization, key rotation, CAS layout, searchable-volume disk-encryption requirement, and secret resolution.
11. ADR-011 — Deletion dependency manifest, tombstone/restore guard, and provider deletion semantics.
12. ADR-012 — Retrieval fusion, graph traversal budgets, context budgets, and explanation trace.
13. ADR-013 — Learning evidence independence, promotion policy, evaluator isolation, canary, and rollback.
14. ADR-014 — Local-only OpenTelemetry privacy/cardinality/retention policy and performance-regression calculations.
15. ADR-015 — Local encrypted backup watermarks, deletion-journal continuity, reference RPO/RTO, isolated Compose restore, and activation.
16. ADR-016 — Image/launcher/offline-bundle signing, SBOM/provenance, supported-version window, and dependency update policy.
17. ADR-017 — Docker Compose topology, networks/volumes/profiles, host launcher, transient MCP bridge, path identity, startup locking, upgrade generations, and scoped uninstall.
18. ADR-018 — Automatic Docker Desktop/Engine provisioning, stable platform channels, runtime prerequisite manifest, native terms/elevation/setup UX, WSL/rootless configuration, reboot resume, existing-runtime adoption, ownership, repair, upgrade, and separate runtime removal.

An ADR MUST contain context, decision, alternatives, consequences, security/privacy impact, migration, rollback, validation, owner, and review date. An ADR cannot waive a MUST in this specification; changing a MUST requires changing this specification with product/security approval.

## 14. Normative configuration defaults

The following defaults eliminate developer guesswork. Administrators may tune values within validated safe ranges; changing a security minimum requires specification revision.

| Setting | Default |
|---|---|
| local hook deadline | 250 ms hard deadline; 50 ms p95 objective |
| REST request body | 1 MiB except explicit streaming/batch routes |
| event inline payload | 64 KiB; larger content uses encrypted blob |
| event batch | 100 events or 1 MiB, whichever comes first |
| interactive recall deadline | 2 s on the local reference profile |
| exact/lexical/vector channel deadline | 500/750/900 ms within caller budget |
| graph expansion | depth 3, 500 nodes, 1,000 edges, 250 ms unless explicit authorized query |
| recall candidates | 50 per channel before fusion; final default 12 |
| context disclosure | brief by default; explicit request for evidence/source |
| provider retry | maximum 3 attempts, exponential full jitter, bounded by deadline |
| job retry | maximum 8 attempts over 24 hours unless job-specific policy |
| circuit breaker | open after 5 qualifying failures in 30 seconds; probe after 30 seconds |
| local spool soft/hard | 80%/95% configured capacity |
| data-volume soft/hard | 80% warning/background throttle; 95% safe capture rejection before ACK |
| job lease | 60 seconds with heartbeat at 20 seconds |
| MCP session lease | 30-second heartbeat; interrupted after 120 seconds missing; token maximum 12 hours and revoked on close |
| bootstrap MCP initialization | p95 below 2 seconds and always within the certified host deadline; long setup continues behind status tools |
| setup surface | host surface or local browser opens within 3 seconds; progress heartbeat at least every second; stalled transfer detected within 30 seconds |
| Compose startup wait | 300 seconds on first model load, 120 seconds otherwise; dependency health is required, not merely running state |
| container runtime bootstrap | automatic on absence; certified stable vendor channel only; exact signed catalog entry and official source; no `latest`, convenience script, or manual command |
| setup consent | non-preselected and bound to exact runtime install-plan plus terms digests; material plan or terms change requires new consent |
| reboot continuation | one-use, same user/machine/operation, 24-hour expiry, no secret, atomically consumed and removed on terminal state |
| runtime ownership | preserve by default; removal is a separate confirmed operation allowed only for provably AgentMemory-provisioned and otherwise-unused runtime |
| local API/UI | port 9411 on `127.0.0.1` and `::1` where supported; persisted alternative chosen only on collision |
| runtime egress | disabled; `remote-providers` requires explicit owner activation and exact destination policy |
| minimum local resources | 4 CPU cores, 16 GiB host RAM with at least 12 GiB available to Docker, 30 GiB free local SSD; installer blocks below this certified floor |
| reference local resources | 8 cores, 32 GiB host RAM with at least 24 GiB available to Docker, 100 GiB free local NVMe before corpus growth |
| audit checkpoint | every 10,000 events or 15 minutes |
| administrative idempotency record | 24 hours minimum; event IDs retained per event retention |
| API cursor expiry | 15 minutes and bound to principal/scope/query |
| stale cache | no serving after grant/deletion change; other caches report generation/freshness |
| canary procedure exposure | 5% eligible cohort and maximum 20 applications until policy expands |
| high-risk procedure | explicit two-person approval; no automatic promotion |
| deletion recall exclusion | synchronous with tombstone commit |
| backup schedule/retention | daily to owner-selected local path; daily 35 days, weekly 13 weeks, monthly 12 months unless stricter policy |
| flaky-test quarantine | maximum 7 days; never for zero-tolerance suites |

Provider item/token/byte limits come from validated profile attestation and MUST be lower than or equal to the provider’s published limits. RPO/RTO, recall, deletion purge completion, and rollback SLOs use the local reference values below; the implementation accepts no null/unbounded values.

### 14.1 Initial local capacity and recovery profile

These are initial release gates and may be improved without a breaking change. A weaker target requires product approval and specification revision. Other hardware/corpus combinations publish measured limits and must not be described as availability tiers.

| Profile | Hardware and corpus | Warm recall p95 | Restart RPO | Disk/machine backup RPO | Restore RTO |
|---|---|---:|---:|---:|---:|
| local reference | 8 physical/logical cores as reported, 32 GiB RAM, local NVMe; up to 1 million searchable units and 10 million graph relationships | 2 s | zero after successful SQLite FULL commit | 24 h with scheduled verified backup | 4 h from a verified recovery point |

A searchable unit is one independently retrievable memory, code/document chunk, symbol revision, or procedure revision. Recall measurement includes authorization, candidate retrieval, fusion, bounded graph expansion, and response assembly but excludes an optional caller-requested generative answer; the response reports generation separately.

Local backup defaults:

- coordinated SQLite online backup plus encrypted CAS/config/audit/deletion data and a Neo4j Community dump or complete rebuild plan;
- encrypted daily recovery points retained 35 days at the configured owner-local/removable destination;
- weekly points retained 13 weeks;
- monthly points retained 12 months where policy permits;
- quarterly automated full restore on the local reference corpus;
- deletion ledger and signed audit checkpoints retained for the policy period without deleted content.

Deletion and rollback targets:

- recall/search exclusion: synchronous at tombstone commit;
- caches, active SQLite/Neo4j/full-text/vector, jobs, and primary CAS blobs: p95 within 24 hours, maximum 72 hours;
- supported provider-side artifacts: request immediately and verify within the provider’s published maximum; otherwise surface PartialFailure;
- backups: purge at backup expiry, or cryptographic erasure within 24 hours when policy requires faster removal and key granularity permits;
- adverse learned procedure suspension: p95 under 60 seconds and maximum 5 minutes from verified adverse event;
- procedure rollback and context-cache invalidation: maximum 5 minutes;
- embedding-generation rollback after operator command: maximum 15 minutes.

Index freshness p95 below 30 seconds applies to the local reference profile under the published change/concurrency workload. Other measured profiles publish steady-state ingestion and backlog-recovery rates; they may not silently redefine freshness by ignoring queued files/tasks.

## 15. Implementation dependency order

This order minimizes rework; it does not create an MVP or make later scope optional. Features remain unreleasable behind disabled flags until their complete acceptance suite passes.

~~~mermaid
flowchart LR
    Standards["Architecture, contracts, CI, security skeleton"] --> Canonical["Identity, event ledger, outbox, audit, deletion guard"]
    Canonical --> Capture["Agent adapters and sessions/tasks"]
    Canonical --> Graph["Neo4j assertion/evidence projection"]
    Capture --> Memory["Memory consolidation"]
    Graph --> Index["Code and topology indexing"]
    Canonical --> Providers["Provider runtime and embedding spaces"]
    Memory --> Retrieval["Hybrid retrieval and briefings"]
    Index --> Retrieval
    Providers --> Retrieval
    Retrieval --> Interfaces["MCP, SDK, CLI, UI"]
    Memory --> Learning["Governed learning"]
    Retrieval --> Learning
    Learning --> Interfaces
    Standards --> Operations["Observability, backup, upgrade, security and evaluation"]
    Operations --> Release["Complete production release"]
    Interfaces --> Release
~~~

Required implementation waves:

1. **Engineering substrate:** repository layout, uv/pnpm locks, import boundaries, base contracts, typed errors, ID/time primitives, CI gates, signing/SBOM, runtime prerequisite catalog/trust and privilege/reboot contracts, pristine-OS test harnesses.
2. **Canonical local foundation:** installation/Brain identity aggregates/repositories, local authentication/grants, SQLite event ledger/outbox/inbox/jobs, audit chain, encrypted CAS, tombstone/restore guard.
3. **Capture and session model:** canonical AgentEvent, generic and certified adapters, offline spool, Session/Task/TaskContract/checkpoint lifecycle.
4. **Knowledge projection:** Neo4j schema/migrations, Assertion/Evidence/Contradiction, temporal projection, graph integrity/rebuild.
5. **Code intelligence:** snapshots, parser SDK, precise/structural language matrix, incremental invalidation, API/dependency/infrastructure topology.
6. **Provider platform:** signed sidecar protocol, built-ins, profiles/routes/probes, batching/retry, immutable embedding spaces, vector indexes, migrations.
7. **Memory and retrieval:** extraction/candidate policy, consolidation/correction/lifecycle, exact/lexical/vector/graph channels, fusion, context budgets, explanation/abstention.
8. **Interfaces and installation:** complete loopback REST/OpenAPI, bootstrap/status MCP, signed native runtime bootstrapper and setup UI, automatic Docker/WSL/rootless provisioning, consent/elevation/reboot/ownership lifecycle, steady-state MCP stdio/loopback HTTP launcher, transient workspace bridge, generated SDKs, containerized CLI, UI, accessibility, import/export.
9. **Governed improvement:** outcomes/mistake taxonomy, evidence lineage, hypotheses, procedures, evaluation, promotion, shadow/canary, monitoring/rollback.
10. **Production qualification:** full security/privacy/adversarial suite, default-offline packet soak, load/soak/chaos, local backup/isolated restore, maintenance upgrade/generation rollback, Docker/OS/architecture matrix, provider/agent certification, golden metrics, SLO/regression budgets.

No wave may defer its tests, migrations, authorization, deletion, audit, observability, docs, or rollback to a later “hardening” phase. Those are part of the implementing story.

## 16. Developer implementation checklist

For each assigned story, the developer follows this exact order:

1. Read the PRD section, story, referenced global requirements, existing ADRs, and public schemas.
2. Add story acceptance tests in tests/end_to_end or the appropriate contract suite and confirm they fail for the intended missing behavior.
3. Add domain unit/property tests for invariants and state transitions; implement the aggregate/value object/domain service minimally.
4. Add application tests with in-memory fakes; implement command/query handler, authorization, idempotency, UoW, events, and typed errors.
5. Define or extend the smallest capability-specific port. Do not add a generic repository or vendor type.
6. Add repository/protocol contract tests before the concrete SQL/Neo4j/provider/adapter implementation.
7. Implement infrastructure adapter with real integration tests, failure/cancellation/concurrency cases, migration, and replay behavior.
8. Add OpenAPI/MCP/CLI/UI translation and generated artifacts where the story exposes an interface.
9. Add privacy classification/egress/deletion propagation, audit event, logs/metrics/traces, dashboard/alert, and runbook.
10. Run format, lint, strict types, architecture, unit/property/contract/integration/E2E, coverage, mutation, security, and schema drift checks.
11. Measure applicable latency/throughput/resource SLI and document result.
12. Demonstrate rollback/restore and compatibility when data/contracts/configuration change.
13. Complete the Definition of Done and obtain CODEOWNER reviews.

If an implementation choice is genuinely not specified, the developer MUST stop that choice, draft an ADR with alternatives and evidence, and obtain the named owner decision. The developer may continue independent specified work. They MUST NOT silently choose a new database, queue, framework, state manager, provider abstraction, authorization model, test threshold, or security behavior.

## 17. Primary technical references

- [Python 3.14 documentation](https://docs.python.org/3/)
- [Go release history](https://go.dev/doc/devel/release)
- [uv projects and workspaces](https://docs.astral.sh/uv/concepts/projects/)
- [FastAPI release notes](https://fastapi.tiangolo.com/release-notes/)
- [Pydantic strict mode](https://docs.pydantic.dev/latest/concepts/strict_mode/)
- [SQLAlchemy 2.0](https://docs.sqlalchemy.org/en/20/)
- [Alembic](https://alembic.sqlalchemy.org/en/latest/)
- [SQLite WAL](https://www.sqlite.org/wal.html)
- [SQLite backup API](https://www.sqlite.org/backup.html)
- [Docker Compose installation](https://docs.docker.com/compose/install/)
- [Docker Desktop installation on macOS](https://docs.docker.com/desktop/setup/install/mac-install/)
- [Docker Desktop installation on Windows](https://docs.docker.com/desktop/setup/install/windows-install/)
- [Docker Engine installation](https://docs.docker.com/engine/install/)
- [Docker Desktop license agreement](https://docs.docker.com/subscription/desktop-license/)
- [Windows Subsystem for Linux installation](https://learn.microsoft.com/windows/wsl/install)
- [WinVerifyTrust](https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust)
- [Docker Compose startup order and health](https://docs.docker.com/compose/how-tos/startup-order/)
- [Docker Compose profiles](https://docs.docker.com/compose/how-tos/profiles/)
- [Docker storage and named volumes](https://docs.docker.com/engine/storage/volumes/)
- [Docker bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)
- [Docker bridge networking and port publishing](https://docs.docker.com/engine/network/drivers/bridge/)
- [Docker rootless mode](https://docs.docker.com/engine/security/rootless/)
- [Sigstore Cosign verification](https://docs.sigstore.dev/cosign/verifying/verify/)
- [Neo4j Operations Manual](https://neo4j.com/docs/operations-manual/current/)
- [Neo4j vector indexes and Cypher SEARCH](https://neo4j.com/docs/cypher-manual/current/indexes/semantic-indexes/vector-indexes/)
- [Neo4j Python Driver](https://neo4j.com/docs/python-manual/current/)
- [Qwen3 Embedding](https://huggingface.co/Qwen/Qwen3-Embedding-0.6B)
- [Qwen3 Reranker](https://huggingface.co/Qwen/Qwen3-Reranker-0.6B)
- [Qwen3 4B GGUF](https://huggingface.co/Qwen/Qwen3-4B-GGUF)
- [Model Context Protocol Python SDK](https://github.com/modelcontextprotocol/python-sdk)
- [Tree-sitter](https://tree-sitter.github.io/tree-sitter/)
- [OpenTelemetry Python](https://opentelemetry.io/docs/languages/python/)
- [Ruff linter and formatter](https://docs.astral.sh/ruff/)
- [mypy strict mode](https://mypy.readthedocs.io/en/stable/command_line.html#cmdoption-mypy-strict)
- [pytest](https://docs.pytest.org/en/stable/)
- [Coverage.py branch coverage](https://coverage.readthedocs.io/en/latest/branch.html)
- [Hypothesis](https://hypothesis.readthedocs.io/en/latest/)
- [Import Linter](https://import-linter.readthedocs.io/)
- [React versions](https://react.dev/versions)
- [TypeScript 6.0](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-6-0.html)
- [Vite releases](https://vite.dev/releases)
- [typescript-eslint typed linting](https://typescript-eslint.io/getting-started/typed-linting/)
- [Playwright](https://playwright.dev/docs/intro)
