# ADR-001: Clean Architecture, bounded contexts, and import contracts

- Status: Accepted
- Decision owners: Architecture Owner and Engineering Quality Owner
- Consulted owners: All bounded-context owners, Launcher, UI, Security
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before adding a bounded context, service, shared abstraction, or layer exception
- Supersedes: None
- Related requirements: Technical Requirements Sections 1, 2.3, 3, 8, 10, and 13

## Context

AgentMemory combines identity, ingestion, memory, graph, indexing, providers, retrieval, learning,
governance, and audit while remaining one local modular monolith. Framework/domain coupling or direct
cross-context persistence access would make authorization, deletion, replay, provider substitution,
and testing inconsistent. The Go launcher and React UI need equivalent enforceable boundaries.

## Decision

### System boundary

The product is a Python modular monolith in one persistent `core` container, one Neo4j projection
container, ephemeral MCP bridges, and constrained provider sidecars. Code package boundaries do not
create network services. SQLite has exactly one owning core process.

The required Python contexts are `identity`, `ingestion`, `sessions`, `memory`, `graph`, `indexing`,
`providers`, `retrieval`, `learning`, `governance`, and `audit`. Each owns its aggregates, ports,
persistence mapping, and public application API. `shared` contains only UUID/time, classification,
pagination, result/error, and event metadata value types.

### Python layers

Every context has `domain`, `application`, `adapters`, `infrastructure`, and `bootstrap.py`.

- `domain` imports only Python standard library and `agentmemory.shared` value types. It owns
  aggregates, immutable value objects, pure policies/services, domain events/errors, and repository/
  capability ports.
- `application` imports its domain, shared contracts, and another context's explicitly versioned
  public application facade only. It owns commands, queries, UoW orchestration, DTOs, and policies.
  It imports no FastAPI, MCP, SQLAlchemy, Neo4j, Docker, HTTP client, provider SDK, filesystem adapter,
  or environment-backed configuration.
- `adapters.inbound` translates REST/MCP/CLI/worker messages into application DTOs and maps typed
  errors once. `adapters.outbound` maps domain/application ports to protocol/persistence records.
  Adapters contain no state-transition, authorization, ranking, retention, or promotion decision.
- `infrastructure` constructs clients, pools, sessions, transaction managers, configuration, crypto/
  filesystem/process primitives, and concrete adapter instances. It may depend inward on port types
  but no inward layer imports it.
- `bootstrap.py` is the sole composition root for that runtime. It chooses concrete implementations
  and performs constructor injection. Ambient clients, mutable global registries, and service locators
  are prohibited.

Each context exposes cross-context synchronous operations only through
`agentmemory.<context>.application.public`. Cross-context facts use immutable schemas under
`contracts/events` and the SQL outbox. Imports of another context's `domain`, internal application
modules, adapters, infrastructure, persistence models, or repositories are prohibited. Public facade
cycles are prohibited; a cycle is split with an integration event or an orchestrating application
use case in the owning caller.

Commands change state inside one UoW and return ID/status DTOs. Queries do not mutate canonical state
and return immutable read DTOs. Workers invoke handlers, never repositories. A SQL-to-Neo4j action
commits SQL plus outbox first; no handler performs a distributed dual write.

Repositories are aggregate-specific and express domain queries. Generic CRUD repositories, Active
Record, ORM leakage, repository commits, and arbitrary SQL/Cypher query parameters are prohibited.
Optimistic concurrency is compare-and-swap on aggregate version.

### Import Linter contracts

Root `.importlinter` defines blocking contracts generated/checked for every context:

1. `domain_independence`: domain packages are independent siblings.
2. `context_independence`: context internals are independent; only `.application.public` and
   versioned contract packages are permitted cross-context imports.
3. `layers_<context>`: `bootstrap -> infrastructure/adapters -> application -> domain`, with shared
   contracts as the only side dependency.
4. `domain_forbidden`: forbid `pydantic`, `fastapi`, `sqlalchemy`, `neo4j`, `httpx`, `mcp`, Docker/
   provider SDKs, filesystem/config implementation packages, and every context adapter/infrastructure.
5. `application_forbidden`: forbid frameworks, database drivers/ORM, Docker, provider SDKs, concrete
   filesystem/network/process/configuration packages, and inbound adapters.
6. `no_cycles`: no package cycle among contexts or layers.
7. `composition_only`: infrastructure/concrete adapter selection is imported only by composition
   roots and infrastructure tests.

There are no blanket ignored imports. A narrow exception requires an ADR amendment naming exact
importer/imported modules, reason, owner, expiry, and removal test; it cannot waive a MUST.

### Domain and dependency rules

Domain entities are plain typed classes; value objects are frozen slotted dataclasses. Boundary DTOs
are strict Pydantic models and persistence records have explicit mappers. UUIDv7, injected UTC Clock,
RFC 3339 microsecond timestamps, Decimal confidence/cost, immutable domain events, and candidate status
for external/model content are mandatory.

SOLID is enforced as contracts: one handler/use case per reason to change, vendor additions through
ports rather than switches, every implementation passing the same contract suite, capability-specific
interfaces, and dependencies pointing inward. KISS limits are those in the technical requirements;
reflection-driven transactions, generated magic repositories, framework base entities, custom queue/
ORM/workflow/policy/crypto/vector database, and inheritance for reuse are rejected.

### Go launcher

`cmd/agentmemory` is the composition root. `internal/domain` owns only install/session/upgrade/
uninstall state and value types. `internal/application` owns use cases and narrow ports.
`internal/adapters` contains runtime, filesystem, trust, consent, privilege, reboot, setup, Docker,
agent-config, platform, and core-API implementations. `internal/contracts` contains generated DTOs only.

The domain/application standard-library allowlist is value packages such as `context`, `errors`,
`fmt`, `time`, `crypto/sha256`, and encoding needed for canonical values. A first-party import checker
rejects `os/exec`, filesystem mutation, network/HTTP, Docker SDK/CLI implementations, keychain/native
privilege APIs, unsafe, agent-config adapters, and outward launcher packages. Every host action uses a
typed port and argv/data, never a shell command.

### TypeScript UI

Dependency direction is app composition/routes -> feature presentation/hooks -> feature view models
-> shared primitives. Feature infrastructure consumes only the generated OpenAPI client. A feature
imports no other feature internal module; cross-feature composition uses public entrypoints at app
level. TanStack Query owns server state. Server authorization/policy is never duplicated in UI.
`dependency-cruiser` and ESLint enforce layers, feature independence, and acyclicity.

## Security and privacy impact

Mandatory `AuthorizedScope` parameters and governance application calls remain visible rather than
hidden in infrastructure. Separation prevents host, database, provider, and UI inputs from acquiring
domain authority. No exception may bypass Brain filters, deletion, egress, audit, or controlled-
learning rules. Architecture metadata contains no user content.

## Compatibility, migration, and rollback

Public facades and integration events are semantically versioned. Additive changes use compatible
schemas; breaking changes add a new major and an upcaster/parallel facade through the supported window.
Moving existing code across boundaries is source-only until public/persisted contracts change. A
boundary migration is staged with compatibility imports only in the composition layer, then removed
before release. Rollback retains the previous facade/event reader.

## Rejected alternatives

- Microservices per context: unnecessary local operational/distributed consistency cost.
- Framework-centric modules: couples business rules to transport/storage.
- Generic repository/service layer: erases aggregate and capability contracts.
- Shared business entities: creates hidden cross-context ownership.
- Direct cross-context tables/repositories: bypasses public policy and events.
- Service locator or globals: hides dependencies and prevents deterministic tests.
- Separate domain logic in launcher/UI: creates inconsistent security behavior.

## Consequences

Translation code and explicit ports add files, but changes remain local, tests use typed fakes, and
adapters/providers can be replaced without domain switches. Cross-context operations sometimes become
asynchronous, which is an intentional consistency boundary.

## Verification

- `lint-imports` passes all named contracts with no ignored imports.
- Architecture fixture tests intentionally introduce each forbidden import/cycle and prove CI fails.
- mypy strict and Ruff ALL pass; repository/UoW contract tests reject commits/ORM leakage.
- Go architecture checker, go vet, strict golangci-lint, race, fuzz, and mutation gates pass.
- TypeScript strict, ESLint, and dependency-cruiser reject feature/layer cycles.
- CODEOWNERS review checks constructor injection, one-use-case handlers, narrow ports, explicit mappers,
  and no duplicated domain policy.
