# ADR-009: Local identity, authorization, and loopback/browser controls

- Status: Accepted
- Decision owners: Governance Owner and Security Owner
- Consulted owners: Launcher, API/MCP, UI, Graph, Operations
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before identity, role, listener, browser-session, or credential changes
- Supersedes: None
- Related requirements: PRD Sections 5, 13, and 15; Technical Requirements Sections 4.6, 6.2, 11.9 RET-001, and 11.12 SEC-001

## Context

AgentMemory is local-only but loopback is not a trust boundary: hostile sites can target localhost,
other local users/containers exist, and MCP sessions must have less authority than the installation
owner. Neo4j Community does not provide per-Brain database isolation.

## Decision

### Installation, owner, and principal identity

Installation creates a random UUIDv7 `installation_id`, a 256-bit installation API credential, and an
Owner principal bound to the invoking OS account and ADR-006 device identity. Native account binding
uses immutable UID plus verified account identity on macOS/Linux and SID on Windows; username alone is
never identity. Owner transfer is an authenticated, audited recovery operation requiring current owner
or verified recovery proof and rotates all installation/browser/session credentials.

`LocalPrincipal` is installation-scoped UUIDv7 plus local subject type/value digest. Raw UID/SID data is
owner-protected and never provider/graph/metric content. Agent adapters, workers, gateways, and MCP
sessions receive separate service/session principals, never Owner credentials.

### Credential forms

- Installation API credential: opaque random 256 bits, stored in OS secret facility/owner-only source;
  core stores only a keyed verifier. It never enters URL, localStorage, Compose, environment, logs, or
  exports.
- MCP session credential: opaque random 256 bits, maximum 12 hours, bound server-side to installation,
  session/process, agent host, requested Brain/project capability, issued/expiry, and security epoch.
  It is mounted as one owner/service-readable file and revoked on close. Heartbeat is 30 seconds and
  interruption occurs after 120 seconds missing.
- Service credentials: independent random identities for core-to-Neo4j, gateway, and each adapter
  capability. They are mount-scoped and rotatable; one service credential cannot call another role.
- Setup/browser launch capability: one-use 256 bits in initial URL fragment only, exchanged through an
  Authorization header and immediately removed from browser history.

Credentials are never self-authorizing bearer claims with embedded grants. Server-side records are
checked on every request so revocation, grant version, deletion, and security epoch apply immediately.

### Roles and authorization decision

Roles are Owner, Admin, Editor, Reader, Auditor, Adapter, and Worker with the exact scope described by
the technical requirements. Grants are Brain-scoped and may narrow project/repository/time. Owner-only
operations include Brain lifecycle/export/destruction and provider egress policy. Worker/Adapter grants
list exact use cases/event/job classes; they cannot recall arbitrary content or administer policy.

`AuthorizationPolicy.authorize(RequestContext, action, resource, scope, purpose)` is deny by default and
evaluates principal/status, credential audience/session, action, resource type/ID, Brain, explicit
project/repository IDs, classification, purpose, host capability, grant/policy/security epochs, and
time. It returns immutable `AuthorizedScope` or a typed denial. Authorization occurs before cache
lookup, counts, exact/lexical/vector search, graph expansion, learning/evaluation, mutation, export,
audit, and provider batch construction; it is rechecked before each graph hop and external side effect.

Repository/query ports require `AuthorizedScope`. SQLite always includes Brain/narrower predicates;
CAS keys are Brain-HMAC scoped; Neo4j uses pre-filtered SEARCH and expansion; provider batches are
homogeneous. Unauthorized absence returns the same `AM_NOT_FOUND` shape/timing class as nonexistent
data where appropriate. Cache keys include principal, grant/policy/security epochs, scope, query, and
generation. Grant/tombstone changes synchronously bump epoch and invalidate affected caches before
commit success.

### Loopback API/UI

API/UI binds only configured `127.0.0.1` and certified `::1`; default port is 9411. The server rejects
wildcard, LAN, Unix-to-TCP proxy, forwarded-host, non-loopback listener, and remote/shared MCP
configuration. It does not trust `X-Forwarded-*`. Unauthenticated liveness returns only alive/not alive.

Accepted `Host` is the exact persisted loopback literal/name and port set; arbitrary hostname resolving
to loopback is rejected to prevent DNS rebinding. Browser requests require exact allowlisted Origin,
`Sec-Fetch-Site` policy where available, no cross-origin resource sharing, body/deadline/rate limits,
and anti-CSRF token on mutation. Responses use restrictive CSP (`default-src 'self'` with explicit
minimal directives), `frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, strict referrer policy,
and no external assets.

The UI launch capability exchanges once for a host-only, `HttpOnly`, `SameSite=Strict` session cookie;
`Secure` is mandatory when loopback TLS is enabled and omitted only for the certified plain-loopback
HTTP mode. A separate random CSRF token remains in page memory and is echoed in a custom header.
Neither credential is persisted by application code. Session expiry/revocation/grant change clears
server state; browser cache headers prevent storage of sensitive API responses.

MCP stdio authenticates the mounted session credential and does not inherit browser/owner authority.
Optional Streamable HTTP has the same Host/Origin/auth policy and no non-loopback mode.

### Defense in depth and audit

Core uses dedicated Neo4j credentials and always passes scope predicates; Neo4j records all carry
Brain. Governed operations append actor, action, scope, policy/grant versions, before/after hashes, and
outcome under ADR-014-safe telemetry/audit rules. Authentication failure never logs the presented token.
Repeated failures are locally rate-limited without creating a network account-lockout denial of service.

## Security and privacy impact

Controls address malicious web origins, DNS rebinding, local confused deputies, stale grants, and
cross-Brain candidate leakage. Credential values stay outside persistence/config/telemetry. Loopback
does not protect against the bound OS owner, root, a compromised browser profile, Docker daemon, or an
unlocked host; those are documented residual risks.

## Compatibility, migration, and rollback

Role/action and credential record schemas are versioned. Additive actions default deny until both old
and new policy understand them. Security-epoch rotation invalidates older sessions. Credential rotation
overlaps only long enough to establish new core connections, then revokes old. A rollback cannot reduce
the current grant/deletion/security epoch or reactivate expired credentials.

## Rejected alternatives

- Trusting loopback without authentication: vulnerable to local web origins/processes.
- OAuth/remote identity/public listener: outside single-user local model.
- Owner credential in every bridge: excessive privilege and weak revocation.
- JWT/self-contained grants: stale authority until expiry.
- Authorization after candidate search: leaks counts/rank/timing/data.
- Neo4j database/labels as sole authorization: not adequate in Community/multi-Brain design.
- Credentials in URL/localStorage/environment: browser/process/diagnostic leakage.

## Consequences

Every port and cache requires scope/epoch context, and browser launch has an exchange flow. This
additional plumbing provides immediate revocation and consistent defense across SQL, graph, vectors,
MCP, API, and providers.

## Verification

- Generated action x role x Brain/project/repository/classification/purpose/time decision table.
- Cross-Brain fuzz and count/error/timing/cache/queue/metric side-channel tests.
- Grant/tombstone/security-epoch commit races prove no stale cache/result after commit.
- Session audience/expiry/revocation/process/host-scope and worker/adapter least-privilege tests.
- LAN/unrelated-container scans and listener configuration rejection on IPv4/IPv6.
- Host/Origin/DNS-rebinding/CORS/CSRF/cookie/capability/history/frame/CSP/rate/body/deadline attacks.
- Credential serialization/log/Compose/environment/export/diagnostic scans and rotation tests.
