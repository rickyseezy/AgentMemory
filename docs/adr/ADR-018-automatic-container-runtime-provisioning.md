# ADR-018: Automatic Docker Desktop and Engine provisioning

- Status: Accepted
- Decision owners: Runtime/Installer Owner and Security Owner
- Consulted owners: Architecture, Release Engineering, Operations, Legal/License Compliance, Accessibility
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before any platform, vendor channel, privilege, terms, reboot, or removal change
- Supersedes: None
- Related requirements: PRD Sections 1.3, 2, 16, and acceptance scenarios 36-55; Technical Requirements Sections 0.1, 1.4, 2.2.1, 2.4, 6.1, 11.1 PF-001/PF-006, 11.12 SEC-006, and 11.13 OPS-001/OPS-007

## Context

Docker is a transitive AgentMemory dependency, not a prerequisite the user is expected to install or
understand. A certified user must be able to choose the MCP installation and complete only unavoidable
native terms, elevation, or reboot decisions. Provisioning nonetheless crosses publisher trust,
licensing, privilege, firmware, WSL/rootless, existing workloads, and destructive-removal boundaries.

## Decision

### 1. Top-level and nested sagas

PF-001 retains the fourteen public Ensure phases:

`VerifyHost -> EnsureContainerRuntime -> VerifyRelease -> ReserveSpace -> EnsureDirectories ->
EnsureKeys -> EnsureComposeBundle -> EnsureNetworkAndVolumes -> RunMigrations -> EnsureCoreAndGraph ->
BootstrapLocalBrain -> MergeAgentConfiguration -> VerifyReadiness -> CommitActiveRelease`.

`EnsureContainerRuntime` is the PF-006 sub-saga:

`DetectHost -> DetectRuntime -> PlanRuntime -> AwaitRuntimeConsent -> AcquireRuntime ->
VerifyRuntimeArtifact -> InstallPrerequisites -> InstallRuntime -> AwaitThirdPartyTerms -> StartRuntime ->
VerifyRuntimeCapabilities`.

Prerequisite/runtime installation may transition to `RebootPending`, then only a verified one-use
`ResumeVerified` continues the recorded next phase. Any phase may produce `Cancelled`,
`PausedForAdministrator`, `UnsupportedHost`, `RuntimeConflict`, or `FailedRecoverable`. PF-006 success
is evidence returned to the top-level phase; it does not create a second installation operation.

Every side effect is preceded and followed by a durable journal record. Each record binds operation
ID, aggregate version, phase/subphase, attempt, canonical plan digest, input/output evidence digest,
artifact digest, runtime ownership, compensation boundary, next safe action, OS principal, machine,
and previous HMAC. Resume starts at the first phase without verified output and re-probes any external
state used by that proof.

### 2. Runtime prerequisite catalog

`RuntimePrerequisiteManifest` is a versioned RFC 8785 document signed and digest-bound as specified in
ADR-016. Each closed platform tuple declares:

- exact OS edition/build or distribution/version, CPU architecture, virtualization/resource floor,
  and support expiry;
- certified stable Docker Desktop or Engine/CLI/containerd/Buildx/Compose/rootless package versions;
- official scheme/host/path allowlist, artifact length/digest, publisher/notarization/Authenticode/
  repository-key/package identity, and anti-rollback sequence;
- closed installer executable and typed argument template, permitted prerequisite operations, known
  reboot exit codes, service identity, and capability probes;
- terms identifier/version/URL/digest, license presentation behavior, redistribution permission, and
  the exact non-interactive acceptance policy;
- required disk, expanded size, proxy capability, rollback limits, and ownership changes.

No `latest`, vendor convenience script, PATH discovery, unsigned mirror, arbitrary URL, mutable package
version, or caller-supplied installer argument is accepted. Catalog verification occurs before plan
display; artifact publisher verification occurs before any elevation or execution.

### 3. Deterministic discovery and plan policy

Discovery is read-only and uses explicit platform APIs and exact endpoint addresses. It records OS,
architecture, firmware/virtualization, resources, software-install policy, local contexts/endpoints,
Engine API, Compose, architecture, Linux-container mode, security mode, bind/network/volume/loopback
probes, cloud/offload/remote state, and unrelated workloads.

`RuntimeInstallPlanPolicy` returns exactly one decision:

- `AdoptCompatible`: compatible, local, running runtime;
- `StartCompatible`: compatible, local, stopped runtime;
- `InstallCertified`: no compatible runtime exists;
- `RepairManaged`: an AgentMemory-owned runtime is incomplete and ownership evidence authorizes the
  exact repair; or
- `Block`: unsupported, remote/cloud/offload, Windows-container, unsafe TCP daemon, conflicting, or
  unrepairable state.

A binary name/version on PATH is never sufficient. A compatible external runtime is addressed by its
proven local endpoint without changing global context, proxy, registry, resource allocation, update
policy, images, containers, networks, volumes, or settings. Starting a compatible stopped runtime is
the only mutation allowed without an external-runtime reconfiguration plan.

### 4. Exact informed consent

Before host mutation, `RuntimeInstallPlan` includes every field required by the technical
specification: platform/runtime/channel, existing contexts/workloads, official sources and
publishers, download/expanded/reserve sizes, changed packages/features/settings, privilege scope,
terms ID/URL/version/digest, reboot probability, proxy mode, rollback limits, and ownership outcome.

The setup surface shows a plain-language summary with a non-preselected decision. Consent binds the
OS principal, operation ID, complete plan digest, exact terms digest, timestamp, expiry, and decision.
A material plan, publisher, permission, or terms change invalidates consent. AgentMemory never decides
Docker Desktop license eligibility, collects organization size/revenue, accepts terms without the
user's explicit act, or records an administrator password.

### 5. Accessible setup surface

A certified agent-host surface is preferred. Otherwise the signed launcher serves embedded static
assets on random IPv4/IPv6 loopback ports and opens the default browser. A one-use 256-bit capability
is in the initial URL fragment, removed with `history.replaceState`, then sent only in an Authorization
header. The server validates exact loopback Host/Origin, anti-CSRF token, user/operation binding,
expiry, rate, and body size. Decisions are idempotent POSTs bound to the current plan digest; progress
uses authenticated SSE at least once per second; the server exits on terminal state.

The surface has no CDN, remote font/script, analytics, or other request and meets WCAG 2.2 AA,
keyboard/screen-reader operation, reduced motion, 200% zoom, and localized message-key contracts. It
shows size, disk, stages, native interaction, restart, retry, and one safe next action. It never shows
raw Docker errors or commands to run. Native elevation/reboot/license surfaces remain native.

### 6. Privilege broker

All acquisition and trust verification runs unprivileged. `PrivilegeBroker` accepts only a closed
typed operation such as `InstallVerifiedPackage`, `EnableWSLFeature`,
`ConfigureSubordinateIds`, or `EnableUserService`. It launches an immutable signed helper bound to
the plan digest and argument allowlist:

- macOS uses Authorization Services/vendor installer authorization;
- Windows uses `ShellExecuteEx` `runas` and a `WinVerifyTrust`-verified helper;
- certified graphical Linux uses the exact signed `/usr/bin/pkexec` package receipt with
  `--disable-internal-agent` and the fixed verified AgentMemory helper. The helper request is bounded
  canonical stdin; no password, shell string, arbitrary program, or caller environment is accepted.

The helper validates caller UID/SID, executable and plan hashes, artifact descriptor/hash, IPC owner/
ACL, nonce, expiry, operation state, and typed parameters. It starts from a trusted directory and
sanitized environment/library path, receives no secret/password in argv/environment, writes one
append-only signed/HMAC result receipt, and exits. No shell, interactive `sudo`, generic command,
generic URL, or arbitrary environment map crosses the boundary.

User refusal is `Cancelled`; policy/MDM denial or unavailable certified native prompt is
`PausedForAdministrator`; firmware-disabled virtualization or unsupported host is `UnsupportedHost`.

### 7. Platform adapters

#### macOS

Supported macOS ARM64/x86_64 catalog cells use the architecture-correct stable Docker Desktop artifact
from the exact official source. Verify TLS, manifest digest, Apple Developer ID, and notarization.
Mount/copy/install with argv-based OS APIs and documented installer behavior only after exact terms
consent. The authenticated AgentMemory consent surface is the sole decision point before the
documented `--accept-license` invocation; a catalog cannot both pass that flag and require a second
vendor decision surface. Launch Desktop and wait for Engine, Compose, Linux container, read-only bind,
network, volume, and persistence probes. No drag/drop, PATH edit, onboarding, account sign-in, or
settings navigation is delegated to the user.

#### Windows

Supported Windows 11 x86_64 cells use Docker's recommended per-user Docker Desktop installation in
WSL2/Linux-container mode below `%LOCALAPPDATA%\Programs\DockerDesktop`. Verify digest and
Authenticode with `WinVerifyTrust`, then extract the one primary signer from the embedded PKCS#7
message and compare the SHA-256 digest of its exact DER leaf certificate to signed catalog
authority. Subject display names or chain success alone are insufficient. Probe build/edition,
virtualization/firmware, Windows features, WSL version, and existing distributions. Install only
the per-user Desktop payload without elevation. Catalog-bound Microsoft-signed WSL prerequisites may
use the fixed UAC plan only when the host proves they are absent or outdated; never mutate existing
WSL distributions. Journal before reboot and resume once after sign-in. The certified Linux-container
flow forbids `docker-users`, `--always-run-service`, Windows containers, and a system-wide Docker
Desktop destination. Windows ARM64 remains outside the current certified cell.

#### Linux

Only signed catalog distribution/version/architecture cells are supported. Configure the official
stable Docker repository and install exact `docker-ce`, `docker-ce-cli`, `containerd.io`,
`docker-buildx-plugin`, `docker-compose-plugin`, and `docker-ce-rootless-extras` through typed apt/dnf
operations. Verify repository metadata/key, package signatures, and installed versions. Configure
rootless prerequisites and subordinate IDs without collision, run the packaged rootless setup tool as
the invoking user, create its user service/context, and prove rootless security options. If safe
rootless operation is unavailable, return administrator action required; never silently start a
rootful daemon or add the user to `docker`.

### 8. Runtime configuration

For an AgentMemory-provisioned runtime, configure an explicit local Linux engine endpoint with no TCP
listener; disable cloud/offload and Kubernetes; avoid account sign-in/extensions; disable analytics,
crash upload, vendor auto-update, and unnecessary cloud features where documented settings permit;
and apply the certified CPU/RAM/disk profile. Runtime update checks occur only as a signed foreground
maintenance operation.

For an external runtime, none of those global settings is changed. If local execution, isolation,
resource sufficiency, file sharing, or endpoint safety cannot be proved, block or present a new exact
remediation plan without interrupting unrelated workloads.

### 9. Reboot continuation

Before reboot/logout, flush the authenticated journal and register an owner-only per-user continuation
containing only launcher path/hash, operation ID, journal path/hash, expiry, and random non-secret
nonce. It expires after 24 hours. Startup verifies binary/journal owner, machine/user/operation,
hashes, current journal state, and nonce; atomically consumes the nonce before continuing; and removes
the entry after success, cancellation, expiry, or terminal failure. It carries no credential, key,
Docker token, or Brain data and cannot be reused.

### 10. Ownership, repair, upgrade, and removal

Before first runtime mutation, persist `RuntimeOwnershipRecord` with disposition
`ReusedExternal` or `ProvisionedByAgentMemory`, vendor/version/channel, endpoint/context, artifact
digest/publisher, plan/consent digests, created components/settings, pre-existing-state hashes,
privilege receipts, continuations, and compatibility probe. At Ready it is copied atomically to the
installation directory, HMAC-protected by the installation key, and summarized to core audit.

Repair/upgrade mutates only recorded AgentMemory-owned components. An external runtime upgrade that
could affect unrelated workloads requires a new plan listing them and explicit approval; no silent
upgrade occurs. Cancellation compensates only AgentMemory-owned partial downloads, continuations, and
settings proven by before/after evidence; it never downgrades or uninstalls an external runtime.

Product uninstall always preserves the runtime. `RemoveManagedRuntime` is a separate operation with a
new plan and second confirmation, allowed only for `ProvisionedByAgentMemory` after exhaustive scan
proves no unrelated container, image, volume, network, context, Compose project, or client depends on
it. Unknown ownership or use preserves the runtime.

### 11. Offline provisioning

An offline bundle may carry a runtime artifact only when the signed catalog declares redistribution
permission. Otherwise setup asks the user to select a separately obtained official vendor installer,
verifies exact catalog digest and native publisher, and then executes it automatically. An incomplete
bundle declares that fact before consent and cannot claim clean-machine offline support. All trust,
terms, privilege, journal, readiness, and ownership rules are identical to online provisioning.

## Security and privacy impact

This design minimizes elevated code, prevents shell/argument injection, binds terms and privilege to
the displayed plan, and resists publisher substitution, catalog rollback, resume replay, malicious
PATH/context/socket state, and accidental destruction of unrelated Docker workloads. Plans and
receipts contain metadata but no credentials or Brain content; raw paths and argv are never logged.

The user or device administrator can deny required actions. A privileged host, compromised Docker
daemon, malicious approved vendor installer, or unlocked physical machine remains a residual risk.

## Compatibility, migration, and rollback

Catalog and journal formats are versioned. Additive catalog fields may be preserved; unknown fields
that affect permissions, trust, terms, prerequisites, rollback, or ownership block the operation.
Journal migration is forward-only, signed/tested, and performed before further side effects. A prior
launcher remains available only for its exact compatible rollback operation.

Vendor runtime rollback occurs only when the catalog defines a safe supported rollback and ownership
proves AgentMemory installed the runtime. Otherwise product recovery preserves the runtime and rolls
back AgentMemory release/data generations. A partial vendor installation is repaired from verified
state; it is never declared compatible from an executable/version string.

## Rejected alternatives

- Requiring users to preinstall Docker or follow Docker documentation.
- Vendor convenience scripts, `curl | sh`, mutable package versions, or arbitrary mirrors.
- Silent acceptance of Docker Desktop terms or collection of organization eligibility facts.
- Generic privileged command execution, hidden terminals, interactive sudo, or password capture.
- Automatic rootful Linux or `docker`-group fallback.
- Changing a reused runtime's global context/settings/update policy.
- Remote Docker contexts, Docker Offload/cloud, Windows-container mode, or unauthenticated TCP daemon.
- Reboot entries containing a credential or reusable continuation.
- Removing Docker as part of ordinary AgentMemory uninstall.

## Consequences

The launcher requires substantial platform-specific code and pristine-OS qualification. Some managed,
offline, firmware-disabled, browserless, or pre-GA environments cannot be certified. This is preferable
to presenting nontechnical users with unsafe manual workarounds or silently changing their machine.

## Verification

- Unit/property/fuzz the phase machine, plan decision table, HMAC journal, consent binding, ownership,
  privilege operations, continuation, and compensation.
- Run pristine and existing-runtime VMs for every certified OS/architecture cell, including
  non-admin, proxies, offline, spaces/Unicode, sleep, logout, and reboot.
- Test exact accept/decline/re-consent, elevation denial, MDM denial, firmware-disabled virtualization,
  Windows WSL absent/outdated, Linux rootless/subuid/systemd/SELinux, and macOS residual vendor UI.
- Attack catalog/artifact publisher/digest/redirect/MITM/rollback, PATH/context/socket, privilege
  nonce/IPC/TOCTOU, setup Host/Origin/CSRF/capability/history, and resume replay/machine-user mismatch.
- Kill power/process/network after every transition and prove one runtime, ownership record, resume,
  and no serving partial Brain.
- Prove external runtime settings/workloads remain byte-for-byte/inventory unchanged; prove ordinary
  uninstall keeps runtime and separate removal refuses any unrelated/uncertain dependency.
- Run novice usability and WCAG/localization suites; successful paths contain no terminal or Docker
  knowledge step.
