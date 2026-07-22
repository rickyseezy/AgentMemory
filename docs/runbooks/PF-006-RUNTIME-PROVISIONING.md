# PF-006 automatic runtime provisioning runbook

## Purpose

Use this runbook when first installation is waiting for runtime consent, administrator authorization,
or restart; cannot acquire, verify, install, start, or capability-test the local runtime; detects an
unsafe existing runtime; resumes after interruption; or evaluates managed-runtime removal.

The normal user journey has no Docker step. Do not ask a nontechnical user to install Docker/Compose,
choose a context, edit daemon or Desktop settings, open a terminal, copy a command, start a service,
change a socket, add a group, disable security, or clean Docker data. The signed launcher performs all
supported work and offers one safe plain-language action when it cannot continue automatically.

## Read the visible setup state

The agent-host setup surface or embedded local setup UI is the primary diagnostic surface. Preserve
only operation ID, phase, state, public reason/action key, progress counts, signed release/plan digest,
platform cell, and timestamps. Do not collect usernames, raw paths, proxy credentials, installer logs,
environment variables, command lines, registry contents, unrelated Docker resource names, or Brain
content.

| State | Meaning | Safe action |
|---|---|---|
| `Running` | A verified transition is executing | Wait for the bounded transition or its typed result |
| `AwaitingConsent` | The exact current plan/terms require a user decision | Show the plan; accept or decline without preselection |
| `PausedForAdministrator` | Device policy or the certified authorization surface blocks progress | Ask the device administrator to approve the displayed product action |
| `UnsupportedHost` | The signed release does not certify this platform/resources/virtualization | Show the single supported-host action; do not improvise installation |
| `RuntimeConflict` | Existing runtime/workload state cannot be changed safely | Preserve it and show the conflict-safe action |
| `FailedRecoverable` | The last transition lacks verified output | Retry the same operation; resume starts at the first unverified phase |
| `RebootPending` | A signed one-use continuation is durable | Restart only after the user approves; resume occurs once after sign-in |
| `Cancelled` | The user declined or cancelled | Preserve prior state; a future install creates/replans authority |
| `Ready` | Runtime and capability evidence are complete | Continue PF-001; do not rerun provisioning |

Do not convert a blocked, partial, unknown, or stale state to Ready manually.

## Phase-by-phase diagnosis

PF-006 executes in this order:

1. **DetectHost** — verify OS/build/distribution, architecture, virtualization, resources, filesystem,
   encryption, principal/machine, policy, and native authorization capability.
2. **DetectRuntime** — inspect only explicit local endpoints and signed/package-owned executable
   authorities; record security mode, Compose/API capability, and unrelated workloads.
3. **PlanRuntime** — join the observed facts to the release-selected signed catalog cell and choose one
   closed action. The canonical plan digest becomes immutable.
4. **AwaitRuntimeConsent** — present the exact plan and terms. Store only an authenticated explicit
   decision for this principal, operation, plan, and terms digest.
5. **AcquireRuntime** — reserve capacity and fetch or materialize only the signed artifact set through
   the bounded proxy/offline policy.
6. **VerifyRuntimeArtifact** — verify size, digest, retained-object identity, native publisher/package
   authority, and current catalog/release binding.
7. **InstallPrerequisites** — execute only the typed prerequisite operations in the signed cell.
8. **InstallRuntime** — install or repair only the exact authorized package/application state.
9. **AwaitThirdPartyTerms** — revalidate the stored decision immediately before any vendor acceptance
   flag or first launch that consumes it.
10. **StartRuntime** — start only the verified local runtime endpoint selected by the plan.
11. **VerifyRuntimeCapabilities** — prove Engine, Compose, Linux execution, read-only bind, volume,
    internal network, loopback publish, security mode, and workload invariants; compensate probes.

At a failure, inspect that phase and the authority it consumes. Do not skip ahead or reuse an output
from another operation, attempt, plan, release, user, machine, platform cell, or runtime endpoint.

## Existing compatible runtime

For `AdoptCompatible`:

1. Confirm discovery proved a local running endpoint and complete signed executable/package authority.
2. Confirm Engine API, Compose, Linux architecture, security, mount, volume, network, loopback, and
   resource probes passed.
3. Confirm the plan performs no runtime acquisition, installation, configuration, or global mutation.
4. Record ownership as `ReusedExternal` and address the exact endpoint explicitly.

For `StartCompatible`, the only permitted mutation is starting that same verified stopped runtime.
Never change its global Docker context, proxy, registry, resources, Kubernetes, cloud/offload, update
channel, file sharing, account, extensions, images, containers, networks, volumes, or settings.

If discovery cannot prove local isolation or finds a remote/cloud endpoint, Windows-container mode,
unsafe TCP listener, insufficient capability, or conflicting workloads, preserve the runtime and block.

## Consent problems

An eligible consent request must show the exact plan, official publisher/source, sizes, changes,
privilege scope, terms ID/version/URL/digest, restart possibility, ownership result, rollback limit, and
one next action.

- A decline transitions to `Cancelled`; do not reprompt within the same immutable decision.
- A missing or unavailable decision surface transitions to `PausedForAdministrator` when policy or
  native authorization is required.
- Changed plan, terms, publisher, privilege scope, principal, or release invalidates the old receipt and
  requires a newly displayed decision.
- Never infer Docker Desktop license eligibility, ask the user to attest employee/revenue facts, or
  store such an answer.
- Never add `--accept-license` unless the exact current terms receipt verifies immediately before the
  installer transition.

The setup capability belongs only in the initial loopback URL fragment. It must disappear from browser
history and then travel only in the authorization header. Treat capability, CSRF, Host, Origin, Fetch
Metadata, principal, plan, expiry, replay, or sequence failure as an integrity event; do not weaken the
local server.

## Acquisition, proxy, and offline failures

1. Confirm the source matches the signed HTTPS scheme, host, path, redirect, and proxy policy.
2. Confirm the reserved physical capacity covers download, expansion, installation, and safety margin
   without deleting unrelated Docker data.
3. For resume, verify every retained chunk and reopen the destination by descriptor before appending.
4. Verify final size/SHA-256 and content-addressed identity before marking acquisition complete.
5. Keep proxy/PAC/TLS-interception credentials in the OS credential flow; never place them in plan,
   journal, argv, environment, log, or setup URL.
6. Distinguish captive portal, proxy authorization, TLS interception, redirect rejection, capacity,
   cancellation, and network interruption using public reason codes only.

An offline bundle may include the artifact only when the signed catalog permits redistribution. If it
does not, allow selection of a separately obtained official installer only when its exact catalog digest
and native publisher pass. An incomplete offline bundle must say so before consent and cannot claim a
clean-machine offline journey.

## Publisher or artifact verification failure

Stop before elevation/execution for any missing, stale, redirected, rolled-back, or substituted:

- outer release object or inner runtime-catalog signature;
- catalog anti-rollback sequence or support window;
- artifact length, SHA-256, filename/identity, or content-addressed location;
- macOS Developer ID, notarization, mounted image, or application identity;
- Windows Authenticode chain or exact DER leaf-certificate digest;
- APT/DNF repository metadata, pinned key, package manifest/signature, version, or architecture;
- executable-role receipt, helper identity, plan/terms digest, or retained descriptor.

Do not bypass native verification because a checksum matches. Do not bypass a digest because a native
signature verifies. Both independent authorities are mandatory.

## Native authorization or privilege failure

The broker may transport only a closed typed request and bounded canonical stdin. Verify operation,
plan/catalog/release, helper, caller, artifact, nonce, expiry, expected state, replay journal, and IPC
ownership before any mutation.

| Result | Public state |
|---|---|
| User declines macOS authorization, UAC, Polkit, terms, or approved restart | `Cancelled` |
| MDM/device policy denies it or no certified prompt exists | `PausedForAdministrator` |
| Firmware virtualization or required host capability is unavailable | `UnsupportedHost` |
| Helper/request/receipt/replay/TOCTOU validation fails | integrity failure; no retry with weaker authority |
| Process/power interruption leaves no verified postcondition | `FailedRecoverable`; replay exact pending transition |

Never request an administrator password, use interactive `sudo`, open a hidden terminal, invoke a
shell, pass a generic command/URL/environment, or expose raw helper output.

## macOS path

1. Confirm the signed cell matches architecture and the currently supported macOS build range.
2. Reopen the exact DMG and verify digest, Developer ID, notarization, mount identity, and bundle.
3. Verify the stored terms receipt before the mounted installer receives `--accept-license` and the
   exact `--user=<principal>`.
4. Preserve unknown/pre-existing Docker Desktop state unless the action is a verified managed repair.
5. Start the exact installed application and wait for the full capability probe.

Do not instruct drag/drop, PATH modification, Docker onboarding, sign-in, or settings navigation. A
no-CGO launcher cannot certify native macOS installation.

## Windows and WSL2 path

1. Confirm Windows 11 x86-64, certified build/edition, SLAT/firmware virtualization, memory, WSL
   features/version, and existing distribution inventory.
2. Use the signed per-user Docker Desktop cell and exact `install --user --quiet --accept-license
   --backend=wsl-2 --no-windows-containers` policy.
3. Never use `--always-run-service`, all-users/Hyper-V installation, Windows containers, or
   `docker-users` membership.
4. If a catalog-bound Microsoft prerequisite is missing/outdated, verify digest and Authenticode leaf
   certificate, then allow only its fixed UAC operation with automatic reboot suppressed.
5. Re-probe all existing distributions after the prerequisite; none may be registered, unregistered,
   upgraded, converted, renamed, stopped, or made default by PF-006.

When restart is required, confirm the one-use continuation was flushed and registered before asking.
Do not run `wsl --install` generically because it may install a default distribution; PF-006 uses only
the catalog's closed prerequisite transactions.

## Linux rootless path

1. Confirm the signed distribution/version/architecture cell and official stable repository metadata.
2. Verify exact Engine/CLI/containerd/Buildx/Compose/rootless packages and native signatures.
3. Confirm the invoking principal has collision-free `/etc/subuid` and `/etc/subgid` ranges of at least
   65,536 IDs; serialize allocation and re-probe after publication.
4. Execute the package-owned rootless setup tool as the invoking user, then establish the exact user
   systemd service, linger state, context, and local socket.
5. Require rootless security evidence and the complete capability probe before Ready.

Do not use convenience scripts, disable an existing rootful daemon/socket, pass `--force`, start a
rootful daemon, add the user to a Docker group, or overwrite ambiguous subordinate-ID state. Preserve
conflicting workloads and return the typed administrator/conflict state.

## Reboot or logout recovery

Before restart, verify the continuation contains only launcher path/hash, operation ID, journal
path/hash, next phase, expiry, and random nonce, and that the operation journal is durable. It must not
contain credentials, keys, tokens, Docker settings, user content, or arbitrary argv.

On sign-in:

1. Verify launcher and journal owner/hash, user, machine, operation, plan, phase, expiry, and nonce.
2. Consume the nonce atomically before resuming.
3. Re-probe prerequisite/runtime state rather than trusting the prior process.
4. Continue the first phase without verified output.
5. Remove the login registration on success, cancellation, expiry, or terminal failure.

A replayed, missing, foreign, stale, or tampered continuation is an integrity failure and performs no
side effect.

## Interrupted installation and compensation

The same operation resumes from its authenticated aggregate. Do not create a second runtime install to
work around a pending one.

1. Load the exact plan-bound operation and ownership preparation.
2. Verify the last completed phase evidence against current external state.
3. If a pending side effect now has its exact postcondition, record it once; otherwise replay only that
   idempotent transition.
4. Preserve verified complete downloads and discard only AgentMemory-owned invalid partials.
5. On cancellation, settle only recorded AgentMemory-owned acquisition slots, continuations, temporary
   probe objects, and settings with matching before/after evidence.
6. If cleanup cannot be proven, keep `FailedRecoverable`; never claim cancellation settlement or Ready.

Never uninstall/downgrade an external runtime, reset Docker, delete global data, remove unrelated
packages, disable WSL, unregister distributions, or restore an unproven setting.

## Capability-probe failure

The final probe must prove every signed requirement independently. For each stage, verify the created
test resource carries the operation identity and is compensated on success and failure.

- Engine endpoint and API/version/architecture;
- Compose capability;
- Linux container execution;
- recursively read-only bind enforcement;
- named-volume write/read persistence;
- internal network isolation and connectivity;
- loopback-only published-port behavior;
- required security/rootless mode; and
- unchanged unrelated workload inventory.

A responsive daemon or successful `docker info` is not enough. Never loosen a mount, use host network,
publish non-loopback, switch container mode/context, or ignore compensation to obtain a passing result.

## Uninstall and managed-runtime removal

Normal AgentMemory uninstall always preserves Docker Desktop/Engine, Compose, WSL, Linux packages,
contexts, distributions, settings, and every unrelated resource.

`RemoveManagedRuntime` is a separate, impact-specific operation. Continue only when:

1. finalized authenticated ownership is `ProvisionedByAgentMemory`;
2. the current runtime/application/packages still match the owned publisher and identity;
3. a fresh exhaustive scan finds no foreign container, image, volume, network, Compose project,
   context, client, package, service, setting, or WSL dependency;
4. the exact removal plan and impact are shown; and
5. the user gives a second plan-bound confirmation.

Unknown ownership, missing evidence, scan error, changed publisher, any unrelated use, or a modified
owned component preserves the runtime. Removal deletes only the exact ownership-recorded components and
then proves their absence; it does not remove data or prerequisites outside that authority.

## Escalate immediately

Stop release promotion and preserve content-free evidence for any shell/generic command boundary,
password or secret in argv/environment/logs, auto-accepted or mismatched terms, mutable URL/version,
unverified redirect, native-signature bypass, catalog/publisher authority collapse, remote/cloud
runtime adoption, global-context mutation, rootful Linux fallback, `docker-users` addition, Windows
container enablement, existing WSL distribution change, helper replay, side effect before durable
ownership, resume without nonce consumption, Ready without every capability, cancellation without
settled compensation, ordinary uninstall removing Docker/WSL, or managed removal with uncertain use.
