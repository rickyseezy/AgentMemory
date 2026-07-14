# ADR-016: Release signing, SBOM, provenance, supported versions, and dependency updates

- Status: Accepted
- Decision owners: Security Owner and Release Engineering Owner
- Consulted owners: Architecture, Runtime/Installer, Operations, Legal/License Compliance
- Decision date: 2026-07-13
- Review date: 2026-10-13 and before any trust-root, signing-service, release-channel, or supported-version change
- Supersedes: None
- Related requirements: PRD Sections 15-17; Technical Requirements Sections 2.1, 2.2.1, 6.1, 9, 11.1 PF-001/PF-006, 11.12 SEC-006, and 11.14 EVA-005/EVA-006

## Context

AgentMemory installs native launchers, third-party container-runtime prerequisites, OCI images,
Compose policy, migrations, model weights, and optionally executable provider adapters on a user's
machine. Installation and upgrade must work online or from an offline bundle, but release mode may
never trust a mutable tag, an online lookup performed after the fact, or a filename as proof of
identity. The exact artifacts qualified by release CI must be the artifacts users execute.

The product also needs an explicit compatibility window. Without it, migrations, rollback, incident
response, and dependency maintenance have no testable boundary.

## Decision

### 1. One canonical signed release manifest

Every release has one RFC 8785-canonicalized `ReleaseManifest` whose schema is versioned under
`contracts/jsonschema/release-manifest/v1.json`. The canonical bytes are signed. The manifest is the
only authority that may bind executable release inputs.

The manifest contains, at minimum:

- product semantic version, build ID, source commit, immutable release sequence, build timestamp,
  channel, and support expiry;
- minimum and maximum compatible launcher, core API, MCP, provider protocol, schema, Compose,
  SQLite, Neo4j, and runtime-prerequisite catalog versions;
- SHA-256 digest, media type, byte length, platform/architecture, purpose, and source allowlist for
  every launcher, helper, OCI index/manifest, Compose lock, migration set, contract bundle, setup UI,
  model/tokenizer/template artifact, and offline-bundle component;
- the OCI platform-manifest digest as well as the multi-architecture index digest; a platform is
  selected only after both are verified;
- the expected native publisher identity and notarization/Authenticode/package-signature policy for
  native artifacts;
- the digest and subject mapping for every CycloneDX and SPDX SBOM and every SLSA provenance
  statement;
- license/vulnerability policy snapshot digests and their qualification results;
- release and runtime trust-root IDs, revocation-set digest, and transparency evidence needed for
  offline verification;
- prior release/data-generation compatibility and the exact rollback release set;
- a closed inventory of Docker services, networks, volumes, profiles, permissions, resource labels,
  health probes, and image digests that may be rendered.

Unknown required fields, duplicate JSON keys, non-canonical encodings, an unsupported manifest major,
or disagreement between any duplicate subject binding is an integrity violation. Consumers preserve
unknown additive fields for signature verification but may act only on fields understood by their
supported schema.

### 2. Signature and trust model

- OCI images, release manifests, provider adapters, SBOMs, and provenance are signed with Cosign.
  Release verification uses an AgentMemory hardware-backed release identity whose public trust root
  is embedded in the signed launcher and in the offline bundle verifier.
- Verification is offline-capable. The release carries the signature bundle, certificate chain or
  public-key identifier, Rekor inclusion proof/checkpoint when the signing mode uses transparency,
  and the trusted-time evidence needed by policy. Installation never requires a live transparency
  lookup to establish trust.
- The launcher and platform helpers additionally pass native platform verification: Apple Developer
  ID and notarization on macOS, Authenticode/`WinVerifyTrust` on Windows, and signed repository/package
  metadata on Linux. AgentMemory signature success does not waive native publisher failure, and the
  inverse is also true.
- Model weights, tokenizers, prompt/templates, grammar packs, migrations, and Compose files are
  content-bound by the signed manifest even where their upstream format has no executable signature.
- The launcher verifies its native signature and its own digest-to-manifest binding before download,
  elevation, Docker access, or setup UI service. A platform that cannot perform the required native
  check is not a certified release target.
- Trust roots are versioned and identified by digest. Root rotation uses an overlap release signed by
  both the current and next roots. Emergency revocation is delivered as a higher monotonic release
  sequence signed by a non-revoked root. A revoked root may verify historical audit evidence but may
  not authorize new installation, repair, adapter activation, or upgrade.

Release verification has no `--insecure`, environment-variable bypass, development certificate
fallback, or network-dependent soft-fail in release builds. Development builds use a separate
visibly marked trust domain, separate installation ID namespace, and cannot open production data
generations.

### 3. Provenance and SBOM contract

Every executable OCI image and native binary has:

1. a CycloneDX JSON SBOM;
2. an SPDX JSON SBOM;
3. SLSA provenance binding source commit, reviewed build recipe, builder identity, locked inputs, and
   output digest;
4. a vulnerability and license scan result bound to the same subject digest.

The verifier checks exact provenance subject, approved builder identity and workflow path, source
repository, source commit, build parameters, dependency-lock digests, and reproducibility policy. An
SBOM merely present beside an artifact is insufficient; its subject and digest must be bound by the
release manifest and signature. A mismatch, missing association, unapproved builder, mutable source,
or policy-expired scan blocks execution.

### 4. Runtime-prerequisite and offline-bundle binding

The runtime prerequisite catalog is independently signed and is also digest-bound by the release
manifest. It has a monotonic catalog sequence and exact stable vendor channel entries. Runtime
artifacts must pass the URL/source allowlist, SHA-256, byte length, platform, publisher, package
signature, terms digest, redistribution, and anti-rollback rules from that catalog.

An offline bundle has a signed top-level manifest that binds the complete release manifest, catalog,
artifacts, signature bundles, SBOMs, provenance, license texts, model weights, and completeness
declaration. Bundle completeness is evaluated before mutation. If redistribution is not authorized,
the bundle declares the missing vendor artifact and accepts only a separately supplied artifact that
matches the exact catalog entry and native publisher policy. The verifier never accepts an arbitrary
replacement executable.

### 5. Immutable publication and promotion

- Candidate artifacts are built once. Release qualification records their digests; promotion copies
  those exact objects and metadata. Rebuild-on-promotion is prohibited.
- OCI references used by Compose contain `name@sha256:<digest>`. Tags may be published for humans but
  are never an execution input.
- GitHub Actions, base images, build containers, Compose includes, and release tools are pinned to a
  reviewed immutable commit or digest.
- The release manifest sequence is strictly increasing per channel. The launcher stores the highest
  accepted sequence in the HMAC-protected installation inventory. A lower sequence is rejected unless
  it is the exact recorded rollback target selected by a journaled failed-upgrade compensation.
- Active release and data-generation pointers are updated atomically only after all release, schema,
  security, readiness, and smoke-test probes pass.

### 6. Supported-version window

AgentMemory supports:

- the latest patch of the current minor release;
- the latest patch of the immediately preceding minor release for 90 days after the current minor is
  published; and
- upgrades from the two immediately preceding minor releases into the current release, provided each
  source remains in its published support period.

Only the current minor receives normal feature fixes. Both supported minors receive critical security,
data-loss, deletion, and cross-Brain isolation fixes. A critical vulnerability may shorten the window
through a signed security notice and replacement release; it cannot silently permit an unverified
artifact.

Database, event, provider, MCP, API, and archive compatibility must cover the published window.
Upgrade CI tests every supported source. An installation older than the direct-upgrade window must use
the signed, documented intermediate upgrade chain or export/import; the launcher must not guess or run
an untested migration path. Rollback is supported only to the exact pre-upgrade signed release and its
compatible preserved data generation or verified recovery archive.

Neo4j Community remains exact-pinned in each AgentMemory BOM. Monthly vendor releases are evaluated in
dependency update work; AgentMemory support is expressed by its BOM, not by a floating Neo4j tag.

### 7. Dependency update policy

- Patch updates may be opened automatically, but merge requires lock regeneration, unit/contract/
  integration/security/mutation suites, SBOM and license diff, vulnerability scan, reproducibility
  check, and performance comparison.
- Minor and major dependency updates require an explicit compatibility change record, public contract
  and migration analysis, replay and restore tests, SLO comparison, supply-chain diff, and rollback
  proof. Major changes that alter a product contract require a specification/ADR revision.
- Pre-release dependencies are prohibited in production except an exact-pinned telemetry
  instrumentation dependency already approved by the technical BOM; it may not define a public
  contract and is replaced when stable.
- A dependency with an unresolved exploitable critical/high vulnerability, disallowed license,
  unverifiable source, or abandoned security ownership blocks release. Exception/waiver code paths do
  not exist for zero-tolerance findings.
- Dependency bots never possess release-signing credentials and cannot promote artifacts.

## Security and privacy impact

This decision prevents publisher substitution, mutable-tag drift, catalog rollback, artifact swapping,
and SBOM/provenance laundering. Verification records contain only artifact metadata and safe publisher
identifiers. They contain no repository content, credentials, host paths, Brain names, or provider
payloads. Signing private keys are never stored in the repository or ordinary CI secrets; release
signing uses isolated short-lived or hardware-backed identity. Diagnostics may report trust-root IDs,
digests, and safe failure codes, never signature-service credentials or full host paths.

The residual risk is compromise of an approved build/signing identity or the local privileged host.
Independent native publisher checks, transparency evidence, provenance, digest pinning, and release
qualification reduce but cannot eliminate that risk.

## Compatibility, migration, and rollback

Adding optional manifest fields is backward compatible when older launchers preserve them and do not
need them for a security decision. A new required security field increments the manifest major and
requires a launcher compatibility release before artifacts using it are published.

Trust-root rotation ships through an overlap release and is verified in online and offline paths.
Artifact or manifest migration never rewrites a prior signed release. Rollback selects the exact
recorded prior manifest, images, Compose lock, and compatible data generation. A security revocation
may intentionally prohibit rollback to a vulnerable executable; recovery then restores data into a
newer verified generation rather than executing the revoked build.

## Rejected alternatives

- **Mutable tags or `latest`:** cannot prove that qualification and execution used the same bytes.
- **Checksums without signatures:** detect accidental corruption but not malicious substitution.
- **Online-only key/transparency lookup:** breaks offline installation and introduces a network trust
  dependency at the moment of install.
- **Native code signing alone:** does not bind OCI images, Compose, schemas, migrations, models, SBOMs,
  or provenance into one release.
- **Cosign verification alone for vendor runtime installers:** cannot replace Apple, Microsoft, or
  Linux package publisher verification and terms/catalog policy.
- **Rebuild artifacts when promoting a candidate:** produces unqualified bytes.
- **Indefinite backward compatibility:** makes migrations and security support untestable.
- **A manual security waiver:** conflicts with zero-tolerance release gates.

## Consequences

Releases carry more metadata and require isolated signing infrastructure, platform publisher checks,
and matrix qualification. Offline bundles are larger. In return, installation, repair, upgrade,
rollback, and adapter activation share one deterministic trust decision and can be proven without a
hosted AgentMemory control plane.

## Verification

Release qualification must automate all of the following:

- canonical-manifest and duplicate-key fixtures, schema-major negotiation, and subject-binding tests;
- wrong digest, wrong platform, wrong native publisher, expired/revoked root, transparency-proof
  tamper, catalog rollback, terms mismatch, SBOM swap, provenance-subject/builder/source mismatch,
  model-weight alteration, and mutable-tag rejection;
- self-verification before launcher side effects and verification-before-first-execution for every
  image/helper/adapter;
- offline verification with outbound network denied and an incomplete-bundle preflight failure;
- artifact-promotion digest equality between candidate, qualified, and published objects;
- supported-source upgrade, interruption, exact rollback, revoked-rollback, and intermediate-chain
  tests;
- SBOM/license/vulnerability diffs for dependency updates and reproducibility evidence;
- static checks proving release mode contains no verification bypass and Compose contains only digest
  references;
- zero-tolerance tests proving a skipped, stale, unsigned, or build-digest-mismatched result cannot
  authorize promotion.

Evidence is retained with the signed release evaluation report and exact artifact digest.
