# PF-001 native certification procedure

This document is the normative release procedure for proving PF-001 on clean
native hosts. Unit tests, cross-compilation, hosted runner success, screenshots,
and an unsigned self-hosted-runner artifact are necessary engineering evidence,
but none of them is a substitute for this campaign.

The executable authorities are:

- `contracts/pf001/support-matrix-v1.json` — the complete supported platform and
  scenario matrix;
- `contracts/jsonschema/pf001-support-matrix/v1.json` — its interchange schema;
- `contracts/jsonschema/pf001-native-certification/v1.json` — the signed report
  interchange schema;
- `tools/check_pf001_certification` — the stricter semantic, cryptographic,
  freshness, path, file-set, and release-binding verifier; and
- `.github/workflows/pf001-native-certification.yml` — hosted reverification of
  every matrix cell and production of the attested qualification artifact.

The Go verifier is authoritative when a JSON Schema rule is less restrictive.
Changing the matrix, schemas, verifier, or workflow requires security review,
TDD, the mandatory 80% coverage gates, and a new campaign. Evidence produced for
an earlier byte digest is not reusable.

## Trust and role separation

Four roles participate in one campaign:

1. The release builder produces the exact signed candidate and publication
   record for one final `vMAJOR.MINOR.PATCH` tag.
2. Native test operators restore and execute trials on the declared clean hosts.
   Operators may collect evidence but cannot waive, reorder, or mark a trial
   passed without its required attachments.
3. The certification authority independently reviews the complete campaign and
   signs the exact canonical report with an externally controlled Ed25519 key.
   Its private key must never enter this repository, GitHub Actions, a release
   asset, an AgentMemory binary, or a campaign evidence directory.
4. Release qualification downloads the immutable campaign, verifies the
   independent signature and exact release binding on GitHub-hosted runners,
   and carries the resulting ZIP unchanged into promotion.

The public key is a standard-base64 32-byte Ed25519 key stored as the protected
repository or environment variable
`AGENTMEMORY_NATIVE_CERTIFICATION_PUBLIC_KEY_BASE64`. Key rotation changes the
derived key ID and requires a new report and immutable campaign release. A
self-hosted GitHub attestation cannot replace the independent signature.

## Closed support matrix

Every release requires all seven cells; there are no optional cells:

| Cell | Required host |
|---|---|
| `darwin-amd64-macos-tahoe-apfs` | Intel macOS Tahoe 26 on APFS |
| `darwin-arm64-macos-tahoe-apfs` | Apple Silicon macOS Tahoe 26 on APFS |
| `linux-amd64-fedora-44-xfs` | Fedora 44 x86-64 on XFS |
| `linux-amd64-ubuntu-24.04-ext4` | Ubuntu 24.04 LTS x86-64 on ext4 |
| `linux-arm64-fedora-44-xfs` | Fedora 44 ARM64 on XFS |
| `linux-arm64-ubuntu-24.04-ext4` | Ubuntu 24.04 LTS ARM64 on ext4 |
| `windows-amd64-11-25h2-ntfs` | Windows 11 25H2 x86-64 on NTFS |

The chosen supported versions are tied to official vendor sources: Apple
documents current macOS security releases and Recovery/DFU restoration,
Canonical publishes the Ubuntu 24.04 release and checksums, Fedora publishes
Fedora 44 installation media, and Microsoft publishes Windows 11 25H2 lifecycle
and download information. The exact URLs and reset authorities are recorded in
the matrix. A later OS family is not silently compatible; changing support is a
reviewed matrix revision.

The matrix derives 54 trials for each macOS and Ubuntu cell, 55 for each Fedora
cell, and 58 for Windows. Run this before a campaign:

```text
go run ./tools/check_pf001_certification
go run ./tools/check_pf001_certification -emit-github-matrix | jq .
```

Both commands must succeed from the exact tagged source with an otherwise clean
worktree.

## Clean-host and snapshot rules

Before each trial, restore a fresh stock image or snapshot descended directly
from the matrix-declared stock image. A trial may not reuse another trial's
`snapshot_id`, including a retry. A failed attempt remains historical evidence;
the retry receives a new snapshot ID and the signed report includes only a
complete passing campaign after the authority has reviewed the failure.

For each cell, retain:

- the official image digest and its vendor signature/checksum verification;
- observed OS version and build within the matrix bounds;
- architecture, physical hardware identity digest, CPU, memory, firmware,
  secure-boot/virtualization state, storage device, filesystem, and mount facts;
- initial Docker/Compose state selected by the trial;
- network/proxy state and packet-capture interface set;
- the exact candidate publication digest, source commit, distribution-manifest
  digest, release-trust digest, and every installed artifact digest; and
- reset method, reset timestamp, operator identity, and unique snapshot ID.

Host clocks must be synchronized to a trusted source. Campaign and trial times
are exact UTC RFC 3339 values. A campaign must finish after it starts, last no
more than 14 days, and be verified within the matrix freshness window (currently
seven days). A trial must finish after it starts, last no more than 48 hours,
and record no more than eight reboots. Every variant containing `reboot` must
record at least one reboot.

## Scenario acceptance contract

Every applicable variant must pass. “Skipped”, “not applicable”, “expected
failure”, manual waiver, missing attachment, or reused snapshot fails the entire
campaign.

| Scenario | Required observable outcome |
|---|---|
| `agent-host-integration` | Claude MCPB, Codex, Cursor, Gemini extension, and generic/custom integration install from their declared user-scoped contract; existing unrelated configuration is byte-preserved; first-MCP timeout reports setup status; reboot reconnect resumes through the authenticated launcher. GLM is covered through the concrete supported host it uses or the generic/custom contract. |
| `fail-closed-host-conditions` | Each declared unsupported, unsafe, substituted, resource-starved, declined, managed-device, mount, signature, provenance, SBOM, port, semantic-smoke, or runtime-context condition remains NotReady and preserves pre-existing user/runtime state. |
| `install-lifecycle` | Pristine online/offline and compatible running/stopped runtime states reach the same verified Ready contract; an exact repeat is idempotent and does not duplicate configuration, resources, consent, or ownership; physical-capacity reservation proves retained allocation and rollback headroom on the cell's native filesystem rather than logical free-space accounting. |
| `interruption-recovery` | Process kill, daemon failure, logout, network loss, reboot, and real power loss at every side-effect checkpoint resume or compensate from durable state without false Ready, foreign-resource deletion, partial activation, or replay. |
| `linux-apt-native` | Exact APT package signatures/receipts, Polkit denial/retry, subordinate-ID absence, missing user service, and uninstall state follow the signed Ubuntu authority and ownership policy. |
| `linux-dnf-native` | Exact RPM/DNF signatures/receipts, Polkit denial/retry, subordinate-ID absence, SELinux enforcing mode, missing user service, and uninstall state follow the signed Fedora authority and ownership policy. |
| `local-semantic-no-egress` | On default local providers, end-to-end write, graph projection, embedding, reranking, extraction, and recall succeed while packet capture and the egress report prove no non-approved network traffic. |
| `macos-native-security` | Developer ID/notarization, Authorization Services denial/retry, Keychain ACL and rollback behavior, package uninstall, and path-swap/hard-link attacks match exact signed authority and fail closed on substitution. |
| `network-adversarial` | Captive portal, authenticated proxy, partial transfer/resume, redirect substitution, and TLS interception never bypass pinned source, digest, publisher, or consent policy; approved recovery remains resumable. |
| `upgrade-removal` | Shadow upgrade/activation and rollback preserve the previous generation; reused runtimes are preserved; only operation-owned runtimes are removable after the exhaustive scan and impact-specific consent. |
| `usability-accessibility` | A novice completes install without Docker knowledge or technical choices; keyboard, screen-reader, focus, contrast, status/error, and localization checks meet the product accessibility contract. |
| `windows-native-security` | Exact Authenticode leaf matching, Credential Manager/DPAPI behavior, protected DACL/reparse/hard-link defenses, UAC denial/retry, and MSI uninstall pass on the declared NTFS host. |
| `windows-wsl-prerequisites` | Current, absent, outdated, and distribution-absent WSL states install or resume only from the signed offline authority; required feature changes and reboots are authenticated and one-use. |

## Evidence file contract

The verifier derives every path; operators do not choose attachment names. For
each `<cell>/<scenario>/<variant>`, required files live at:

```text
evidence/<cell>/<scenario>/<variant>/<kind>.<extension>
```

Kinds are sorted and exactly match the matrix. Their content contract is:

| Kind | Required content |
|---|---|
| `host-attestation` | Canonical JSON containing the clean-image, reset, OS/build, architecture, hardware, storage/filesystem, clock, candidate, operator, and snapshot bindings listed above. |
| `journal` | Canonical sanitized installer/runtime journal proving ordered durable states, operation and plan digests, attempts, compensation boundaries, ownership, and terminal state. No secret or raw source content is permitted. |
| `result` | Canonical JSON listing every variant assertion, expected value, observed value, pass state, and cited attachment digest. A boolean without assertions is insufficient. |
| `transcript` | UTF-8 text with the exact user-visible prompts, decisions, progress, errors, retry, restart, and Ready output; redact only through the approved deterministic redaction policy. |
| `security-report` | Canonical JSON for signature/publisher, permissions/ACL, identity, path/link/race, privilege, secret, and rollback checks applicable to the trial. |
| `recovery-trace` | Canonical JSON timeline from injected interruption through durable restart, revalidation, compensation/resume, and terminal state. |
| `egress-report` | Canonical JSON of interfaces, DNS, destinations, proxy decisions, allow/deny results, capture time bounds, and packet-capture digest. |
| `packet-capture` | The bounded PCAP covering the complete relevant trial interval. It must include every active interface or explain an independently verified capture boundary in the egress report. |
| `accessibility-report` | Signed PDF containing tool versions, WCAG checks, assistive technologies, locales, findings, and pass/fail disposition. |
| `study-record` | Canonical de-identified JSON for participant eligibility, novice criteria, task script, assistance, completion, timing, errors, and consent/retention policy. |

Each attachment is non-empty, regular, link-free, at most 1 GiB, and bound by
lowercase SHA-256 and exact byte size in the report. Total declared evidence is
at most 16 GiB and the complete campaign contains no undeclared file. The ZIP
is stored (no compression), lexically ordered, fixed to the canonical 1980 UTC
timestamp, mode `0600`, and contains neither directories nor hidden, absolute,
backslash, dot, or traversal paths.

## Report, external signature, and canonical bundle

The report is `native-certification.json`; its detached envelope is
`native-certification.signature.json`. Report cells, trials, and evidence must
appear in the exact order generated from the matrix. `no_waivers` is always
`true`.

Derive the public key ID before constructing the report:

```text
go run ./tools/check_pf001_certification \
  -print-authority-key-id \
  -public-key-base64 "$AGENTMEMORY_NATIVE_CERTIFICATION_PUBLIC_KEY_BASE64"
```

After the evidence collector creates a schema-valid draft, canonicalize it and
replace the draft atomically with the output:

```text
go run ./tools/check_pf001_certification \
  -canonicalize-report /absolute/campaign/native-certification.draft.json \
  > /absolute/campaign/native-certification.json
```

The certification authority reviews the complete file set and signs the exact
bytes of `native-certification.json` with pure Ed25519. The authority returns
only the raw 64-byte signature. Assemble and independently verify the canonical
envelope without exposing the private key:

```text
go run ./tools/check_pf001_certification \
  -assemble-signature-report /absolute/campaign/native-certification.json \
  -raw-signature /secure-handoff/native-certification.ed25519 \
  -public-key-base64 "$AGENTMEMORY_NATIVE_CERTIFICATION_PUBLIC_KEY_BASE64" \
  > /absolute/campaign/native-certification.signature.json
```

Create the canonical ZIP outside the campaign directory. The command first
verifies the raw directory, writes deterministic bytes, and reverifies the final
ZIP before success:

```text
go run ./tools/check_pf001_certification \
  -campaign-root /absolute/campaign \
  -publication /absolute/release-build/publication.json \
  -public-key-base64 "$AGENTMEMORY_NATIVE_CERTIFICATION_PUBLIC_KEY_BASE64" \
  -expected-version "$VERSION" \
  -expected-source-commit "$SOURCE_COMMIT" \
  -verification-time-unix "$(date -u +%s)" \
  -output "/absolute/output/agentmemory-native-cert-v$VERSION-$SOURCE_COMMIT-$CAMPAIGN_ID.zip"
```

Re-run the verifier against that ZIP from a separate clean checkout before
publication. Any changed byte, missing or extra file, stale time, wrong cell,
wrong matrix, wrong candidate, wrong key, noncanonical JSON/ZIP metadata, failed
trial, reused snapshot, or evidence substitution must fail.

## Immutable staging and GitHub verification

Create a draft GitHub release whose tag is:

```text
native-cert-v<VERSION>-<40-character-source-commit>-<campaign-id>
```

The tag must point to the same commit as `v<VERSION>`. Name the sole campaign
asset `agentmemory-<campaign-tag>.zip`, record its lowercase SHA-256, attach it
to the draft, and publish only after review. GitHub release immutability must be
enabled; the published staging release must report `immutable: true`. GitHub's
documented immutable-release flow locks the tag and assets and creates a release
attestation. The workflow additionally runs `gh release verify` and
`gh release verify-asset`.

Dispatch `.github/workflows/pf001-native-certification.yml` from the exact
`v<VERSION>` tag with the host-package build run/artifact and immutable campaign
tag/name/SHA-256. The workflow:

1. proves both tags resolve to the same source and the campaign release is
   immutable;
2. derives the seven-cell matrix from the reviewed contract;
3. re-verifies the campaign independently once per required cell on hosted
   Ubuntu runners;
4. re-verifies the complete campaign again;
5. creates a GitHub-hosted build-provenance attestation for the unchanged ZIP;
   and
6. uploads exactly `agentmemory-native-certification.zip` as
   `pf001-native-certification-<source-commit>-<run-id>`.

Release qualification validates the run identity, run conclusion, workflow
path, tag, source commit, artifact metadata, hosted-runner attestation with
`--deny-self-hosted-runners`, and independent Ed25519 signature. It adds the ZIP
as the 117th qualified object. Immutable promotion repeats both verification
layers before and after staging and publishes the same bytes without rebuilding
or resigning the campaign.

## Failure and retention rules

- Do not edit or replace an immutable failed campaign. Start a new campaign ID,
  restore every trial to a new snapshot, and produce a new report and release.
- Do not extend freshness, reduce trials, remove a cell, or change a status to
  pass as an operational workaround. Such changes are product contract changes.
- Retain raw evidence and authority review records according to the security and
  privacy retention policy. The public production release retains the canonical
  ZIP; access-controlled raw working copies must be encrypted at rest.
- Revoke the public key from protected configuration immediately on suspected
  authority compromise. Every report signed by that key becomes NotReady until
  independently reviewed and recertified under an approved replacement key.
- PF-001 remains NotReady if any required clean host, signing authority, vendor
  approval, campaign attachment, environment approval, or immutable-release
  control is unavailable. Repository tests must never synthesize a release pass.
