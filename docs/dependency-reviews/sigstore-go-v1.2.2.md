# Dependency review: sigstore-go v1.2.2

Status: approved for the PF-001 offline release-verification adapter on 2026-07-14.

## Identity and immutability

- Module: `github.com/sigstore/sigstore-go`
- Version: `v1.2.2`, the latest stable release at review time
- Immutable tag commit: `55aa6240784677449a564e66a0fca7a6a3605ecd`
- Go module checksum: `h1:xAJ8hxaoecC0HKBYVbrwUjkeAI+GJYu6vLqbxDlD2Q0=`
- Go module-file checksum: `h1:MIFwBxAHJD+/lKgZzt9n/4Zhq/3T2+EuGX8iGrIsZgU=`
- Downloaded module ZIP SHA-256: `79fcef099b900093796e106ad46b08d6f15a58f72ef4320107f6ffb6051c522b`
- Downloaded `go.mod` SHA-256: `c123ff7c324bbf780be9ec0967a88fb1c493af22edd8fecc53640b50f23fd8e9`

The Git tag and GitHub release both resolve to the commit above. GitHub marks the
release tag signature as verified. The module is pinned in `go.mod`; builds also
verify its public Go checksum-database hashes recorded in `go.sum`.

## Provenance, compatibility, and license

- Upstream release: <https://github.com/sigstore/sigstore-go/releases/tag/v1.2.2>
- Upstream source: <https://github.com/sigstore/sigstore-go/tree/v1.2.2>
- Upstream module file: <https://raw.githubusercontent.com/sigstore/sigstore-go/v1.2.2/go.mod>
- License: Apache License 2.0, reviewed from the immutable tag at
  <https://raw.githubusercontent.com/sigstore/sigstore-go/v1.2.2/LICENSE>
- Upstream minimum Go version: 1.25.8
- AgentMemory Go version: 1.26.5

The release includes certificate-chain verification support and fails closed
when certificate identity policy omits SAN or issuer criteria. Those upstream
changes directly match this adapter's use case.

## Approved surface and controls

Production code may import only `pkg/bundle`, `pkg/root`, and `pkg/verify` for
this feature. It must not call TUF-fetching helpers, Sigstore clients, ambient
system-root loaders, command execution, or network transports.

The adapter:

1. accepts an official Sigstore bundle and official trusted-root JSON as exact,
   bounded, duplicate-key-free byte inputs;
2. constructs the verifier exclusively from injected trusted material;
3. narrows Rekor trust to one configured lowercase SHA-256 log ID and key;
4. requires one verified inclusion proof/checkpoint, one observer timestamp,
   and one SCT;
5. requires exact Fulcio SAN and OIDC issuer matches (no regular expressions);
6. accepts only a v0.3 SHA-256 `messageSignature` over the exact canonical
   release manifest (a DSSE subject claim is not accepted as its signature);
7. validates independently signed revocation and trusted-time evidence through
   the existing offline-trust port before a release can be accepted.

Any version change, new production import surface, online trust discovery, or
relaxation of these verifier thresholds requires a new dependency review.

## Vulnerability review

`govulncheck v1.4.0` reported no reachable symbol or imported-package
vulnerabilities for the release-verification adapter. It reported the
module-level advisory `GO-2026-5932` because the transitive
`golang.org/x/crypto` module contains the unmaintained `openpgp` package. The
adapter does not import or reach `openpgp`, and the advisory has no fixed
version. CI must continue running reachability analysis; any future reachable
finding blocks release and requires this review to be reopened.
