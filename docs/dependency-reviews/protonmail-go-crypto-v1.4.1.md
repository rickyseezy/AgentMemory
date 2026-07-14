# Dependency review: ProtonMail go-crypto v1.4.1

Status: approved for the PF-001 APT/DNF repository-signature verification
adapter on 2026-07-14, with CIRCL fixed at v1.6.3.

## Identity and immutability

- Module: `github.com/ProtonMail/go-crypto`
- Version: `v1.4.1`, the latest stable v1 release at review time
- Immutable tag commit: `2e73b118bb72881b92b292f85cb2d057c3d7bef0`
- Go module checksum: `h1:9RfcZHqEQUvP8RzecWEUafnZVtEvrBVL9BiF67IQOfM=`
- Go module-file checksum: `h1:e1OaTyu5SYVrO9gKOEhTc+5UcXtTUa+P3uLudwcgPqo=`
- Downloaded module ZIP SHA-256: `70bbdc0f9e926738193aed968f7901efab41493752277c4c94c9b751aa55c42a`
- Downloaded `go.mod` SHA-256: `54a615125cdd4e48ce23567071b5b8d2965d83c045d8ec32e5b700628c69b152`

The exact tag is a direct `go.mod` pin. Public checksum-database values are in
`go.sum`, and `go mod verify` remains mandatory.

## Provenance, compatibility, and license

- Upstream source: <https://github.com/ProtonMail/go-crypto/tree/v1.4.1>
- API documentation: <https://pkg.go.dev/github.com/ProtonMail/go-crypto@v1.4.1/openpgp>
- License: BSD 3-Clause
- Upstream minimum Go version: 1.23.0
- AgentMemory Go version: 1.26.5

This maintained OpenPGP implementation replaces the unmaintained
`golang.org/x/crypto/openpgp` API for reachable production verification.

## Approved surface and controls

Production code may import only `openpgp`, `openpgp/clearsign`, and
`openpgp/packet` from this module, exclusively in the native repository-trust
adapter. The adapter:

1. accepts only exact CAS-verified, catalog-pinned key and signature bytes;
2. allows public keys only and requires an exact uppercase primary-key
   fingerprint;
3. accepts only SHA-256, SHA-384, or SHA-512 repository signatures;
4. supplies trusted UTC time, enforces key/signature validity, and rejects
   future signatures;
5. requires a complete clear-signed message with no suffix;
6. never encrypts, signs, generates production keys, reads ambient keyrings,
   executes GnuPG, or performs network access.

Any version change, additional package import, accepted weak hash, ambient
keyring, signing/encryption use, or relaxed fingerprint/time policy requires a
new review.

## Transitive cryptography and vulnerability review

The module requests `github.com/cloudflare/circl v1.6.2`. `govulncheck v1.4.0`
found reachable `GO-2026-4550` in that version. AgentMemory therefore pins the
fixed `github.com/cloudflare/circl v1.6.3` through Go minimum-version selection:

- immutable commit `24ae53c5d6f7fe18203adc125ba3ed76a38703e1`;
- module checksum `h1:9GPOhQGF9MCYUeXyMYlqTR6a5gTrgR/fBLXvUgtVcg8=`;
- module ZIP SHA-256 `9aed6385d52ccd66e0a3b8cc093b5f0e7744640485405dd08c8ef89ef6bbeb06`.

After that pin, `govulncheck v1.4.0` reported no reachable vulnerabilities for
the runtime-provision adapter. Downgrading CIRCL below v1.6.3 is release
blocking.
