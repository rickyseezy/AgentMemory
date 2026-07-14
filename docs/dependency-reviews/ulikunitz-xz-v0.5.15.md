# Dependency review: ulikunitz/xz v0.5.15

Status: approved for bounded PF-001 Debian package-index decompression on
2026-07-14.

## Identity and immutability

- Module: `github.com/ulikunitz/xz`
- Version: `v0.5.15`
- Immutable annotated-tag commit: `7eee8a8a405163554a9accec7b9402ee21400769`
- Go module checksum: `h1:9DNdB5s+SgV3bQ2ApL10xRc35ck0DuIX/isZvIk+ubY=`
- Go module-file checksum: `h1:nbz6k7qbPmH4IRqmfOplQw/tblSgqTqBwxkY0oWt/14=`
- Downloaded module ZIP SHA-256: `ca1830f9abc6c99a003ad28f2b145ea0af0c99d5769ddff08d23ce055959fd12`
- Downloaded `go.mod` SHA-256: `393876046d63d90f35f21c1bb4651b0985e76d8f14a48a7279ff947b96956e7b`

The exact tag is a direct `go.mod` pin with checksum-database values in
`go.sum`. `go mod verify` remains mandatory.

## Provenance, compatibility, and license

- Upstream source: <https://github.com/ulikunitz/xz/tree/v0.5.15>
- API documentation: <https://pkg.go.dev/github.com/ulikunitz/xz@v0.5.15>
- License: BSD 3-Clause
- Upstream minimum Go version: 1.12
- AgentMemory Go version: 1.26.5

The implementation is pure Go and shares no code with the compromised upstream
XZ Utils releases associated with CVE-2024-3094.

## Approved surface and controls

Production code may import only the module root and call `NewReader` for a
catalog-pinned APT `Packages.xz` object. Compressed input is already bounded and
SHA-256 verified by the CAS. Decompressed output is limited to 256 MiB, must be
read completely, and is then processed by the strict Debian-control parser.
Writing archives, command packages, filesystem access, unbounded streams, and
all other subpackages are outside the approved surface.

Any version change, writer use, larger bound, new compression mode, or expanded
import surface requires a new review.

## Vulnerability review

Version v0.5.15 is the first version fixed for `GO-2025-3922`
(CVE-2025-58058), a corrupted multi-stream LZMA memory leak. `govulncheck
v1.4.0` reported no reachable vulnerability in the runtime-provision adapter
with this version. A downgrade below v0.5.15 is release blocking.
