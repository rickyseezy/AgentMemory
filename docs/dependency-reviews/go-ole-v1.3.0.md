# Dependency review: go-ole v1.3.0

Status: approved for the PF-001 Windows BitLocker host-attestation adapter on
2026-07-14.

## Identity and immutability

- Module: `github.com/go-ole/go-ole`
- Version: `v1.3.0`, the latest tagged module release at review time
- Immutable tag commit: `de26f2b218c772f7a1000022d58d2df1d2428a2d`
- Go module checksum: `h1:Dt6ye7+vXGIKZ7Xtk4s6/xVdGDQynvom7xCFEdWr6uE=`
- Go module-file checksum: `h1:5LS6F96DhAwUc7C+1HLexzMXY1xGRSryjyPPKW6zv78=`
- Downloaded module ZIP SHA-256: `bbf5b3bfa227a5daa06eb16ecdecccc0b20e08749bf103afb523fd72764e727a`
- Downloaded `go.mod` SHA-256: `fcf0840f2ff50fbc3b5a54b9d4cb240c64d47003ab03e420aeff0057015a8953`

The immutable Git tag and the public Go module proxy metadata resolve to the
same commit. The module is an exact direct pin in `go.mod`; its public checksum
database hashes are recorded in `go.sum` and `go mod verify` must remain a
release gate.

## Provenance, compatibility, and license

- Upstream source: <https://github.com/go-ole/go-ole/tree/v1.3.0>
- Upstream module file: <https://raw.githubusercontent.com/go-ole/go-ole/v1.3.0/go.mod>
- License: MIT, reviewed from the immutable tag at
  <https://raw.githubusercontent.com/go-ole/go-ole/v1.3.0/LICENSE>
- Upstream minimum Go version: 1.12
- AgentMemory Go version: 1.26.5

The dependency is Windows-only in AgentMemory. It supplies the COM/OLE
Automation boundary required to use the operating system's registered
`WbemScripting.SWbemLocator`; it does not add a service, subprocess, network
client, or PowerShell dependency.

## Approved surface and controls

Production code may import only the module root and `oleutil`, and only from a
Windows-build-tagged host-verification adapter. The approved calls are limited
to:

1. initialize and uninitialize COM on one locked, serialized OS-thread worker;
2. create `WbemScripting.SWbemLocator` and connect only to the local
   `ROOT\CIMV2\Security\MicrosoftVolumeEncryption` namespace;
3. execute one exact escaped `DeviceID` equality query for
   `Win32_EncryptableVolume`;
4. obtain exact-cardinality records and invoke only `GetConversionStatus` and
   `GetProtectionStatus` through `ExecMethod_`;
5. decode only exact `VT_I4`, `VT_BSTR`, and `VT_DISPATCH` values required by
   those contracts; and
6. deterministically clear every owned `VARIANT`, release every COM interface,
   and uninitialize COM on the worker thread.

AgentMemory code must not import `unsafe` for this adapter. It must not use
ambient commands, PowerShell, remote WMI targets, credential parameters,
moniker input, type coercion, enumeration queries, provider mutations, or any
other COM program identifier. Errors and raw host identifiers must not leave
the adapter; every unavailable, malformed, ambiguous, cancelled, timed-out, or
noncompliant result maps to the existing privacy-safe encryption-unavailable
failure.

Any version change, additional production import, new COM program identifier,
remote namespace, provider mutation, accepted VARIANT type, or expanded method
surface requires a new dependency review.

## Vulnerability review

`govulncheck v1.4.0` reported no vulnerabilities for the Windows/amd64
host-verification package graph on 2026-07-14. CI must continue scanning the
Windows build graph; any future reachable finding blocks release and requires
this review to be reopened.
