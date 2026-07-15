# Windows native package

The Windows release is a WiX 7.0.0 per-machine MSI for x64 or ARM64. It
installs the signed launcher at `C:\Program Files\AgentMemory\agentmemory.exe`,
the independently verified privilege helper below `bin`, and the shared
retained release below `resources\bundle`.

`Sign-Binaries.ps1` signs the reproducible launcher and helper once with
SHA-256 Authenticode and an approved RFC 3161 timestamp, verifies the exact
signer-certificate SHA-256 digest, and atomically publishes the signed inputs.
Those exact bytes must then be entered into the canonical release manifest.
`agentmemory-native-package-stage` verifies the complete release and stages
only the manifest-bound bytes. `Build-Package.ps1` verifies the payload and
certificate again, builds and validates the MSI with pinned WiX, signs the MSI,
and publishes it only after SignTool and certificate verification succeed.

The MSI contains no custom action and does not guess or mutate a user's agent
configuration from an elevated installer context. The installed
`agentmemory mcp --agent <host>` command performs owner-scoped first-start setup
when the configured MCP host starts it.

WiX licensing/maintenance-fee approval, the protected Authenticode signing
operation, the exact signer certificate, and the timestamp authority are
external release inputs. They must never be replaced by a development
certificate in a production release.
