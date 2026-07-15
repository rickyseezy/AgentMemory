# macOS native package

The macOS release is a per-architecture, system-domain Installer package. It
installs the signed launcher at `/usr/local/bin/agentmemory`, the independently
verified privilege helper at
`/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper`, and
the shared retained release at
`/Library/Application Support/AgentMemory/resources/bundle`.

Release engineering must first sign the reproducible native binaries with
`sign-binaries.sh`, enter those exact signed bytes and certificate bindings into
the canonical release manifest, and run `agentmemory-native-package-stage`
against the fully verified bundle. `build-package.sh` never modifies those
manifest-bound binaries. It verifies them, creates the product package, signs
the outer package with Developer ID Installer, submits that exact package to
Apple notarization, staples the ticket, and verifies the signature, ticket, and
Gatekeeper assessment before atomically publishing it.

The package does not mutate any user's agent configuration from a root
installer context. The installed `agentmemory mcp --agent <host>` entry point
performs owner-scoped first-start setup when the MCP host starts it.

Required environment variables are declared and fail closed in both scripts.
Signing identities and the `notarytool` Keychain profile are external release
inputs and must never be stored in this repository.
