# Custom agent registration contract

| Field | Value |
|---|---|
| Contract ID | `agentmemory.custom-agent-registration.v1` |
| Transport | MCP stdio |
| Launcher arguments | `mcp --agent custom` |
| Configuration owner | The custom host or its plugin/marketplace installer |
| AgentMemory host-config mutation | None |
| Status | Production contract for PF-001 |

This contract is the path-neutral installation boundary for any MCP-capable AI agent that does
not have a separately certified AgentMemory configuration adapter. It lets a nontechnical user
install the host's AgentMemory plugin while preventing AgentMemory from guessing an undocumented
configuration path or format.

Normative terms such as MUST, MUST NOT, and SHOULD are requirements for a conforming custom-host
adapter.

## Registration responsibilities

The host or its plugin/marketplace installer MUST own creation, update, and removal of its MCP
configuration entry. It MUST register the packaged, platform-verified AgentMemory launcher as an
argv-based stdio process with exactly these arguments:

```text
<absolute packaged launcher path> mcp --agent custom
```

The adapter:

- MUST obtain the absolute launcher path from its installed package authority; it MUST NOT resolve
  a mutable executable from `PATH`, accept a launcher path from a prompt, or invoke a shell;
- MUST pass exactly the two arguments `--agent` and `custom` after the `mcp` command, with no URL,
  credential, configuration path, workspace path, or opaque adapter payload;
- MUST inherit the active project directory as the child working directory without normalizing it
  through a shell string;
- MUST connect the launcher's stdin and stdout directly to MCP framing and reserve stderr for
  bounded diagnostics;
- MUST preserve byte-exact stdio, cancellation, EOF, and process-exit behavior;
- MUST start one launcher process per MCP session and MUST NOT reuse a process across unrelated
  operating-system users; and
- MUST NOT inject provider credentials, Docker endpoints, database credentials, proxy secrets, or
  authority-changing environment variables.

An adapter that cannot meet every item is unsupported. AgentMemory does not fall back to editing a
guessed file or asking the user to run a terminal command.

## AgentMemory verification behavior

On first invocation, `--agent custom` participates in the same protected first-start and resumable
installation saga as a built-in host. The signed installation plan contains an AgentMemory-owned
binding locator under the invoking user's AgentMemory state root. That locator is a namespace
binding only: the custom registration application never passes it to a filesystem configuration
store and never reads, creates, backs up, replaces, or removes a custom-host file.

During `MergeAgentConfiguration`, AgentMemory:

1. reconstructs the exact release-verified launcher authority and digest;
2. derives the canonical `agentmemory.custom-agent-registration.v1` binding from the installation
   ID, stable entry ID, custom host mode, launcher path/digest, and exact argv;
3. executes a bounded MCP `initialize`, `notifications/initialized`, and `tools/list` exchange
   through the no-shell publisher-bound process runner;
4. accepts only the AgentMemory server identity, a supported MCP revision, and the exact three-tool
   bootstrap surface while installation is incomplete;
5. records the deterministic `verify_custom` result digest in the authenticated PF-001 operation
   journal; and
6. leaves every host-owned configuration byte untouched on success, failure, cancellation, retry,
   upgrade, and uninstall.

No managed-entry digest is accepted for custom mode because AgentMemory does not own a custom-host
document. Supplying one is an integrity error. A failed or malformed handshake remains recoverable
and NotReady; it never causes a host-config compensation attempt.

## Runtime identity and model neutrality

`custom` identifies the bootstrap registration contract, not a model provider and not permission to
invent host telemetry. The MCP client's protocol identity and the later certified
`AdapterCapabilityManifest` provide runtime provenance. A GLM, Qwen, Claude, Gemini, OpenAI, or
other model used inside a custom host still uses this host contract; model selection never changes
installation authority.

## Conformance requirements

A custom-host integration is certifiable only when automated tests prove all of the following:

- exact argv and absolute packaged launcher selection, without shell or mutable `PATH` resolution;
- active-directory inheritance for spaces, Unicode, metacharacters, symlinks, worktrees, Windows
  drive paths, and supported UNC cases;
- stdout contains MCP frames only and stderr cannot contaminate protocol output;
- successful initialize/tool discovery during first-start, retry, and Ready handoff;
- malformed frames, extra stdout, unsupported MCP versions, wrong server identity, wrong tool set,
  timeout, cancellation, EOF, and abrupt host termination fail safely;
- two concurrent directories create distinct launcher sessions without sharing credentials or
  mounts;
- no custom-host configuration store method is called by AgentMemory;
- no secret, path, raw process error, or host-owned document enters the installation journal; and
- update/uninstall changes only the host-owned registration entry selected by that host's own
  ownership mechanism.

Native certification evidence MUST name the host/version, platform/architecture, exact launcher
digest, adapter package digest, contract ID, and conformance result. Documentation or a passing unit
test is not a substitute for that evidence.

## Illustrative host-owned entry

The following shape is illustrative only. It is not a file format or location that AgentMemory will
discover or mutate:

```json
{
  "command": "/absolute/package/path/agentmemory",
  "args": ["mcp", "--agent", "custom"]
}
```

The host adapter must translate the exact command/argv contract into its own supported registration
API or configuration format.

## Protocol basis

The contract follows the official MCP
[stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports),
[connection lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle), and
[tools discovery](https://modelcontextprotocol.io/specification/2025-11-25/server/tools) contracts.
The installer verifier sends `initialize` first and waits for its response before sending
`notifications/initialized`; only then does it send `tools/list`. Every message is one UTF-8
newline-delimited JSON-RPC value, stdout is protocol-only, stderr is bounded diagnostics, stdin is
closed for graceful shutdown, and cancellation settles the complete process tree.
