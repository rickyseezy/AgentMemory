package agentconfig

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// MaxDocumentBytes is the fail-closed host-neutral JSON input limit.
	MaxDocumentBytes  = 1 << 20
	managedServerName = "agentmemory"
	managedByValue    = "agentmemory"
	markerVersion     = uint32(1)
	maximumCommandLen = 4096
)

// AgentHost identifies the documented host configuration and launcher
// compatibility contract. It is not a model-provider identity: GLM-backed
// tools select the concrete host they run in whenever possible.
type AgentHost string

const (
	// AgentHostGeneric uses the portable top-level mcpServers JSON contract.
	AgentHostGeneric AgentHost = "generic"
	// AgentHostCodex uses Codex's documented config.toml MCP tables.
	AgentHostCodex AgentHost = "codex"
	// AgentHostClaude uses Claude Code/Desktop's documented JSON MCP entry.
	AgentHostClaude AgentHost = "claude"
	// AgentHostGemini uses Gemini CLI's documented settings.json MCP entry.
	AgentHostGemini AgentHost = "gemini"
	// AgentHostCursor uses Cursor's documented global ~/.cursor/mcp.json
	// portable MCP entry. Project-local Cursor configuration is deliberately
	// not mutated by the installer.
	AgentHostCursor AgentHost = "cursor"
	// AgentHostGLM is reserved for a certified GLM-native host exposing the
	// portable JSON MCP contract; GLM used inside Claude/Codex selects that host.
	AgentHostGLM AgentHost = "glm"
	// AgentHostCustom is the path-neutral MCP registration contract. The host
	// or plugin marketplace owns its configuration and invokes the exact signed
	// launcher; AgentMemory verifies the handshake without guessing or mutating
	// a host configuration file.
	AgentHostCustom AgentHost = "custom"
)

// Valid reports whether the host has a closed configuration policy.
func (h AgentHost) Valid() bool {
	switch h {
	case AgentHostGeneric, AgentHostCodex, AgentHostClaude, AgentHostGemini, AgentHostCursor, AgentHostGLM,
		AgentHostCustom:
		return true
	default:
		return false
	}
}

// Digest is one SHA-256 value used to bind exact configuration and canonical
// managed-entry bytes.
type Digest [sha256.Size]byte

// DigestBytes hashes bytes exactly as supplied.
func DigestBytes(value []byte) Digest { return sha256.Sum256(value) }

// DigestFromHex parses one lowercase SHA-256 digest.
func DigestFromHex(value string) (Digest, error) {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return Digest{}, fmt.Errorf("%w: digest encoding is invalid", ErrInvalidTarget)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return Digest{}, fmt.Errorf("%w: digest encoding is invalid", ErrInvalidTarget)
	}
	var digest Digest
	copy(digest[:], decoded)
	return digest, nil
}

// String returns the lowercase fixed-width encoding.
func (d Digest) String() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether no digest was supplied.
func (d Digest) IsZero() bool {
	return d.Equal(Digest{})
}

// Equal compares digest bytes without a content-dependent early return.
func (d Digest) Equal(other Digest) bool { return hmac.Equal(d[:], other[:]) }

// Target is the exact AgentMemory-managed MCP entry desired by one signed
// installation. The command path is platform-validated before construction.
type Target struct {
	host           AgentHost
	installationID string
	entryID        string
	command        string
	launcherDigest Digest
}

// NewTarget validates stable ownership and signed-launcher metadata.
func NewTarget(
	installationID string,
	entryID string,
	command string,
	launcherDigest Digest,
) (Target, error) {
	return NewTargetForAgent(AgentHostGeneric, installationID, entryID, command, launcherDigest)
}

// NewTargetForAgent binds the desired entry to one documented agent-host
// format and exact launcher mode.
func NewTargetForAgent(
	host AgentHost,
	installationID string,
	entryID string,
	command string,
	launcherDigest Digest,
) (Target, error) {
	if !validUUIDv7(installationID) || !validUUIDv7(entryID) ||
		!host.Valid() ||
		command == "" || len(command) > maximumCommandLen ||
		strings.ContainsAny(command, "\x00\r\n") || launcherDigest.IsZero() {
		return Target{}, ErrInvalidTarget
	}
	return Target{
		host:           host,
		installationID: installationID,
		entryID:        entryID,
		command:        command,
		launcherDigest: launcherDigest,
	}, nil
}

// Host returns the exact host-format and launcher mode.
func (t Target) Host() AgentHost { return t.host }

// InstallationID returns the owning installation UUIDv7.
func (t Target) InstallationID() string { return t.installationID }

// EntryID returns the stable managed-entry UUIDv7.
func (t Target) EntryID() string { return t.entryID }

// Command returns the platform-validated signed launcher path.
func (t Target) Command() string { return t.command }

// LauncherDigest returns the expected signed launcher SHA-256.
func (t Target) LauncherDigest() Digest { return t.launcherDigest }

// Arguments returns the exact host-neutral generic MCP invocation.
func (t Target) Arguments() []string { return []string{"mcp", "--agent", string(t.host)} }

func validUUIDv7(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' ||
		value[14] != '7' || !strings.ContainsRune("89ab", rune(value[19])) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
