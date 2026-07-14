package agentconfigadapter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/pelletier/go-toml/v2"
	port "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/agentconfig"
	domain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
)

const (
	codexManagedBegin = "# agentmemory-managed-begin v1"
	codexManagedEnd   = "# agentmemory-managed-end v1"
	managedServerName = "agentmemory"
)

// Digest is the host-neutral configuration digest used by this syntax adapter.
type Digest = domain.Digest

// MergePlan is the immutable domain merge decision returned by this adapter.
type MergePlan = domain.MergePlan

// Target is the exact signed launcher entry desired in Codex configuration.
type Target = domain.Target

const (
	// AgentHostCodex selects Codex's documented TOML configuration format.
	AgentHostCodex = domain.AgentHostCodex
	// MaxDocumentBytes is the shared bounded configuration input size.
	MaxDocumentBytes = domain.MaxDocumentBytes
	// MergeActionAdd creates a new managed entry.
	MergeActionAdd = domain.MergeActionAdd
	// MergeActionNoChange confirms an identical managed entry.
	MergeActionNoChange = domain.MergeActionNoChange
	// MergeActionReplaceManaged replaces only a receipt-bound managed entry.
	MergeActionReplaceManaged = domain.MergeActionReplaceManaged
)

var (
	// ErrAmbiguousOwnership rejects an entry without exact ownership evidence.
	ErrAmbiguousOwnership = domain.ErrAmbiguousOwnership
	// ErrInvalidDocument rejects malformed or unsupported TOML.
	ErrInvalidDocument = domain.ErrInvalidDocument
	// ErrInvalidTarget rejects an invalid signed-launcher target.
	ErrInvalidTarget = domain.ErrInvalidTarget
	// ErrManagedEntryConflict rejects a contradictory managed entry.
	ErrManagedEntryConflict = domain.ErrManagedEntryConflict
)

// CodexPolicy is the syntax adapter for Codex's documented config.toml MCP
// tables. It performs no filesystem IO and returns domain-owned merge plans.
type CodexPolicy struct{}

// Supports reports the one exact host format owned by this adapter.
func (CodexPolicy) Supports(host domain.AgentHost) bool { return host == domain.AgentHostCodex }

// Validate rejects malformed or ambiguously owned Codex TOML.
func (CodexPolicy) Validate(contents []byte) error {
	_, err := parseCodexDocument(contents)
	return err
}

// PlanMerge constructs one byte-preserving Codex mutation plan.
func (CodexPolicy) PlanMerge(
	contents []byte,
	existed bool,
	target domain.Target,
	expected domain.Digest,
) (domain.MergePlan, error) {
	return planCodexMerge(contents, existed, target, expected)
}

// VerifyManagedEntry proves exact Codex configuration after publication.
func (CodexPolicy) VerifyManagedEntry(contents []byte, target domain.Target) error {
	return verifyCodexManagedEntry(contents, target)
}

type codexDocument struct {
	contents     []byte
	managedBlock []byte
	managedStart int
	server       map[string]any
}

type codexOwnership struct {
	installationID string
	entryID        string
	launcherDigest Digest
}

func parseCodexDocument(contents []byte) (codexDocument, error) {
	if len(contents) > MaxDocumentBytes || !utf8.Valid(contents) {
		return codexDocument{}, ErrInvalidDocument
	}

	root := make(map[string]any)
	if len(contents) > 0 {
		decoder := toml.NewDecoder(bytes.NewReader(contents))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&root); err != nil {
			return codexDocument{}, ErrInvalidDocument
		}
	}

	var server map[string]any
	if encodedServers, found := root["mcp_servers"]; found {
		servers, ok := encodedServers.(map[string]any)
		if !ok {
			return codexDocument{}, ErrInvalidDocument
		}
		if encodedServer, exists := servers[managedServerName]; exists {
			server, ok = encodedServer.(map[string]any)
			if !ok {
				return codexDocument{}, ErrAmbiguousOwnership
			}
		}
	}

	managedStart, managedBlock, found := codexManagedSuffix(contents)
	containsMarker := bytes.Contains(contents, []byte(codexManagedBegin)) ||
		bytes.Contains(contents, []byte(codexManagedEnd))
	if server != nil && !found {
		return codexDocument{}, ErrAmbiguousOwnership
	}
	if server == nil && containsMarker {
		return codexDocument{}, ErrAmbiguousOwnership
	}
	if found && (!containsMarker || server == nil) {
		return codexDocument{}, ErrAmbiguousOwnership
	}

	return codexDocument{
		contents:     append([]byte(nil), contents...),
		managedBlock: managedBlock,
		managedStart: managedStart,
		server:       server,
	}, nil
}

func codexManagedSuffix(contents []byte) (int, []byte, bool) {
	begin := []byte(codexManagedBegin + "\n")
	start := bytes.LastIndex(contents, begin)
	if start < 0 || (start > 0 && contents[start-1] != '\n') {
		return 0, nil, false
	}
	block := contents[start:]
	if !bytes.HasSuffix(block, []byte(codexManagedEnd+"\n")) ||
		bytes.Count(contents, []byte(codexManagedBegin)) != 1 ||
		bytes.Count(contents, []byte(codexManagedEnd)) != 1 {
		return 0, nil, false
	}
	return start, append([]byte(nil), block...), true
}

func planCodexMerge(
	original []byte,
	originalExisted bool,
	target Target,
	expectedManagedEntryDigest Digest,
) (MergePlan, error) {
	if target.Host() != AgentHostCodex || target.Command() == "" || target.LauncherDigest().IsZero() {
		return MergePlan{}, ErrInvalidTarget
	}
	if !originalExisted && len(original) != 0 {
		return MergePlan{}, ErrInvalidDocument
	}
	parsed, err := parseCodexDocument(original)
	if err != nil {
		return MergePlan{}, err
	}
	desired, desiredDigest, err := desiredCodexBlock(target)
	if err != nil {
		return MergePlan{}, err
	}

	action := MergeActionAdd
	if parsed.server != nil {
		ownership, currentDigest, inspectErr := inspectCodexManagedBlock(parsed.managedBlock)
		if inspectErr != nil || ownership.installationID != target.InstallationID() || ownership.entryID != target.EntryID() {
			return MergePlan{}, ErrAmbiguousOwnership
		}
		if err := verifyCodexServer(parsed.server, target); err == nil && currentDigest.Equal(desiredDigest) {
			return domain.NewMergePlan(
				MergeActionNoChange,
				originalExisted,
				original,
				original,
				desiredDigest,
				target,
			)
		}
		if expectedManagedEntryDigest.IsZero() || !currentDigest.Equal(expectedManagedEntryDigest) {
			return MergePlan{}, ErrManagedEntryConflict
		}
		action = MergeActionReplaceManaged
	}

	after := make([]byte, 0, len(original)+len(desired)+1)
	if action == MergeActionReplaceManaged {
		after = append(after, original[:parsed.managedStart]...)
	} else {
		after = append(after, original...)
		if len(after) > 0 && after[len(after)-1] != '\n' {
			after = append(after, '\n')
		}
	}
	after = append(after, desired...)
	if len(after) > MaxDocumentBytes {
		return MergePlan{}, ErrInvalidDocument
	}
	if _, err := parseCodexDocument(after); err != nil {
		return MergePlan{}, err
	}
	return domain.NewMergePlan(action, originalExisted, original, after, desiredDigest, target)
}

func desiredCodexBlock(target Target) ([]byte, Digest, error) {
	command, err := json.Marshal(target.Command())
	if err != nil {
		return nil, Digest{}, fmt.Errorf("%w: encode Codex command", ErrInvalidTarget)
	}
	block := []byte(strings.Join([]string{
		codexManagedBegin,
		`# installation_id = "` + target.InstallationID() + `"`,
		`# entry_id = "` + target.EntryID() + `"`,
		`# launcher_sha256 = "` + target.LauncherDigest().String() + `"`,
		"[mcp_servers." + managedServerName + "]",
		"command = " + string(command),
		`args = ["mcp", "--agent", "codex"]`,
		"required = true",
		codexManagedEnd,
		"",
	}, "\n"))
	return block, domain.DigestBytes(block), nil
}

func inspectCodexManagedBlock(block []byte) (codexOwnership, Digest, error) {
	lines := strings.Split(string(block), "\n")
	if len(lines) != 10 || lines[0] != codexManagedBegin || lines[4] != "[mcp_servers.agentmemory]" ||
		lines[6] != `args = ["mcp", "--agent", "codex"]` || lines[7] != "required = true" ||
		lines[8] != codexManagedEnd || lines[9] != "" {
		return codexOwnership{}, Digest{}, ErrAmbiguousOwnership
	}
	installationID, ok := parseCodexMarkerValue(lines[1], "# installation_id = ")
	if !ok || !validUUIDv7(installationID) {
		return codexOwnership{}, Digest{}, ErrAmbiguousOwnership
	}
	entryID, ok := parseCodexMarkerValue(lines[2], "# entry_id = ")
	if !ok || !validUUIDv7(entryID) {
		return codexOwnership{}, Digest{}, ErrAmbiguousOwnership
	}
	launcherHex, ok := parseCodexMarkerValue(lines[3], "# launcher_sha256 = ")
	launcherDigest, digestErr := domain.DigestFromHex(launcherHex)
	if !ok || digestErr != nil || launcherDigest.IsZero() {
		return codexOwnership{}, Digest{}, ErrAmbiguousOwnership
	}
	if !strings.HasPrefix(lines[5], "command = ") {
		return codexOwnership{}, Digest{}, ErrAmbiguousOwnership
	}
	var command string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[5], "command = ")), &command); err != nil || command == "" {
		return codexOwnership{}, Digest{}, ErrAmbiguousOwnership
	}
	return codexOwnership{
		installationID: installationID,
		entryID:        entryID,
		launcherDigest: launcherDigest,
	}, domain.DigestBytes(block), nil
}

func parseCodexMarkerValue(line string, prefix string) (string, bool) {
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	encoded := strings.TrimPrefix(line, prefix)
	var value string
	if json.Unmarshal([]byte(encoded), &value) != nil || encoded != `"`+value+`"` {
		return "", false
	}
	return value, true
}

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

func verifyCodexManagedEntry(contents []byte, target Target) error {
	if target.Host() != AgentHostCodex {
		return ErrInvalidTarget
	}
	parsed, err := parseCodexDocument(contents)
	if err != nil {
		return err
	}
	if parsed.server == nil {
		return ErrManagedEntryConflict
	}
	ownership, currentDigest, err := inspectCodexManagedBlock(parsed.managedBlock)
	if err != nil || ownership.installationID != target.InstallationID() || ownership.entryID != target.EntryID() {
		return ErrAmbiguousOwnership
	}
	desired, desiredDigest, err := desiredCodexBlock(target)
	if err != nil {
		return err
	}
	if len(desired) == 0 || !currentDigest.Equal(desiredDigest) {
		return ErrManagedEntryConflict
	}
	return verifyCodexServer(parsed.server, target)
}

func verifyCodexServer(server map[string]any, target Target) error {
	if len(server) != 3 {
		return ErrManagedEntryConflict
	}
	command, ok := server["command"].(string)
	if !ok || command != target.Command() {
		return ErrManagedEntryConflict
	}
	args, ok := server["args"].([]any)
	if !ok || len(args) != 3 {
		return ErrManagedEntryConflict
	}
	wantArgs := target.Arguments()
	for index, value := range args {
		argument, stringOK := value.(string)
		if !stringOK || argument != wantArgs[index] {
			return ErrManagedEntryConflict
		}
	}
	required, ok := server["required"].(bool)
	if !ok || !required {
		return ErrManagedEntryConflict
	}
	return nil
}

var _ port.DocumentPolicy = CodexPolicy{}
