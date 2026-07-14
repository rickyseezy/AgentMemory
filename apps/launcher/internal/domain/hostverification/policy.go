package hostverification

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const (
	// SupportedSchema is the only host-plan schema this launcher understands.
	SupportedSchema = uint16(1)
	maximumPlanSize = 1 << 20
)

// OperatingSystem is the closed native host family vocabulary.
type OperatingSystem string

const (
	// OperatingSystemMacOS identifies Apple's macOS host family.
	OperatingSystemMacOS OperatingSystem = "macos"
	// OperatingSystemLinux identifies the Linux kernel host family.
	OperatingSystemLinux OperatingSystem = "linux"
	// OperatingSystemWindows identifies the Microsoft Windows host family.
	OperatingSystemWindows OperatingSystem = "windows"
)

// Architecture is the closed CPU architecture vocabulary.
type Architecture string

const (
	// ArchitectureAMD64 identifies the x86-64 execution architecture.
	ArchitectureAMD64 Architecture = "amd64"
	// ArchitectureARM64 identifies the AArch64 execution architecture.
	ArchitectureARM64 Architecture = "arm64"
)

// StorageTargetMode defines where the concrete probe target is authorized.
// Exact is retained for already-authored policies; owner_selected lets one
// immutable release bind a per-user target in the parent installation plan.
type StorageTargetMode string

const (
	// StorageTargetExact binds policy and plan to one signed absolute path.
	StorageTargetExact StorageTargetMode = "exact"
	// StorageTargetOwnerSelected lets the canonical per-host plan bind the path.
	StorageTargetOwnerSelected StorageTargetMode = "owner_selected"
)

// LoopbackFamily identifies an exact local address family.
type LoopbackFamily string

const (
	// LoopbackIPv4 binds only 127.0.0.1.
	LoopbackIPv4 LoopbackFamily = "ipv4"
	// LoopbackIPv6 binds only ::1.
	LoopbackIPv6 LoopbackFamily = "ipv6"
)

// LoopbackEndpoint is one exact address-family and port pair. Addresses are
// implied as 127.0.0.1 and ::1 so a policy cannot smuggle another interface.
type LoopbackEndpoint struct {
	Family LoopbackFamily `json:"family"`
	Port   uint16         `json:"port"`
}

// PlatformTuple is one exact supported OS product, architecture, version, and
// build. It deliberately has no ranges, wildcards, or "latest" semantics.
type PlatformTuple struct {
	OperatingSystem OperatingSystem `json:"operating_system"`
	Product         string          `json:"product"`
	Architecture    Architecture    `json:"architecture"`
	Version         string          `json:"version"`
	Build           string          `json:"build"`
}

// Input contains the complete immutable host certification authority.
type Input struct {
	PolicyID             string
	SigningKeyID         string
	Platform             PlatformTuple
	MinimumCPUCores      uint32
	MinimumMemoryBytes   uint64
	MinimumFreeDiskBytes uint64
	StorageTargetMode    StorageTargetMode
	StorageTarget        string
	RequiredPorts        []LoopbackEndpoint
}

type canonicalPlan struct {
	SchemaVersion        uint16             `json:"schema_version"`
	PolicyID             string             `json:"policy_id"`
	SigningKeyID         string             `json:"signing_key_id"`
	Platform             PlatformTuple      `json:"platform"`
	MinimumCPUCores      uint32             `json:"minimum_cpu_cores"`
	MinimumMemoryBytes   uint64             `json:"minimum_memory_bytes"`
	MinimumFreeDiskBytes uint64             `json:"minimum_free_disk_bytes"`
	StorageTargetMode    StorageTargetMode  `json:"storage_target_mode"`
	StorageTarget        string             `json:"storage_target"`
	RequiredPorts        []LoopbackEndpoint `json:"required_loopback_ports"`
}

// Plan is an immutable-by-copy signed-policy payload.
type Plan struct {
	canonical            []byte
	digest               install.Digest
	policyID             string
	signingKeyID         string
	platform             PlatformTuple
	minimumCPUCores      uint32
	minimumMemoryBytes   uint64
	minimumFreeDiskBytes uint64
	storageTargetMode    StorageTargetMode
	storageTarget        string
	requiredPorts        []LoopbackEndpoint
}

// NewPlan validates and canonically encodes one v1 policy.
func NewPlan(input Input) (Plan, error) {
	document, err := documentFromInput(input)
	if err != nil {
		return Plan{}, ErrIntegrity
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return Plan{}, ErrIntegrity
	}
	return planFromDocument(document, canonical)
}

// DecodePlan accepts only exact canonical schema-v1 bytes.
func DecodePlan(raw []byte) (Plan, error) {
	if len(raw) == 0 || len(raw) > maximumPlanSize {
		return Plan{}, ErrMalformed
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document canonicalPlan
	if err := decoder.Decode(&document); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return Plan{}, ErrUnknownField
		}
		return Plan{}, ErrMalformed
	}
	if err := requireEOF(decoder); err != nil {
		return Plan{}, ErrMalformed
	}
	if document.SchemaVersion != SupportedSchema {
		return Plan{}, ErrUnsupportedSchema
	}
	plan, err := planFromDocument(document, raw)
	if err != nil {
		return Plan{}, err
	}
	if !bytes.Equal(raw, plan.canonical) {
		return Plan{}, ErrNonCanonical
	}
	return plan, nil
}

func documentFromInput(input Input) (canonicalPlan, error) {
	ports := append([]LoopbackEndpoint(nil), input.RequiredPorts...)
	slices.SortFunc(ports, compareEndpoint)
	mode := input.StorageTargetMode
	if mode == "" {
		mode = StorageTargetExact
	}
	validStorage := mode == StorageTargetExact && validTarget(input.Platform.OperatingSystem, input.StorageTarget) ||
		mode == StorageTargetOwnerSelected && input.StorageTarget == ""
	if !validIdentifier(input.PolicyID) ||
		!validIdentifier(input.SigningKeyID) || !validPlatform(input.Platform) ||
		input.MinimumCPUCores == 0 || input.MinimumMemoryBytes == 0 ||
		input.MinimumFreeDiskBytes == 0 || !validStorage ||
		!validEndpoints(ports) {
		return canonicalPlan{}, ErrIntegrity
	}
	return canonicalPlan{
		SchemaVersion: SupportedSchema,
		PolicyID:      input.PolicyID, SigningKeyID: input.SigningKeyID, Platform: input.Platform,
		MinimumCPUCores: input.MinimumCPUCores, MinimumMemoryBytes: input.MinimumMemoryBytes,
		MinimumFreeDiskBytes: input.MinimumFreeDiskBytes, StorageTargetMode: mode, StorageTarget: input.StorageTarget,
		RequiredPorts: ports,
	}, nil
}

func planFromDocument(document canonicalPlan, supplied []byte) (Plan, error) {
	normalized, err := documentFromInput(Input{
		PolicyID: document.PolicyID, SigningKeyID: document.SigningKeyID,
		Platform: document.Platform, MinimumCPUCores: document.MinimumCPUCores,
		MinimumMemoryBytes: document.MinimumMemoryBytes, MinimumFreeDiskBytes: document.MinimumFreeDiskBytes,
		StorageTargetMode: document.StorageTargetMode, StorageTarget: document.StorageTarget, RequiredPorts: document.RequiredPorts,
	})
	if err != nil {
		return Plan{}, ErrIntegrity
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return Plan{}, ErrIntegrity
	}
	if supplied != nil && !bytes.Equal(supplied, canonical) {
		return Plan{}, ErrNonCanonical
	}
	return Plan{
		canonical: canonical, digest: install.DigestBytes(canonical),
		policyID: normalized.PolicyID, signingKeyID: normalized.SigningKeyID, platform: normalized.Platform,
		minimumCPUCores: normalized.MinimumCPUCores, minimumMemoryBytes: normalized.MinimumMemoryBytes,
		minimumFreeDiskBytes: normalized.MinimumFreeDiskBytes, storageTargetMode: normalized.StorageTargetMode,
		storageTarget: normalized.StorageTarget,
		requiredPorts: append([]LoopbackEndpoint(nil), normalized.RequiredPorts...),
	}, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return ErrMalformed
}

func validPlatform(platform PlatformTuple) bool {
	if platform.OperatingSystem != OperatingSystemMacOS && platform.OperatingSystem != OperatingSystemLinux &&
		platform.OperatingSystem != OperatingSystemWindows {
		return false
	}
	return (platform.Architecture == ArchitectureAMD64 || platform.Architecture == ArchitectureARM64) &&
		validIdentifier(platform.Product) && validVersionToken(platform.Version) && validVersionToken(platform.Build)
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 || value != strings.ToLower(value) {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			continue
		}
		if index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validVersionToken(value string) bool {
	if value == "" || len(value) > 128 || strings.EqualFold(value, "latest") {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("._+-~", character) {
			continue
		}
		return false
	}
	return true
}

func validTarget(os OperatingSystem, target string) bool {
	if target == "" || len(target) > 4096 || strings.IndexByte(target, 0) >= 0 {
		return false
	}
	switch os {
	case OperatingSystemMacOS, OperatingSystemLinux:
		if !strings.HasPrefix(target, "/") || strings.Contains(target, "//") || target != "/" && strings.HasSuffix(target, "/") {
			return false
		}
		return !unsafePathComponent(strings.Split(target, "/"))
	case OperatingSystemWindows:
		if len(target) < 3 || target[1] != ':' || target[2] != '\\' ||
			!asciiLetter(target[0]) ||
			strings.Contains(target, "/") || strings.Contains(target, "\\\\") || strings.HasSuffix(target, "\\") {
			return false
		}
		return !unsafePathComponent(strings.Split(target[3:], "\\"))
	}
	return false
}

func asciiLetter(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z'
}

func unsafePathComponent(parts []string) bool {
	for _, part := range parts {
		if part == "." || part == ".." {
			return true
		}
	}
	return false
}

func validEndpoints(endpoints []LoopbackEndpoint) bool {
	if len(endpoints) == 0 || len(endpoints) > 32 {
		return false
	}
	for index, endpoint := range endpoints {
		if endpoint.Port == 0 || endpoint.Family != LoopbackIPv4 && endpoint.Family != LoopbackIPv6 {
			return false
		}
		if index > 0 && compareEndpoint(endpoints[index-1], endpoint) == 0 {
			return false
		}
	}
	return true
}

func compareEndpoint(left, right LoopbackEndpoint) int {
	if left.Family < right.Family {
		return -1
	}
	if left.Family > right.Family {
		return 1
	}
	return int(left.Port) - int(right.Port)
}

// CanonicalBytes returns a caller-owned copy of signed policy bytes.
func (p Plan) CanonicalBytes() []byte { return append([]byte(nil), p.canonical...) }

// Digest returns the exact canonical host-plan binding.
func (p Plan) Digest() install.Digest { return p.digest }

// PolicyID returns the signed policy namespace.
func (p Plan) PolicyID() string { return p.policyID }

// SigningKeyID returns the declared detached-signature key.
func (p Plan) SigningKeyID() string { return p.signingKeyID }

// Platform returns the exact supported host tuple.
func (p Plan) Platform() PlatformTuple { return p.platform }

// MinimumCPUCores returns the signed CPU floor.
func (p Plan) MinimumCPUCores() uint32 { return p.minimumCPUCores }

// MinimumMemoryBytes returns the signed physical-memory floor.
func (p Plan) MinimumMemoryBytes() uint64 { return p.minimumMemoryBytes }

// MinimumFreeDiskBytes returns the signed target free-space floor.
func (p Plan) MinimumFreeDiskBytes() uint64 { return p.minimumFreeDiskBytes }

// StorageTarget returns the exact owner-controlled probe target.
func (p Plan) StorageTarget() string { return p.storageTarget }

// StorageTargetMode returns whether the target is release-exact or selected
// and bound by the per-host parent installation plan.
func (p Plan) StorageTargetMode() StorageTargetMode { return p.storageTargetMode }

// RequiredPorts returns a caller-owned copy of exact loopback endpoints.
func (p Plan) RequiredPorts() []LoopbackEndpoint {
	return append([]LoopbackEndpoint(nil), p.requiredPorts...)
}

// Valid reports whether the immutable representation still matches all fields.
func (p Plan) Valid() bool {
	rebuilt, err := NewPlan(Input{
		PolicyID: p.policyID, SigningKeyID: p.signingKeyID,
		Platform: p.platform, MinimumCPUCores: p.minimumCPUCores,
		MinimumMemoryBytes: p.minimumMemoryBytes, MinimumFreeDiskBytes: p.minimumFreeDiskBytes,
		StorageTargetMode: p.storageTargetMode, StorageTarget: p.storageTarget, RequiredPorts: p.requiredPorts,
	})
	return err == nil && bytes.Equal(rebuilt.canonical, p.canonical) && rebuilt.digest.Equal(p.digest)
}
