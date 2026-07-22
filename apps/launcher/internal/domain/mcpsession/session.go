// Package mcpsession owns the immutable PF-005 session sandbox contract.
package mcpsession

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	workspaceTarget      = "/workspace"
	credentialTarget     = "/run/secrets/agentmemory-session"
	temporaryTarget      = "/tmp"
	bindPropagation      = "rprivate"
	maximumIdentityBytes = 256
	maximumPathBytes     = 4096
	maximumImageBytes    = 1024
	maximumNetworkBytes  = 128
	credentialMaximumAge = 12 * time.Hour
	sessionMemoryBytes   = 512 * 1024 * 1024
	sessionNanoCPUs      = 1_000_000_000
	sessionPIDsLimit     = 128
	sha256HexLength      = 64
)

var errInvalidSession = errors.New("MCP session authority is invalid")

// GitCoverage reports whether the selected mount includes all repository metadata.
type GitCoverage string

const (
	// GitCoverageNone means the workspace is not a Git checkout.
	GitCoverageNone GitCoverage = "none"
	// GitCoveragePartial means identity was resolved on the host but metadata lies outside the mount.
	GitCoveragePartial GitCoverage = "partial"
	// GitCoverageComplete means repository and worktree metadata are visible from the selected root.
	GitCoverageComplete GitCoverage = "complete"
)

// WorkspaceIdentityInput is trusted host-path and Git evidence from platform adapters.
type WorkspaceIdentityInput struct {
	LogicalPath     string
	RealPath        string
	DeviceIdentity  string
	PathFingerprint string
	GitRepositoryID string
	GitWorktreeID   string
	GitCoverage     GitCoverage
}

// WorkspaceIdentity binds logical and real host paths without widening the mount.
type WorkspaceIdentity struct{ input WorkspaceIdentityInput }

// NewWorkspaceIdentity validates already-canonical host identity evidence.
func NewWorkspaceIdentity(input WorkspaceIdentityInput) (WorkspaceIdentity, error) {
	if !validHostPath(input.LogicalPath) || !validHostPath(input.RealPath) ||
		!validOpaque(input.DeviceIdentity) || !validSHA256(input.PathFingerprint) ||
		!validGitEvidence(input.GitRepositoryID, input.GitWorktreeID, input.GitCoverage) {
		return WorkspaceIdentity{}, errInvalidSession
	}
	return WorkspaceIdentity{input: input}, nil
}

// LogicalPath returns the user-selected canonical logical path.
func (w WorkspaceIdentity) LogicalPath() string { return w.input.LogicalPath }

// RealPath returns the resolved source mounted into the transient container.
func (w WorkspaceIdentity) RealPath() string { return w.input.RealPath }

// DeviceIdentity returns the host volume/device binding.
func (w WorkspaceIdentity) DeviceIdentity() string { return w.input.DeviceIdentity }

// PathFingerprint returns the keyed path identity proof.
func (w WorkspaceIdentity) PathFingerprint() string { return w.input.PathFingerprint }

// GitRepositoryID returns the host-resolved repository identity, when present.
func (w WorkspaceIdentity) GitRepositoryID() string { return w.input.GitRepositoryID }

// GitWorktreeID returns the host-resolved worktree identity, when present.
func (w WorkspaceIdentity) GitWorktreeID() string { return w.input.GitWorktreeID }

// GitCoverage returns complete, partial, or absent Git metadata coverage.
func (w WorkspaceIdentity) GitCoverage() GitCoverage { return w.input.GitCoverage }

func (w WorkspaceIdentity) valid() bool {
	_, err := NewWorkspaceIdentity(w.input)
	return err == nil
}

// CredentialLease is a reference to owner-protected short-lived credential material.
type CredentialLease struct {
	digest        string
	protectedFile string
	issuedAt      time.Time
	expiresAt     time.Time
}

// NewCredentialLease validates a credential reference without accepting secret bytes.
func NewCredentialLease(
	digest string,
	protectedFile string,
	issuedAt time.Time,
	expiresAt time.Time,
) (CredentialLease, error) {
	issuedAt = issuedAt.UTC().Truncate(time.Microsecond)
	expiresAt = expiresAt.UTC().Truncate(time.Microsecond)
	if !validSHA256(digest) || !validHostPath(protectedFile) || issuedAt.IsZero() ||
		expiresAt.IsZero() || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > credentialMaximumAge {
		return CredentialLease{}, errInvalidSession
	}
	return CredentialLease{
		digest: digest, protectedFile: protectedFile, issuedAt: issuedAt, expiresAt: expiresAt,
	}, nil
}

// Digest returns the non-secret credential binding.
func (c CredentialLease) Digest() string { return c.digest }

// ProtectedFile returns the exact owner-protected source reference.
func (c CredentialLease) ProtectedFile() string { return c.protectedFile }

// IssuedAt returns the normalized credential issue time.
func (c CredentialLease) IssuedAt() time.Time { return c.issuedAt }

// ExpiresAt returns the normalized credential expiry time.
func (c CredentialLease) ExpiresAt() time.Time { return c.expiresAt }

func (c CredentialLease) valid() bool {
	_, err := NewCredentialLease(c.digest, c.protectedFile, c.issuedAt, c.expiresAt)
	return err == nil
}

// Valid reports whether the lease still satisfies its immutable structural contract.
func (c CredentialLease) Valid() bool { return c.valid() }

// ExecutionPlanInput contains only release-verified session authority.
type ExecutionPlanInput struct {
	SessionID       string
	InstallationID  string
	AgentID         string
	ReleaseID       string
	ManifestDigest  string
	SecurityEpoch   uint64
	RuntimeEndpoint string
	Workspace       WorkspaceIdentity
	Image           string
	Network         string
	Credential      CredentialLease
}

// Mount is one exact, non-widening container mount.
type Mount struct {
	source            string
	target            string
	readOnly          bool
	propagation       string
	recursiveReadOnly bool
}

// Source returns the host source path.
func (m Mount) Source() string { return m.source }

// Target returns the fixed container target.
func (m Mount) Target() string { return m.target }

// ReadOnly reports whether Docker must deny writes.
func (m Mount) ReadOnly() bool { return m.readOnly }

// Propagation returns the fixed bind-propagation policy.
func (m Mount) Propagation() string { return m.propagation }

// RecursiveReadOnly reports whether nested mounts must also be read-only.
func (m Mount) RecursiveReadOnly() bool { return m.recursiveReadOnly }

// SandboxSecurity is the closed PF-005 container security profile.
type SandboxSecurity struct{}

// AutoRemove requires cleanup by Docker and explicit post-run verification.
func (SandboxSecurity) AutoRemove() bool { return true }

// ReadOnlyRootFS denies mutation of the image filesystem.
func (SandboxSecurity) ReadOnlyRootFS() bool { return true }

// DropAllCapabilities requires Linux capability set ALL to be removed.
func (SandboxSecurity) DropAllCapabilities() bool { return true }

// NoNewPrivileges prevents privilege gain through exec.
func (SandboxSecurity) NoNewPrivileges() bool { return true }

// TTY remains false because stdout belongs exclusively to MCP frames.
func (SandboxSecurity) TTY() bool { return false }

// PublishPorts remains false because sessions cannot listen on the host.
func (SandboxSecurity) PublishPorts() bool { return false }

// MountDockerSocket remains false to prevent daemon-level privilege escalation.
func (SandboxSecurity) MountDockerSocket() bool { return false }

// Privileged remains false.
func (SandboxSecurity) Privileged() bool { return false }

// PIDsLimit returns the certified process limit.
func (SandboxSecurity) PIDsLimit() int64 { return sessionPIDsLimit }

// MemoryBytes returns the certified memory limit.
func (SandboxSecurity) MemoryBytes() int64 { return sessionMemoryBytes }

// NanoCPUs returns the certified CPU quota in Docker nanocpus.
func (SandboxSecurity) NanoCPUs() int64 { return sessionNanoCPUs }

// TmpfsTarget returns the sole writable scratch mount.
func (SandboxSecurity) TmpfsTarget() string { return temporaryTarget }

// ExecutionPlan is the immutable command authority consumed by the Docker adapter.
type ExecutionPlan struct {
	input      ExecutionPlanInput
	workspace  Mount
	credential Mount
}

// Valid reports whether the plan still satisfies every immutable authority invariant.
func (p ExecutionPlan) Valid() bool {
	_, err := NewExecutionPlan(p.input)
	return err == nil
}

// NewExecutionPlan validates identity and fixes every least-privilege control.
func NewExecutionPlan(input ExecutionPlanInput) (ExecutionPlan, error) {
	if !validUUIDv7(input.SessionID) || !validUUIDv7(input.InstallationID) ||
		!validAgentID(input.AgentID) || !validOpaque(input.ReleaseID) ||
		!validSHA256(input.ManifestDigest) || input.SecurityEpoch == 0 ||
		!validRuntimeEndpoint(input.RuntimeEndpoint) || !input.Workspace.valid() || !validImage(input.Image) ||
		!validNetwork(input.Network) || !input.Credential.valid() {
		return ExecutionPlan{}, errInvalidSession
	}
	return ExecutionPlan{
		input: input,
		workspace: Mount{
			source: input.Workspace.RealPath(), target: workspaceTarget, readOnly: true,
			propagation: bindPropagation, recursiveReadOnly: true,
		},
		credential: Mount{
			source: input.Credential.ProtectedFile(), target: credentialTarget, readOnly: true,
			propagation: bindPropagation,
		},
	}, nil
}

// SessionID returns the UUIDv7 session identity.
func (p ExecutionPlan) SessionID() string { return p.input.SessionID }

// InstallationID returns the owning installation identity.
func (p ExecutionPlan) InstallationID() string { return p.input.InstallationID }

// AgentID returns the configured agent adapter identity.
func (p ExecutionPlan) AgentID() string { return p.input.AgentID }

// ReleaseID returns the signed active release identity.
func (p ExecutionPlan) ReleaseID() string { return p.input.ReleaseID }

// ManifestDigest returns the release manifest binding used for labels and inspection.
func (p ExecutionPlan) ManifestDigest() string { return p.input.ManifestDigest }

// SecurityEpoch returns the active credential-policy epoch.
func (p ExecutionPlan) SecurityEpoch() uint64 { return p.input.SecurityEpoch }

// RuntimeEndpoint returns the exact recorded local Docker endpoint.
func (p ExecutionPlan) RuntimeEndpoint() string { return p.input.RuntimeEndpoint }

// Image returns the exact manifest-bound digest reference.
func (p ExecutionPlan) Image() string { return p.input.Image }

// Network returns the exact installation-scoped internal network.
func (p ExecutionPlan) Network() string { return p.input.Network }

// Workspace returns the complete host identity evidence.
func (p ExecutionPlan) Workspace() WorkspaceIdentity { return p.input.Workspace }

// Credential returns the non-secret protected credential reference.
func (p ExecutionPlan) Credential() CredentialLease { return p.input.Credential }

// WorkspaceMount returns the sole project source mount.
func (p ExecutionPlan) WorkspaceMount() Mount { return p.workspace }

// CredentialMount returns the sole session credential mount.
func (p ExecutionPlan) CredentialMount() Mount { return p.credential }

// Security returns the fixed closed sandbox policy.
func (ExecutionPlan) Security() SandboxSecurity { return SandboxSecurity{} }

func validGitEvidence(repositoryID, worktreeID string, coverage GitCoverage) bool {
	switch coverage {
	case GitCoverageNone:
		return repositoryID == "" && worktreeID == ""
	case GitCoveragePartial:
		return validOptionalOpaque(repositoryID) && validOptionalOpaque(worktreeID) &&
			(repositoryID != "" || worktreeID != "")
	case GitCoverageComplete:
		return validOpaque(repositoryID) && validOpaque(worktreeID)
	default:
		return false
	}
}

func validOptionalOpaque(value string) bool { return value == "" || validOpaque(value) }

func validOpaque(value string) bool {
	if value == "" || len(value) > maximumIdentityBytes || !utf8.ValidString(value) ||
		value != strings.TrimSpace(value) {
		return false
	}
	return !strings.ContainsAny(value, "\x00\r\n")
}

func validAgentID(value string) bool {
	if !validOpaque(value) || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

// ValidAgentID reports whether a configured host identity is safe and bounded.
func ValidAgentID(value string) bool { return validAgentID(value) }

func validSHA256(value string) bool {
	if len(value) != sha256HexLength {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// ValidSHA256Digest reports whether value is canonical lowercase SHA-256 hex.
func ValidSHA256Digest(value string) bool { return validSHA256(value) }

func validImage(value string) bool {
	if value == "" || len(value) > maximumImageBytes || strings.ContainsAny(value, "\x00\r\n ") {
		return false
	}
	name, digest, found := strings.Cut(value, "@sha256:")
	return found && name != "" && !strings.Contains(name, "@") && validSHA256(digest)
}

// ValidImageReference reports whether value is an immutable sha256 image reference.
func ValidImageReference(value string) bool { return validImage(value) }

func validNetwork(value string) bool {
	if len(value) < len("agentmemory__internal") || len(value) > maximumNetworkBytes ||
		!strings.HasPrefix(value, "agentmemory_") || !strings.HasSuffix(value, "_internal") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
			character == '_' {
			continue
		}
		return false
	}
	return true
}

// ValidNetworkName reports whether value is an installation-scoped internal network.
func ValidNetworkName(value string) bool { return validNetwork(value) }

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

// ValidUUIDv7 reports whether value is a canonical lowercase RFC 9562 UUIDv7.
func ValidUUIDv7(value string) bool { return validUUIDv7(value) }

func validRuntimeEndpoint(value string) bool {
	if value == "" || len(value) > maximumPathBytes || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	if strings.HasPrefix(value, "unix:///") {
		return validPathSegments(strings.TrimPrefix(value, "unix://"), "/", 1)
	}
	if strings.HasPrefix(value, "npipe:////./pipe/") {
		name := strings.TrimPrefix(value, "npipe:////./pipe/")
		return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, `/\`)
	}
	return false
}

func validHostPath(value string) bool {
	if value == "" || len(value) > maximumPathBytes || !utf8.ValidString(value) ||
		strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	switch {
	case strings.HasPrefix(value, "/"):
		return validPathSegments(value, "/", 1)
	case len(value) >= 3 && isASCIIAlpha(value[0]) && value[1] == ':' &&
		(value[2] == '\\' || value[2] == '/'):
		return validPathSegments(value, string(value[2]), 3)
	case strings.HasPrefix(value, `\\`):
		return validUNCPath(value)
	default:
		return false
	}
}

func validPathSegments(value, separator string, prefixBytes int) bool {
	remainder := value[prefixBytes:]
	if remainder == "" {
		return prefixBytes == 1 || prefixBytes == 3
	}
	if strings.HasSuffix(value, separator) || strings.Contains(remainder, separator+separator) {
		return false
	}
	for _, segment := range strings.Split(remainder, separator) {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validUNCPath(value string) bool {
	if strings.Contains(value[2:], "/") || strings.HasSuffix(value, `\`) ||
		strings.Contains(value[2:], `\\`) {
		return false
	}
	segments := strings.Split(value[2:], `\`)
	if len(segments) < 2 {
		return false
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func isASCIIAlpha(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
