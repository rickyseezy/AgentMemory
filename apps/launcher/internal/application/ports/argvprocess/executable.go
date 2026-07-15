package argvprocess

import (
	"crypto/sha256"
	"strings"
)

const maximumExecutableIdentityBytes = 256

// ExecutableRole is the closed semantic capability granted to one executable.
// A Docker Engine CLI authority can never be substituted for the independently
// signed Compose executable (or vice versa), even when bytes happen to match.
type ExecutableRole string

// Closed executable roles understood by the signed launcher plan.
const (
	ExecutableRoleDockerCLI     ExecutableRole = "docker-cli"
	ExecutableRoleComposePlugin ExecutableRole = "compose-plugin"
	// ExecutableRoleRootlessSetup authorizes only the publisher-verified
	// docker-ce-rootless-extras setup tool under its closed adapter.
	ExecutableRoleRootlessSetup ExecutableRole = "rootless-setup"
	// ExecutableRoleRPMKeys authorizes only publisher-verified RPM signature
	// verification in an isolated, operation-owned key database.
	ExecutableRoleRPMKeys ExecutableRole = "rpmkeys"
	// ExecutableRolePrivilegeBroker authorizes only the signed `/usr/bin/pkexec`
	// transport that launches AgentMemory's immutable typed Linux helper.
	ExecutableRolePrivilegeBroker ExecutableRole = "privilege-broker"
	// ExecutableRoleAPTTransaction authorizes the fixed offline apt transaction adapter.
	ExecutableRoleAPTTransaction ExecutableRole = "apt-transaction"
	// ExecutableRoleDNFTransaction authorizes the fixed local-RPM DNF5 transaction adapter.
	ExecutableRoleDNFTransaction ExecutableRole = "dnf-transaction"
	// ExecutableRoleDPKGQuery authorizes exact installed Debian package receipt queries.
	ExecutableRoleDPKGQuery ExecutableRole = "dpkg-query"
	// ExecutableRoleRPMQuery authorizes exact installed RPM package receipt queries.
	ExecutableRoleRPMQuery ExecutableRole = "rpm-query"
	// ExecutableRoleLoginCTL authorizes only numeric-UID linger operations.
	ExecutableRoleLoginCTL ExecutableRole = "loginctl"
	// ExecutableRoleSystemCTL authorizes only the managed user-service operations.
	ExecutableRoleSystemCTL ExecutableRole = "systemctl"
	// ExecutableRoleAgentMemoryLauncher authorizes only the signed host launcher.
	ExecutableRoleAgentMemoryLauncher ExecutableRole = "agentmemory-launcher"
)

func (r ExecutableRole) valid() bool {
	return r == ExecutableRoleDockerCLI || r == ExecutableRoleComposePlugin ||
		r == ExecutableRoleRootlessSetup || r == ExecutableRoleRPMKeys ||
		r == ExecutableRolePrivilegeBroker || r == ExecutableRoleAPTTransaction ||
		r == ExecutableRoleDNFTransaction || r == ExecutableRoleDPKGQuery ||
		r == ExecutableRoleRPMQuery || r == ExecutableRoleLoginCTL || r == ExecutableRoleSystemCTL ||
		r == ExecutableRoleAgentMemoryLauncher
}

// ExecutableAuthorityInput is populated only from an authenticated signed
// release/runtime plan. Discovery output is never authority for these fields.
type ExecutableAuthorityInput struct {
	CanonicalID           string
	CanonicalPath         string
	SHA256                [sha256.Size]byte
	OwnerIdentity         string
	PublisherIdentity     string
	PublisherPolicyID     string
	PublisherTrustDigest  [sha256.Size]byte
	ReleaseManifestDigest [sha256.Size]byte
	RuntimePlanDigest     [sha256.Size]byte
	Role                  ExecutableRole
	Platform              string
	Architecture          string
}

// ExecutableAuthority is the immutable execution policy consumed by the host
// process adapter. The adapter still proves every field against the opened OS
// object immediately before launch.
type ExecutableAuthority struct {
	canonicalID           string
	canonicalPath         string
	sha256                [sha256.Size]byte
	ownerIdentity         string
	publisherIdentity     string
	publisherPolicyID     string
	publisherTrustDigest  [sha256.Size]byte
	releaseManifestDigest [sha256.Size]byte
	runtimePlanDigest     [sha256.Size]byte
	role                  ExecutableRole
	platform              string
	architecture          string
}

// NewExecutableAuthority closes and copies one signed execution policy. It
// deliberately rejects cross-platform plans and mutable/ambiguous paths.
func NewExecutableAuthority(input ExecutableAuthorityInput) (ExecutableAuthority, error) {
	if !validAuthorityIdentity(input.CanonicalID) || !validAuthorityIdentity(input.OwnerIdentity) ||
		!validAuthorityIdentity(input.PublisherIdentity) || !validAuthorityIdentity(input.PublisherPolicyID) ||
		input.PublisherTrustDigest == [sha256.Size]byte{} ||
		!input.Role.valid() || input.ReleaseManifestDigest == [sha256.Size]byte{} ||
		input.RuntimePlanDigest == [sha256.Size]byte{} ||
		!validAuthorityPlatform(input.Platform) || !validAuthorityArchitecture(input.Architecture) ||
		!validAuthorityPath(input.CanonicalPath, input.Platform) ||
		len(input.CanonicalPath) > 4096 || strings.IndexByte(input.CanonicalPath, 0) >= 0 ||
		input.SHA256 == [sha256.Size]byte{} {
		return ExecutableAuthority{}, ErrInvalidInvocation
	}
	return ExecutableAuthority{
		canonicalID:           input.CanonicalID,
		canonicalPath:         input.CanonicalPath,
		sha256:                input.SHA256,
		ownerIdentity:         input.OwnerIdentity,
		publisherIdentity:     input.PublisherIdentity,
		publisherPolicyID:     input.PublisherPolicyID,
		publisherTrustDigest:  input.PublisherTrustDigest,
		releaseManifestDigest: input.ReleaseManifestDigest,
		runtimePlanDigest:     input.RuntimePlanDigest,
		role:                  input.Role,
		platform:              input.Platform,
		architecture:          input.Architecture,
	}, nil
}

func validAuthorityIdentity(value string) bool {
	if value == "" || len(value) > maximumExecutableIdentityBytes || value != strings.TrimSpace(value) ||
		strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._:-@+/", character) || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validAuthorityPlatform(value string) bool {
	return value == "darwin" || value == "linux" || value == "windows"
}

func validAuthorityArchitecture(value string) bool { return value == "amd64" || value == "arm64" }

func validAuthorityPath(path, platform string) bool {
	if path == "" || strings.ContainsAny(path, "\x00\r\n") {
		return false
	}
	separator := "/"
	prefixLength := 1
	switch platform {
	case "darwin", "linux":
		if !strings.HasPrefix(path, "/") || strings.HasSuffix(path, "/") {
			return false
		}
	case "windows":
		separator = `\`
		prefixLength = 3
		if len(path) < prefixLength || path[1] != ':' || path[2] != '\\' ||
			(path[0] < 'A' || path[0] > 'Z') || strings.Contains(path, "/") || strings.HasSuffix(path, `\`) {
			return false
		}
	default:
		return false
	}
	for _, component := range strings.Split(path[prefixLength:], separator) {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

// Valid reports whether the value came through the closed constructor.
func (a ExecutableAuthority) Valid() bool {
	return a.canonicalID != "" && a.canonicalPath != "" && a.sha256 != [sha256.Size]byte{} &&
		a.ownerIdentity != "" && a.publisherIdentity != "" && a.publisherPolicyID != "" &&
		a.publisherTrustDigest != [sha256.Size]byte{} &&
		a.releaseManifestDigest != [sha256.Size]byte{} && a.runtimePlanDigest != [sha256.Size]byte{} &&
		a.role.valid() &&
		validAuthorityPlatform(a.platform) && validAuthorityArchitecture(a.architecture) &&
		validAuthorityPath(a.canonicalPath, a.platform)
}

// CanonicalID returns the signed logical executable identity.
func (a ExecutableAuthority) CanonicalID() string { return a.canonicalID }

// CanonicalPath returns the exact absolute executable path.
func (a ExecutableAuthority) CanonicalPath() string { return a.canonicalPath }

// SHA256 returns the signed executable content digest.
func (a ExecutableAuthority) SHA256() [sha256.Size]byte { return a.sha256 }

// OwnerIdentity returns the required native file owner.
func (a ExecutableAuthority) OwnerIdentity() string { return a.ownerIdentity }

// PublisherIdentity returns the exact native signing publisher.
func (a ExecutableAuthority) PublisherIdentity() string { return a.publisherIdentity }

// PublisherPolicyID returns the signed native verification policy.
func (a ExecutableAuthority) PublisherPolicyID() string { return a.publisherPolicyID }

// PublisherTrustDigest returns the signed platform-native trust anchor. On
// Windows this is the SHA-256 digest of the exact Authenticode leaf
// certificate DER; other platforms bind their equivalent signed trust record.
func (a ExecutableAuthority) PublisherTrustDigest() [sha256.Size]byte {
	return a.publisherTrustDigest
}

// ReleaseManifestDigest returns the authorizing signed release digest.
func (a ExecutableAuthority) ReleaseManifestDigest() [sha256.Size]byte {
	return a.releaseManifestDigest
}

// RuntimePlanDigest returns the authorizing runtime-plan digest.
func (a ExecutableAuthority) RuntimePlanDigest() [sha256.Size]byte { return a.runtimePlanDigest }

// Role returns the executable's closed capability role.
func (a ExecutableAuthority) Role() ExecutableRole { return a.role }

// Platform returns the signed target operating system.
func (a ExecutableAuthority) Platform() string { return a.platform }

// Architecture returns the signed target architecture.
func (a ExecutableAuthority) Architecture() string { return a.architecture }

// SameSignedPlan reports whether two distinct executable roles came from the
// exact same authenticated release manifest and runtime plan.
func (a ExecutableAuthority) SameSignedPlan(other ExecutableAuthority) bool {
	return a.Valid() && other.Valid() && a.releaseManifestDigest == other.releaseManifestDigest &&
		a.runtimePlanDigest == other.runtimePlanDigest && a.platform == other.platform &&
		a.architecture == other.architecture
}

// Equal performs exact value equality without exposing mutable state.
func (a ExecutableAuthority) Equal(other ExecutableAuthority) bool { return a == other }
