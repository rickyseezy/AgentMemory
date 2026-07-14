// Package runtimecatalog defines the capability-free, signed PF-006 runtime
// prerequisite catalog consumed by the native launcher.
package runtimecatalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	// SupportedSchemaVersion is the only runtime catalog wire schema accepted by this launcher.
	SupportedSchemaVersion   uint32 = 1
	maximumRawManifestBytes         = 4 * 1024 * 1024
	maximumManifestJSONDepth        = 48
	maximumSafeJSONInteger   uint64 = 1<<53 - 1
	maximumIdentifierLength         = 128
	maximumPathLength               = 2048
)

var (
	// ErrManifestMalformed means the input is not one bounded JSON object.
	ErrManifestMalformed = errors.New("runtime prerequisite manifest JSON is malformed")
	// ErrManifestDuplicateKey means an object repeats a key at any depth.
	ErrManifestDuplicateKey = errors.New("runtime prerequisite manifest contains a duplicate JSON key")
	// ErrManifestUnknownField means schema v1 does not understand a field.
	ErrManifestUnknownField = errors.New("runtime prerequisite manifest contains an unknown field")
	// ErrManifestNonCanonical means the bytes are not the exact canonical representation.
	ErrManifestNonCanonical = errors.New("runtime prerequisite manifest JSON is not canonical")
	// ErrManifestUnsupportedSchema means the declared schema major is unsupported.
	ErrManifestUnsupportedSchema = errors.New("runtime prerequisite manifest schema is unsupported")
	// ErrManifestIntegrity means a recognized field violates signed policy.
	ErrManifestIntegrity = errors.New("runtime prerequisite manifest integrity validation failed")
	// ErrSourceDenied means acquisition is not authorized by the signed source policy.
	ErrSourceDenied = errors.New("runtime artifact source is not authorized")
	// ErrUnsupportedHost means the host is outside the exact certified platform cell.
	ErrUnsupportedHost = errors.New("runtime catalog does not support this host")
)

// Digest is an immutable SHA-256 digest.
type Digest [sha256.Size]byte

// DigestBytes calculates a SHA-256 digest over exact bytes.
func DigestBytes(value []byte) Digest { return sha256.Sum256(value) }

// ParseDigest parses one lowercase SHA-256 hexadecimal digest.
func ParseDigest(value string) (Digest, error) {
	var result Digest
	if len(value) != sha256.Size*2 || strings.ToLower(value) != value {
		return result, errors.New("digest is not canonical lowercase SHA-256")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return result, errors.New("digest is invalid")
	}
	copy(result[:], decoded)
	if result.IsZero() {
		return Digest{}, errors.New("digest must not be zero")
	}
	return result, nil
}

// Hex returns lowercase hexadecimal.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether no digest was supplied.
func (d Digest) IsZero() bool { return d == Digest{} }

// Equal compares two digests without converting them to text.
func (d Digest) Equal(other Digest) bool { return d == other }

// OSKind is the closed operating-system family set.
type OSKind string

// Supported operating-system families.
const (
	OSKindMacOS   OSKind = "macos"
	OSKindWindows OSKind = "windows"
	OSKindLinux   OSKind = "linux"
)

func (k OSKind) valid() bool { return k == OSKindMacOS || k == OSKindWindows || k == OSKindLinux }

// Architecture is the closed runtime CPU architecture set.
type Architecture string

// Supported runtime architectures.
const (
	ArchitectureARM64 Architecture = "arm64"
	ArchitectureX8664 Architecture = "x86_64"
)

func (a Architecture) valid() bool { return a == ArchitectureARM64 || a == ArchitectureX8664 }

// RuntimeProduct identifies the certified vendor product.
type RuntimeProduct string

// Closed runtime products.
const (
	RuntimeProductDockerDesktop RuntimeProduct = "docker_desktop"
	RuntimeProductDockerEngine  RuntimeProduct = "docker_engine"
)

func (p RuntimeProduct) valid() bool {
	return p == RuntimeProductDockerDesktop || p == RuntimeProductDockerEngine
}

// RuntimeChannel is a closed vendor publication channel.
type RuntimeChannel string

// StableChannel is the only channel authorized for production provisioning.
const StableChannel RuntimeChannel = "stable"

// ComponentName identifies one exact runtime component.
type ComponentName string

// Closed component identities.
const (
	ComponentEngine         ComponentName = "engine"
	ComponentCLI            ComponentName = "cli"
	ComponentContainerd     ComponentName = "containerd"
	ComponentBuildx         ComponentName = "buildx"
	ComponentCompose        ComponentName = "compose"
	ComponentRootlessExtras ComponentName = "rootless_extras"
)

func (n ComponentName) valid() bool {
	switch n {
	case ComponentEngine, ComponentCLI, ComponentContainerd, ComponentBuildx, ComponentCompose,
		ComponentRootlessExtras:
		return true
	default:
		return false
	}
}

func componentRank(name ComponentName) int {
	switch name {
	case ComponentEngine:
		return 1
	case ComponentCLI:
		return 2
	case ComponentContainerd:
		return 3
	case ComponentBuildx:
		return 4
	case ComponentCompose:
		return 5
	case ComponentRootlessExtras:
		return 6
	default:
		return 0
	}
}

// ProxyMode declares the only network mediation accepted during acquisition.
type ProxyMode string

// Closed acquisition proxy modes.
const (
	ProxyModeSystem          ProxyMode = "system_proxy"
	ProxyModeDirectAndSystem ProxyMode = "direct_and_system_proxy"
)

func (m ProxyMode) valid() bool { return m == ProxyModeSystem || m == ProxyModeDirectAndSystem }

// OfflinePolicy declares how the exact artifact may enter an offline install.
type OfflinePolicy string

// Closed offline acquisition policies.
const (
	OfflinePolicyBundled              OfflinePolicy = "bundled"
	OfflinePolicyUserSelectedOfficial OfflinePolicy = "user_selected_official"
)

func (p OfflinePolicy) valid() bool {
	return p == OfflinePolicyBundled || p == OfflinePolicyUserSelectedOfficial
}

// SourceMode is the acquisition mode selected before any download or execution.
type SourceMode string

// Closed source modes.
const (
	SourceModeUnknown             SourceMode = ""
	SourceModeOnline              SourceMode = "online"
	SourceModeOfflineBundle       SourceMode = "offline_bundle"
	SourceModeOfflineUserSelected SourceMode = "offline_user_selected"
)

// NativeVerification is the platform trust mechanism required for the artifact.
type NativeVerification string

// Closed native publisher verification mechanisms.
const (
	NativeVerificationAppleNotarized   NativeVerification = "apple_developer_id_notarized"
	NativeVerificationAuthenticode     NativeVerification = "authenticode"
	NativeVerificationPackageSignature NativeVerification = "package_signature"
)

func (v NativeVerification) valid() bool {
	return v == NativeVerificationAppleNotarized || v == NativeVerificationAuthenticode ||
		v == NativeVerificationPackageSignature
}

// InstallerExecutable is a semantic executable selected by a platform adapter.
// It is deliberately not an arbitrary filesystem path or command.
type InstallerExecutable string

// Closed installer executable capabilities.
const (
	InstallerExecutableMacOSInstaller InstallerExecutable = "macos_installer"
	InstallerExecutableWindowsHelper  InstallerExecutable = "windows_verified_helper"
	InstallerExecutableAPT            InstallerExecutable = "apt"
	InstallerExecutableDNF            InstallerExecutable = "dnf"
	InstallerExecutableRootlessSetup  InstallerExecutable = "rootless_setup"
)

func (e InstallerExecutable) valid() bool {
	switch e {
	case InstallerExecutableMacOSInstaller, InstallerExecutableWindowsHelper,
		InstallerExecutableAPT, InstallerExecutableDNF,
		InstallerExecutableRootlessSetup:
		return true
	default:
		return false
	}
}

// ArgumentKind is a typed installer argument slot.
type ArgumentKind string

// Closed argument kinds. No caller-supplied generic argument exists.
const (
	ArgumentKindLiteral              ArgumentKind = "literal"
	ArgumentKindArtifactPath         ArgumentKind = "artifact_path"
	ArgumentKindPlanDigest           ArgumentKind = "plan_digest"
	ArgumentKindInstallRoot          ArgumentKind = "install_root"
	ArgumentKindOperationReceiptPath ArgumentKind = "operation_receipt_path"
)

func (k ArgumentKind) valid() bool {
	switch k {
	case ArgumentKindLiteral, ArgumentKindArtifactPath, ArgumentKindPlanDigest,
		ArgumentKindInstallRoot, ArgumentKindOperationReceiptPath:
		return true
	default:
		return false
	}
}

// RollbackStrategy is the maximum runtime compensation authorized by the catalog.
type RollbackStrategy string

// Closed rollback strategies.
const (
	RollbackStrategyPreserve       RollbackStrategy = "preserve_runtime"
	RollbackStrategyManagedRemove  RollbackStrategy = "managed_remove"
	RollbackStrategyPackageManager RollbackStrategy = "package_manager_rollback"
)

func (s RollbackStrategy) valid() bool {
	return s == RollbackStrategyPreserve || s == RollbackStrategyManagedRemove ||
		s == RollbackStrategyPackageManager
}

// PrerequisiteOperation is a privileged semantic operation, never a command.
type PrerequisiteOperation string

// Closed prerequisite operations accepted by the privilege broker.
const (
	PrerequisiteConfigureOfficialRepository PrerequisiteOperation = "configure_official_repository"
	PrerequisiteEnableWSLFeature            PrerequisiteOperation = "enable_wsl_feature"
	PrerequisiteInstallVerifiedPackage      PrerequisiteOperation = "install_verified_package"
	PrerequisiteInstallWSLKernelUpdate      PrerequisiteOperation = "install_wsl_kernel_update"
	PrerequisiteConfigureSubordinateIDs     PrerequisiteOperation = "configure_subordinate_ids"
	PrerequisiteEnableUserService           PrerequisiteOperation = "enable_user_service"
)

func (o PrerequisiteOperation) valid() bool {
	switch o {
	case PrerequisiteConfigureOfficialRepository, PrerequisiteEnableWSLFeature,
		PrerequisiteInstallVerifiedPackage, PrerequisiteInstallWSLKernelUpdate,
		PrerequisiteConfigureSubordinateIDs, PrerequisiteEnableUserService:
		return true
	default:
		return false
	}
}

// CapabilityProbe is a closed post-install proof.
type CapabilityProbe string

// Closed capability probes.
const (
	CapabilityBindReadOnly      CapabilityProbe = "bind_read_only"
	CapabilityCloudOffloadOff   CapabilityProbe = "cloud_offload_disabled"
	CapabilityComposeVersion    CapabilityProbe = "compose_version"
	CapabilityEngineAPI         CapabilityProbe = "engine_api"
	CapabilityLinuxContainers   CapabilityProbe = "linux_containers"
	CapabilityLocalEndpoint     CapabilityProbe = "local_endpoint"
	CapabilityNetworkIsolation  CapabilityProbe = "network_isolation"
	CapabilityNoTCPListener     CapabilityProbe = "no_tcp_listener"
	CapabilityRootless          CapabilityProbe = "rootless"
	CapabilitySecurityMode      CapabilityProbe = "security_mode"
	CapabilityVolumePersistence CapabilityProbe = "volume_persistence"
)

func (p CapabilityProbe) valid() bool {
	switch p {
	case CapabilityBindReadOnly, CapabilityCloudOffloadOff, CapabilityComposeVersion,
		CapabilityEngineAPI, CapabilityLinuxContainers, CapabilityLocalEndpoint,
		CapabilityNetworkIsolation, CapabilityNoTCPListener, CapabilityRootless,
		CapabilitySecurityMode, CapabilityVolumePersistence:
		return true
	default:
		return false
	}
}

// TermsPresentation declares where the exact third-party terms must be shown.
type TermsPresentation string

// Closed terms presentation modes.
const (
	TermsPresentationAgentMemory           TermsPresentation = "agentmemory"
	TermsPresentationNative                TermsPresentation = "native_vendor_ui"
	TermsPresentationAgentMemoryThenNative TermsPresentation = "agentmemory_then_native"
)

func (p TermsPresentation) valid() bool {
	return p == TermsPresentationAgentMemory || p == TermsPresentationNative ||
		p == TermsPresentationAgentMemoryThenNative
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > maximumIdentifierLength {
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

func validSafeToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || strings.ContainsRune(`\\"'<>$;&|`+"`", character) {
			return false
		}
	}
	return true
}

func validExactVersion(value string) bool {
	if value == "" || len(value) > 128 || value == "latest" {
		return false
	}
	for index, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || index > 0 && strings.ContainsRune(".+_~-", character) {
			continue
		}
		return false
	}
	return true
}
