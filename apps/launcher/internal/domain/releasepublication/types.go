// Package releasepublication defines the immutable top-level release record
// that binds already-qualified native packages to one signed distribution
// envelope. It has no filesystem, network, process, or signing capabilities.
package releasepublication

import (
	"errors"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

const (
	// SupportedSchemaMajor is the only publication-record major understood by
	// this launcher version.
	SupportedSchemaMajor uint16 = 1
	maxSafeJSONInteger          = uint64(1<<53 - 1)
)

// ArtifactKind is a closed promoted-object role.
type ArtifactKind string

const (
	// ArtifactKindNativePackage is a signed native operating-system installer.
	ArtifactKindNativePackage ArtifactKind = "native_package"
	// ArtifactKindOfflineBundle is the one all-platform retained release tree.
	ArtifactKindOfflineBundle ArtifactKind = "offline_bundle"
)

// Format is a closed publication representation.
type Format string

const (
	// FormatPKG is an Apple installer product archive.
	FormatPKG Format = "pkg"
	// FormatMSI is a Windows Installer database.
	FormatMSI Format = "msi"
	// FormatDEB is a Debian-family package.
	FormatDEB Format = "deb"
	// FormatRPM is an RPM-family package.
	FormatRPM Format = "rpm"
	// FormatTarZstd is a Zstandard-compressed tar release bundle.
	FormatTarZstd Format = "tar.zst"
)

// NativePublisherPolicy selects the independent platform authority that must
// have accepted the exact promoted object before this record is signed.
type NativePublisherPolicy string

const (
	// PublisherPolicyAppleNotarized requires Developer ID and notarization.
	PublisherPolicyAppleNotarized NativePublisherPolicy = "apple_developer_id_notarized"
	// PublisherPolicyMicrosoftAuthenticode requires the release-bound Authenticode signer.
	PublisherPolicyMicrosoftAuthenticode NativePublisherPolicy = "microsoft_authenticode"
	// PublisherPolicyLinuxPackage requires the release Linux package authority.
	PublisherPolicyLinuxPackage NativePublisherPolicy = "linux_package_signature"
	// PublisherPolicyManifestOnly applies to the independently signed offline bundle.
	PublisherPolicyManifestOnly NativePublisherPolicy = "manifest_signature"
)

// ArtifactInput is copied into an immutable Artifact.
type ArtifactInput struct {
	ID                    string
	Kind                  ArtifactKind
	OperatingSystem       string
	Architecture          string
	Format                Format
	FileName              string
	MediaType             string
	Digest                releaseinventory.Digest
	Size                  uint64
	CycloneDXSBOMDigest   releaseinventory.Digest
	ProvenanceDigest      releaseinventory.Digest
	SignatureBundleDigest releaseinventory.Digest
	NativePublisherPolicy NativePublisherPolicy
}

// Artifact is one exact, evidence-bound object copied during promotion.
type Artifact struct {
	id                    string
	kind                  ArtifactKind
	operatingSystem       string
	architecture          string
	format                Format
	fileName              string
	mediaType             string
	digest                releaseinventory.Digest
	size                  uint64
	cycloneDXSBOMDigest   releaseinventory.Digest
	provenanceDigest      releaseinventory.Digest
	signatureBundleDigest releaseinventory.Digest
	nativePublisherPolicy NativePublisherPolicy
}

func newArtifact(input ArtifactInput) (Artifact, error) {
	if !validIdentifier(input.ID) || !validFileName(input.FileName, input.Format) ||
		!validSafeText(input.MediaType, 256) || input.Size == 0 || input.Size > maxSafeJSONInteger ||
		input.Digest.IsZero() || input.CycloneDXSBOMDigest.IsZero() || input.ProvenanceDigest.IsZero() ||
		input.SignatureBundleDigest.IsZero() {
		return Artifact{}, errors.New("publication artifact metadata is invalid")
	}
	if input.Kind == ArtifactKindNativePackage {
		if !validNativeCell(input.OperatingSystem, input.Architecture, input.Format, input.NativePublisherPolicy) {
			return Artifact{}, errors.New("native publication cell is invalid")
		}
	} else if input.Kind != ArtifactKindOfflineBundle || input.OperatingSystem != "" ||
		input.Architecture != "" || input.Format != FormatTarZstd ||
		input.NativePublisherPolicy != PublisherPolicyManifestOnly {
		return Artifact{}, errors.New("publication artifact role is invalid")
	}
	return Artifact{
		id: input.ID, kind: input.Kind, operatingSystem: input.OperatingSystem,
		architecture: input.Architecture, format: input.Format, fileName: input.FileName,
		mediaType: input.MediaType, digest: input.Digest, size: input.Size,
		cycloneDXSBOMDigest: input.CycloneDXSBOMDigest, provenanceDigest: input.ProvenanceDigest,
		signatureBundleDigest: input.SignatureBundleDigest,
		nativePublisherPolicy: input.NativePublisherPolicy,
	}, nil
}

func validNativeCell(os string, architecture string, format Format, policy NativePublisherPolicy) bool {
	switch os + "/" + architecture + "/" + string(format) {
	case "darwin/amd64/pkg", "darwin/arm64/pkg":
		return policy == PublisherPolicyAppleNotarized
	case "windows/amd64/msi":
		return policy == PublisherPolicyMicrosoftAuthenticode
	case "linux/amd64/deb", "linux/amd64/rpm", "linux/arm64/deb", "linux/arm64/rpm":
		return policy == PublisherPolicyLinuxPackage
	default:
		return false
	}
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > 128 {
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

func validSafeText(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '\\' || character == '"' {
			return false
		}
	}
	return true
}

func validFileName(value string, format Format) bool {
	if !validSafeText(value, 255) || value == "." || value == ".." ||
		strings.ContainsAny(value, `/<>:"\|?*`) || strings.HasSuffix(value, ".") ||
		strings.HasSuffix(value, " ") {
		return false
	}
	return strings.HasSuffix(value, "."+string(format))
}

// ID returns the stable artifact identifier.
func (a Artifact) ID() string { return a.id }

// Kind returns the promoted-object role.
func (a Artifact) Kind() ArtifactKind { return a.kind }

// OperatingSystem returns the target OS, or empty for an all-platform bundle.
func (a Artifact) OperatingSystem() string { return a.operatingSystem }

// Architecture returns the target architecture, or empty for an all-platform bundle.
func (a Artifact) Architecture() string { return a.architecture }

// Format returns the exact publication representation.
func (a Artifact) Format() Format { return a.format }

// FileName returns the safe release-asset leaf name.
func (a Artifact) FileName() string { return a.fileName }

// MediaType returns the signed media-type declaration.
func (a Artifact) MediaType() string { return a.mediaType }

// Digest returns the exact promoted-object SHA-256.
func (a Artifact) Digest() releaseinventory.Digest { return a.digest }

// Size returns the exact promoted-object byte length.
func (a Artifact) Size() uint64 { return a.size }

// CycloneDXSBOMDigest returns the object's associated CycloneDX digest.
func (a Artifact) CycloneDXSBOMDigest() releaseinventory.Digest { return a.cycloneDXSBOMDigest }

// ProvenanceDigest returns the object's signed provenance digest.
func (a Artifact) ProvenanceDigest() releaseinventory.Digest { return a.provenanceDigest }

// SignatureBundleDigest returns the object's offline signature-bundle digest.
func (a Artifact) SignatureBundleDigest() releaseinventory.Digest {
	return a.signatureBundleDigest
}

// NativePublisherPolicy returns the required independent platform authority.
func (a Artifact) NativePublisherPolicy() NativePublisherPolicy { return a.nativePublisherPolicy }
