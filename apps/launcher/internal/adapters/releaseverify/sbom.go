package releaseverifyadapter

import (
	"context"
	"errors"
	"strings"
	"time"

	application "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// CanonicalSBOMVerifier implements the AgentMemory release profile for
// CycloneDX 1.6 JSON and SPDX 2.3 JSON. The profile intentionally closes the
// execution-relevant schema: publishers must canonicalize the exact supported
// fields and a future required field needs an explicit adapter revision.
type CanonicalSBOMVerifier struct {
	source ResourceContentSource
}

var _ application.SBOMVerifier = (*CanonicalSBOMVerifier)(nil)

// NewCanonicalSBOMVerifier requires immutable, locally acquired evidence.
func NewCanonicalSBOMVerifier(source ResourceContentSource) (*CanonicalSBOMVerifier, error) {
	if adapterNil(source) {
		return nil, errors.New("release SBOM content source is required")
	}
	return &CanonicalSBOMVerifier{source: source}, nil
}

// VerifySBOMs rechecks content identity and exact subject binding in both
// independent SBOM representations.
func (v *CanonicalSBOMVerifier) VerifySBOMs(
	ctx context.Context,
	subject releaseinventory.Resource,
	cycloneDX releaseinventory.Resource,
	spdx releaseinventory.Resource,
) error {
	if err := adapterContextError(ctx); err != nil {
		return err
	}
	if !validSBOMEvidence(subject, cycloneDX, releaseinventory.ResourceKindCycloneDXSBOM) ||
		!validSBOMEvidence(subject, spdx, releaseinventory.ResourceKindSPDXSBOM) {
		return application.ErrSBOMInvalid
	}
	cycloneRaw, err := readEvidence(ctx, v.source, cycloneDX)
	if err != nil {
		return evidencePortError(application.ErrSBOMInvalid, err)
	}
	if err := verifyCycloneDX(cycloneRaw, subject); err != nil {
		return evidencePortError(application.ErrSBOMInvalid, err)
	}
	spdxRaw, err := readEvidence(ctx, v.source, spdx)
	if err != nil {
		return evidencePortError(application.ErrSBOMInvalid, err)
	}
	if err := verifySPDX(spdxRaw, subject); err != nil {
		return evidencePortError(application.ErrSBOMInvalid, err)
	}
	return nil
}

func validSBOMEvidence(
	subject releaseinventory.Resource,
	evidence releaseinventory.Resource,
	kind releaseinventory.ResourceKind,
) bool {
	return !subject.Kind().IsEvidence() && evidence.Kind() == kind &&
		evidence.SubjectResourceID() == subject.ID() &&
		evidence.SubjectDigest().Equal(subject.Digest())
}

type cycloneDXDocument struct {
	BOMFormat    string               `json:"bomFormat"`
	Components   []cycloneDXComponent `json:"components"`
	Metadata     cycloneDXMetadata    `json:"metadata"`
	SerialNumber string               `json:"serialNumber"`
	SpecVersion  string               `json:"specVersion"`
	Version      uint64               `json:"version"`
}

type cycloneDXMetadata struct {
	Component cycloneDXComponent `json:"component"`
	Timestamp string             `json:"timestamp"`
}

type cycloneDXComponent struct {
	BOMRef  string          `json:"bom-ref"`
	Hashes  []cycloneDXHash `json:"hashes"`
	Name    string          `json:"name"`
	PURL    string          `json:"purl"`
	Type    string          `json:"type"`
	Version string          `json:"version"`
}

type cycloneDXHash struct {
	Algorithm string `json:"alg"`
	Content   string `json:"content"`
}

func verifyCycloneDX(raw []byte, subject releaseinventory.Resource) error {
	var document cycloneDXDocument
	if err := decodeCanonicalJSON(raw, &document); err != nil {
		return err
	}
	if document.BOMFormat != "CycloneDX" || document.SpecVersion != "1.6" || document.Version == 0 ||
		!validUUIDURN(document.SerialNumber) ||
		!validRFC3339UTC(document.Metadata.Timestamp) {
		return errEvidenceContent
	}
	if !cycloneDXComponentBinds(document.Metadata.Component, subject) {
		return errEvidenceContent
	}
	seen := make(map[string]struct{}, len(document.Components)+1)
	seen[document.Metadata.Component.BOMRef] = struct{}{}
	previous := ""
	for index, component := range document.Components {
		if !validCycloneDXComponent(component) || component.BOMRef == subject.ID() {
			return errEvidenceContent
		}
		if _, duplicate := seen[component.BOMRef]; duplicate {
			return errEvidenceContent
		}
		if index > 0 && component.BOMRef <= previous {
			return errEvidenceNonCanonical
		}
		seen[component.BOMRef] = struct{}{}
		previous = component.BOMRef
	}
	return nil
}

func cycloneDXComponentBinds(component cycloneDXComponent, subject releaseinventory.Resource) bool {
	return component.BOMRef == subject.ID() && component.Name == subject.ID() &&
		validCycloneDXComponent(component) && exactSHA256Hash(component.Hashes, subject.Digest().Hex())
}

func validCycloneDXComponent(component cycloneDXComponent) bool {
	if !validSafeEvidenceText(component.BOMRef, 256) || !validSafeEvidenceText(component.Name, 256) ||
		!validSafeEvidenceText(component.Version, 128) || len(component.Hashes) != 1 {
		return false
	}
	if component.PURL != "" && (!validSafeEvidenceText(component.PURL, 2048) || !strings.HasPrefix(component.PURL, "pkg:")) {
		return false
	}
	switch component.Type {
	case "application", "container", "device", "file", "firmware", "framework", "library", "operating-system":
	default:
		return false
	}
	return component.Hashes[0].Algorithm == "SHA-256" && validHexDigest(component.Hashes[0].Content)
}

func exactSHA256Hash(hashes []cycloneDXHash, expected string) bool {
	matches := 0
	for _, hash := range hashes {
		if hash.Algorithm == "SHA-256" {
			matches++
			if hash.Content != expected {
				return false
			}
		}
	}
	return matches == 1
}

type spdxDocument struct {
	CreationInfo      spdxCreationInfo `json:"creationInfo"`
	DataLicense       string           `json:"dataLicense"`
	DocumentDescribes []string         `json:"documentDescribes"`
	DocumentNamespace string           `json:"documentNamespace"`
	Name              string           `json:"name"`
	Packages          []spdxPackage    `json:"packages"`
	SPDXID            string           `json:"SPDXID"`
	SPDXVersion       string           `json:"spdxVersion"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Checksums        []spdxChecksum `json:"checksums"`
	CopyrightText    string         `json:"copyrightText"`
	DownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed    bool           `json:"filesAnalyzed"`
	LicenseConcluded string         `json:"licenseConcluded"`
	LicenseDeclared  string         `json:"licenseDeclared"`
	Name             string         `json:"name"`
	SPDXID           string         `json:"SPDXID"`
	VersionInfo      string         `json:"versionInfo"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

func verifySPDX(raw []byte, subject releaseinventory.Resource) error {
	var document spdxDocument
	if err := decodeCanonicalJSON(raw, &document); err != nil {
		return err
	}
	expectedID := "SPDXRef-" + subject.ID()
	if document.SPDXVersion != "SPDX-2.3" || document.DataLicense != "CC0-1.0" ||
		document.SPDXID != "SPDXRef-DOCUMENT" || !validSafeEvidenceText(document.Name, 256) ||
		!strings.HasPrefix(document.DocumentNamespace, "https://agentmemory.local/spdx/") ||
		!validSafeEvidenceText(document.DocumentNamespace, 2048) ||
		len(document.DocumentDescribes) != 1 || document.DocumentDescribes[0] != expectedID ||
		!validRFC3339UTC(document.CreationInfo.Created) ||
		len(document.CreationInfo.Creators) == 0 ||
		!exactUniqueStrings(document.CreationInfo.Creators, true) || len(document.Packages) == 0 {
		return errEvidenceContent
	}
	seen := make(map[string]struct{}, len(document.Packages))
	subjectMatches := 0
	previous := ""
	for index, pkg := range document.Packages {
		if !validSPDXPackage(pkg) {
			return errEvidenceContent
		}
		if _, duplicate := seen[pkg.SPDXID]; duplicate {
			return errEvidenceContent
		}
		if index > 0 && pkg.SPDXID <= previous {
			return errEvidenceNonCanonical
		}
		seen[pkg.SPDXID] = struct{}{}
		previous = pkg.SPDXID
		if pkg.SPDXID == expectedID {
			subjectMatches++
			if pkg.Name != subject.ID() || !exactSPDXSHA256(pkg.Checksums, subject.Digest().Hex()) {
				return errEvidenceContent
			}
		}
	}
	return requireExactlyOne(subjectMatches)
}

func validSPDXPackage(pkg spdxPackage) bool {
	if !strings.HasPrefix(pkg.SPDXID, "SPDXRef-") || !validSafeEvidenceText(pkg.SPDXID, 256) ||
		!validSafeEvidenceText(pkg.Name, 256) || !validSafeEvidenceText(pkg.VersionInfo, 128) ||
		!validSafeEvidenceText(pkg.DownloadLocation, 2048) ||
		!validSafeEvidenceText(pkg.LicenseConcluded, 512) ||
		!validSafeEvidenceText(pkg.LicenseDeclared, 512) ||
		!validSafeEvidenceText(pkg.CopyrightText, 1024) || len(pkg.Checksums) == 0 || len(pkg.Checksums) > 8 {
		return false
	}
	seen := make(map[string]struct{}, len(pkg.Checksums))
	previous := ""
	for index, checksum := range pkg.Checksums {
		if !validSafeEvidenceText(checksum.Algorithm, 16) || !validHexDigest(checksum.ChecksumValue) {
			return false
		}
		if _, duplicate := seen[checksum.Algorithm]; duplicate {
			return false
		}
		if index > 0 && checksum.Algorithm <= previous {
			return false
		}
		seen[checksum.Algorithm] = struct{}{}
		previous = checksum.Algorithm
	}
	return true
}

func exactSPDXSHA256(checksums []spdxChecksum, expected string) bool {
	matches := 0
	for _, checksum := range checksums {
		if checksum.Algorithm == "SHA256" {
			matches++
			if checksum.ChecksumValue != expected {
				return false
			}
		}
	}
	return matches == 1
}

func validHexDigest(value string) bool {
	_, err := releaseinventory.ParseDigest(value)
	return err == nil
}

func validRFC3339UTC(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}

func validUUIDURN(value string) bool {
	const prefix = "urn:uuid:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+36 {
		return false
	}
	uuid := strings.TrimPrefix(value, prefix)
	for index, character := range uuid {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if character < '0' || character > '9' && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func requireExactlyOne(count int) error {
	if count != 1 {
		return errEvidenceContent
	}
	return nil
}

func evidencePortError(sentinel error, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errors.Join(sentinel, err)
}
