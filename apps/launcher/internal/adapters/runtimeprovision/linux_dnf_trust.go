package runtimeprovision

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

const maximumDNFMetadataBytes = 256 << 20

var errDNFTrust = errors.New("dnf repository trust validation failed")

type dnfRepositoryTrustInput struct {
	Now                time.Time
	Architecture       string
	Repository         dnfRepositoryExpectation
	Packages           []dnfPackageExpectation
	SigningKey         []byte
	RepositoryMetadata []byte
	MetadataSignature  []byte
	PackageIndex       []byte
}

type dnfRepositoryExpectation struct {
	ID                     string
	BasePath               string
	SigningKeyFingerprint  string
	MetadataAuthentication string
	Index                  aptArtifactExpectation
}

type dnfPackageExpectation struct {
	Name         string
	Version      string
	RepositoryID string
	Path         string
	Size         uint64
	SHA256       string
}

func verifyDNFRepositoryTrust(input dnfRepositoryTrustInput) error {
	if input.Now.Location() != time.UTC || input.Architecture == "" || len(input.Packages) == 0 ||
		len(input.SigningKey) == 0 || len(input.RepositoryMetadata) == 0 || len(input.PackageIndex) == 0 {
		return errDNFTrust
	}
	keyring, err := readAPTKeyring(input.SigningKey)
	if err != nil || !keyringContainsExactFingerprint(keyring, input.Repository.SigningKeyFingerprint) {
		return errDNFTrust
	}
	switch input.Repository.MetadataAuthentication {
	case "detached":
		if verifyDNFDetachedMetadata(
			keyring, input.RepositoryMetadata, input.MetadataSignature,
			input.Repository.SigningKeyFingerprint, input.Now,
		) != nil {
			return errDNFTrust
		}
	case "package_signatures":
		if len(input.MetadataSignature) != 0 {
			return errDNFTrust
		}
	default:
		return errDNFTrust
	}
	if verifyDNFRepoMD(input.RepositoryMetadata, input.Repository) != nil {
		return errDNFTrust
	}
	decoded, err := decodeDNFPrimary(input.PackageIndex)
	if err != nil || verifyDNFPrimary(decoded, input.Architecture, input.Repository, input.Packages) != nil {
		return errDNFTrust
	}
	return nil
}

func keyringContainsExactFingerprint(keyring openpgp.EntityList, fingerprint string) bool {
	found := false
	for _, entity := range keyring {
		if entity == nil || entity.PrimaryKey == nil {
			return false
		}
		actual := strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint))
		if actual == fingerprint {
			found = true
		} else {
			return false
		}
	}
	return found
}

func verifyDNFDetachedMetadata(
	keyring openpgp.EntityList,
	metadata []byte,
	signature []byte,
	fingerprint string,
	now time.Time,
) error {
	if len(signature) == 0 {
		return errDNFTrust
	}
	reader := io.Reader(bytes.NewReader(signature))
	if bytes.HasPrefix(bytes.TrimSpace(signature), []byte("-----BEGIN PGP SIGNATURE-----")) {
		block, err := armor.Decode(reader)
		if err != nil || block.Type != openpgp.SignatureType {
			return errDNFTrust
		}
		reader = block.Body
	}
	config := &packet.Config{Time: func() time.Time { return now }, MinRSABits: 2048}
	signaturePacket, signer, err := openpgp.VerifyDetachedSignatureAndHash(
		keyring, bytes.NewReader(metadata), reader,
		[]crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}, config,
	)
	if err != nil || signer == nil || signer.PrimaryKey == nil || signaturePacket == nil ||
		signaturePacket.CreationTime.IsZero() ||
		signaturePacket.CreationTime.After(now.Add(maximumClockSkew)) ||
		strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint)) != fingerprint {
		return errDNFTrust
	}
	return nil
}

type dnfRepoMD struct {
	XMLName xml.Name        `xml:"repomd"`
	Data    []dnfRepoMDData `xml:"data"`
}

type dnfRepoMDData struct {
	Type     string         `xml:"type,attr"`
	Checksum dnfXMLChecksum `xml:"checksum"`
	Location dnfXMLLocation `xml:"location"`
	Size     string         `xml:"size"`
}

type dnfXMLChecksum struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type dnfXMLLocation struct {
	Href string `xml:"href,attr"`
}

func verifyDNFRepoMD(value []byte, repository dnfRepositoryExpectation) error {
	var document dnfRepoMD
	if decodeStrictXML(value, &document) != nil || document.XMLName.Local != "repomd" {
		return errDNFTrust
	}
	found := false
	for _, data := range document.Data {
		if data.Type != "primary" {
			continue
		}
		if found || data.Checksum.Type != "sha256" || strings.TrimSpace(data.Checksum.Value) != repository.Index.SHA256 ||
			data.Location.Href == "" || !safeRepositoryPath(data.Location.Href) {
			return errDNFTrust
		}
		size, err := parseCanonicalPositiveUint(strings.TrimSpace(data.Size))
		relative, present := dnfRepositoryRelativePath(repository.BasePath, repository.Index.Path)
		if err != nil || !present || data.Location.Href != relative || size != repository.Index.Size {
			return errDNFTrust
		}
		found = true
	}
	if !found {
		return errDNFTrust
	}
	return nil
}

func dnfRepositoryRelativePath(basePath, path string) (string, bool) {
	prefix := strings.TrimSuffix(basePath, "/") + "/"
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	relative := strings.TrimPrefix(path, prefix)
	return relative, safeRepositoryPath(relative)
}

func decodeDNFPrimary(value []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(value))
	if err != nil {
		return nil, errDNFTrust
	}
	defer reader.Close() //nolint:errcheck // read-to-EOF authenticates the complete gzip stream.
	decoded, err := io.ReadAll(io.LimitReader(reader, maximumDNFMetadataBytes+1))
	if err != nil || len(decoded) == 0 || len(decoded) > maximumDNFMetadataBytes {
		return nil, errDNFTrust
	}
	return decoded, nil
}

type dnfPrimaryMetadata struct {
	XMLName  xml.Name        `xml:"metadata"`
	Packages []dnfXMLPackage `xml:"package"`
}

type dnfXMLPackage struct {
	Type     string         `xml:"type,attr"`
	Name     string         `xml:"name"`
	Arch     string         `xml:"arch"`
	Version  dnfXMLVersion  `xml:"version"`
	Checksum dnfXMLChecksum `xml:"checksum"`
	Size     dnfXMLSize     `xml:"size"`
	Location dnfXMLLocation `xml:"location"`
}

type dnfXMLVersion struct {
	Epoch   string `xml:"epoch,attr"`
	Version string `xml:"ver,attr"`
	Release string `xml:"rel,attr"`
}

type dnfXMLSize struct {
	Package string `xml:"package,attr"`
}

func verifyDNFPrimary(
	value []byte,
	architecture string,
	repository dnfRepositoryExpectation,
	expected []dnfPackageExpectation,
) error {
	var document dnfPrimaryMetadata
	if decodeStrictXML(value, &document) != nil || document.XMLName.Local != "metadata" {
		return errDNFTrust
	}
	wanted := make(map[string]dnfPackageExpectation, len(expected))
	for _, pkg := range expected {
		if pkg.RepositoryID != repository.ID {
			return errDNFTrust
		}
		key := pkg.Name + "\x00" + pkg.Version
		if _, duplicate := wanted[key]; duplicate {
			return errDNFTrust
		}
		wanted[key] = pkg
	}
	found := make(map[string]struct{}, len(wanted))
	for _, pkg := range document.Packages {
		version, valid := canonicalRPMVersion(pkg.Version)
		if !valid {
			return errDNFTrust
		}
		key := strings.TrimSpace(pkg.Name) + "\x00" + version
		expectedPackage, present := wanted[key]
		if !present {
			continue
		}
		if _, duplicate := found[key]; duplicate {
			return errDNFTrust
		}
		size, err := parseCanonicalPositiveUint(pkg.Size.Package)
		relative, pathPresent := dnfRepositoryRelativePath(repository.BasePath, expectedPackage.Path)
		if pkg.Type != "rpm" || strings.TrimSpace(pkg.Arch) != architecture ||
			pkg.Checksum.Type != "sha256" || strings.TrimSpace(pkg.Checksum.Value) != expectedPackage.SHA256 ||
			err != nil || size != expectedPackage.Size || !pathPresent || pkg.Location.Href != relative {
			return errDNFTrust
		}
		found[key] = struct{}{}
	}
	if len(found) != len(wanted) {
		return errDNFTrust
	}
	return nil
}

func canonicalRPMVersion(version dnfXMLVersion) (string, bool) {
	epoch := strings.TrimSpace(version.Epoch)
	value := strings.TrimSpace(version.Version)
	release := strings.TrimSpace(version.Release)
	if value == "" || release == "" || strings.ContainsAny(value+release, "\x00\r\n") {
		return "", false
	}
	if epoch == "" {
		epoch = "0"
	}
	parsed, err := strconv.ParseUint(epoch, 10, 32)
	if err != nil || strconv.FormatUint(parsed, 10) != epoch {
		return "", false
	}
	result := value + "-" + release
	if parsed != 0 {
		result = epoch + ":" + result
	}
	return result, true
}

func decodeStrictXML(value []byte, target any) error {
	if len(value) == 0 || len(value) > maximumDNFMetadataBytes {
		return errDNFTrust
	}
	decoder := xml.NewDecoder(bytes.NewReader(value))
	decoder.Strict = true
	if err := decoder.Decode(target); err != nil {
		return errDNFTrust
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errDNFTrust
	}
	return nil
}
