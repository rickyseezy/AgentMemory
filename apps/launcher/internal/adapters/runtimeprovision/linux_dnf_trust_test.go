package runtimeprovision

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestDNFRepositoryTrustAuthenticatesDetachedMetadataAndExactPrimaryRecords(t *testing.T) {
	input := signedDNFTrustInput(t, "detached")
	if err := verifyDNFRepositoryTrust(input); err != nil {
		t.Fatalf("verifyDNFRepositoryTrust() error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*dnfRepositoryTrustInput)
	}{
		{name: "wrong fingerprint", mutate: func(v *dnfRepositoryTrustInput) {
			v.Repository.SigningKeyFingerprint = strings.Repeat("A", 40)
		}},
		{name: "tampered repomd", mutate: func(v *dnfRepositoryTrustInput) {
			v.RepositoryMetadata = append([]byte(nil), v.RepositoryMetadata...)
			v.RepositoryMetadata[len(v.RepositoryMetadata)-10] ^= 1
		}},
		{name: "tampered signature", mutate: func(v *dnfRepositoryTrustInput) {
			v.MetadataSignature = append([]byte(nil), v.MetadataSignature...)
			v.MetadataSignature[len(v.MetadataSignature)/2] ^= 1
		}},
		{name: "wrong package digest", mutate: func(v *dnfRepositoryTrustInput) {
			v.Packages = append([]dnfPackageExpectation(nil), v.Packages...)
			v.Packages[0].SHA256 = strings.Repeat("0", 64)
		}},
		{name: "wrong repository", mutate: func(v *dnfRepositoryTrustInput) {
			v.Packages = append([]dnfPackageExpectation(nil), v.Packages...)
			v.Packages[0].RepositoryID = "other"
		}},
		{name: "truncated primary", mutate: func(v *dnfRepositoryTrustInput) {
			v.PackageIndex = append([]byte(nil), v.PackageIndex[:len(v.PackageIndex)-1]...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			test.mutate(&candidate)
			if err := verifyDNFRepositoryTrust(candidate); err == nil {
				t.Fatal("invalid DNF trust chain was accepted")
			}
		})
	}
}

func TestDNFRepositoryTrustAcceptsCatalogPinnedMetadataOnlyWithPackageSignaturePolicy(t *testing.T) {
	input := signedDNFTrustInput(t, "package_signatures")
	input.MetadataSignature = nil
	if err := verifyDNFRepositoryTrust(input); err != nil {
		t.Fatalf("verifyDNFRepositoryTrust() error = %v", err)
	}
	input.MetadataSignature = []byte("invented signature")
	if err := verifyDNFRepositoryTrust(input); err == nil {
		t.Fatal("package-signature-only repository accepted detached metadata bytes")
	}
}

func TestDNFPrimaryRejectsDuplicateMissingAndSubstitutedRecords(t *testing.T) {
	pkg := dnfPackageExpectation{
		Name: "docker-ce", Version: "3:28.3.2-1.fc44", RepositoryID: "docker-stable",
		Path: "/linux/fedora/44/x86_64/stable/Packages/docker-ce.rpm", Size: 25,
		SHA256: strings.Repeat("a", 64),
	}
	repository := dnfRepositoryExpectation{ID: "docker-stable", BasePath: "/linux/fedora/44/x86_64/stable/"}
	validPackage := dnfPackageXML(pkg, "x86_64")
	valid := []byte(`<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">` + validPackage + `</metadata>`)
	if err := verifyDNFPrimary(valid, "x86_64", repository, []dnfPackageExpectation{pkg}); err != nil {
		t.Fatalf("verifyDNFPrimary() error = %v", err)
	}
	invalid := [][]byte{
		[]byte(`<metadata>` + validPackage + validPackage + `</metadata>`),
		[]byte(strings.Replace(string(valid), `<arch>x86_64</arch>`, `<arch>aarch64</arch>`, 1)),
		[]byte(strings.Replace(string(valid), `package="25"`, `package="025"`, 1)),
		[]byte(strings.Replace(string(valid), `Packages/docker-ce.rpm`, `../docker-ce.rpm`, 1)),
		[]byte(strings.Replace(string(valid), strings.Repeat("a", 64), strings.Repeat("b", 64), 1)),
		[]byte(`<metadata></metadata>`),
	}
	for index, value := range invalid {
		if err := verifyDNFPrimary(value, "x86_64", repository, []dnfPackageExpectation{pkg}); err == nil {
			t.Fatalf("invalid primary metadata %d was accepted", index)
		}
	}
}

func signedDNFTrustInput(t testing.TB, metadataAuthentication string) dnfRepositoryTrustInput {
	t.Helper()
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	entity, err := openpgp.NewEntity("Docker Test", "", "security@example.test", &packet.Config{
		Time: func() time.Time { return now.Add(-time.Hour) }, DefaultHash: crypto.SHA512,
		Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048,
	})
	if err != nil {
		t.Fatal(err)
	}
	var key bytes.Buffer
	armoredKey, err := armor.Encode(&key, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = entity.Serialize(armoredKey); err != nil {
		t.Fatal(err)
	}
	if err = armoredKey.Close(); err != nil {
		t.Fatal(err)
	}
	pkg := dnfPackageExpectation{
		Name: "docker-ce", Version: "3:28.3.2-1.fc44", RepositoryID: "docker-stable",
		Path: "/linux/fedora/44/x86_64/stable/Packages/docker-ce.rpm", Size: 25,
		SHA256: strings.Repeat("a", 64),
	}
	primaryDocument := []byte(`<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">` +
		dnfPackageXML(pkg, "x86_64") + `</metadata>`)
	var primary bytes.Buffer
	compressor := gzip.NewWriter(&primary)
	if _, err = compressor.Write(primaryDocument); err != nil {
		t.Fatal(err)
	}
	if err = compressor.Close(); err != nil {
		t.Fatal(err)
	}
	primaryDigest := sha256.Sum256(primary.Bytes())
	primaryPath := "/linux/fedora/44/x86_64/stable/repodata/example-primary.xml.gz"
	repomd := []byte(fmt.Sprintf(
		`<repomd xmlns="http://linux.duke.edu/metadata/repo"><data type="primary"><checksum type="sha256">%s</checksum><location href="repodata/example-primary.xml.gz"/><size>%d</size></data></repomd>`,
		hex.EncodeToString(primaryDigest[:]), primary.Len(),
	))
	var signature bytes.Buffer
	if err = openpgp.ArmoredDetachSign(&signature, entity, bytes.NewReader(repomd), &packet.Config{
		Time: func() time.Time { return now.Add(-time.Hour) }, DefaultHash: crypto.SHA512,
	}); err != nil {
		t.Fatal(err)
	}
	return dnfRepositoryTrustInput{
		Now: now, Architecture: "x86_64",
		Repository: dnfRepositoryExpectation{
			ID: "docker-stable", BasePath: "/linux/fedora/44/x86_64/stable/",
			SigningKeyFingerprint:  strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)),
			MetadataAuthentication: metadataAuthentication,
			Index: aptArtifactExpectation{
				Path:   primaryPath,
				Size:   uint64(primary.Len()), // #nosec G115 -- bounded in-memory test fixture.
				SHA256: hex.EncodeToString(primaryDigest[:]),
			},
		},
		Packages: []dnfPackageExpectation{pkg}, SigningKey: key.Bytes(), RepositoryMetadata: repomd,
		MetadataSignature: signature.Bytes(), PackageIndex: primary.Bytes(),
	}
}

func dnfPackageXML(pkg dnfPackageExpectation, architecture string) string {
	epoch, version := "0", pkg.Version
	if splitEpoch, remainder, present := strings.Cut(version, ":"); present {
		epoch, version = splitEpoch, remainder
	}
	versionValue, release, _ := strings.Cut(version, "-")
	return fmt.Sprintf(
		`<package type="rpm"><name>%s</name><arch>%s</arch><version epoch="%s" ver="%s" rel="%s"/><checksum type="sha256" pkgid="YES">%s</checksum><size package="%d"/><location href="%s"/></package>`,
		pkg.Name, architecture, epoch, versionValue, release, pkg.SHA256, pkg.Size,
		strings.TrimPrefix(pkg.Path, "/linux/fedora/44/x86_64/stable/"),
	)
}
