package runtimeprovision

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ulikunitz/xz"
)

func TestAPTRepositoryTrustAuthenticatesExactSignedPackageChain(t *testing.T) {
	input := signedAPTTrustInput(t)
	keyring, err := readAPTKeyring(input.SigningKey)
	if err != nil {
		t.Fatalf("readAPTKeyring() error = %v", err)
	}
	plaintext, _, fingerprint, err := verifyAPTInRelease(keyring, input.InRelease, input.Now)
	if err != nil || fingerprint != input.Repository.SigningKeyFingerprint {
		t.Fatalf("verifyAPTInRelease() fingerprint=%q error=%v", fingerprint, err)
	}
	if err = verifyAPTRelease(plaintext, input.Now, input.Architecture, input.Repository); err != nil {
		t.Fatalf("verifyAPTRelease() error = %v", err)
	}
	decoded, err := decodeAPTIndex(input.Repository.Index.Path, input.PackageIndex)
	if err != nil {
		t.Fatalf("decodeAPTIndex() error = %v", err)
	}
	if err = verifyAPTPackageIndex(decoded, input.Architecture, input.Repository, input.Packages); err != nil {
		t.Fatalf("verifyAPTPackageIndex() error = %v", err)
	}
	if err := verifyAPTRepositoryTrust(input); err != nil {
		t.Fatalf("verifyAPTRepositoryTrust() error = %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*aptRepositoryTrustInput)
	}{
		{name: "wrong fingerprint", mutate: func(v *aptRepositoryTrustInput) {
			v.Repository.SigningKeyFingerprint = strings.Repeat("A", 40)
		}},
		{name: "tampered signature", mutate: func(v *aptRepositoryTrustInput) {
			v.InRelease = append([]byte(nil), v.InRelease...)
			v.InRelease[len(v.InRelease)-20] ^= 1
		}},
		{name: "expired metadata", mutate: func(v *aptRepositoryTrustInput) {
			v.Now = v.Now.Add(8 * 24 * time.Hour)
		}},
		{name: "wrong package digest", mutate: func(v *aptRepositoryTrustInput) {
			v.Packages = append([]aptPackageExpectation(nil), v.Packages...)
			v.Packages[0].SHA256 = strings.Repeat("0", 64)
		}},
		{name: "wrong repository", mutate: func(v *aptRepositoryTrustInput) {
			v.Packages = append([]aptPackageExpectation(nil), v.Packages...)
			v.Packages[0].RepositoryID = "other"
		}},
		{name: "truncated index", mutate: func(v *aptRepositoryTrustInput) {
			v.PackageIndex = append([]byte(nil), v.PackageIndex[:len(v.PackageIndex)-1]...)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := input
			test.mutate(&candidate)
			if err := verifyAPTRepositoryTrust(candidate); !errors.Is(err, errAPTTrust) {
				t.Fatalf("verifyAPTRepositoryTrust() error = %v", err)
			}
		})
	}
}

func TestAPTPackageIndexRejectsDuplicateMissingMalformedAndSubstitutedRecords(t *testing.T) {
	expectation := aptPackageExpectation{
		Name: "docker-ce", Version: "5:28.3.2-1~ubuntu.24.04~noble", RepositoryID: "docker-stable",
		Path: "/linux/ubuntu/dists/noble/pool/stable/amd64/docker-ce.deb", Size: 25,
		SHA256: strings.Repeat("a", 64),
	}
	repository := aptRepositoryExpectation{ID: "docker-stable", BasePath: "/linux/ubuntu/"}
	valid := aptPackageParagraph(expectation, "amd64")
	if err := verifyAPTPackageIndex([]byte(valid), "amd64", repository, []aptPackageExpectation{expectation}); err != nil {
		t.Fatalf("verifyAPTPackageIndex() error = %v", err)
	}
	invalid := []string{
		valid + "\n" + valid,
		strings.Replace(valid, "Architecture: amd64", "Architecture: arm64", 1),
		strings.Replace(valid, "Size: 25", "Size: 025", 1),
		strings.Replace(valid, "Filename: dists/", "Filename: ../", 1),
		strings.Replace(valid, "SHA256: "+strings.Repeat("a", 64), "SHA256: "+strings.Repeat("b", 64), 1),
		strings.Replace(valid, "Package: docker-ce", "Package docker-ce", 1),
		strings.Replace(valid, "Version:", "Package: duplicate\nVersion:", 1),
	}
	for index, value := range invalid {
		if err := verifyAPTPackageIndex([]byte(value), "amd64", repository, []aptPackageExpectation{expectation}); err == nil {
			t.Fatalf("invalid index %d was accepted", index)
		}
	}
}

func TestAPTIndexDecoderBoundsAndSupportsRequiredCompression(t *testing.T) {
	plain := []byte("Package: docker-ce\n\n")
	var gzipBuffer bytes.Buffer
	gzipWriter := gzip.NewWriter(&gzipBuffer)
	if _, err := gzipWriter.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	var xzBuffer bytes.Buffer
	xzWriter, err := xz.NewWriter(&xzBuffer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = xzWriter.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err = xzWriter.Close(); err != nil {
		t.Fatal(err)
	}
	for path, encoded := range map[string][]byte{
		"/Packages": plain, "/Packages.gz": gzipBuffer.Bytes(), "/Packages.xz": xzBuffer.Bytes(),
	} {
		decoded, decodeError := decodeAPTIndex(path, encoded)
		if decodeError != nil || !bytes.Equal(decoded, plain) {
			t.Fatalf("decodeAPTIndex(%s) = %q, %v", path, decoded, decodeError)
		}
	}
	if _, err = decodeAPTIndex("/Packages.zip", plain); err == nil {
		t.Fatal("unsupported package-index compression was accepted")
	}
}

func signedAPTTrustInput(t testing.TB) aptRepositoryTrustInput {
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
	pkg := aptPackageExpectation{
		Name: "docker-ce", Version: "5:28.3.2-1~ubuntu.24.04~noble", RepositoryID: "docker-stable",
		Path: "/linux/ubuntu/dists/noble/pool/stable/amd64/docker-ce.deb", Size: 25,
		SHA256: strings.Repeat("a", 64),
	}
	packageDocument := []byte(aptPackageParagraph(pkg, "amd64"))
	var compressed bytes.Buffer
	compressor := gzip.NewWriter(&compressed)
	if _, err = compressor.Write(packageDocument); err != nil {
		t.Fatal(err)
	}
	if err = compressor.Close(); err != nil {
		t.Fatal(err)
	}
	indexDigest := sha256.Sum256(compressed.Bytes())
	indexPath := "/linux/ubuntu/dists/noble/stable/binary-amd64/Packages.gz"
	indexSize := uint64(compressed.Len()) // #nosec G115 -- bounded in-memory test fixture.
	release := fmt.Sprintf(
		"Architectures: amd64 arm64\nComponents: stable\nDate: %s\nValid-Until: %s\nSuite: noble\nSHA256:\n %s %d stable/binary-amd64/Packages.gz\n",
		now.Add(-time.Hour).Format(time.RFC1123Z), now.Add(24*time.Hour).Format(time.RFC1123Z),
		hex.EncodeToString(indexDigest[:]), compressed.Len(),
	)
	var inRelease bytes.Buffer
	cleartext, err := clearsign.Encode(&inRelease, entity.PrivateKey, &packet.Config{
		Time: func() time.Time { return now.Add(-time.Hour) }, DefaultHash: crypto.SHA512,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = cleartext.Write([]byte(release)); err != nil {
		t.Fatal(err)
	}
	if err = cleartext.Close(); err != nil {
		t.Fatal(err)
	}
	return aptRepositoryTrustInput{
		Now: now, Architecture: "amd64",
		Repository: aptRepositoryExpectation{
			ID: "docker-stable", BasePath: "/linux/ubuntu/", Suite: "noble", Component: "stable",
			SigningKeyFingerprint: strings.ToUpper(hex.EncodeToString(entity.PrimaryKey.Fingerprint)),
			Index:                 aptArtifactExpectation{Path: indexPath, Size: indexSize, SHA256: hex.EncodeToString(indexDigest[:])},
		},
		Packages: []aptPackageExpectation{pkg}, SigningKey: key.Bytes(),
		InRelease: inRelease.Bytes(), PackageIndex: compressed.Bytes(),
	}
}

func aptPackageParagraph(pkg aptPackageExpectation, architecture string) string {
	return fmt.Sprintf(
		"Package: %s\nVersion: %s\nArchitecture: %s\nFilename: %s\nSize: %d\nSHA256: %s\n\n",
		pkg.Name, pkg.Version, architecture, strings.TrimPrefix(pkg.Path, "/linux/ubuntu/"), pkg.Size, pkg.SHA256,
	)
}
