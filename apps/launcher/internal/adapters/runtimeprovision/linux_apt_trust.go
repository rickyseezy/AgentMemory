package runtimeprovision

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ulikunitz/xz"
)

const (
	maximumAPTIndexBytes = 256 << 20
	maximumAPTLineBytes  = 1 << 20
	maximumAPTStanzas    = 1_000_000
	maximumAPTAge        = 7 * 24 * time.Hour
	maximumClockSkew     = 10 * time.Minute
)

type aptRepositoryTrustInput struct {
	Now          time.Time
	Architecture string
	Repository   aptRepositoryExpectation
	Packages     []aptPackageExpectation
	SigningKey   []byte
	InRelease    []byte
	PackageIndex []byte
}

type aptRepositoryExpectation struct {
	ID                    string
	BasePath              string
	Suite                 string
	Component             string
	SigningKeyFingerprint string
	Index                 aptArtifactExpectation
}

type aptArtifactExpectation struct {
	Path   string
	Size   uint64
	SHA256 string
}

type aptPackageExpectation struct {
	Name         string
	Version      string
	RepositoryID string
	Path         string
	Size         uint64
	SHA256       string
}

func verifyAPTRepositoryTrust(input aptRepositoryTrustInput) error {
	if input.Now.Location() != time.UTC || input.Architecture == "" || len(input.Packages) == 0 ||
		len(input.SigningKey) == 0 || len(input.InRelease) == 0 || len(input.PackageIndex) == 0 {
		return errAPTTrust
	}
	keyring, err := readAPTKeyring(input.SigningKey)
	if err != nil {
		return errAPTTrust
	}
	plaintext, signatureTime, signerFingerprint, err := verifyAPTInRelease(keyring, input.InRelease, input.Now)
	if err != nil || signerFingerprint != input.Repository.SigningKeyFingerprint ||
		signatureTime.After(input.Now.Add(maximumClockSkew)) {
		return errAPTTrust
	}
	if verifyAPTRelease(
		plaintext, input.Now, input.Architecture, input.Repository,
	) != nil {
		return errAPTTrust
	}
	decoded, err := decodeAPTIndex(input.Repository.Index.Path, input.PackageIndex)
	if err != nil {
		return errAPTTrust
	}
	if err = verifyAPTPackageIndex(decoded, input.Architecture, input.Repository, input.Packages); err != nil {
		return errAPTTrust
	}
	return nil
}

var errAPTTrust = errors.New("apt repository trust validation failed")

func readAPTKeyring(value []byte) (openpgp.EntityList, error) {
	reader := bytes.NewReader(value)
	var (
		keyring openpgp.EntityList
		err     error
	)
	if bytes.HasPrefix(bytes.TrimSpace(value), []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		keyring, err = openpgp.ReadArmoredKeyRing(reader)
	} else {
		keyring, err = openpgp.ReadKeyRing(reader)
	}
	if err != nil || len(keyring) == 0 {
		return nil, errAPTTrust
	}
	for _, entity := range keyring {
		if entity == nil || entity.PrimaryKey == nil || entity.PrivateKey != nil {
			return nil, errAPTTrust
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				return nil, errAPTTrust
			}
		}
	}
	return keyring, nil
}

func verifyAPTInRelease(
	keyring openpgp.EntityList,
	value []byte,
	now time.Time,
) ([]byte, time.Time, string, error) {
	if !bytes.HasPrefix(value, []byte("-----BEGIN PGP SIGNED MESSAGE-----\n")) &&
		!bytes.HasPrefix(value, []byte("-----BEGIN PGP SIGNED MESSAGE-----\r\n")) {
		return nil, time.Time{}, "", errAPTTrust
	}
	block, rest := clearsign.Decode(value)
	if block == nil || len(rest) != 0 || block.ArmoredSignature == nil {
		return nil, time.Time{}, "", errAPTTrust
	}
	config := &packet.Config{Time: func() time.Time { return now }, MinRSABits: 2048}
	signature, signer, err := openpgp.VerifyDetachedSignatureAndHash(
		keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body,
		[]crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512}, config,
	)
	if err != nil || signer == nil || signer.PrimaryKey == nil || signature == nil ||
		signature.SigType != packet.SigTypeText || signature.CreationTime.IsZero() {
		return nil, time.Time{}, "", errAPTTrust
	}
	return append([]byte(nil), block.Plaintext...), signature.CreationTime.UTC(),
		strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint)), nil
}

func verifyAPTRelease(
	plaintext []byte,
	now time.Time,
	architecture string,
	repository aptRepositoryExpectation,
) error {
	fields, err := parseAPTControlParagraph(plaintext)
	if err != nil || !listContains(fields["architectures"], architecture) ||
		!listContains(fields["components"], repository.Component) ||
		fields["suite"] != repository.Suite && fields["codename"] != repository.Suite {
		return errAPTTrust
	}
	releaseDate, err := parseAPTTime(fields["date"])
	if err != nil || releaseDate.After(now.Add(maximumClockSkew)) || now.Sub(releaseDate) > maximumAPTAge {
		return errAPTTrust
	}
	if validUntilValue := fields["valid-until"]; validUntilValue != "" {
		validUntil, validUntilError := parseAPTTime(validUntilValue)
		if validUntilError != nil || !validUntil.After(releaseDate) || now.After(validUntil) {
			return errAPTTrust
		}
	}
	relative, present := aptReleaseRelativePath(repository)
	if !present {
		return errAPTTrust
	}
	checksums, err := parseAPTReleaseChecksums(fields["sha256"])
	if err != nil {
		return errAPTTrust
	}
	entry, present := checksums[relative]
	if !present || entry.size != repository.Index.Size || entry.digest != repository.Index.SHA256 {
		return errAPTTrust
	}
	return nil
}

type aptReleaseChecksum struct {
	digest string
	size   uint64
}

func parseAPTReleaseChecksums(value string) (map[string]aptReleaseChecksum, error) {
	result := make(map[string]aptReleaseChecksum)
	for _, line := range strings.Split(value, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 || len(parts[0]) != 64 || !lowerHex(parts[0]) || !safeRepositoryPath(parts[2]) {
			return nil, errAPTTrust
		}
		size, err := parseCanonicalPositiveUint(parts[1])
		if err != nil {
			return nil, errAPTTrust
		}
		if _, duplicate := result[parts[2]]; duplicate {
			return nil, errAPTTrust
		}
		result[parts[2]] = aptReleaseChecksum{digest: parts[0], size: size}
	}
	if len(result) == 0 {
		return nil, errAPTTrust
	}
	return result, nil
}

func aptReleaseRelativePath(repository aptRepositoryExpectation) (string, bool) {
	prefix := strings.TrimSuffix(repository.BasePath, "/") + "/dists/" + repository.Suite + "/"
	path := repository.Index.Path
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	relative := strings.TrimPrefix(path, prefix)
	return relative, safeRepositoryPath(relative)
}

func decodeAPTIndex(path string, value []byte) ([]byte, error) {
	var reader io.Reader = bytes.NewReader(value)
	switch {
	case strings.HasSuffix(path, ".gz"):
		gzipReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, errAPTTrust
		}
		defer gzipReader.Close() //nolint:errcheck // a read-to-EOF below authenticates the complete gzip stream.
		reader = gzipReader
	case strings.HasSuffix(path, ".xz"):
		xzReader, err := xz.NewReader(reader)
		if err != nil {
			return nil, errAPTTrust
		}
		reader = xzReader
	case !strings.HasSuffix(path, "/Packages"):
		return nil, errAPTTrust
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, maximumAPTIndexBytes+1))
	if err != nil || len(decoded) == 0 || len(decoded) > maximumAPTIndexBytes {
		return nil, errAPTTrust
	}
	return decoded, nil
}

func verifyAPTPackageIndex(
	value []byte,
	architecture string,
	repository aptRepositoryExpectation,
	expected []aptPackageExpectation,
) error {
	wanted := make(map[string]aptPackageExpectation, len(expected))
	for _, pkg := range expected {
		if pkg.RepositoryID != repository.ID {
			return errAPTTrust
		}
		wanted[pkg.Name+"\x00"+pkg.Version] = pkg
	}
	found := make(map[string]struct{}, len(wanted))
	err := scanAPTParagraphs(value, true, func(fields map[string]string) error {
		key := fields["package"] + "\x00" + fields["version"]
		pkg, present := wanted[key]
		if !present {
			return nil
		}
		if _, duplicate := found[key]; duplicate {
			return errAPTTrust
		}
		size, sizeError := parseCanonicalPositiveUint(fields["size"])
		filename, filenamePresent := aptPackageRelativePath(repository, pkg)
		if sizeError != nil || !filenamePresent || fields["filename"] != filename ||
			fields["architecture"] != architecture && fields["architecture"] != "all" ||
			fields["sha256"] != pkg.SHA256 || size != pkg.Size {
			return errAPTTrust
		}
		found[key] = struct{}{}
		return nil
	})
	if err != nil || len(found) != len(wanted) {
		return errAPTTrust
	}
	return nil
}

func aptPackageRelativePath(
	repository aptRepositoryExpectation,
	pkg aptPackageExpectation,
) (string, bool) {
	prefix := strings.TrimSuffix(repository.BasePath, "/") + "/"
	path := pkg.Path
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	relative := strings.TrimPrefix(path, prefix)
	return relative, safeRepositoryPath(relative)
}

func scanAPTParagraphs(value []byte, requirePackage bool, visit func(map[string]string) error) error {
	scanner := bufio.NewScanner(bytes.NewReader(value))
	scanner.Buffer(make([]byte, 64*1024), maximumAPTLineBytes)
	fields := make(map[string]string)
	lastField := ""
	stanzas := 0
	flush := func() error {
		if len(fields) == 0 {
			return nil
		}
		stanzas++
		if stanzas > maximumAPTStanzas || requirePackage && fields["package"] == "" {
			return errAPTTrust
		}
		if err := visit(fields); err != nil {
			return err
		}
		fields = make(map[string]string)
		lastField = ""
		return nil
	}
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.ContainsRune(line, '\x00') {
			return errAPTTrust
		}
		if line == "" {
			if err := flush(); err != nil {
				return err
			}
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastField == "" {
				return errAPTTrust
			}
			fields[lastField] += "\n" + strings.TrimSpace(line)
			continue
		}
		name, fieldValue, present := strings.Cut(line, ":")
		name = strings.ToLower(name)
		if !present || !validAPTFieldName(name) {
			return errAPTTrust
		}
		if _, duplicate := fields[name]; duplicate {
			return errAPTTrust
		}
		fields[name] = strings.TrimSpace(fieldValue)
		lastField = name
	}
	if scanner.Err() != nil {
		return errAPTTrust
	}
	return flush()
}

func parseAPTControlParagraph(value []byte) (map[string]string, error) {
	var result map[string]string
	err := scanAPTParagraphs(value, false, func(fields map[string]string) error {
		if result != nil {
			return errAPTTrust
		}
		result = fields
		return nil
	})
	if err != nil || result == nil {
		return nil, errAPTTrust
	}
	return result, nil
}

func parseAPTTime(value string) (time.Time, error) {
	if parsed, err := http.ParseTime(value); err == nil {
		return parsed.UTC(), nil
	}
	parsed, err := time.Parse(time.RFC1123Z, value)
	if err != nil {
		return time.Time{}, errAPTTrust
	}
	return parsed.UTC(), nil
}

func listContains(value string, wanted string) bool {
	for _, item := range strings.Fields(value) {
		if item == wanted {
			return true
		}
	}
	return false
}

func validAPTFieldName(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func lowerHex(value string) bool {
	for _, character := range value {
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func parseCanonicalPositiveUint(value string) (uint64, error) {
	if value == "" || value == "0" || len(value) > 1 && value[0] == '0' {
		return 0, errAPTTrust
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 {
		return 0, errAPTTrust
	}
	return parsed, nil
}

func safeRepositoryPath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") ||
		strings.Contains(value, "//") || strings.ContainsAny(value, "\x00\r\n\\%?#") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
