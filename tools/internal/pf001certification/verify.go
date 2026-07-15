package pf001certification

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"
)

const (
	reportPath    = "native-certification.json"
	signaturePath = "native-certification.signature.json"
)

var canonicalZIPTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

// VerifyOptions binds a native campaign to the reviewed matrix, exact release,
// external public authority, and qualification time.
type VerifyOptions struct {
	Matrix           SupportMatrix
	MatrixSHA256     string
	Publication      PublicationBinding
	PublicKey        ed25519.PublicKey
	VerificationTime time.Time
	RequiredCell     string
}

// Verification is the immutable result needed to assemble and reverify the
// canonical release evidence bundle.
type Verification struct {
	Report       CertificationReport
	ReportRaw    []byte
	SignatureRaw []byte
	Paths        []string
	Digests      map[string]string
	Sizes        map[string]uint64
}

type campaignSource interface {
	paths() ([]string, error)
	readSmall(string, int64) ([]byte, error)
	hash(string) (string, uint64, error)
}

// DecodePublicKeyBase64 validates one standard-base64 Ed25519 public key.
func DecodePublicKeyBase64(encoded string) (ed25519.PublicKey, error) {
	if encoded == "" || strings.TrimSpace(encoded) != encoded {
		return nil, errors.New("native certification public key is absent")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("native certification public key is invalid")
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

// AuthorityKeyID derives the report key identity from the exact public bytes.
func AuthorityKeyID(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("native certification public key is invalid")
	}
	digest := sha256.Sum256(publicKey)
	return "native-certification-" + hex.EncodeToString(digest[:16]), nil
}

// VerifyRoot verifies a raw external campaign directory without following
// links and without trusting attachment names from the filesystem.
func VerifyRoot(root string, options VerifyOptions) (Verification, error) {
	source, err := newRootSource(root)
	if err != nil {
		return Verification{}, err
	}
	return verifySource(source, options)
}

// VerifyBundle reverifies the canonical ZIP carried into qualification and
// immutable promotion.
func VerifyBundle(path string, options VerifyOptions) (Verification, error) {
	source, closer, err := newZIPSource(path)
	if err != nil {
		return Verification{}, err
	}
	defer func() { _ = closer.Close() }()
	return verifySource(source, options)
}

func verifySource(source campaignSource, options VerifyOptions) (Verification, error) {
	if source == nil || options.Matrix.validate() != nil || !validSHA256(options.MatrixSHA256) ||
		options.Publication.Version == "" || len(options.PublicKey) != ed25519.PublicKeySize ||
		options.VerificationTime.IsZero() || options.VerificationTime.Location() != time.UTC {
		return Verification{}, errors.New("native certification verification inputs are invalid")
	}
	reportRaw, err := source.readSmall(reportPath, maximumAuthorityBytes)
	if err != nil {
		return Verification{}, errors.New("native certification report is unavailable")
	}
	report, err := decodeCanonicalReport(reportRaw)
	if err != nil {
		return Verification{}, err
	}
	signatureRaw, err := source.readSmall(signaturePath, 16*1024)
	if err != nil {
		return Verification{}, errors.New("native certification signature is unavailable")
	}
	signature, err := decodeCanonicalSignature(signatureRaw)
	if err != nil {
		return Verification{}, err
	}
	keyID, _ := AuthorityKeyID(options.PublicKey)
	decodedSignature, decodeError := base64.StdEncoding.Strict().DecodeString(signature.Signature)
	if signature.SchemaVersion != SignatureSchemaVersion || signature.Algorithm != "ed25519" ||
		signature.KeyID != keyID || signature.ReportSHA256 != sha256Hex(reportRaw) ||
		decodeError != nil || len(decodedSignature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(decodedSignature) != signature.Signature ||
		!ed25519.Verify(options.PublicKey, reportRaw, decodedSignature) {
		return Verification{}, errors.New("native certification signature verification failed")
	}
	paths, digests, sizes, err := validateReportAndEvidence(source, report, options, keyID)
	if err != nil {
		return Verification{}, err
	}
	digests[reportPath], sizes[reportPath] = sha256Hex(reportRaw), uint64(len(reportRaw))
	digests[signaturePath], sizes[signaturePath] = sha256Hex(signatureRaw), uint64(len(signatureRaw))
	return Verification{
		Report: report, ReportRaw: reportRaw, SignatureRaw: signatureRaw,
		Paths: paths, Digests: digests, Sizes: sizes,
	}, nil
}

func validateReportAndEvidence(
	source campaignSource,
	report CertificationReport,
	options VerifyOptions,
	keyID string,
) ([]string, map[string]string, map[string]uint64, error) {
	publication := options.Publication
	if report.SchemaVersion != CertificationSchemaVersion || report.MatrixID != options.Matrix.MatrixID ||
		report.MatrixSHA256 != options.MatrixSHA256 || report.Version != publication.Version ||
		report.SourceCommit != publication.SourceCommit || report.PublicationSHA256 != publication.SHA256 ||
		report.DistributionManifestSHA256 != publication.DistributionManifestSHA256 ||
		report.ReleaseTrustSHA256 != publication.ReleaseTrustSHA256 || !safeID(report.CampaignID) ||
		report.AuthorityKeyID != keyID || report.ProcedureVersion != options.Matrix.ProcedureVersion || !report.NoWaivers ||
		len(report.Cells) != len(options.Matrix.Cells) {
		return nil, nil, nil, errors.New("native certification release authority does not match")
	}
	campaignStart, err := exactUTC(report.StartedAt)
	if err != nil {
		return nil, nil, nil, errors.New("native certification campaign start is invalid")
	}
	campaignEnd, err := exactUTC(report.CompletedAt)
	if err != nil || !campaignEnd.After(campaignStart) || campaignEnd.Sub(campaignStart) > 14*24*time.Hour ||
		campaignEnd.After(options.VerificationTime.Add(5*time.Minute)) ||
		options.VerificationTime.Sub(campaignEnd) > time.Duration(options.Matrix.MaximumEvidenceAgeSec)*time.Second {
		return nil, nil, nil, errors.New("native certification campaign time is invalid or stale")
	}
	expectedPaths := []string{reportPath, signaturePath}
	digests := make(map[string]string)
	sizes := make(map[string]uint64)
	seenSnapshots := make(map[string]struct{})
	requiredCellFound := options.RequiredCell == ""
	var totalBytes uint64
	for cellIndex, result := range report.Cells {
		cell := options.Matrix.Cells[cellIndex]
		if result.CellID != cell.ID || result.Filesystem != cell.Filesystem ||
			!validNumericVersion(result.ObservedVersion) ||
			compareNumericVersions(result.ObservedVersion, cell.MinimumOSVersion) < 0 ||
			compareNumericVersions(result.ObservedVersion, cell.MaximumOSVersion) > 0 ||
			result.ObservedBuild < cell.MinimumBuild || result.ObservedBuild > cell.MaximumBuild ||
			!validSHA256(result.StockImageSHA256) || !validSHA256(result.HardwareSHA256) {
			return nil, nil, nil, fmt.Errorf("native certification cell %q does not match support authority", cell.ID)
		}
		if result.CellID == options.RequiredCell {
			requiredCellFound = true
		}
		expectedTrials, _ := options.Matrix.Trials(cell.ID)
		if len(result.Trials) != len(expectedTrials) {
			return nil, nil, nil, fmt.Errorf("native certification cell %q has skipped trials", cell.ID)
		}
		for trialIndex, observed := range result.Trials {
			expected := expectedTrials[trialIndex]
			if observed.ScenarioID != expected.ScenarioID || observed.Variant != expected.Variant ||
				observed.Status != "passed" || !safeID(observed.SnapshotID) ||
				len(observed.Evidence) != len(expected.EvidenceKinds) {
				return nil, nil, nil, fmt.Errorf("native certification trial %s/%s/%s is absent, skipped, or invalid", cell.ID, expected.ScenarioID, expected.Variant)
			}
			if _, reused := seenSnapshots[observed.SnapshotID]; reused {
				return nil, nil, nil, fmt.Errorf("native certification snapshot %q was reused", observed.SnapshotID)
			}
			seenSnapshots[observed.SnapshotID] = struct{}{}
			trialStart, startError := exactUTC(observed.StartedAt)
			trialEnd, endError := exactUTC(observed.CompletedAt)
			if startError != nil || endError != nil || trialStart.Before(campaignStart) || trialEnd.After(campaignEnd) ||
				!trialEnd.After(trialStart) || trialEnd.Sub(trialStart) > 48*time.Hour ||
				observed.RebootCount > 8 || strings.Contains(observed.Variant, "reboot") && observed.RebootCount == 0 {
				return nil, nil, nil, fmt.Errorf("native certification trial %s/%s/%s has invalid time or reboot evidence", cell.ID, expected.ScenarioID, expected.Variant)
			}
			for evidenceIndex, evidence := range observed.Evidence {
				kind := expected.EvidenceKinds[evidenceIndex]
				expectedPath := expectedEvidencePath(expected, kind)
				if evidence.Kind != kind || evidence.Path != expectedPath || evidence.MediaType != evidenceMediaTypes[kind] ||
					!validSHA256(evidence.SHA256) || evidence.Size == 0 || evidence.Size > MaximumEvidenceFileBytes {
					return nil, nil, nil, fmt.Errorf("native certification evidence %q is invalid", expectedPath)
				}
				actualDigest, actualSize, hashError := source.hash(expectedPath)
				if hashError != nil || actualDigest != evidence.SHA256 || actualSize != evidence.Size {
					return nil, nil, nil, fmt.Errorf("native certification evidence %q does not match", expectedPath)
				}
				if totalBytes > MaximumEvidenceTotalBytes-evidence.Size {
					return nil, nil, nil, errors.New("native certification evidence exceeds the total byte limit")
				}
				totalBytes += evidence.Size
				expectedPaths = append(expectedPaths, expectedPath)
				digests[expectedPath], sizes[expectedPath] = actualDigest, actualSize
			}
		}
	}
	if !requiredCellFound {
		return nil, nil, nil, fmt.Errorf("required native certification cell %q is absent", options.RequiredCell)
	}
	if len(expectedPaths) > MaximumEvidenceFiles+2 {
		return nil, nil, nil, errors.New("native certification evidence file count exceeds the limit")
	}
	slices.Sort(expectedPaths)
	actualPaths, err := source.paths()
	if err != nil || !slices.Equal(actualPaths, expectedPaths) {
		return nil, nil, nil, errors.New("native certification evidence set is incomplete or contains foreign files")
	}
	return expectedPaths, digests, sizes, nil
}

func exactUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, errors.New("timestamp is not exact UTC RFC3339")
	}
	return parsed, nil
}

type rootSource struct{ root string }

func newRootSource(root string) (*rootSource, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("native certification root must be an absolute clean path")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("native certification root is not a directory")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || !filepath.IsAbs(resolved) {
		return nil, errors.New("native certification root cannot be resolved")
	}
	return &rootSource{root: filepath.Clean(resolved)}, nil
}

func (s *rootSource) paths() ([]string, error) {
	paths := make([]string, 0, 128)
	err := filepath.WalkDir(s.root, func(path string, entry fs.DirEntry, walkError error) error {
		if walkError != nil {
			return walkError
		}
		if path == s.root {
			return nil
		}
		info, err := entry.Info()
		if err != nil || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("native certification tree contains an unsafe entry")
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || !validEvidenceFileSize(info.Size()) {
			return errors.New("native certification tree contains a non-regular or oversized file")
		}
		relative, err := filepath.Rel(s.root, path)
		if err != nil || relative == "." || strings.Contains(relative, "\\") && runtime.GOOS != "windows" {
			return errors.New("native certification tree path is invalid")
		}
		paths = append(paths, filepath.ToSlash(relative))
		if len(paths) > MaximumEvidenceFiles+2 {
			return errors.New("native certification tree contains too many files")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.Sort(paths)
	return paths, nil
}

func (s *rootSource) readSmall(path string, maximum int64) ([]byte, error) {
	return readBoundedRegular(filepath.Join(s.root, filepath.FromSlash(path)), maximum)
}

func (s *rootSource) hash(path string) (string, uint64, error) {
	target := filepath.Join(s.root, filepath.FromSlash(path))
	info, err := os.Lstat(target)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		!validEvidenceFileSize(info.Size()) {
		return "", 0, errors.New("native certification evidence file is unsafe")
	}
	// #nosec G304 -- path is derived from the closed matrix evidence set.
	file, err := os.Open(target)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = file.Close() }()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, int64(MaximumEvidenceFileBytes)+1)) // #nosec G115 -- the constant is within int64.
	if err != nil || written != info.Size() {
		return "", 0, errors.New("native certification evidence read is unstable")
	}
	return hex.EncodeToString(digest.Sum(nil)), uint64(written), nil // #nosec G115 -- file size equality proves non-negativity.
}

type zipSource struct {
	reader *zip.ReadCloser
	files  map[string]*zip.File
	order  []string
}

func newZIPSource(path string) (*zipSource, io.Closer, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		!validBundleFileSize(info.Size()) {
		return nil, nil, errors.New("native certification bundle is unsafe")
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		return nil, nil, errors.New("native certification bundle is invalid")
	}
	source := &zipSource{reader: reader, files: make(map[string]*zip.File), order: make([]string, 0, len(reader.File))}
	for _, file := range reader.File {
		if file == nil || !safeArchivePath(file.Name) || file.Method != zip.Store || file.Mode().Perm() != 0o600 ||
			!file.Mode().IsRegular() || !file.Modified.Equal(canonicalZIPTime) ||
			file.UncompressedSize64 == 0 || file.UncompressedSize64 > MaximumEvidenceFileBytes {
			_ = reader.Close()
			return nil, nil, errors.New("native certification bundle entry is noncanonical")
		}
		if _, duplicate := source.files[file.Name]; duplicate {
			_ = reader.Close()
			return nil, nil, errors.New("native certification bundle entry is duplicated")
		}
		source.files[file.Name] = file
		source.order = append(source.order, file.Name)
	}
	if len(source.order) == 0 || len(source.order) > MaximumEvidenceFiles+2 || !slices.IsSorted(source.order) {
		_ = reader.Close()
		return nil, nil, errors.New("native certification bundle entries are absent or unordered")
	}
	return source, reader, nil
}

func (s *zipSource) paths() ([]string, error) { return append([]string(nil), s.order...), nil }

func (s *zipSource) readSmall(path string, maximum int64) ([]byte, error) {
	file := s.files[path]
	if file == nil || maximum <= 0 || file.UncompressedSize64 > boundedPositiveSize(maximum) {
		return nil, errors.New("native certification bundle authority is unavailable")
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()
	return io.ReadAll(io.LimitReader(reader, maximum+1))
}

func (s *zipSource) hash(path string) (string, uint64, error) {
	file := s.files[path]
	if file == nil || file.UncompressedSize64 > MaximumEvidenceFileBytes {
		return "", 0, errors.New("native certification bundle evidence is unavailable")
	}
	reader, err := file.Open()
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = reader.Close() }()
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(reader, int64(MaximumEvidenceFileBytes)+1)) // #nosec G115 -- constant is within int64.
	if err != nil || written < 0 || uint64(written) != file.UncompressedSize64 {
		return "", 0, errors.New("native certification bundle evidence is truncated")
	}
	return hex.EncodeToString(digest.Sum(nil)), uint64(written), nil // #nosec G115 -- negativity is checked above.
}

func safeArchivePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "\\") ||
		strings.ContainsRune(value, 0) || strings.HasSuffix(value, "/") {
		return false
	}
	parts := strings.Split(value, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return false
		}
	}
	return true
}

// CreateBundle publishes a deterministic stored ZIP only from an already
// verified raw campaign and reverifies the final bytes before returning.
func CreateBundle(root, output string, options VerifyOptions) error {
	verification, err := VerifyRoot(root, options)
	if err != nil {
		return err
	}
	if output == "" || !filepath.IsAbs(output) || filepath.Clean(output) != output {
		return errors.New("native certification bundle output path is invalid")
	}
	if _, err := os.Lstat(output); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("native certification bundle output already exists or cannot be inspected")
	}
	parent, err := os.Lstat(filepath.Dir(output))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("native certification bundle output parent is unsafe")
	}
	temporary := output + ".partial"
	// #nosec G304 -- output is an absolute caller-selected publication path validated above.
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	archive := zip.NewWriter(file)
	for _, path := range verification.Paths {
		header := &zip.FileHeader{Name: path, Method: zip.Store}
		header.SetMode(0o600)
		header.Modified = canonicalZIPTime
		entry, createError := archive.CreateHeader(header)
		if createError != nil {
			return createError
		}
		target := filepath.Join(root, filepath.FromSlash(path))
		// #nosec G304 -- path belongs to the fully verified closed evidence set.
		source, openError := os.Open(target)
		if openError != nil {
			return openError
		}
		digest := sha256.New()
		written, copyError := io.Copy(io.MultiWriter(entry, digest), source)
		closeError := source.Close()
		if copyError != nil || closeError != nil || written < 0 || uint64(written) != verification.Sizes[path] ||
			hex.EncodeToString(digest.Sum(nil)) != verification.Digests[path] {
			return errors.New("native certification evidence changed during bundling")
		}
	}
	if err := archive.Close(); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("native certification bundle could not be durably finalized")
	}
	if err := os.Rename(temporary, output); err != nil {
		return err
	}
	committed = true
	if _, err := VerifyBundle(output, options); err != nil {
		_ = os.Remove(output)
		return errors.New("native certification bundle failed final reverification")
	}
	return nil
}

func validEvidenceFileSize(size int64) bool {
	return size >= 0 && size <= 1<<30
}

func validBundleFileSize(size int64) bool {
	return size > 0 && size <= 16<<30+maximumAuthorityBytes
}

func boundedPositiveSize(size int64) uint64 {
	//nolint:gosec // G115: every caller proves size is positive before conversion.
	return uint64(size)
}

func signReportForTest(report []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("test signing key is invalid")
	}
	keyID, _ := AuthorityKeyID(privateKey.Public().(ed25519.PublicKey))
	signature := DetachedSignature{
		SchemaVersion: SignatureSchemaVersion, Algorithm: "ed25519", KeyID: keyID,
		ReportSHA256: sha256Hex(report), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, report)),
	}
	return canonicalSignature(signature)
}
