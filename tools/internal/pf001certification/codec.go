package pf001certification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maximumAuthorityBytes = 4 << 20

// DecodeSupportMatrix strictly decodes and validates one matrix and returns
// the digest of the exact reviewed bytes.
func DecodeSupportMatrix(raw []byte) (SupportMatrix, string, error) {
	var matrix SupportMatrix
	if len(raw) == 0 || len(raw) > maximumAuthorityBytes || rejectDuplicateJSONKeys(raw) != nil ||
		decodeStrictJSON(raw, &matrix) != nil || matrix.validate() != nil {
		return SupportMatrix{}, "", errors.New("PF-001 support matrix is invalid")
	}
	return matrix, sha256Hex(raw), nil
}

// LoadSupportMatrix reads one bounded regular matrix file.
func LoadSupportMatrix(path string) (SupportMatrix, string, error) {
	raw, err := readBoundedRegular(path, maximumAuthorityBytes)
	if err != nil {
		return SupportMatrix{}, "", fmt.Errorf("read PF-001 support matrix: %w", err)
	}
	return DecodeSupportMatrix(raw)
}

// DecodePublicationBinding extracts only the exact release fields that native
// campaign evidence must bind. The publication command separately re-verifies
// the complete record and candidate tree before this function is called.
func DecodePublicationBinding(raw []byte) (PublicationBinding, error) {
	if len(raw) == 0 || len(raw) > maximumAuthorityBytes || rejectDuplicateJSONKeys(raw) != nil {
		return PublicationBinding{}, errors.New("release publication binding is invalid")
	}
	var document struct {
		SchemaVersion              int    `json:"schema_version"`
		Version                    string `json:"version"`
		SourceCommit               string `json:"source_commit"`
		DistributionManifestSHA256 string `json:"distribution_manifest_sha256"`
		ReleaseTrustSHA256         string `json:"release_trust_sha256"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		document.SchemaVersion != 1 || !validStableVersion(document.Version) ||
		!validSourceCommit(document.SourceCommit) || !validSHA256(document.DistributionManifestSHA256) ||
		!validSHA256(document.ReleaseTrustSHA256) ||
		document.DistributionManifestSHA256 == document.ReleaseTrustSHA256 {
		return PublicationBinding{}, errors.New("release publication binding is invalid")
	}
	return PublicationBinding{
		Version: document.Version, SourceCommit: document.SourceCommit, SHA256: sha256Hex(raw),
		DistributionManifestSHA256: document.DistributionManifestSHA256,
		ReleaseTrustSHA256:         document.ReleaseTrustSHA256,
	}, nil
}

// LoadPublicationBinding reads one bounded regular publication record.
func LoadPublicationBinding(path string) (PublicationBinding, error) {
	raw, err := readBoundedRegular(path, maximumAuthorityBytes)
	if err != nil {
		return PublicationBinding{}, fmt.Errorf("read release publication: %w", err)
	}
	return DecodePublicationBinding(raw)
}

// CanonicalizeReport strictly removes presentation-level JSON differences so
// the external authority signs one deterministic byte sequence.
func CanonicalizeReport(raw []byte) ([]byte, error) {
	var report CertificationReport
	if len(raw) == 0 || len(raw) > maximumAuthorityBytes || rejectDuplicateJSONKeys(raw) != nil ||
		decodeStrictJSON(raw, &report) != nil {
		return nil, errors.New("native certification report is invalid")
	}
	canonical, err := json.Marshal(report)
	if err != nil {
		return nil, errors.New("native certification report cannot be canonicalized")
	}
	return append(canonical, '\n'), nil
}

func decodeCanonicalReport(raw []byte) (CertificationReport, error) {
	canonical, err := CanonicalizeReport(raw)
	if err != nil || !bytes.Equal(raw, canonical) {
		return CertificationReport{}, errors.New("native certification report is not canonical")
	}
	var report CertificationReport
	if err := decodeStrictJSON(raw, &report); err != nil {
		return CertificationReport{}, errors.New("native certification report is invalid")
	}
	return report, nil
}

func canonicalSignature(signature DetachedSignature) ([]byte, error) {
	raw, err := json.Marshal(signature)
	if err != nil {
		return nil, errors.New("native certification signature cannot be canonicalized")
	}
	return append(raw, '\n'), nil
}

func decodeCanonicalSignature(raw []byte) (DetachedSignature, error) {
	var signature DetachedSignature
	if len(raw) == 0 || len(raw) > 16*1024 || rejectDuplicateJSONKeys(raw) != nil ||
		decodeStrictJSON(raw, &signature) != nil {
		return DetachedSignature{}, errors.New("native certification signature is invalid")
	}
	canonical, err := canonicalSignature(signature)
	if err != nil || !bytes.Equal(raw, canonical) {
		return DetachedSignature{}, errors.New("native certification signature is not canonical")
	}
	return signature, nil
}

// AssembleDetachedSignature verifies a raw hardware-signer result and emits
// the one canonical envelope accepted by release qualification. Private key
// material never enters AgentMemory or this process.
func AssembleDetachedSignature(
	reportRaw []byte,
	publicKey ed25519.PublicKey,
	rawSignature []byte,
) ([]byte, error) {
	if _, err := decodeCanonicalReport(reportRaw); err != nil || len(publicKey) != ed25519.PublicKeySize ||
		len(rawSignature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, reportRaw, rawSignature) {
		return nil, errors.New("native certification raw signature is invalid")
	}
	keyID, err := AuthorityKeyID(publicKey)
	if err != nil {
		return nil, err
	}
	return canonicalSignature(DetachedSignature{
		SchemaVersion: SignatureSchemaVersion,
		Algorithm:     "ed25519",
		KeyID:         keyID,
		ReportSHA256:  sha256Hex(reportRaw),
		Signature:     base64.StdEncoding.EncodeToString(rawSignature),
	})
}

func decodeStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, composite := token.(json.Delim)
		if !composite {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, keyError := decoder.Token()
				key, valid := keyToken.(string)
				if keyError != nil || !valid {
					return errors.New("JSON object key is invalid")
				}
				if _, duplicate := seen[key]; duplicate {
					return fmt.Errorf("JSON object key %q is duplicated", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errors.New("JSON object is not closed")
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errors.New("JSON array is not closed")
			}
		default:
			return errors.New("JSON delimiter is invalid")
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > maximum {
		return nil, errors.New("authority path is not a bounded regular file")
	}
	// #nosec G304 -- callers provide one closed, separately validated CLI path.
	return os.ReadFile(path)
}

func sha256Hex(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func validStableVersion(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 10 || len(part) > 1 && part[0] == '0' {
			return false
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return false
			}
		}
	}
	return true
}

func validSourceCommit(value string) bool {
	if len(value) != 40 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 20 && value != strings.Repeat("0", 40)
}
