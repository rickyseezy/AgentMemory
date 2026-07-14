// Package releaseinventory defines the immutable, signed release inventory
// understood by the native launcher. It has no host, network, persistence, or
// process capabilities.
package releaseinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	maxIdentifierLength = 128
	maxSafeJSONInteger  = uint64(1<<53 - 1)
)

// Digest is an immutable SHA-256 subject digest.
type Digest [sha256.Size]byte

// DigestBytes calculates a SHA-256 digest over exact bytes.
func DigestBytes(value []byte) Digest { return sha256.Sum256(value) }

// ParseDigest parses exactly 64 lowercase hexadecimal characters.
func ParseDigest(value string) (Digest, error) {
	var digest Digest
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return digest, errors.New("SHA-256 digest must be lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return digest, errors.New("SHA-256 digest must be lowercase hexadecimal")
	}
	copy(digest[:], decoded)
	if digest.IsZero() {
		return Digest{}, errors.New("SHA-256 digest cannot be zero")
	}
	return digest, nil
}

// Hex returns the lowercase hexadecimal digest.
func (d Digest) Hex() string { return hex.EncodeToString(d[:]) }

// IsZero reports whether no digest was supplied.
func (d Digest) IsZero() bool { return d == Digest{} }

// Equal compares two digests without converting them to strings.
func (d Digest) Equal(other Digest) bool { return d == other }

// Platform is a canonical operating-system and architecture tuple. Its zero
// value means a platform-independent resource, never the current host.
type Platform struct {
	operatingSystem string
	architecture    string
}

// NewPlatform accepts only launcher-certified canonical platform vocabulary.
func NewPlatform(operatingSystem string, architecture string) (Platform, error) {
	if !oneOf(operatingSystem, "darwin", "linux", "windows") {
		return Platform{}, errors.New("release platform operating system is invalid")
	}
	if !oneOf(architecture, "amd64", "arm64") {
		return Platform{}, errors.New("release platform architecture is invalid")
	}
	return Platform{operatingSystem: operatingSystem, architecture: architecture}, nil
}

// OS returns the canonical operating-system name.
func (p Platform) OS() string { return p.operatingSystem }

// Architecture returns the canonical architecture name.
func (p Platform) Architecture() string { return p.architecture }

// IsAny reports whether a resource is platform independent.
func (p Platform) IsAny() bool { return p == Platform{} }

// Valid reports whether both platform components are present or both absent.
func (p Platform) Valid() bool {
	if p.IsAny() {
		return true
	}
	_, err := NewPlatform(p.operatingSystem, p.architecture)
	return err == nil
}

func (p Platform) String() string {
	if p.IsAny() {
		return "any"
	}
	return p.operatingSystem + "/" + p.architecture
}

// ProtocolRange is an inclusive compatibility window.
type ProtocolRange struct {
	minimum uint32
	maximum uint32
}

// NewProtocolRange constructs a nonzero, ordered protocol window.
func NewProtocolRange(minimum uint32, maximum uint32) (ProtocolRange, error) {
	if minimum == 0 || maximum < minimum {
		return ProtocolRange{}, errors.New("release protocol range is invalid")
	}
	return ProtocolRange{minimum: minimum, maximum: maximum}, nil
}

// Minimum returns the oldest supported protocol revision.
func (r ProtocolRange) Minimum() uint32 { return r.minimum }

// Maximum returns the newest supported protocol revision.
func (r ProtocolRange) Maximum() uint32 { return r.maximum }

// Contains reports whether a protocol revision is supported.
func (r ProtocolRange) Contains(version uint32) bool {
	return r.minimum != 0 && version >= r.minimum && version <= r.maximum
}

// Valid reports whether the compatibility range is usable.
func (r ProtocolRange) Valid() bool { return r.minimum != 0 && r.maximum >= r.minimum }

// SignatureTrustMode selects the offline trust evidence contract.
type SignatureTrustMode string

const (
	// SignatureTrustModeKeyID verifies a signature against an exact embedded key
	// ID. It is not Cosign certificate/transparency verification.
	SignatureTrustModeKeyID SignatureTrustMode = "key_id"
	// SignatureTrustModeCertificateTransparency requires a certificate chain,
	// Rekor inclusion proof/checkpoint, revocation data, and trusted-time proof.
	SignatureTrustModeCertificateTransparency SignatureTrustMode = "certificate_transparency"
)

// TrustPolicy is the signed manifest's offline signature policy.
type TrustPolicy struct {
	mode                SignatureTrustMode
	trustRootID         string
	runtimeTrustRootID  string
	revocationSetDigest Digest
	transparencyLogID   string
}

// NewTrustPolicy creates an exact trust-root and revocation binding.
func NewTrustPolicy(
	mode SignatureTrustMode,
	trustRootID string,
	revocationSetDigest Digest,
	transparencyLogID string,
) (TrustPolicy, error) {
	return NewTrustPolicyWithRuntimeRoot(
		mode,
		trustRootID,
		trustRootID,
		revocationSetDigest,
		transparencyLogID,
	)
}

// NewTrustPolicyWithRuntimeRoot creates separate exact release and runtime trust bindings.
func NewTrustPolicyWithRuntimeRoot(
	mode SignatureTrustMode,
	trustRootID string,
	runtimeTrustRootID string,
	revocationSetDigest Digest,
	transparencyLogID string,
) (TrustPolicy, error) {
	if mode != SignatureTrustModeKeyID && mode != SignatureTrustModeCertificateTransparency {
		return TrustPolicy{}, errors.New("release signature trust mode is invalid")
	}
	if !validIdentifier(trustRootID) || !validIdentifier(runtimeTrustRootID) || revocationSetDigest.IsZero() {
		return TrustPolicy{}, errors.New("release trust policy is incomplete")
	}
	if mode == SignatureTrustModeCertificateTransparency && !validIdentifier(transparencyLogID) {
		return TrustPolicy{}, errors.New("release transparency log ID is required")
	}
	if mode == SignatureTrustModeKeyID && transparencyLogID != "" {
		return TrustPolicy{}, errors.New("key-ID trust mode cannot declare a transparency log")
	}
	return TrustPolicy{
		mode:                mode,
		trustRootID:         trustRootID,
		runtimeTrustRootID:  runtimeTrustRootID,
		revocationSetDigest: revocationSetDigest,
		transparencyLogID:   transparencyLogID,
	}, nil
}

// Mode returns the required offline signature mode.
func (p TrustPolicy) Mode() SignatureTrustMode { return p.mode }

// TrustRootID returns the signed trust-root identifier.
func (p TrustPolicy) TrustRootID() string { return p.trustRootID }

// RuntimeTrustRootID returns the independently signed runtime trust-root identifier.
func (p TrustPolicy) RuntimeTrustRootID() string { return p.runtimeTrustRootID }

// RevocationSetDigest returns the expected offline revocation-set digest.
func (p TrustPolicy) RevocationSetDigest() Digest { return p.revocationSetDigest }

// TransparencyLogID returns the required log ID when transparency is enabled.
func (p TrustPolicy) TransparencyLogID() string { return p.transparencyLogID }

// Valid reports whether the policy can authorize verification.
func (p TrustPolicy) Valid() bool {
	_, err := NewTrustPolicyWithRuntimeRoot(
		p.mode,
		p.trustRootID,
		p.runtimeTrustRootID,
		p.revocationSetDigest,
		p.transparencyLogID,
	)
	return err == nil
}

func validIdentifier(value string) bool {
	if value == "" || len(value) > maxIdentifierLength {
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

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func checkedSafeJSONInteger(value uint64, field string) error {
	if value == 0 || value > maxSafeJSONInteger {
		return fmt.Errorf("%s is outside the canonical JSON integer range", field)
	}
	return nil
}
