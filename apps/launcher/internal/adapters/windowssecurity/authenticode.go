// Package windowssecurity centralizes reviewed Windows-native security
// boundaries and their platform-independent policy helpers.
package windowssecurity

import (
	"crypto/sha256"
	"errors"
)

const maximumAuthenticodeCertificateBytes = 1 << 20

// ErrAuthenticodeIdentity is returned when a signed Windows object cannot be
// bound to one unambiguous primary signer certificate.
var ErrAuthenticodeIdentity = errors.New("windows Authenticode signer identity is invalid")

func authenticodeCertificateDigest(encoded []byte) ([sha256.Size]byte, error) {
	if len(encoded) == 0 || len(encoded) > maximumAuthenticodeCertificateBytes {
		return [sha256.Size]byte{}, ErrAuthenticodeIdentity
	}
	return sha256.Sum256(encoded), nil
}
