package windowssecurity

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestPF001AuthenticodeCertificateDigestIsExactAndBounded(t *testing.T) {
	t.Parallel()
	der := []byte{0x30, 0x03, 0x02, 0x01, 0x01}
	digest, err := authenticodeCertificateDigest(der)
	if err != nil || digest != sha256.Sum256(der) {
		t.Fatalf("authenticodeCertificateDigest() = %x, %v", digest, err)
	}
	der[0] = 0
	if digest == sha256.Sum256(der) {
		t.Fatal("returned digest retained mutable certificate input")
	}
	for _, invalid := range [][]byte{nil, {}, make([]byte, maximumAuthenticodeCertificateBytes+1)} {
		if _, err := authenticodeCertificateDigest(invalid); !errors.Is(err, ErrAuthenticodeIdentity) {
			t.Fatalf("invalid certificate length %d error = %v", len(invalid), err)
		}
	}
}
