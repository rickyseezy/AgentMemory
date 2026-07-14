package runtimeprovision

import (
	"context"
	"crypto/rand"
	"io"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

// CryptoNonceSource supplies one-use privilege challenges from the operating
// system CSPRNG. It has no deterministic or weak-random fallback.
type CryptoNonceSource struct {
	entropy io.Reader
}

// NewCryptoNonceSource constructs the production nonce source.
func NewCryptoNonceSource() *CryptoNonceSource {
	return &CryptoNonceSource{entropy: rand.Reader}
}

func newCryptoNonceSourceWithEntropy(entropy io.Reader) (*CryptoNonceSource, error) {
	if nilDependency(entropy) {
		return nil, ErrProvisionIntegrity
	}
	return &CryptoNonceSource{entropy: entropy}, nil
}

// NewPrivilegeNonce reads exactly 256 bits and rejects cancellation, short
// reads, entropy failures, and the all-zero sentinel.
func (s *CryptoNonceSource) NewPrivilegeNonce(ctx context.Context) (runtimeport.Nonce, error) {
	if ctx == nil {
		return runtimeport.Nonce{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.Nonce{}, err
	}
	if s == nil || nilDependency(s.entropy) {
		return runtimeport.Nonce{}, ErrProvisionIntegrity
	}
	var nonce runtimeport.Nonce
	if _, err := io.ReadFull(s.entropy, nonce[:]); err != nil || nonce.IsZero() {
		return runtimeport.Nonce{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.Nonce{}, err
	}
	return nonce, nil
}

// UTCClock supplies wall-clock observations normalized to UTC for signed
// privilege request and receipt expiry checks.
type UTCClock struct{}

// Now returns the current wall clock in UTC.
func (UTCClock) Now() time.Time { return time.Now().UTC() }

var (
	_ runtimeport.NonceSource = (*CryptoNonceSource)(nil)
	_ runtimeport.Clock       = UTCClock{}
)
