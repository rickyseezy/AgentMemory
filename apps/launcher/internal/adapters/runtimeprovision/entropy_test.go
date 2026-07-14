package runtimeprovision

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestCryptoNonceSourceReadsExactEntropyAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	wanted := bytes.Repeat([]byte{0x5a}, 32)
	source, err := newCryptoNonceSourceWithEntropy(bytes.NewReader(wanted))
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := source.NewPrivilegeNonce(context.Background())
	if err != nil || nonce != runtimeport.Nonce([32]byte{
		0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
		0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
		0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
		0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a, 0x5a,
	}) {
		t.Fatalf("nonce/error = %x/%v", nonce, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.NewPrivilegeNonce(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled nonce error = %v", err)
	}
}

func TestCryptoNonceSourceFailsClosedOnInvalidEntropy(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		entropy io.Reader
	}{
		{name: "short", entropy: bytes.NewReader([]byte{1})},
		{name: "zero", entropy: bytes.NewReader(make([]byte, 32))},
		{name: "failure", entropy: errorReader{}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			source, err := newCryptoNonceSourceWithEntropy(test.entropy)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := source.NewPrivilegeNonce(context.Background()); !errors.Is(err, ErrProvisionIntegrity) {
				t.Fatalf("nonce error = %v", err)
			}
		})
	}
	if _, err := newCryptoNonceSourceWithEntropy(nil); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil entropy error = %v", err)
	}
	var nilSource *CryptoNonceSource
	if _, err := nilSource.NewPrivilegeNonce(context.Background()); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil source error = %v", err)
	}
	var nilContext context.Context
	if _, err := NewCryptoNonceSource().NewPrivilegeNonce(nilContext); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestUTCClockAlwaysReturnsUTC(t *testing.T) {
	t.Parallel()
	now := (UTCClock{}).Now()
	if now.IsZero() || now.Location() != time.UTC {
		t.Fatalf("UTC clock = %v", now)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("entropy unavailable") }
