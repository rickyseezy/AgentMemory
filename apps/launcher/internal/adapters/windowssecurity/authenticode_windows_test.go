//go:build windows

package windowssecurity

import (
	"context"
	"errors"
	"testing"
)

func TestPF001AuthenticodeSignerRejectsMissingContextAndAmbientPath(t *testing.T) {
	t.Parallel()
	var nilContext context.Context
	if _, err := AuthenticodeLeafCertificateSHA256(nilContext, `C:\signed.exe`); !errors.Is(err, ErrAuthenticodeIdentity) {
		t.Fatalf("nil context error = %v", err)
	}
	if _, err := AuthenticodeLeafCertificateSHA256(context.Background(), `signed.exe`); !errors.Is(err, ErrAuthenticodeIdentity) {
		t.Fatalf("relative path error = %v", err)
	}
}
