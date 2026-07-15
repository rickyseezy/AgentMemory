//go:build windows

package runtimeprovision

import (
	"context"
	"errors"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

func TestPF001NativeDesktopWindowsSignerRejectsUnboundAuthority(t *testing.T) {
	t.Parallel()
	verifier := NewNativeDesktopWindowsSignerIdentityVerifier()
	if verifier == nil {
		t.Fatal("native desktop Windows signer verifier is nil")
	}
	if _, err := verifier.VerifyWindowsDesktopSigner(context.Background(), runtimeport.DesktopAuthority{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("artifact authority error = %v", err)
	}
	if _, err := verifier.VerifyWindowsDesktopApplicationSigner(
		context.Background(), runtimeport.DesktopAuthority{},
	); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("application authority error = %v", err)
	}
}
