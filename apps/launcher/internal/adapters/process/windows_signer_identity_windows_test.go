//go:build windows

package process

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001NativeWindowsSignerIdentityRejectsUnboundEvidence(t *testing.T) {
	t.Parallel()
	verifier := NewNativeWindowsSignerIdentityVerifier()
	if verifier == nil {
		t.Fatal("native Windows signer verifier is nil")
	}
	if err := verifier.VerifyWindowsSignerIdentity(
		context.Background(), argvprocess.ExecutableAuthority{}, ExecutableEvidence{},
	); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("unbound evidence error = %v", err)
	}
}
