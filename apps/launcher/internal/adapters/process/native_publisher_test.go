//go:build !darwin || cgo

package process

import (
	"context"
	"errors"
	"runtime"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

func TestPF001NativePublisherVerifierFailsClosedOnPolicySubstitution(t *testing.T) {
	t.Parallel()
	dependencies := NativePublisherDependencies{}
	switch runtime.GOOS {
	case "linux":
		dependencies.LinuxPackageReceipt = packageReceiptStub{}
	case "windows":
		dependencies.WindowsSignerIdentity = windowsSignerStub{}
	}
	verifier, err := NewNativePublisherVerifier(dependencies)
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		if err == nil {
			t.Fatal("unsupported platform constructed a native verifier")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	authority := testExecutableAuthority(t, testCurrentExecutable(t))
	evidence := ExecutableEvidence{Digest: authority.SHA256()}
	if err := verifier.VerifyExecutablePublisher(context.Background(), authority, evidence); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("publisher policy substitution error = %v", err)
	}
}

func TestPF001NativePublisherVerifierRequiresPlatformReceiptDependencies(t *testing.T) {
	t.Parallel()
	_, err := NewNativePublisherVerifier(NativePublisherDependencies{})
	switch runtime.GOOS {
	case "linux", "windows":
		if err == nil {
			t.Fatal("missing authenticated platform receipt dependency was accepted")
		}
	case "darwin":
		if err != nil {
			t.Fatalf("macOS native verifier construction error = %v", err)
		}
	}
}
