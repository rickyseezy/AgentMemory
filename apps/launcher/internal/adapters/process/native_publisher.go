package process

import (
	"context"
	"reflect"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
)

const (
	dockerPublisherIdentity = "teamid:9BNSXJN65R"
	darwinPublisherPolicy   = "apple:developer-id-notarized:v1"
	windowsPublisherPolicy  = "windows:authenticode:v1"
	linuxPublisherPolicy    = "linux:package-receipt:v1"
)

// LinuxPackageReceiptVerifier proves that the exact executable evidence was
// recorded by the authenticated runtime-catalog/install-ownership aggregate.
// Discovery output and package-manager presence alone are not sufficient.
type LinuxPackageReceiptVerifier interface {
	VerifyLinuxPackageReceipt(context.Context, argvprocess.ExecutableAuthority, ExecutableEvidence) error
}

// WindowsSignerIdentityVerifier binds a WinVerifyTrust-successful file to the
// exact signer certificate identity declared by the signed runtime plan.
type WindowsSignerIdentityVerifier interface {
	VerifyWindowsSignerIdentity(context.Context, argvprocess.ExecutableAuthority, ExecutableEvidence) error
}

// NativePublisherDependencies contains only authenticated platform evidence
// which cannot be derived from executable discovery.
type NativePublisherDependencies struct {
	LinuxPackageReceipt   LinuxPackageReceiptVerifier
	WindowsSignerIdentity WindowsSignerIdentityVerifier
}

func nilTrustDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Non-nilable reflection kinds are intentionally handled by default.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
