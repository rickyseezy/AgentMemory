//go:build windows

package process

import (
	"context"
	"errors"
	"runtime"
	"unsafe"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	"golang.org/x/sys/windows"
)

type nativePublisherVerifier struct{ signer WindowsSignerIdentityVerifier }

// NewNativePublisherVerifier requires both native Authenticode chain
// validation and an authenticated exact signer-certificate binding.
func NewNativePublisherVerifier(dependencies NativePublisherDependencies) (PublisherVerifier, error) {
	if nilTrustDependency(dependencies.WindowsSignerIdentity) {
		return nil, errors.New("authenticated Windows signer identity verifier is required")
	}
	return nativePublisherVerifier{signer: dependencies.WindowsSignerIdentity}, nil
}

func (v nativePublisherVerifier) VerifyExecutablePublisher(
	ctx context.Context,
	authority argvprocess.ExecutableAuthority,
	evidence ExecutableEvidence,
) error {
	if ctx == nil || ctx.Err() != nil || !authority.Valid() ||
		authority.PublisherPolicyID() != windowsPublisherPolicy || evidence.Digest != authority.SHA256() ||
		nilTrustDependency(v.signer) || evidence.retainedHandle == 0 ||
		windows.Handle(evidence.retainedHandle) == windows.InvalidHandle {
		return argvprocess.ErrInvalidInvocation
	}
	path, err := windows.UTF16PtrFromString(authority.CanonicalPath())
	if err != nil {
		return argvprocess.ErrInvalidInvocation
	}
	fileInfo := &windows.WinTrustFileInfo{
		Size: uint32(unsafe.Sizeof(windows.WinTrustFileInfo{})), FilePath: path,
		File: windows.Handle(evidence.retainedHandle),
	}
	data := &windows.WinTrustData{
		Size: uint32(unsafe.Sizeof(windows.WinTrustData{})), UIChoice: windows.WTD_UI_NONE,
		RevocationChecks: windows.WTD_REVOKE_WHOLECHAIN, UnionChoice: windows.WTD_CHOICE_FILE,
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(fileInfo),
		// Offline installation must not turn native signature validation into
		// ambient network egress. Release qualification preloads and binds the
		// required revocation material; absent cached evidence fails closed.
		ProvFlags: windows.WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | windows.WTD_DISABLE_MD2_MD4 |
			windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
		UIContext: windows.WTD_UICONTEXT_EXECUTE,
	}
	verifyError := windows.WinVerifyTrustEx(
		windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data,
	)
	data.StateAction = windows.WTD_STATEACTION_CLOSE
	closeError := windows.WinVerifyTrustEx(
		windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, data,
	)
	runtime.KeepAlive(fileInfo)
	runtime.KeepAlive(path)
	if verifyError != nil || closeError != nil || ctx.Err() != nil {
		return argvprocess.ErrInvalidInvocation
	}
	if err := v.signer.VerifyWindowsSignerIdentity(ctx, authority, evidence); err != nil {
		return argvprocess.ErrInvalidInvocation
	}
	return nil
}
