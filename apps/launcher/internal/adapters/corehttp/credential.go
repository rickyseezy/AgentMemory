package corehttp

import "context"

// NativeCredentialSource reads the protected Core API credential through the
// platform's descriptor/handle, owner, ACL, link, and stable-identity checks.
type NativeCredentialSource struct{}

// NewNativeCredentialSource constructs the production credential source.
func NewNativeCredentialSource() *NativeCredentialSource { return &NativeCredentialSource{} }

// ReadCredential returns caller-owned bytes only after the complete native proof.
func (s *NativeCredentialSource) ReadCredential(ctx context.Context, path string) ([]byte, error) {
	if s == nil {
		return nil, errorsCredentialUnavailable()
	}
	return readNativeCredential(ctx, path)
}

var _ CredentialSource = (*NativeCredentialSource)(nil)

func errorsCredentialUnavailable() error { return errCredentialUnavailable }
