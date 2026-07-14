//go:build windows

package setuphost

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const windowsPrincipalDomain = "agentmemory.setup-principal.windows.v1"

// PrincipalVerifier binds setup authority to the current process-token SID.
type PrincipalVerifier struct{}

// NewPrincipalVerifier constructs the native verifier.
func NewPrincipalVerifier() *PrincipalVerifier { return &PrincipalVerifier{} }

// CurrentPrincipal returns a domain-separated non-reversible SID digest.
func (*PrincipalVerifier) CurrentPrincipal(ctx context.Context) (install.Digest, error) {
	if ctx == nil {
		return install.Digest{}, errors.New("setup principal context is invalid")
	}
	if err := ctx.Err(); err != nil {
		return install.Digest{}, err
	}
	_, sid, err := windowssecurity.CurrentUserSID(ctx)
	if err != nil || sid == "" {
		return install.Digest{}, errors.New("setup principal is unavailable")
	}
	return install.DigestBytes([]byte(windowsPrincipalDomain + "\x00" + sid)), nil
}
