//go:build !darwin && !linux && !windows

package setuphost

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// PrincipalVerifier is the fail-closed unsupported-platform implementation.
type PrincipalVerifier struct{}

// NewPrincipalVerifier constructs the fail-closed verifier.
func NewPrincipalVerifier() *PrincipalVerifier { return &PrincipalVerifier{} }

// CurrentPrincipal never manufactures authority on an uncertified platform.
func (*PrincipalVerifier) CurrentPrincipal(context.Context) (install.Digest, error) {
	return install.Digest{}, errors.New("setup principal platform is unsupported")
}
