//go:build darwin || linux

package setuphost

import (
	"context"
	"errors"
	"os"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

const unixPrincipalDomain = "agentmemory.setup-principal.unix.v1"

// PrincipalVerifier binds setup authority to the non-privileged real and
// effective user identity that launched AgentMemory.
type PrincipalVerifier struct{}

// NewPrincipalVerifier constructs the native verifier without observing host
// state; every authority boundary re-observes the current identity.
func NewPrincipalVerifier() *PrincipalVerifier { return &PrincipalVerifier{} }

// CurrentPrincipal returns only a non-reversible digest. A set-user-ID or root
// transition is never accepted as the original user's browser authority.
func (*PrincipalVerifier) CurrentPrincipal(ctx context.Context) (install.Digest, error) {
	if ctx == nil {
		return install.Digest{}, errors.New("setup principal context is invalid")
	}
	if err := ctx.Err(); err != nil {
		return install.Digest{}, err
	}
	uid, effectiveUID := os.Getuid(), os.Geteuid()
	if uid <= 0 || effectiveUID != uid {
		return install.Digest{}, errors.New("setup principal is unavailable")
	}
	binding := unixPrincipalDomain + "\x00" + strconv.Itoa(uid)
	return install.DigestBytes([]byte(binding)), nil
}
