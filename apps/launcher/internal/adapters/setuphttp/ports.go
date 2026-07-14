// Package setuphttp exposes the generated setup UI only through authenticated
// dual-stack loopback HTTP listeners.
package setuphttp

import (
	"context"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// Clock supplies explicit expiry and rate-limit policy time.
type Clock interface {
	Now() time.Time
}

// PrincipalVerifier returns the non-reversible digest of the current server OS
// principal at every authority boundary.
type PrincipalVerifier interface {
	CurrentPrincipal(context.Context) (install.Digest, error)
}

// BrowserOpener opens only the loopback setup URL assembled by Server.
type BrowserOpener interface {
	Open(context.Context, string) error
}
