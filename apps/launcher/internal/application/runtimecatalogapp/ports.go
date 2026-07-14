// Package runtimecatalogapp verifies signed runtime prerequisite catalog cells
// without acquiring or executing an artifact.
package runtimecatalogapp

import (
	"context"
	"errors"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// Typed outbound-port errors used for fail-closed application mapping.
var (
	ErrUntrustedSigner        = errors.New("runtime catalog signer is not trusted")
	ErrSignatureInvalid       = errors.New("runtime catalog signature is invalid")
	ErrNativePublisherInvalid = errors.New("runtime native publisher policy is invalid")
	ErrCatalogAnchorNotFound  = errors.New("runtime catalog anti-rollback anchor was not found")
	ErrCatalogAnchorConflict  = errors.New("runtime catalog anti-rollback anchor changed")
	ErrCatalogAnchorIntegrity = errors.New("runtime catalog anti-rollback anchor integrity failed")
	ErrDependencyUnavailable  = errors.New("runtime catalog verification dependency is unavailable")
)

// Clock supplies the trusted policy time established by the launcher's trust-evidence subsystem.
type Clock interface {
	Now() time.Time
}

// HostProvider returns a read-only validated host capability projection.
type HostProvider interface {
	CurrentHost(context.Context) (runtimecatalog.Host, error)
}

// ManifestSignatureVerifier verifies detached signature bytes against the declared catalog key.
type ManifestSignatureVerifier interface {
	VerifyManifestSignature(context.Context, runtimecatalog.SignedManifest) error
}

// NativePublisherVerifier qualifies the declared native publisher, key, and package identities.
// Actual downloaded bytes must still pass native verification in VerifyRuntimeArtifact.
type NativePublisherVerifier interface {
	VerifyNativePublisherPolicy(context.Context, runtimecatalog.PublisherPolicy) error
}

// AntiRollbackRepository atomically persists a per-catalog monotonic high-water mark.
type AntiRollbackRepository interface {
	LoadCatalogAnchor(context.Context, string) (CatalogAnchor, error)
	CompareAndSwapCatalogAnchor(context.Context, *CatalogAnchor, CatalogAnchor) error
}
