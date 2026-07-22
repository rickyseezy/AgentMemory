// Package provideradaptertrust adapts the launcher's audited offline trust
// implementation to the narrow PRO-002 supply-chain ports.
package provideradaptertrust

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/provideradapterapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// OfflineArtifactVerifier is implemented by the launcher's Sigstore bundle verifier.
type OfflineArtifactVerifier interface {
	VerifyArtifactSignature(context.Context, releaseinventory.Digest, []byte) error
}

// SigstoreImagePolicy verifies an exact OCI descriptor with pre-distributed offline roots.
type SigstoreImagePolicy struct{ verifier OfflineArtifactVerifier }

// NewSigstoreImagePolicy requires the audited offline certificate/transparency verifier.
func NewSigstoreImagePolicy(verifier OfflineArtifactVerifier) (*SigstoreImagePolicy, error) {
	if nilInterface(verifier) {
		return nil, provideradapterapp.ErrVerification
	}
	return &SigstoreImagePolicy{verifier: verifier}, nil
}

// Verify rechecks the reference binding before delegating to offline Sigstore verification.
func (p *SigstoreImagePolicy) Verify(
	ctx context.Context,
	image string,
	digest provideradapter.Digest,
	bundle []byte,
) error {
	if p == nil || ctx == nil || digest.IsZero() || len(bundle) == 0 ||
		!strings.HasSuffix(image, "@sha256:"+digest.Hex()) {
		return provideradapterapp.ErrVerification
	}
	if err := p.verifier.VerifyArtifactSignature(ctx, releaseinventory.Digest(digest), bundle); err != nil {
		return errors.Join(provideradapterapp.ErrVerification, err)
	}
	return nil
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	//nolint:exhaustive // Every non-nilable concrete kind is a valid verifier.
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var _ provideradapterapp.ImageSignaturePolicy = (*SigstoreImagePolicy)(nil)
