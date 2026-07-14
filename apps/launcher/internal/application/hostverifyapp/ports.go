// Package hostverifyapp certifies one signed PF-001 host policy against
// platform-native evidence without performing installation side effects.
package hostverifyapp

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
)

var (
	// ErrUntrustedSigner means the declared host-policy key is not embedded.
	ErrUntrustedSigner = errors.New("host verification signer is not trusted")
	// ErrSignatureInvalid means detached signature verification failed.
	ErrSignatureInvalid = errors.New("host verification signature is invalid")
	// ErrDependencyUnavailable means a non-policy trust capability failed.
	ErrDependencyUnavailable = errors.New("host verification dependency is unavailable")
)

// PlanSignatureVerifier verifies the detached signature over exact canonical bytes.
type PlanSignatureVerifier interface {
	VerifyHostPlanSignature(context.Context, hostverification.SignedPlan) error
}

// NativeHostProbe returns either complete native evidence or one closed
// rejection. It may not decide whether evidence satisfies policy.
type NativeHostProbe interface {
	ProbeHost(context.Context, hostverification.Plan) (hostverification.ProbeResult, error)
}
