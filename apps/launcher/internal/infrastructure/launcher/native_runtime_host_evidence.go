package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
)

// nativeRuntimeHostReattestor binds runtime discovery to the same
// release-authenticated native host proof committed by VerifyHost.
type nativeRuntimeHostReattestor struct {
	verifier *hostverifyapp.Application
}

func (r nativeRuntimeHostReattestor) ReattestHost(
	ctx context.Context,
	request installplanapp.RuntimeEvidenceRequest,
) error {
	if r.verifier == nil {
		return errNativeInstallerIntegrity
	}
	verification, err := r.verifier.Verify(ctx, hostverifyapp.Command{
		OperationID: request.OperationID, ParentPlanDigest: request.ParentPlanDigest,
		SignedPlan: request.SignedHostPlan, StorageTarget: request.HostStorageTarget,
	})
	if err != nil || !verification.ValidFor(request.OperationID, request.ParentPlanDigest) ||
		!verification.Certified() ||
		!verification.HostPlanDigest().Equal(request.SignedHostPlan.Plan().Digest()) ||
		!verification.EvidenceDigest().Equal(request.HostEvidenceDigest) {
		return errNativeInstallerIntegrity
	}
	return nil
}
