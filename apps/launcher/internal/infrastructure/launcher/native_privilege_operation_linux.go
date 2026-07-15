//go:build linux

package launcher

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

// nativePrivilegeOperationExecutor constructs request-scoped runners only
// after the helper has independently verified release, catalog, host, helper,
// and plan authority.
type nativePrivilegeOperationExecutor struct{}

func (*nativePrivilegeOperationExecutor) ExecutePrivilegeOperation(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
	artifacts runtimeprovision.PrivilegeArtifactSet,
	evidence runtimeprovision.PrivilegeAuthorityEvidence,
) (runtimeprovision.PrivilegeOperationObservationInput, error) {
	if ctx == nil || request.Digest().IsZero() || evidence.Authority().Digest() != request.Authority().Digest() ||
		evidence.ReleaseManifestDigest().IsZero() {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	authority := evidence.Authority()
	runners, err := newNativeLinuxPrivilegeRunnerSet(
		authority, releaseinventory.Digest(evidence.ReleaseManifestDigest()),
	)
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	writer, err := runtimeprovision.NewNativePrivilegeProtectedFileWriter()
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	repository, err := runtimeprovision.NewCanonicalPrivilegeRepositoryManager(writer)
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	packagesState, err := runtimeprovision.NewNativePrivilegePackageStateProbe(runners.query)
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	packages, err := runtimeprovision.NewExactPrivilegePackageManager(runners.transaction, packagesState)
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	subordinates, err := runtimeprovision.NewNativePrivilegeSubordinateIDManager()
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	service, err := runtimeprovision.NewNativePrivilegeUserServiceManager(runners.loginctl, runners.systemctl)
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	repositoryState, err := runtimeprovision.NewNativePrivilegeRepositoryStateProbe()
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	observer, err := runtimeprovision.NewNativePrivilegeManagedStateObserver(
		runtimeprovision.PrivilegeManagedStateDependencies{
			Repository: repositoryState, Packages: packagesState,
			Subordinates: subordinates, Service: service,
		},
	)
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	executor, err := runtimeprovision.NewClosedPrivilegeOperationExecutor(
		runtimeprovision.PrivilegeOperationDependencies{
			Repository: repository, Packages: packages, Subordinates: subordinates,
			Service: service, Observer: observer,
		},
	)
	if err != nil {
		return runtimeprovision.PrivilegeOperationObservationInput{}, runtimeport.ErrPrivilegeIntegrity
	}
	return executor.ExecutePrivilegeOperation(ctx, request, artifacts, evidence)
}

var _ runtimeprovision.PrivilegeOperationExecutor = (*nativePrivilegeOperationExecutor)(nil)
