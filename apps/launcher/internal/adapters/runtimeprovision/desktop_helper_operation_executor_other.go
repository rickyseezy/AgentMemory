//go:build (!darwin && !windows) || (darwin && !cgo)

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

type unavailableDesktopMutationBackend struct{}

func newNativeDesktopMutationBackend(
	DesktopMutationCommandRunner,
	DesktopMutationReleaseArtifactSource,
) desktopMutationNativeBackend {
	return unavailableDesktopMutationBackend{}
}

func (unavailableDesktopMutationBackend) ExecuteNativeDesktopMutation(
	context.Context,
	runtimeport.DesktopMutationRequest,
	DesktopMutationArtifactBinding,
	bool,
	DesktopMutationAuthorityEvidence,
) (uint32, error) {
	return 0, ErrUnsupportedHost
}
