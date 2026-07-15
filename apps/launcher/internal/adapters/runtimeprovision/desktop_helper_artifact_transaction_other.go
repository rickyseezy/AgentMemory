//go:build !darwin && !windows

package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

type unavailableDesktopMutationArtifactCopier struct{}

func newNativeDesktopMutationArtifactCopier() desktopMutationArtifactCopier {
	return unavailableDesktopMutationArtifactCopier{}
}

func (unavailableDesktopMutationArtifactCopier) CopyDesktopMutationArtifact(
	context.Context,
	runtimeport.DesktopMutationRequest,
	DesktopMutationTransactionArtifact,
) error {
	return ErrUnsupportedHost
}

var _ desktopMutationArtifactCopier = unavailableDesktopMutationArtifactCopier{}
