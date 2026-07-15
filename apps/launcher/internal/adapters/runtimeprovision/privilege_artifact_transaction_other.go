//go:build !linux

package runtimeprovision

import "context"

type unavailablePrivilegeArtifactCopier struct{}

func newNativePrivilegeArtifactCopier() privilegeArtifactCopier {
	return unavailablePrivilegeArtifactCopier{}
}

func (unavailablePrivilegeArtifactCopier) CopyPrivilegeArtifacts(
	context.Context,
	string,
	uint32,
	uint32,
	[]PrivilegeTransactionArtifact,
) error {
	return ErrUnsupportedHost
}
