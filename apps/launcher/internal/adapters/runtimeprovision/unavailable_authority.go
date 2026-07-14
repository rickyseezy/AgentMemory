package runtimeprovision

import (
	"context"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

// UnavailableSignedAuthority is the production fail-closed resolver used when
// a release does not carry the signed Linux execution projection described by
// LinuxAuthorityInput. It never derives or defaults a missing field.
type UnavailableSignedAuthority struct{}

// ResolveLinuxAuthority always requires a correctly signed release update.
func (UnavailableSignedAuthority) ResolveLinuxAuthority(
	ctx context.Context,
	_ []byte,
) (runtimeport.LinuxAuthority, error) {
	if ctx == nil {
		return runtimeport.LinuxAuthority{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.LinuxAuthority{}, err
	}
	return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityUnavailable
}

// UnavailablePrivilegeBroker is the production fail-closed broker until a
// publisher-signed Polkit helper and authenticated IPC/receipt verifier are
// installed. It never attempts sudo, pkexec command strings, or rootful Docker.
type UnavailablePrivilegeBroker struct{}

// Execute always returns the typed administrator-required dependency outcome.
func (UnavailablePrivilegeBroker) Execute(
	ctx context.Context,
	_ runtimeport.PrivilegeRequest,
) (runtimeport.PrivilegeReceipt, error) {
	if ctx == nil {
		return runtimeport.PrivilegeReceipt{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.PrivilegeReceipt{}, err
	}
	return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeUnavailable
}

var (
	_ runtimeport.AuthorityResolver = UnavailableSignedAuthority{}
	_ runtimeport.PrivilegeBroker   = UnavailablePrivilegeBroker{}
)
