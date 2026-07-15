package runtimeprovision

import (
	"context"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
)

const nativeLinuxRuntimeHelperPath = "/usr/libexec/agentmemory/agentmemory-runtime-helper"

// PrivilegeTransportCodec owns the canonical authenticated helper wire
// format. The broker never decodes or broadens the typed operation itself.
type PrivilegeTransportCodec interface {
	EncodePrivilegeRequest(runtimeport.PrivilegeRequest) ([]byte, error)
	DecodePrivilegeReceipt([]byte) (runtimeport.PrivilegeReceipt, error)
}

// PolkitPrivilegeBroker transports exactly one closed request over stdin to
// the fixed release-owned helper through the signed pkexec authority.
type PolkitPrivilegeBroker struct {
	runner argvprocess.Runner
	codec  PrivilegeTransportCodec
}

// NewPolkitPrivilegeBroker constructs the graphical Linux elevation boundary.
func NewPolkitPrivilegeBroker(
	runner argvprocess.Runner,
	codec PrivilegeTransportCodec,
) (*PolkitPrivilegeBroker, error) {
	if nilDependency(runner) || nilDependency(codec) {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	authority := runner.ExecutableAuthority()
	if !authority.Valid() || authority.Role() != argvprocess.ExecutableRolePrivilegeBroker ||
		authority.Platform() != "linux" || authority.CanonicalPath() != "/usr/bin/pkexec" ||
		authority.OwnerIdentity() != "uid:0" || authority.PublisherPolicyID() != "linux:package-receipt:v1" {
		return nil, runtimeport.ErrPrivilegeIntegrity
	}
	return &PolkitPrivilegeBroker{runner: runner, codec: codec}, nil
}

// Execute invokes no shell and returns only the typed receipt or a closed
// semantic error. Native stderr and codec diagnostics never cross the adapter.
func (b *PolkitPrivilegeBroker) Execute(
	ctx context.Context,
	request runtimeport.PrivilegeRequest,
) (runtimeport.PrivilegeReceipt, error) {
	if ctx == nil {
		return runtimeport.PrivilegeReceipt{}, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return runtimeport.PrivilegeReceipt{}, err
	}
	if b == nil || nilDependency(b.runner) || nilDependency(b.codec) ||
		request.Digest().IsZero() || !request.Authority().Valid() {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	raw, err := b.codec.EncodePrivilegeRequest(request)
	if err != nil {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	defer clear(raw)
	invocation, err := argvprocess.NewPrivilegeBrokerInvocation(
		b.runner.ExecutableAuthority().CanonicalPath(), nativeLinuxRuntimeHelperPath, raw,
	)
	if err != nil {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	result, runError := b.runner.Run(ctx, invocation)
	if err := ctx.Err(); err != nil {
		return runtimeport.PrivilegeReceipt{}, err
	}
	if result.ExitCode == 126 {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeDenied
	}
	if result.ExitCode == 127 || runError != nil {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeUnavailable
	}
	if result.ExitCode != 0 || result.OutputTruncated || len(result.StandardOutput) == 0 ||
		len(result.StandardError) != 0 {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	receipt, err := b.codec.DecodePrivilegeReceipt(result.StandardOutput)
	if err != nil || receipt.Digest().IsZero() {
		return runtimeport.PrivilegeReceipt{}, runtimeport.ErrPrivilegeIntegrity
	}
	return receipt, nil
}

var _ runtimeport.PrivilegeBroker = (*PolkitPrivilegeBroker)(nil)
