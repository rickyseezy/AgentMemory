package runtimeprovision

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type privilegedLinuxIdentity struct {
	uid     uint32
	gid     uint32
	account string
	home    string
}

func (i privilegedLinuxIdentity) valid() bool {
	return i.uid != 0 && i.gid != 0 && validPrivilegedLinuxAccount(i.account) &&
		i.home != "" && filepath.IsAbs(i.home) && filepath.Clean(i.home) == i.home &&
		!strings.ContainsAny(i.home, "\x00\r\n")
}

func validPrivilegedLinuxAccount(value string) bool {
	if value == "" || len(value) > 32 || value[0] == '-' || value[0] >= '0' && value[0] <= '9' {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

type privilegedLinuxIdentitySource interface {
	CurrentPrivilegedLinuxIdentity(context.Context) (privilegedLinuxIdentity, error)
}

type privilegedLinuxMachineSource interface {
	CurrentPrivilegedLinuxMachine(context.Context) (string, runtimeinstall.Hash, error)
}

// PrivilegedLinuxHostBindingProvider reconstitutes the original non-root
// account independently inside the root helper. It grants no package or
// command authority.
type PrivilegedLinuxHostBindingProvider struct {
	identity privilegedLinuxIdentitySource
	machine  privilegedLinuxMachineSource
}

func newPrivilegedLinuxHostBindingProvider(
	identity privilegedLinuxIdentitySource,
	machine privilegedLinuxMachineSource,
) (*PrivilegedLinuxHostBindingProvider, error) {
	if nilDependency(identity) || nilDependency(machine) {
		return nil, errors.New("protected privileged Linux identity and machine sources are required")
	}
	return &PrivilegedLinuxHostBindingProvider{identity: identity, machine: machine}, nil
}

// CurrentLinuxHostBinding returns only the independently reconstructed
// original non-root principal and machine binding.
func (p *PrivilegedLinuxHostBindingProvider) CurrentLinuxHostBinding(
	ctx context.Context,
) (runtimecatalogapp.LinuxHostBinding, error) {
	if p == nil || ctx == nil || nilDependency(p.identity) || nilDependency(p.machine) {
		return runtimecatalogapp.LinuxHostBinding{}, ErrUnsupportedHost
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, err
	}
	identity, err := p.identity.CurrentPrivilegedLinuxIdentity(ctx)
	if err != nil || !identity.valid() {
		return runtimecatalogapp.LinuxHostBinding{}, sanitizedContextError(ctx, ErrUnsupportedHost)
	}
	version, machine, err := p.machine.CurrentPrivilegedLinuxMachine(ctx)
	if err != nil || version == "" || machine.IsZero() {
		return runtimecatalogapp.LinuxHostBinding{}, sanitizedContextError(ctx, ErrUnsupportedHost)
	}
	uid := strconv.FormatUint(uint64(identity.uid), 10)
	runtimeDirectory := "/run/user/" + uid
	binding, err := runtimecatalogapp.NewLinuxHostBinding(runtimecatalogapp.LinuxHostBindingInput{
		VersionID: version, InvokingUID: identity.uid, InvokingGID: identity.gid,
		AccountName: identity.account, PrincipalID: "linux:uid:" + uid,
		MachineDigest: machine, HomeDirectory: identity.home,
		RuntimeDirectory: runtimeDirectory, Endpoint: "unix://" + runtimeDirectory + "/docker.sock",
	})
	if err != nil {
		return runtimecatalogapp.LinuxHostBinding{}, ErrUnsupportedHost
	}
	return binding, nil
}

var _ LinuxHostBindingProvider = (*PrivilegedLinuxHostBindingProvider)(nil)
