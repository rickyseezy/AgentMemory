//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"golang.org/x/sys/unix"
)

// NewPrivilegedDesktopHostBindingProvider resolves the real invoking user
// rather than the root effective identity inherited by Authorization Services.
func NewPrivilegedDesktopHostBindingProvider(principalID string) (DesktopHostBindingProvider, error) {
	uidValue := strings.TrimPrefix(principalID, "uid:")
	uid, parseError := strconv.Atoi(uidValue)
	if os.Geteuid() != 0 || uidValue == principalID || parseError != nil || uid <= 0 {
		return nil, ErrUnsupportedHost
	}
	return &NativeDesktopHostBindingProvider{
		uid:         func() int { return uid },
		currentUser: func() (*user.User, error) { return user.LookupId(strconv.Itoa(uid)) },
		home: func() (string, error) {
			current, err := user.LookupId(strconv.Itoa(uid))
			if err != nil {
				return "", err
			}
			return current.HomeDir, nil
		},
		machine: nativeDarwinMachineDigest, architecture: runtime.GOARCH,
	}, nil
}

// PrivilegedDesktopCatalogHostProvider independently re-probes macOS catalog
// admission facts while retaining the real-user home/storage boundary.
type PrivilegedDesktopCatalogHostProvider struct {
	bindings DesktopHostBindingProvider
}

// NewPrivilegedDesktopCatalogHostProvider binds catalog host probing to the
// authenticated invoking-user desktop authority.
func NewPrivilegedDesktopCatalogHostProvider(
	bindings DesktopHostBindingProvider,
) (*PrivilegedDesktopCatalogHostProvider, error) {
	if nilDependency(bindings) {
		return nil, ErrUnsupportedHost
	}
	return &PrivilegedDesktopCatalogHostProvider{bindings: bindings}, nil
}

// CurrentHost independently probes the privileged macOS host and returns only
// catalog-admission facts joined to the real-user storage boundary.
func (p *PrivilegedDesktopCatalogHostProvider) CurrentHost(
	ctx context.Context,
) (runtimecatalog.Host, error) {
	if p == nil || ctx == nil || nilDependency(p.bindings) || os.Geteuid() != 0 {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalog.Host{}, err
	}
	// A fixed non-zero digest and filename are used only to recover the same
	// protected real-user binding; neither participates in returned authority.
	binding, err := p.bindings.CurrentDesktopHostBinding(
		ctx, runtimecatalog.DigestBytes([]byte("privileged-desktop-host-probe")), "host-probe.dmg",
	)
	if err != nil {
		return runtimecatalog.Host{}, privilegedDesktopCatalogContextOrUnavailable(ctx)
	}
	version, versionError := unix.Sysctl("kern.osproductversion")
	cpu, cpuError := unix.SysctlUint32("hw.physicalcpu")
	memory, memoryError := unix.SysctlUint64("hw.memsize")
	hypervisor, hypervisorError := unix.SysctlUint32("kern.hv_support")
	build, buildError := numericDesktopBuild(version)
	free, local, filesystemError := darwinDesktopFilesystem(binding.HomeDirectory())
	if versionError != nil || cpuError != nil || memoryError != nil || hypervisorError != nil ||
		buildError != nil || filesystemError != nil || !local || hypervisor != 1 || cpu == 0 ||
		memory == 0 || free == 0 {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	architecture := runtimecatalog.ArchitectureARM64
	if runtime.GOARCH == "amd64" {
		architecture = runtimecatalog.ArchitectureX8664
	} else if runtime.GOARCH != "arm64" {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindMacOS, Architecture: architecture,
		Edition: "desktop", Distribution: "macos", OSVersion: version, Build: uint64(build),
		CPUCores: cpu, MemoryBytes: memory, FreeDiskBytes: free, Virtualization: true,
	})
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	return host, nil
}

var _ runtimecatalogapp.HostProvider = (*PrivilegedDesktopCatalogHostProvider)(nil)
