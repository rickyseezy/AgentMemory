//go:build linux

package runtimeprovision

import (
	"context"
	"os"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

const maximumLinuxCPUInfoBytes = 8 << 20

// PrivilegedLinuxCatalogHostProvider independently re-probes the actual root
// helper host for signed catalog platform admission.
type PrivilegedLinuxCatalogHostProvider struct {
	bindings LinuxHostBindingProvider
}

// NewPrivilegedLinuxCatalogHostProvider constructs the production root-host
// catalog projection from the protected original principal source.
func NewPrivilegedLinuxCatalogHostProvider(
	bindings LinuxHostBindingProvider,
) (*PrivilegedLinuxCatalogHostProvider, error) {
	if nilDependency(bindings) {
		return nil, ErrUnsupportedHost
	}
	return &PrivilegedLinuxCatalogHostProvider{bindings: bindings}, nil
}

// CurrentHost derives the exact signed-catalog host facts from the privileged
// Linux helper's independently verified invoking-user binding.
func (p *PrivilegedLinuxCatalogHostProvider) CurrentHost(
	ctx context.Context,
) (runtimecatalog.Host, error) {
	if p == nil || ctx == nil || nilDependency(p.bindings) || os.Geteuid() != 0 || runtime.GOOS != "linux" {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalog.Host{}, err
	}
	binding, err := p.bindings.CurrentLinuxHostBinding(ctx)
	if err != nil {
		return runtimecatalog.Host{}, privilegedCatalogContextOrUnavailable(ctx)
	}
	distribution, versionID, err := linuxOSRelease()
	if err != nil || versionID != binding.VersionID() {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	version, err := normalizedPrivilegeCatalogVersion(versionID)
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	kernel, architecture, err := linuxKernelArchitecture()
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	build, err := normalizedPrivilegeCatalogBuild(kernel)
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	cpuCores, totalMemory, _, err := linuxResources()
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	freeDisk, localFilesystem, err := linuxHomeFilesystem(binding.HomeDirectory())
	if err != nil || !localFilesystem {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	virtualization, err := privilegedLinuxVirtualizationAvailable()
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	var catalogArchitecture runtimecatalog.Architecture
	switch architecture {
	case runtimeinstall.ArchitectureAMD64:
		catalogArchitecture = runtimecatalog.ArchitectureX8664
	case runtimeinstall.ArchitectureARM64:
		catalogArchitecture = runtimecatalog.ArchitectureARM64
	case runtimeinstall.ArchitectureUnknown:
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	default:
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindLinux, Architecture: catalogArchitecture,
		Edition: "workstation", Distribution: distribution, OSVersion: version, Build: build,
		CPUCores: uint32(cpuCores), MemoryBytes: totalMemory, FreeDiskBytes: freeDisk,
		Virtualization: virtualization,
	})
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	return host, nil
}

func privilegedLinuxVirtualizationAvailable() (bool, error) {
	if info, err := os.Lstat("/dev/kvm"); err == nil {
		return info.Mode()&os.ModeDevice != 0 && info.Mode()&os.ModeCharDevice != 0 &&
			info.Mode()&os.ModeSymlink == 0, nil
	}
	raw, err := readRootOwnedRegular("/proc/cpuinfo", maximumLinuxCPUInfoBytes)
	if err != nil {
		return false, err
	}
	return privilegedLinuxVirtualizationFlags(raw), nil
}

func privilegedCatalogContextOrUnavailable(ctx context.Context) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return runtimecatalogapp.ErrDependencyUnavailable
}

var _ runtimecatalogapp.HostProvider = (*PrivilegedLinuxCatalogHostProvider)(nil)
