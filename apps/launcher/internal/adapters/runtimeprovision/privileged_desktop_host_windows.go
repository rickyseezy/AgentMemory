//go:build windows

package runtimeprovision

import (
	"context"
	"math"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"golang.org/x/sys/windows"
)

// NewPrivilegedDesktopHostBindingProvider uses the elevated process token,
// whose user SID remains the invoking UAC principal.
func NewPrivilegedDesktopHostBindingProvider(principalID string) (DesktopHostBindingProvider, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return nil, ErrUnsupportedHost
	}
	_, sid, err := windowssecurity.CurrentUserSID(context.Background())
	if err != nil || !strings.EqualFold(principalID, "sid:"+sid) {
		return nil, ErrUnsupportedHost
	}
	return NewNativeDesktopHostBindingProvider(), nil
}

// PrivilegedDesktopCatalogHostProvider independently re-probes the Windows
// catalog-admission facts inside the elevated helper.
type PrivilegedDesktopCatalogHostProvider struct {
	bindings DesktopHostBindingProvider
}

func NewPrivilegedDesktopCatalogHostProvider(
	bindings DesktopHostBindingProvider,
) (*PrivilegedDesktopCatalogHostProvider, error) {
	if nilDependency(bindings) {
		return nil, ErrUnsupportedHost
	}
	return &PrivilegedDesktopCatalogHostProvider{bindings: bindings}, nil
}

func (p *PrivilegedDesktopCatalogHostProvider) CurrentHost(
	ctx context.Context,
) (runtimecatalog.Host, error) {
	if p == nil || ctx == nil || nilDependency(p.bindings) || !windows.GetCurrentProcessToken().IsElevated() {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalog.Host{}, err
	}
	binding, err := p.bindings.CurrentDesktopHostBinding(
		ctx, runtimecatalog.DigestBytes([]byte("privileged-desktop-host-probe")), "host-probe.exe",
	)
	if err != nil {
		return runtimecatalog.Host{}, privilegedDesktopCatalogContextOrUnavailable(ctx)
	}
	version := windows.RtlGetVersion()
	memory, memoryOK := windowsDesktopMemory()
	cpus := windows.GetActiveProcessorCount(allWindowsProcessorGroups)
	free, local, filesystemError := windowsDesktopFilesystem(binding.HomeDirectory())
	if version == nil || version.MajorVersion != 10 || version.BuildNumber < 22000 || !memoryOK ||
		cpus == 0 || cpus > math.MaxUint32 || filesystemError != nil || !local || free == 0 ||
		!windows.IsProcessorFeaturePresent(windows.PF_VIRT_FIRMWARE_ENABLED) {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindWindows, Architecture: runtimecatalog.ArchitectureX8664,
		Edition: "desktop", Distribution: "windows-11", OSVersion: "10.0.0",
		Build: uint64(version.BuildNumber), CPUCores: cpus,
		MemoryBytes: memory.TotalPhysical, FreeDiskBytes: free, Virtualization: true,
	})
	if err != nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	return host, nil
}

var _ runtimecatalogapp.HostProvider = (*PrivilegedDesktopCatalogHostProvider)(nil)
