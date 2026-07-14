//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

const catalogDockerApplicationPath = "/Applications/Docker.app"

type nativeCatalogObservationBackend struct {
	host    func(CatalogObservationInput) (runtimeinstall.HostCapabilities, string, error)
	runtime func(context.Context, CatalogObservationInput, string, string) (runtimeinstall.RuntimeDiscovery, bool, bool, error)
}

func newNativeCatalogObservationBackend() catalogObservationBackend {
	return nativeCatalogObservationBackend{host: observeDarwinCatalogHost, runtime: observeDarwinCatalogRuntime}
}

func (b nativeCatalogObservationBackend) ObserveCatalogRuntime(
	ctx context.Context,
	input CatalogObservationInput,
) (CatalogObservationResult, error) {
	manifest := input.Catalog.Manifest()
	if ctx == nil || !manifest.Valid() || manifest.Platform().OperatingSystem() != runtimecatalog.OSKindMacOS ||
		input.NativePublisherTrust.IsZero() || !filepath.IsAbs(input.HostStorageTarget) ||
		!strings.HasPrefix(input.RuntimeEndpoint, "unix://") {
		return CatalogObservationResult{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return CatalogObservationResult{}, err
	}
	endpoint := strings.TrimPrefix(input.RuntimeEndpoint, "unix://")
	if !filepath.IsAbs(endpoint) || filepath.Clean(endpoint) != endpoint {
		return CatalogObservationResult{}, ErrProvisionIntegrity
	}
	if input.CertifiedRuntime.Platform() != runtimeinstall.PlatformDarwin || b.host == nil || b.runtime == nil {
		return CatalogObservationResult{}, ErrProvisionIntegrity
	}
	host, version, err := b.host(input)
	if err != nil {
		return CatalogObservationResult{}, err
	}
	discovery, applicationPresent, endpointPresent, err := b.runtime(ctx, input, catalogDockerApplicationPath, endpoint)
	if err != nil {
		return CatalogObservationResult{}, err
	}
	encoded, _ := json.Marshal(struct {
		Application bool   `json:"application_present"`
		Catalog     string `json:"catalog_digest"`
		Endpoint    bool   `json:"endpoint_present"`
		Host        string `json:"host_version"`
		Publisher   string `json:"publisher_trust"`
	}{
		Application: applicationPresent, Catalog: input.Catalog.ManifestDigest().Hex(),
		Endpoint: endpointPresent, Host: version, Publisher: input.NativePublisherTrust.Hex(),
	})
	return CatalogObservationResult{Host: host, Discovery: discovery, Evidence: runtimeinstall.Sum(encoded)}, nil
}

func observeDarwinCatalogHost(input CatalogObservationInput) (runtimeinstall.HostCapabilities, string, error) {
	version, versionError := unix.Sysctl("kern.osproductversion")
	cpu, cpuError := unix.SysctlUint32("hw.physicalcpu")
	total, totalError := unix.SysctlUint64("hw.memsize")
	hypervisor, hypervisorError := unix.SysctlUint32("kern.hv_support")
	available := nativeDarwinAvailableMemory()
	freeDisk, local, diskError := darwinDesktopFilesystem(input.HostStorageTarget)
	if versionError != nil || cpuError != nil || totalError != nil || hypervisorError != nil || diskError != nil ||
		cpu == 0 || cpu > math.MaxUint16 || total == 0 || available == 0 || available > total ||
		hypervisor != 1 || !local || !nativeDarwinEncrypted(input.HostStorageTarget) {
		return runtimeinstall.HostCapabilities{}, "", ErrUnsupportedHost
	}
	architecture := runtimeinstall.ArchitectureARM64
	if runtime.GOARCH == "amd64" {
		architecture = runtimeinstall.ArchitectureAMD64
	} else if runtime.GOARCH != "arm64" {
		return runtimeinstall.HostCapabilities{}, "", ErrUnsupportedHost
	}
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformDarwin, architecture, version, true, true, true, true,
		uint16(cpu), total, available, freeDisk,
	)
	if err != nil {
		return runtimeinstall.HostCapabilities{}, "", ErrProbeFailed
	}
	return host, version, nil
}

func observeDarwinCatalogRuntime(
	ctx context.Context,
	input CatalogObservationInput,
	applicationPath string,
	endpoint string,
) (runtimeinstall.RuntimeDiscovery, bool, bool, error) {
	application, applicationError := os.Lstat(applicationPath)
	applicationPresent := applicationError == nil
	if applicationError != nil && !errors.Is(applicationError, os.ErrNotExist) {
		return runtimeinstall.RuntimeDiscovery{}, false, false, ErrProbeFailed
	}
	if applicationPresent && (!application.IsDir() || application.Mode()&os.ModeSymlink != 0) {
		return runtimeinstall.RuntimeDiscovery{}, true, false, ErrRuntimeConflict
	}
	endpointInfo, endpointError := os.Lstat(endpoint)
	endpointPresent := endpointError == nil
	if endpointError != nil && !errors.Is(endpointError, os.ErrNotExist) {
		return runtimeinstall.RuntimeDiscovery{}, applicationPresent, false, ErrProbeFailed
	}
	if endpointPresent {
		stat, ok := endpointInfo.Sys().(*syscall.Stat_t)
		euid := os.Geteuid()
		if euid < 0 || uint64(euid) > math.MaxUint32 || !ok || endpointInfo.Mode()&os.ModeSocket == 0 ||
			endpointInfo.Mode()&os.ModeSymlink != 0 || stat.Uid != uint32(euid) || // #nosec G115 -- euid is bounded above.
			endpointInfo.Mode().Perm()&0o077 != 0 {
			return runtimeinstall.RuntimeDiscovery{}, applicationPresent, true, ErrRuntimeConflict
		}
	}
	if !applicationPresent && !endpointPresent {
		return runtimeinstall.NewAbsentRuntimeDiscovery(), false, false, nil
	}
	if !applicationPresent {
		return runtimeinstall.RuntimeDiscovery{}, false, true, ErrRuntimeConflict
	}
	trust := runtimeinstall.Hash(input.NativePublisherTrust)
	version, verified := darwinDockerApplicationVersion(ctx, applicationPath, trust)
	if !verified {
		return runtimeinstall.RuntimeDiscovery{}, true, endpointPresent, ErrRuntimeConflict
	}
	condition := runtimeinstall.RuntimeConditionStopped
	if endpointPresent {
		condition = runtimeinstall.RuntimeConditionIncompatible
	}
	discovery, err := runtimeinstall.NewRuntimeDiscovery(
		condition, "docker_desktop", version, input.RuntimeEndpoint, true, true, false,
		runtimeinstall.OwnershipReusedExternal, 0,
	)
	if err != nil {
		return runtimeinstall.RuntimeDiscovery{}, true, endpointPresent, ErrProbeFailed
	}
	return discovery, true, endpointPresent, nil
}

var _ catalogObservationBackend = nativeCatalogObservationBackend{}
