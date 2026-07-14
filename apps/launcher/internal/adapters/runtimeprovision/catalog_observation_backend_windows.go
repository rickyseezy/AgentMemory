//go:build windows

package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

const (
	catalogWindowsDockerEndpoint = `npipe:////./pipe/docker_engine`
	catalogWindowsDockerPipe     = `\\.\pipe\docker_engine`
)

type nativeCatalogObservationBackend struct {
	host    func(CatalogObservationInput) (runtimeinstall.HostCapabilities, string, error)
	runtime func(context.Context, CatalogObservationInput, string, string, string) (runtimeinstall.RuntimeDiscovery, bool, bool, error)
}

func newNativeCatalogObservationBackend() catalogObservationBackend {
	return nativeCatalogObservationBackend{host: observeWindowsCatalogHost, runtime: observeWindowsCatalogRuntime}
}

func (b nativeCatalogObservationBackend) ObserveCatalogRuntime(
	ctx context.Context,
	input CatalogObservationInput,
) (CatalogObservationResult, error) {
	manifest := input.Catalog.Manifest()
	if ctx == nil || !manifest.Valid() || manifest.Platform().OperatingSystem() != runtimecatalog.OSKindWindows ||
		input.CertifiedRuntime.Platform() != runtimeinstall.PlatformWindows ||
		input.CertifiedRuntime.Architecture() != runtimeinstall.ArchitectureAMD64 || runtime.GOARCH != "amd64" ||
		input.NativePublisherTrust.IsZero() || input.RuntimeEndpoint != catalogWindowsDockerEndpoint ||
		!filepath.IsAbs(input.HostStorageTarget) || filepath.Clean(input.HostStorageTarget) != input.HostStorageTarget ||
		b.host == nil || b.runtime == nil {
		return CatalogObservationResult{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return CatalogObservationResult{}, err
	}
	host, version, err := b.host(input)
	if err != nil {
		return CatalogObservationResult{}, err
	}
	applicationPath, executablePath, err := catalogWindowsDesktopPaths()
	if err != nil {
		return CatalogObservationResult{}, err
	}
	discovery, applicationPresent, endpointPresent, err := b.runtime(
		ctx, input, applicationPath, executablePath, catalogWindowsDockerPipe,
	)
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

func catalogWindowsDesktopPaths() (string, string, error) {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) || filepath.Clean(home) != home {
		return "", "", ErrProbeFailed
	}
	root := filepath.Join(home, "AppData", "Local", "Programs", "DockerDesktop")
	return root, filepath.Join(root, "Docker Desktop.exe"), nil
}

func observeWindowsCatalogHost(input CatalogObservationInput) (runtimeinstall.HostCapabilities, string, error) {
	version := windows.RtlGetVersion()
	memory, memoryOK := windowsDesktopMemory()
	cpus := windows.GetActiveProcessorCount(allWindowsProcessorGroups)
	freeDisk, local, diskError := windowsDesktopFilesystem(input.HostStorageTarget)
	if version == nil || version.MajorVersion != 10 || version.BuildNumber < 22000 || !memoryOK ||
		cpus == 0 || cpus > math.MaxUint16 || diskError != nil || !local ||
		!windows.IsProcessorFeaturePresent(windows.PF_VIRT_FIRMWARE_ENABLED) ||
		input.Catalog.Manifest().Platform().Architecture() != runtimecatalog.ArchitectureX8664 {
		return runtimeinstall.HostCapabilities{}, "", ErrUnsupportedHost
	}
	// BitLocker/device encryption was just re-attested by the exact
	// operation-scoped host receipt before this backend was invoked.
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformWindows, runtimeinstall.ArchitectureAMD64, "10.0.0", true, true, local, true,
		uint16(cpus), memory.TotalPhysical, memory.AvailablePhysical, freeDisk, // #nosec G115 -- processor count is bounded above.
	)
	if err != nil {
		return runtimeinstall.HostCapabilities{}, "", ErrProbeFailed
	}
	return host, "10.0." + strconv.FormatUint(uint64(version.BuildNumber), 10), nil
}

func observeWindowsCatalogRuntime(
	ctx context.Context,
	input CatalogObservationInput,
	applicationPath string,
	executablePath string,
	pipePath string,
) (runtimeinstall.RuntimeDiscovery, bool, bool, error) {
	applicationPresent, executablePresent, endpointPresent, err := observeWindowsRuntimeSurfaces(
		ctx, applicationPath, executablePath, pipePath, windowsDockerPipePresent,
	)
	if err != nil {
		return runtimeinstall.RuntimeDiscovery{}, applicationPresent, endpointPresent, err
	}
	if !applicationPresent && !executablePresent && !endpointPresent {
		return runtimeinstall.NewAbsentRuntimeDiscovery(), false, false, nil
	}
	if !applicationPresent || !executablePresent {
		return runtimeinstall.RuntimeDiscovery{}, applicationPresent, endpointPresent, ErrRuntimeConflict
	}
	// Existing Windows installations are blocked until their exact signer leaf
	// digest and capability probe can be bound to this catalog observation.
	discovery, err := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionIncompatible, "docker_desktop", input.Catalog.Manifest().Runtime().Version(),
		input.RuntimeEndpoint, endpointPresent, false, false, runtimeinstall.OwnershipReusedExternal, 0,
	)
	if err != nil {
		return runtimeinstall.RuntimeDiscovery{}, true, endpointPresent, ErrProbeFailed
	}
	return discovery, true, endpointPresent, nil
}

type windowsPipeProbe func(string) (bool, error)

func observeWindowsRuntimeSurfaces(
	ctx context.Context,
	applicationPath string,
	executablePath string,
	pipePath string,
	pipe windowsPipeProbe,
) (bool, bool, bool, error) {
	if ctx == nil || !filepath.IsAbs(applicationPath) || !filepath.IsAbs(executablePath) ||
		filepath.Clean(applicationPath) != applicationPath || filepath.Clean(executablePath) != executablePath ||
		!strings.HasPrefix(pipePath, `\\.\pipe\`) || pipe == nil {
		return false, false, false, ErrProvisionIntegrity
	}
	application, applicationError := os.Lstat(applicationPath)
	executable, executableError := os.Lstat(executablePath)
	applicationPresent := applicationError == nil
	executablePresent := executableError == nil
	if applicationError != nil && !errors.Is(applicationError, os.ErrNotExist) ||
		executableError != nil && !errors.Is(executableError, os.ErrNotExist) {
		return applicationPresent, executablePresent, false, ErrProbeFailed
	}
	if applicationPresent && (!application.IsDir() || application.Mode()&os.ModeSymlink != 0) ||
		executablePresent && (!executable.Mode().IsRegular() || executable.Mode()&os.ModeSymlink != 0) {
		return applicationPresent, executablePresent, false, ErrRuntimeConflict
	}
	endpointPresent, err := pipe(pipePath)
	if err != nil {
		return applicationPresent, executablePresent, false, ErrProbeFailed
	}
	if err := ctx.Err(); err != nil {
		return applicationPresent, executablePresent, endpointPresent, err
	}
	return applicationPresent, executablePresent, endpointPresent, nil
}

func windowsDockerPipePresent(path string) (bool, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, ErrProvisionIntegrity
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0,
	)
	if err == nil {
		return true, windows.CloseHandle(handle)
	}
	if errors.Is(err, windows.ERROR_PIPE_BUSY) {
		return true, nil
	}
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return false, nil
	}
	return false, err
}

var _ catalogObservationBackend = nativeCatalogObservationBackend{}
