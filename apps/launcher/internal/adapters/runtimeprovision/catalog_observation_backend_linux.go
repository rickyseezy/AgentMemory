//go:build linux

package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

type nativeCatalogObservationBackend struct {
	host    func(CatalogObservationInput, uint32) (runtimeinstall.HostCapabilities, string, error)
	runtime func(context.Context, CatalogObservationInput, uint32, uint32, string) (runtimeinstall.RuntimeDiscovery, bool, error)
}

func newNativeCatalogObservationBackend() catalogObservationBackend {
	return nativeCatalogObservationBackend{host: observeLinuxCatalogHost, runtime: observeLinuxCatalogRuntime}
}

func (b nativeCatalogObservationBackend) ObserveCatalogRuntime(
	ctx context.Context,
	input CatalogObservationInput,
) (CatalogObservationResult, error) {
	manifest := input.Catalog.Manifest()
	uid, gid, endpoint, err := linuxCatalogPrincipal(input.RuntimeEndpoint)
	if ctx == nil || !manifest.Valid() || manifest.Platform().OperatingSystem() != runtimecatalog.OSKindLinux ||
		input.CertifiedRuntime.Platform() != runtimeinstall.PlatformLinux || input.NativePublisherTrust.IsZero() ||
		!filepath.IsAbs(input.HostStorageTarget) || filepath.Clean(input.HostStorageTarget) != input.HostStorageTarget ||
		err != nil || b.host == nil || b.runtime == nil {
		return CatalogObservationResult{}, ErrProvisionIntegrity
	}
	if err := ctx.Err(); err != nil {
		return CatalogObservationResult{}, err
	}
	host, version, err := b.host(input, uid)
	if err != nil {
		return CatalogObservationResult{}, err
	}
	discovery, candidatePresent, err := b.runtime(ctx, input, uid, gid, endpoint)
	if err != nil {
		return CatalogObservationResult{}, err
	}
	encoded, _ := json.Marshal(struct {
		Candidate bool   `json:"candidate_present"`
		Catalog   string `json:"catalog_digest"`
		Endpoint  string `json:"endpoint"`
		Host      string `json:"host_version"`
		Publisher string `json:"publisher_trust"`
		UID       uint32 `json:"uid"`
	}{
		Candidate: candidatePresent, Catalog: input.Catalog.ManifestDigest().Hex(), Endpoint: endpoint,
		Host: version, Publisher: input.NativePublisherTrust.Hex(), UID: uid,
	})
	return CatalogObservationResult{Host: host, Discovery: discovery, Evidence: runtimeinstall.Sum(encoded)}, nil
}

func linuxCatalogPrincipal(endpoint string) (uint32, uint32, string, error) {
	euid, egid := os.Geteuid(), os.Getegid()
	if euid <= 0 || egid <= 0 || uint64(euid) > math.MaxUint32 || uint64(egid) > math.MaxUint32 {
		return 0, 0, "", ErrUnsupportedHost
	}
	uid, gid := uint32(euid), uint32(egid) // #nosec G115 -- both values are proven positive uint32 values above.
	expected := "/run/user/" + strconv.FormatUint(uint64(uid), 10) + "/docker.sock"
	if endpoint != "unix://"+expected {
		return 0, 0, "", ErrProvisionIntegrity
	}
	return uid, gid, expected, nil
}

func observeLinuxCatalogHost(
	input CatalogObservationInput,
	uid uint32,
) (runtimeinstall.HostCapabilities, string, error) {
	manifest := input.Catalog.Manifest()
	execution, present := manifest.LinuxExecution()
	distribution, version, releaseError := linuxOSRelease()
	kernel, architecture, kernelError := linuxKernelArchitecture()
	cpus, total, available, resourceError := linuxResources()
	freeDisk, local, diskError := linuxHomeFilesystem(input.HostStorageTarget)
	namespaces, namespaceError := linuxUserNamespaces()
	selinux, selinuxError := linuxSELinuxEnforcing()
	current, identityError := user.Current()
	if !present || releaseError != nil || kernelError != nil || resourceError != nil || diskError != nil ||
		namespaceError != nil || selinuxError != nil || identityError != nil || distribution != manifest.Platform().Distribution() ||
		compareKernel(kernel, execution.MinimumKernel()) < 0 || !local || !namespaces ||
		available < execution.MinimumAvailableMemory() || selinux && !execution.SELinuxEnforcingSupported() ||
		current.Uid != strconv.FormatUint(uint64(uid), 10) || current.Gid != strconv.Itoa(os.Getegid()) ||
		validateOwnerDirectory(input.HostStorageTarget, uid, false) != nil {
		return runtimeinstall.HostCapabilities{}, "", ErrUnsupportedHost
	}
	expectedArchitecture, err := linuxCatalogArchitecture(manifest.Platform().Architecture())
	if err != nil || architecture != expectedArchitecture || input.CertifiedRuntime.Architecture() != expectedArchitecture {
		return runtimeinstall.HostCapabilities{}, "", ErrUnsupportedHost
	}
	// Active encryption and KVM were just re-attested by the exact
	// operation-scoped host receipt before this backend was invoked. This probe
	// independently refreshes identity, resources, filesystem, namespace,
	// kernel, distribution, and SELinux state.
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, architecture, version, true, true, local, true,
		cpus, total, available, freeDisk,
	)
	if err != nil {
		return runtimeinstall.HostCapabilities{}, "", ErrProbeFailed
	}
	return host, distribution + ":" + version + ":" + kernel, nil
}

func linuxCatalogArchitecture(value runtimecatalog.Architecture) (runtimeinstall.Architecture, error) {
	switch value {
	case runtimecatalog.ArchitectureX8664:
		return runtimeinstall.ArchitectureAMD64, nil
	case runtimecatalog.ArchitectureARM64:
		return runtimeinstall.ArchitectureARM64, nil
	default:
		return runtimeinstall.ArchitectureUnknown, ErrUnsupportedHost
	}
}

func observeLinuxCatalogRuntime(
	ctx context.Context,
	input CatalogObservationInput,
	uid uint32,
	gid uint32,
	endpoint string,
) (runtimeinstall.RuntimeDiscovery, bool, error) {
	execution, present := input.Catalog.Manifest().LinuxExecution()
	if !present {
		return runtimeinstall.RuntimeDiscovery{}, false, ErrProvisionIntegrity
	}
	paths := []string{
		execution.RootlessToolPath(), "/usr/bin/docker", "/usr/bin/dockerd", "/usr/bin/containerd",
		"/usr/libexec/docker/cli-plugins/docker-compose", "/usr/lib/docker/cli-plugins/docker-compose",
	}
	candidatePresent, endpointPresent, err := observeLinuxRuntimeSurfaces(
		ctx, uid, gid, endpoint, []string{"/run/docker.sock", "/var/run/docker.sock"}, paths,
	)
	if err != nil {
		return runtimeinstall.RuntimeDiscovery{}, candidatePresent, err
	}
	if !candidatePresent {
		return runtimeinstall.NewAbsentRuntimeDiscovery(), false, nil
	}
	discovery, err := runtimeinstall.NewRuntimeDiscovery(
		runtimeinstall.RuntimeConditionIncompatible, "docker_engine", input.Catalog.Manifest().Runtime().Version(),
		input.RuntimeEndpoint, endpointPresent, false, false, runtimeinstall.OwnershipReusedExternal, 0,
	)
	if err != nil {
		return runtimeinstall.RuntimeDiscovery{}, true, ErrProbeFailed
	}
	return discovery, true, nil
}

func observeLinuxRuntimeSurfaces(
	ctx context.Context,
	uid uint32,
	gid uint32,
	endpoint string,
	rootfulPaths []string,
	candidatePaths []string,
) (bool, bool, error) {
	if ctx == nil || uid == 0 || gid == 0 || !filepath.IsAbs(endpoint) || filepath.Clean(endpoint) != endpoint ||
		len(rootfulPaths) != 2 || len(candidatePaths) == 0 {
		return false, false, ErrProvisionIntegrity
	}
	for _, rootful := range rootfulPaths {
		if !filepath.IsAbs(rootful) || filepath.Clean(rootful) != rootful {
			return false, false, ErrProvisionIntegrity
		}
		if _, err := os.Lstat(rootful); err == nil {
			return true, false, ErrRuntimeConflict
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, false, ErrProbeFailed
		}
	}
	endpointInfo, endpointError := os.Lstat(endpoint)
	endpointPresent := endpointError == nil
	if endpointError != nil && !errors.Is(endpointError, os.ErrNotExist) {
		return false, false, ErrProbeFailed
	}
	if endpointPresent {
		stat, ok := endpointInfo.Sys().(*syscall.Stat_t)
		permissions := endpointInfo.Mode().Perm()
		if !ok || endpointInfo.Mode()&os.ModeSocket == 0 || endpointInfo.Mode()&os.ModeSymlink != 0 ||
			stat.Uid != uid || stat.Gid != gid || permissions&0o600 != 0o600 || permissions&0o007 != 0 || permissions&0o110 != 0 {
			return true, true, ErrRuntimeConflict
		}
	}
	candidatePresent := endpointPresent
	for _, candidate := range candidatePaths {
		if candidate == "" || !filepath.IsAbs(candidate) || filepath.Clean(candidate) != candidate {
			return candidatePresent, endpointPresent, ErrProvisionIntegrity
		}
		if _, err := os.Lstat(candidate); err == nil {
			candidatePresent = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return candidatePresent, endpointPresent, ErrProbeFailed
		}
	}
	if err := ctx.Err(); err != nil {
		return candidatePresent, endpointPresent, err
	}
	return candidatePresent, endpointPresent, nil
}

var _ catalogObservationBackend = nativeCatalogObservationBackend{}
