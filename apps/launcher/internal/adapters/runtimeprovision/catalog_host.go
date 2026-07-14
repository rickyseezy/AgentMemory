package runtimeprovision

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

// CertifiedCatalogHostProvider projects the already certified PF-001 host
// evidence into the runtime-catalog vocabulary. It never claims resource
// capacity above the signed parent host-plan floors.
type CertifiedCatalogHostProvider struct {
	host runtimecatalog.Host
}

// NewCertifiedCatalogHostProvider requires a valid signed parent policy and
// the non-zero output digest of its successful native verification phase.
func NewCertifiedCatalogHostProvider(
	signed hostverification.SignedPlan,
	hostEvidence install.Digest,
) (*CertifiedCatalogHostProvider, error) {
	if !signed.Valid() || hostEvidence.IsZero() {
		return nil, runtimecatalogapp.ErrDependencyUnavailable
	}
	input, err := catalogHostInput(signed.Plan())
	if err != nil {
		return nil, runtimecatalogapp.ErrDependencyUnavailable
	}
	host, err := runtimecatalog.NewHost(input)
	if err != nil {
		return nil, runtimecatalogapp.ErrDependencyUnavailable
	}
	return &CertifiedCatalogHostProvider{host: host}, nil
}

// CurrentHost returns the immutable lower-bound host projection already
// certified by the native PF-001 host phase.
func (p *CertifiedCatalogHostProvider) CurrentHost(ctx context.Context) (runtimecatalog.Host, error) {
	if p == nil || ctx == nil {
		return runtimecatalog.Host{}, runtimecatalogapp.ErrDependencyUnavailable
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalog.Host{}, err
	}
	return p.host, nil
}

func catalogHostInput(plan hostverification.Plan) (runtimecatalog.HostInput, error) {
	if !plan.Valid() {
		return runtimecatalog.HostInput{}, errors.New("parent host policy is invalid")
	}
	platform := plan.Platform()
	operatingSystem, architecture, edition, distribution, err := catalogPlatformIdentity(platform)
	if err != nil {
		return runtimecatalog.HostInput{}, err
	}
	version, err := normalizedCatalogVersion(platform.Version)
	if err != nil {
		return runtimecatalog.HostInput{}, err
	}
	build, err := normalizedCatalogBuild(platform.OperatingSystem, platform.Build)
	if err != nil {
		return runtimecatalog.HostInput{}, err
	}
	return runtimecatalog.HostInput{
		OperatingSystem: operatingSystem, Architecture: architecture,
		Edition: edition, Distribution: distribution, OSVersion: version, Build: build,
		CPUCores: plan.MinimumCPUCores(), MemoryBytes: plan.MinimumMemoryBytes(),
		FreeDiskBytes: plan.MinimumFreeDiskBytes(), Virtualization: true,
	}, nil
}

func catalogPlatformIdentity(
	platform hostverification.PlatformTuple,
) (runtimecatalog.OSKind, runtimecatalog.Architecture, string, string, error) {
	var operatingSystem runtimecatalog.OSKind
	var edition, distribution string
	switch platform.OperatingSystem {
	case hostverification.OperatingSystemMacOS:
		operatingSystem, edition, distribution = runtimecatalog.OSKindMacOS, "desktop", "macos"
		if platform.Product != "macos" {
			return "", "", "", "", errors.New("macOS product is invalid")
		}
	case hostverification.OperatingSystemWindows:
		operatingSystem, edition, distribution = runtimecatalog.OSKindWindows, "desktop", "windows"
		if !strings.HasPrefix(platform.Product, "product_") {
			return "", "", "", "", errors.New("windows product is invalid")
		}
	case hostverification.OperatingSystemLinux:
		operatingSystem, edition, distribution = runtimecatalog.OSKindLinux, "workstation", platform.Product
	default:
		return "", "", "", "", errors.New("operating system is invalid")
	}
	var architecture runtimecatalog.Architecture
	switch platform.Architecture {
	case hostverification.ArchitectureAMD64:
		architecture = runtimecatalog.ArchitectureX8664
	case hostverification.ArchitectureARM64:
		architecture = runtimecatalog.ArchitectureARM64
	default:
		return "", "", "", "", errors.New("architecture is invalid")
	}
	return operatingSystem, architecture, edition, distribution, nil
}

func normalizedCatalogVersion(value string) (string, error) {
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return "", errors.New("platform version is invalid")
	}
	normalized := make([]string, 3)
	for index := range normalized {
		if index >= len(parts) {
			normalized[index] = "0"
			continue
		}
		parsed, err := strconv.ParseUint(parts[index], 10, 32)
		if err != nil {
			return "", errors.New("platform version is invalid")
		}
		normalized[index] = strconv.FormatUint(parsed, 10)
	}
	return strings.Join(normalized, "."), nil
}

func normalizedCatalogBuild(operatingSystem hostverification.OperatingSystem, value string) (uint64, error) {
	switch operatingSystem {
	case hostverification.OperatingSystemMacOS:
		// Apple build identifiers begin with the Darwin major (for example,
		// 24B83). PF-006 uses major*1000 as its explicit numeric range key;
		// the opaque train/suffix remains certified by the parent host plan.
		end := 0
		for end < len(value) && value[end] >= '0' && value[end] <= '9' {
			end++
		}
		if end == 0 || end == len(value) {
			return 0, errors.New("macOS build is invalid")
		}
		major, err := strconv.ParseUint(value[:end], 10, 53)
		if err != nil || major == 0 || major > (1<<53-1)/1000 {
			return 0, errors.New("macOS build is invalid")
		}
		return major * 1000, nil
	case hostverification.OperatingSystemWindows:
		build, err := strconv.ParseUint(value, 10, 53)
		if err != nil || build == 0 {
			return 0, errors.New("windows build is invalid")
		}
		return build, nil
	case hostverification.OperatingSystemLinux:
		parts := strings.FieldsFunc(value, func(character rune) bool { return character < '0' || character > '9' })
		if len(parts) < 2 {
			return 0, errors.New("linux build is invalid")
		}
		values := [3]uint64{}
		for index := range values {
			if index >= len(parts) {
				break
			}
			parsed, err := strconv.ParseUint(parts[index], 10, 16)
			if err != nil || parsed > 99 {
				return 0, errors.New("linux build is invalid")
			}
			values[index] = parsed
		}
		build := values[0]*10000 + values[1]*100 + values[2]
		if build == 0 {
			return 0, errors.New("linux build is invalid")
		}
		return build, nil
	default:
		return 0, errors.New("operating system is invalid")
	}
}

var _ runtimecatalogapp.HostProvider = (*CertifiedCatalogHostProvider)(nil)
