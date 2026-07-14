package runtimecatalogapp

import (
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// LinuxHostBindingInput contains only native, read-only identity facts that
// cannot be declared by a signed catalog. It deliberately contains no command,
// package, source, or publisher authority.
type LinuxHostBindingInput struct {
	VersionID        string
	InvokingUID      uint32
	InvokingGID      uint32
	AccountName      string
	PrincipalID      string
	MachineDigest    runtimeinstall.Hash
	HomeDirectory    string
	RuntimeDirectory string
	Endpoint         string
}

// LinuxHostBinding is an immutable invocation-to-machine binding.
type LinuxHostBinding struct{ input LinuxHostBindingInput }

// NewLinuxHostBinding validates all non-catalog host facts before projection.
func NewLinuxHostBinding(input LinuxHostBindingInput) (LinuxHostBinding, error) {
	if input.VersionID == "" || len(input.VersionID) > 64 || input.VersionID != strings.TrimSpace(input.VersionID) ||
		input.InvokingUID == 0 || input.InvokingGID == 0 ||
		input.PrincipalID != "linux:uid:"+strconv.FormatUint(uint64(input.InvokingUID), 10) ||
		input.MachineDigest.IsZero() || input.RuntimeDirectory != "/run/user/"+strconv.FormatUint(uint64(input.InvokingUID), 10) ||
		input.Endpoint != "unix://"+input.RuntimeDirectory+"/docker.sock" {
		return LinuxHostBinding{}, errors.New("linux runtime host binding is invalid")
	}
	return LinuxHostBinding{input: input}, nil
}

// LinuxAuthority projects a signature-verified catalog plus independently
// observed host identity into the only PF-006 Linux execution authority.
func (c VerifiedCatalog) LinuxAuthority(
	canonicalPlan []byte,
	host LinuxHostBinding,
) (runtimeport.LinuxAuthority, error) {
	if !c.manifest.Valid() || c.verifiedAt.IsZero() || c.verifiedAt.Location() != time.UTC ||
		len(canonicalPlan) == 0 || host.input.InvokingUID == 0 {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityUnavailable
	}
	plan, err := runtimeinstall.DecodePlanV1(canonicalPlan)
	if err != nil || runtimecatalog.Digest(plan.CatalogDigest()) != c.manifest.Digest() ||
		runtimecatalog.Digest(plan.TermsDigest()) != c.manifest.Terms().Digest() {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityInvalid
	}
	platform := c.manifest.Platform()
	execution, present := c.manifest.LinuxExecution()
	if !present || platform.OperatingSystem() != runtimecatalog.OSKindLinux ||
		platform.MinimumCPUCores() > math.MaxUint16 || plan.HostOSVersion() != host.input.VersionID ||
		!linuxVersionIDMatches(host.input.VersionID, platform) {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityInvalid
	}
	architecture, err := linuxRuntimeArchitecture(platform.Architecture())
	if err != nil {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityInvalid
	}
	manager, err := linuxPackageManager(execution.PackageManager())
	if err != nil {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityInvalid
	}
	packages, err := linuxAuthorityPackages(execution.Packages())
	if err != nil {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityInvalid
	}
	repository := execution.Repository()
	terms := c.manifest.Terms()
	input := runtimeport.LinuxAuthorityInput{
		PlanDigest: plan.Digest(), CatalogDigest: plan.CatalogDigest(), TermsDigest: plan.TermsDigest(),
		TermsID: terms.ID(), TermsVersion: terms.Version(), TermsURL: sourceURL(terms.URL()),
		TermsPresentation: string(terms.Presentation()),
		ArtifactDigest:    runtimeinstall.Hash(execution.PackageSetDigest()),
		SigningKeyID:      c.manifest.SigningKeyID(), Architecture: architecture,
		Distribution: platform.Distribution(), VersionID: host.input.VersionID,
		Codename: execution.Codename(), MinimumKernel: execution.MinimumKernel(),
		MinimumCPUs:            uint16(platform.MinimumCPUCores()), // #nosec G115 -- MaxUint16 is proven above.
		MinimumTotalMemory:     platform.MinimumMemoryBytes(),
		MinimumAvailableMemory: execution.MinimumAvailableMemory(),
		MinimumFreeDisk:        platform.MinimumFreeDiskBytes(),
		PackageManager:         manager, PackageManagerVersion: execution.PackageManagerVersion(),
		Repository: runtimeport.RepositoryInput{
			ID: repository.ID(), URL: sourceURL(repository.URL()), Suite: repository.Suite(),
			Component: repository.Component(), SigningKeyFingerprint: repository.SigningKeyFingerprint(),
			SigningKeyDigest:    runtimeinstall.Hash(repository.SigningKeyDigest()),
			ConfigurationDigest: runtimeinstall.Hash(repository.ConfigurationDigest()),
			MetadataDigest:      runtimeinstall.Hash(repository.MetadataDigest()),
		},
		Packages: packages, RuntimeVersion: c.manifest.Runtime().Version(),
		ComposeVersion:     c.manifest.Runtime().ComposeVersion(),
		UnrelatedWorkloads: plan.UnrelatedWorkloads(),
		InvokingUID:        host.input.InvokingUID, InvokingGID: host.input.InvokingGID,
		AccountName: host.input.AccountName, PrincipalID: host.input.PrincipalID,
		MachineDigest: host.input.MachineDigest, HomeDirectory: host.input.HomeDirectory,
		RuntimeDirectory: host.input.RuntimeDirectory, Endpoint: host.input.Endpoint,
		SubordinateIDCount: execution.SubordinateIDCount(),
		SELinuxEnforcing:   execution.SELinuxEnforcingSupported(), ServiceID: execution.ServiceID(),
		ServiceUnitDigest:  runtimeinstall.Hash(execution.ServiceUnitDigest()),
		RootlessToolPath:   execution.RootlessToolPath(),
		RootlessToolDigest: runtimeinstall.Hash(execution.RootlessToolDigest()),
		ProbeImage:         execution.ProbeImage(), ProbeImageDigest: runtimeinstall.Hash(execution.ProbeImageDigest()),
		ProbeContractVersion:   execution.ProbeContractVersion(),
		CapabilityPolicyDigest: runtimeinstall.Hash(execution.CapabilityPolicyDigest()),
	}
	authority, err := runtimeport.NewLinuxAuthority(input)
	if err != nil || !authority.ValidFor(plan) {
		return runtimeport.LinuxAuthority{}, runtimeport.ErrAuthorityInvalid
	}
	return authority, nil
}

func linuxAuthorityPackages(packages []runtimecatalog.LinuxPackage) ([]runtimeport.PackageInput, error) {
	result := make([]runtimeport.PackageInput, 0, len(packages))
	for _, pkg := range packages {
		var purpose runtimeport.PackagePurpose
		switch pkg.Purpose() {
		case runtimecatalog.LinuxPackagePurposePrerequisite:
			purpose = runtimeport.PackagePurposePrerequisite
		case runtimecatalog.LinuxPackagePurposeRuntime:
			purpose = runtimeport.PackagePurposeRuntime
		default:
			return nil, runtimeport.ErrAuthorityInvalid
		}
		result = append(result, runtimeport.PackageInput{
			Name: pkg.Name(), Version: pkg.Version(), Purpose: purpose,
			NativeReceiptDigest: runtimeinstall.Hash(pkg.NativeReceiptDigest()),
		})
	}
	return result, nil
}

func linuxPackageManager(manager runtimecatalog.LinuxPackageManager) (runtimeport.PackageManager, error) {
	switch manager {
	case runtimecatalog.LinuxPackageManagerAPT:
		return runtimeport.PackageManagerAPT, nil
	case runtimecatalog.LinuxPackageManagerDNF:
		return runtimeport.PackageManagerDNF, nil
	default:
		return "", runtimeport.ErrAuthorityInvalid
	}
}

func linuxRuntimeArchitecture(architecture runtimecatalog.Architecture) (runtimeinstall.Architecture, error) {
	switch architecture {
	case runtimecatalog.ArchitectureX8664:
		return runtimeinstall.ArchitectureAMD64, nil
	case runtimecatalog.ArchitectureARM64:
		return runtimeinstall.ArchitectureARM64, nil
	default:
		return runtimeinstall.ArchitectureUnknown, runtimeport.ErrAuthorityInvalid
	}
}

func sourceURL(source runtimecatalog.SourceLocation) string {
	return source.Scheme() + "://" + source.Host() + source.PathPrefix()
}

func linuxVersionIDMatches(versionID string, platform runtimecatalog.PlatformPolicy) bool {
	parsed, valid := parseLinuxVersionID(versionID)
	if !valid {
		return false
	}
	return parsed == platformVersion(platform.MinimumOSVersion()) &&
		parsed == platformVersion(platform.MaximumOSVersion())
}

func parseLinuxVersionID(value string) ([3]uint64, bool) {
	var result [3]uint64
	parts := strings.Split(value, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return result, false
	}
	for index, part := range parts {
		if part == "" {
			return [3]uint64{}, false
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return [3]uint64{}, false
		}
		result[index] = parsed
	}
	return result, true
}

func platformVersion(value string) [3]uint64 {
	result, valid := parseLinuxVersionID(value)
	if !valid {
		return [3]uint64{math.MaxUint64, math.MaxUint64, math.MaxUint64}
	}
	return result
}
