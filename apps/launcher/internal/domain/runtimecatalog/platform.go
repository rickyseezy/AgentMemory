package runtimecatalog

import (
	"errors"
	"strconv"
	"strings"
)

// HostInput contains read-only host facts supplied by a platform adapter.
type HostInput struct {
	OperatingSystem OSKind
	Architecture    Architecture
	Edition         string
	Distribution    string
	OSVersion       string
	Build           uint64
	CPUCores        uint32
	MemoryBytes     uint64
	FreeDiskBytes   uint64
	Virtualization  bool
}

// Host is a validated immutable host capability projection.
type Host struct {
	operatingSystem OSKind
	architecture    Architecture
	edition         string
	distribution    string
	osVersion       string
	parsedVersion   [3]uint32
	build           uint64
	cpuCores        uint32
	memoryBytes     uint64
	freeDiskBytes   uint64
	virtualization  bool
}

// NewHost validates a capability projection without deciding certification.
func NewHost(input HostInput) (Host, error) {
	version, err := parseStableVersion(input.OSVersion)
	if !input.OperatingSystem.valid() || !input.Architecture.valid() ||
		!validIdentifier(input.Edition) || !validIdentifier(input.Distribution) || err != nil ||
		input.Build == 0 || input.Build > maximumSafeJSONInteger || input.CPUCores == 0 ||
		input.MemoryBytes == 0 || input.MemoryBytes > maximumSafeJSONInteger ||
		input.FreeDiskBytes == 0 || input.FreeDiskBytes > maximumSafeJSONInteger {
		return Host{}, errors.New("host capability projection is invalid")
	}
	return Host{
		operatingSystem: input.OperatingSystem, architecture: input.Architecture,
		edition: input.Edition, distribution: input.Distribution,
		osVersion: input.OSVersion, parsedVersion: version, build: input.Build,
		cpuCores: input.CPUCores, memoryBytes: input.MemoryBytes,
		freeDiskBytes: input.FreeDiskBytes, virtualization: input.Virtualization,
	}, nil
}

// OperatingSystem returns the detected OS family.
func (h Host) OperatingSystem() OSKind { return h.operatingSystem }

// Architecture returns the detected CPU architecture.
func (h Host) Architecture() Architecture { return h.architecture }

// OSVersion returns the exact detected stable version.
func (h Host) OSVersion() string { return h.osVersion }

// Build returns the detected platform build number.
func (h Host) Build() uint64 { return h.build }

// PlatformPolicyInput declares one exact supported host range and resource floor.
type PlatformPolicyInput struct {
	OperatingSystem        OSKind
	Architecture           Architecture
	Edition                string
	Distribution           string
	MinimumOSVersion       string
	MaximumOSVersion       string
	MinimumBuild           uint64
	MaximumBuild           uint64
	MinimumCPUCores        uint32
	MinimumMemoryBytes     uint64
	MinimumFreeDiskBytes   uint64
	VirtualizationRequired bool
}

// PlatformPolicy is an immutable certified host cell.
type PlatformPolicy struct {
	operatingSystem        OSKind
	architecture           Architecture
	edition                string
	distribution           string
	minimumOSVersion       string
	maximumOSVersion       string
	minimumParsedVersion   [3]uint32
	maximumParsedVersion   [3]uint32
	minimumBuild           uint64
	maximumBuild           uint64
	minimumCPUCores        uint32
	minimumMemoryBytes     uint64
	minimumFreeDiskBytes   uint64
	virtualizationRequired bool
}

func newPlatformPolicy(input PlatformPolicyInput) (PlatformPolicy, error) {
	minimum, minimumError := parseStableVersion(input.MinimumOSVersion)
	maximum, maximumError := parseStableVersion(input.MaximumOSVersion)
	if !input.OperatingSystem.valid() || !input.Architecture.valid() ||
		!validIdentifier(input.Edition) || !validIdentifier(input.Distribution) ||
		minimumError != nil || maximumError != nil || compareVersion(minimum, maximum) > 0 ||
		input.MinimumBuild == 0 || input.MinimumBuild > input.MaximumBuild ||
		input.MaximumBuild > maximumSafeJSONInteger || input.MinimumCPUCores == 0 ||
		input.MinimumMemoryBytes == 0 || input.MinimumMemoryBytes > maximumSafeJSONInteger ||
		input.MinimumFreeDiskBytes == 0 || input.MinimumFreeDiskBytes > maximumSafeJSONInteger {
		return PlatformPolicy{}, ErrManifestIntegrity
	}
	return PlatformPolicy{
		operatingSystem: input.OperatingSystem, architecture: input.Architecture,
		edition: input.Edition, distribution: input.Distribution,
		minimumOSVersion: input.MinimumOSVersion, maximumOSVersion: input.MaximumOSVersion,
		minimumParsedVersion: minimum, maximumParsedVersion: maximum,
		minimumBuild: input.MinimumBuild, maximumBuild: input.MaximumBuild,
		minimumCPUCores: input.MinimumCPUCores, minimumMemoryBytes: input.MinimumMemoryBytes,
		minimumFreeDiskBytes:   input.MinimumFreeDiskBytes,
		virtualizationRequired: input.VirtualizationRequired,
	}, nil
}

// OperatingSystem returns the certified OS family.
func (p PlatformPolicy) OperatingSystem() OSKind { return p.operatingSystem }

// Architecture returns the certified architecture.
func (p PlatformPolicy) Architecture() Architecture { return p.architecture }

// Edition returns the exact certified OS edition.
func (p PlatformPolicy) Edition() string { return p.edition }

// Distribution returns the exact certified distribution.
func (p PlatformPolicy) Distribution() string { return p.distribution }

// MinimumOSVersion returns the inclusive version floor.
func (p PlatformPolicy) MinimumOSVersion() string { return p.minimumOSVersion }

// MaximumOSVersion returns the inclusive version ceiling.
func (p PlatformPolicy) MaximumOSVersion() string { return p.maximumOSVersion }

// MinimumBuild returns the inclusive build floor.
func (p PlatformPolicy) MinimumBuild() uint64 { return p.minimumBuild }

// MaximumBuild returns the inclusive build ceiling.
func (p PlatformPolicy) MaximumBuild() uint64 { return p.maximumBuild }

// MinimumCPUCores returns the CPU floor.
func (p PlatformPolicy) MinimumCPUCores() uint32 { return p.minimumCPUCores }

// MinimumMemoryBytes returns the memory floor.
func (p PlatformPolicy) MinimumMemoryBytes() uint64 { return p.minimumMemoryBytes }

// MinimumFreeDiskBytes returns the free-disk floor.
func (p PlatformPolicy) MinimumFreeDiskBytes() uint64 { return p.minimumFreeDiskBytes }

// VirtualizationRequired reports whether hardware virtualization must be proven.
func (p PlatformPolicy) VirtualizationRequired() bool { return p.virtualizationRequired }

// Supports fails closed when any exact platform or resource boundary differs.
func (p PlatformPolicy) Supports(host Host) error {
	if !p.valid() || host.operatingSystem != p.operatingSystem || host.architecture != p.architecture ||
		host.edition != p.edition || host.distribution != p.distribution ||
		compareVersion(host.parsedVersion, p.minimumParsedVersion) < 0 ||
		compareVersion(host.parsedVersion, p.maximumParsedVersion) > 0 ||
		host.build < p.minimumBuild || host.build > p.maximumBuild ||
		host.cpuCores < p.minimumCPUCores || host.memoryBytes < p.minimumMemoryBytes ||
		host.freeDiskBytes < p.minimumFreeDiskBytes || p.virtualizationRequired && !host.virtualization {
		return ErrUnsupportedHost
	}
	return nil
}

func (p PlatformPolicy) valid() bool {
	validated, err := newPlatformPolicy(PlatformPolicyInput{
		OperatingSystem: p.operatingSystem, Architecture: p.architecture,
		Edition: p.edition, Distribution: p.distribution,
		MinimumOSVersion: p.minimumOSVersion, MaximumOSVersion: p.maximumOSVersion,
		MinimumBuild: p.minimumBuild, MaximumBuild: p.maximumBuild,
		MinimumCPUCores: p.minimumCPUCores, MinimumMemoryBytes: p.minimumMemoryBytes,
		MinimumFreeDiskBytes:   p.minimumFreeDiskBytes,
		VirtualizationRequired: p.virtualizationRequired,
	})
	return err == nil && validated.minimumParsedVersion == p.minimumParsedVersion &&
		validated.maximumParsedVersion == p.maximumParsedVersion
}

func parseStableVersion(value string) ([3]uint32, error) {
	var result [3]uint32
	parts := strings.Split(value, ".")
	if len(parts) != len(result) {
		return result, errors.New("version must contain three components")
	}
	for index, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return [3]uint32{}, errors.New("version is not canonical")
		}
		parsed, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return [3]uint32{}, errors.New("version component is invalid")
		}
		result[index] = uint32(parsed)
	}
	return result, nil
}

func compareVersion(left [3]uint32, right [3]uint32) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}
