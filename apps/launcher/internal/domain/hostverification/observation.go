package hostverification

import (
	"bytes"
	"encoding/binary"
	"slices"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// VirtualizationKind is the native proof mechanism used for this host.
type VirtualizationKind string

const (
	// VirtualizationHypervisorFramework is macOS's native hardware proof.
	VirtualizationHypervisorFramework VirtualizationKind = "hypervisor_framework"
	// VirtualizationKVM is a successful Linux KVM API capability proof.
	VirtualizationKVM VirtualizationKind = "kvm"
	// VirtualizationWindowsFirmware is Windows's firmware virtualization flag.
	VirtualizationWindowsFirmware VirtualizationKind = "windows_firmware"
)

// EncryptionKind is the active at-rest encryption mechanism for the target.
type EncryptionKind string

const (
	// EncryptionFileVault is active encrypted internal media on macOS.
	EncryptionFileVault EncryptionKind = "filevault"
	// EncryptionDMcrypt is a complete Linux dm-crypt backing-device chain.
	EncryptionDMcrypt EncryptionKind = "dm_crypt"
	// EncryptionFScrypt is an active Linux per-directory fscrypt policy.
	EncryptionFScrypt EncryptionKind = "fscrypt"
	// EncryptionBitLocker is active Windows BitLocker/device encryption.
	EncryptionBitLocker EncryptionKind = "bitlocker"
)

// ObservationInput contains native facts. Constructors reject claims whose
// proof mechanism is not valid for the observed OS.
type ObservationInput struct {
	Platform       PlatformTuple
	CPUCores       uint32
	MemoryBytes    uint64
	FreeDiskBytes  uint64
	StorageTarget  string
	Virtualization VirtualizationKind
	Encryption     EncryptionKind
	AvailablePorts []LoopbackEndpoint
}

// Observation is immutable-by-copy native host evidence.
type Observation struct {
	platform       PlatformTuple
	cpuCores       uint32
	memoryBytes    uint64
	freeDiskBytes  uint64
	storageTarget  string
	virtualization VirtualizationKind
	encryption     EncryptionKind
	availablePorts []LoopbackEndpoint
	digest         install.Digest
}

// NewObservation validates a complete positive native evidence set.
func NewObservation(input ObservationInput) (Observation, error) {
	ports := append([]LoopbackEndpoint(nil), input.AvailablePorts...)
	slices.SortFunc(ports, compareEndpoint)
	if !validPlatform(input.Platform) || input.CPUCores == 0 || input.MemoryBytes == 0 ||
		input.FreeDiskBytes == 0 || !validTarget(input.Platform.OperatingSystem, input.StorageTarget) ||
		!validEndpoints(ports) || !validProofKinds(input.Platform.OperatingSystem, input.Virtualization, input.Encryption) {
		return Observation{}, ErrIntegrity
	}
	observation := Observation{
		platform: input.Platform, cpuCores: input.CPUCores, memoryBytes: input.MemoryBytes,
		freeDiskBytes: input.FreeDiskBytes, storageTarget: input.StorageTarget,
		virtualization: input.Virtualization, encryption: input.Encryption, availablePorts: ports,
	}
	observation.digest = install.DigestBytes(observation.canonical())
	return observation, nil
}

func validProofKinds(os OperatingSystem, virtualization VirtualizationKind, encryption EncryptionKind) bool {
	switch os {
	case OperatingSystemMacOS:
		return virtualization == VirtualizationHypervisorFramework && encryption == EncryptionFileVault
	case OperatingSystemLinux:
		return virtualization == VirtualizationKVM && (encryption == EncryptionDMcrypt || encryption == EncryptionFScrypt)
	case OperatingSystemWindows:
		return virtualization == VirtualizationWindowsFirmware && encryption == EncryptionBitLocker
	}
	return false
}

func (o Observation) canonical() []byte {
	var buffer bytes.Buffer
	writeField := func(value string) {
		_ = binary.Write(&buffer, binary.BigEndian, uint64(len(value)))
		buffer.WriteString(value)
	}
	writeField(string(o.platform.OperatingSystem))
	writeField(o.platform.Product)
	writeField(string(o.platform.Architecture))
	writeField(o.platform.Version)
	writeField(o.platform.Build)
	_ = binary.Write(&buffer, binary.BigEndian, o.cpuCores)
	_ = binary.Write(&buffer, binary.BigEndian, o.memoryBytes)
	_ = binary.Write(&buffer, binary.BigEndian, o.freeDiskBytes)
	writeField(o.storageTarget)
	writeField(string(o.virtualization))
	writeField(string(o.encryption))
	_ = binary.Write(&buffer, binary.BigEndian, uint64(len(o.availablePorts)))
	for _, endpoint := range o.availablePorts {
		writeField(string(endpoint.Family))
		_ = binary.Write(&buffer, binary.BigEndian, endpoint.Port)
	}
	return buffer.Bytes()
}

// Platform returns the exact natively observed tuple.
func (o Observation) Platform() PlatformTuple { return o.platform }

// CPUCores returns the natively available core count.
func (o Observation) CPUCores() uint32 { return o.cpuCores }

// MemoryBytes returns observed physical memory.
func (o Observation) MemoryBytes() uint64 { return o.memoryBytes }

// FreeDiskBytes returns caller-available bytes at the exact target.
func (o Observation) FreeDiskBytes() uint64 { return o.freeDiskBytes }

// StorageTarget returns the exact descriptor-proved target.
func (o Observation) StorageTarget() string { return o.storageTarget }

// Virtualization returns the native proof mechanism.
func (o Observation) Virtualization() VirtualizationKind { return o.virtualization }

// Encryption returns the active target encryption mechanism.
func (o Observation) Encryption() EncryptionKind { return o.encryption }

// AvailablePorts returns a caller-owned endpoint evidence copy.
func (o Observation) AvailablePorts() []LoopbackEndpoint {
	return append([]LoopbackEndpoint(nil), o.availablePorts...)
}

// Digest returns the canonical native-evidence binding.
func (o Observation) Digest() install.Digest { return o.digest }

func (o Observation) valid() bool {
	rebuilt, err := NewObservation(ObservationInput{
		Platform: o.platform, CPUCores: o.cpuCores, MemoryBytes: o.memoryBytes,
		FreeDiskBytes: o.freeDiskBytes, StorageTarget: o.storageTarget,
		Virtualization: o.virtualization, Encryption: o.encryption, AvailablePorts: o.availablePorts,
	})
	return err == nil && rebuilt.digest.Equal(o.digest)
}

// FailureReason is the complete privacy-safe host rejection vocabulary.
type FailureReason string

const (
	// FailureNone means every proof and comparison succeeded.
	FailureNone FailureReason = "none"
	// FailureUnsupportedPlatform means the exact tuple is not authorized.
	FailureUnsupportedPlatform FailureReason = "unsupported_platform"
	// FailureInsufficientCPU means the signed CPU floor was not met.
	FailureInsufficientCPU FailureReason = "insufficient_cpu"
	// FailureInsufficientMemory means the signed memory floor was not met.
	FailureInsufficientMemory FailureReason = "insufficient_memory"
	// FailureInsufficientDisk means the signed disk floor was not met.
	FailureInsufficientDisk FailureReason = "insufficient_disk"
	// FailureTargetNotOwnerControlled means target ownership was not proved.
	FailureTargetNotOwnerControlled FailureReason = "target_not_owner_controlled"
	// FailurePlatformProofUnavailable means the platform tuple was unavailable.
	FailurePlatformProofUnavailable FailureReason = "platform_proof_unavailable"
	// FailureResourceProofUnavailable means resource evidence was unavailable.
	FailureResourceProofUnavailable FailureReason = "resource_proof_unavailable"
	// FailureVirtualizationUnavailable means hardware virtualization was unavailable.
	FailureVirtualizationUnavailable FailureReason = "virtualization_unavailable"
	// FailureEncryptionUnavailable means target encryption was unavailable.
	FailureEncryptionUnavailable FailureReason = "encryption_unavailable"
	// FailureLoopbackPortUnavailable means an exact loopback bind failed.
	FailureLoopbackPortUnavailable FailureReason = "loopback_port_unavailable"
)

func (r FailureReason) validFailure() bool {
	switch r {
	case FailureNone:
		return false
	case FailureUnsupportedPlatform, FailureInsufficientCPU, FailureInsufficientMemory,
		FailureInsufficientDisk, FailureTargetNotOwnerControlled, FailurePlatformProofUnavailable,
		FailureResourceProofUnavailable, FailureVirtualizationUnavailable,
		FailureEncryptionUnavailable, FailureLoopbackPortUnavailable:
		return true
	}
	return false
}

// Evaluate applies policy in a stable order so the same evidence always emits
// the same single closed rejection reason.
func (p Plan) Evaluate(observation Observation) FailureReason {
	if !p.Valid() || !observation.valid() {
		return FailurePlatformProofUnavailable
	}
	if observation.platform != p.platform {
		return FailureUnsupportedPlatform
	}
	if observation.cpuCores < p.minimumCPUCores {
		return FailureInsufficientCPU
	}
	if observation.memoryBytes < p.minimumMemoryBytes {
		return FailureInsufficientMemory
	}
	if observation.freeDiskBytes < p.minimumFreeDiskBytes {
		return FailureInsufficientDisk
	}
	if observation.storageTarget != p.storageTarget {
		return FailureTargetNotOwnerControlled
	}
	if !validProofKinds(observation.platform.OperatingSystem, observation.virtualization, observation.encryption) {
		return FailurePlatformProofUnavailable
	}
	if !slices.Equal(observation.availablePorts, p.requiredPorts) {
		return FailureLoopbackPortUnavailable
	}
	return FailureNone
}

// ProbeResult is either one complete positive observation or one closed native
// failure. Its private fields prevent an adapter from returning both.
type ProbeResult struct {
	observation Observation
	failure     FailureReason
}

// NewObservedResult creates a positive result from complete native evidence.
func NewObservedResult(observation Observation) (ProbeResult, error) {
	if !observation.valid() {
		return ProbeResult{}, ErrIntegrity
	}
	return ProbeResult{observation: observation, failure: FailureNone}, nil
}

// NewRejectedResult creates a negative result from one closed reason.
func NewRejectedResult(reason FailureReason) (ProbeResult, error) {
	if !reason.validFailure() {
		return ProbeResult{}, ErrIntegrity
	}
	return ProbeResult{failure: reason}, nil
}

// Observation returns positive native evidence when present.
func (r ProbeResult) Observation() (Observation, bool) {
	return r.observation, r.failure == FailureNone && r.observation.valid()
}

// Failure returns FailureNone or the exact closed rejection reason.
func (r ProbeResult) Failure() FailureReason { return r.failure }

// Valid reports whether exactly one positive or negative state is present.
func (r ProbeResult) Valid() bool {
	if r.failure == FailureNone {
		return r.observation.valid()
	}
	return r.failure.validFailure() && !r.observation.valid()
}
