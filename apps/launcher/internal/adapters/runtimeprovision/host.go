// Package runtimeprovision implements the production PF-006 platform runtime
// adapters without PATH, shell, global Docker context, or rootful fallback.
package runtimeprovision

import (
	"context"
	"encoding/json"
	"errors"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

var (
	// ErrUnsupportedHost means independently probed facts do not match the signed cell.
	ErrUnsupportedHost = errors.New("linux runtime host is unsupported")
	// ErrAdministratorRequired means a safe rootless prerequisite or certified
	// native authorization surface is unavailable.
	ErrAdministratorRequired = errors.New("linux runtime provisioning requires administrator action")
	// ErrRuntimeConflict preserves incompatible, remote, rootful, or unsafe runtime state.
	ErrRuntimeConflict = errors.New("linux container runtime conflicts with signed policy")
	// ErrProvisionIntegrity rejects authority, executable, socket, receipt, or state substitution.
	ErrProvisionIntegrity = errors.New("linux runtime provisioning integrity validation failed")
	// ErrProbeFailed sanitizes a bounded native or Docker capability failure.
	ErrProbeFailed = errors.New("linux runtime capability probe failed")
)

// HostEvidence contains bounded non-secret facts gathered without mutation.
type HostEvidence struct {
	distribution      string
	versionID         string
	kernel            string
	architecture      runtimeinstall.Architecture
	uid               uint32
	gid               uint32
	cpus              uint16
	totalMemory       uint64
	availableMemory   uint64
	freeDisk          uint64
	userNamespaces    bool
	userSystemd       bool
	localFilesystem   bool
	dockerGroupAbsent bool
	selinuxEnforcing  bool
	subordinateUIDs   uint32
	subordinateGIDs   uint32
	machineDigest     runtimeinstall.Hash
	digest            runtimeinstall.Hash
}

// HostEvidenceInput is used by native probes and hermetic tests.
type HostEvidenceInput struct {
	Distribution      string
	VersionID         string
	Kernel            string
	Architecture      runtimeinstall.Architecture
	UID               uint32
	GID               uint32
	CPUs              uint16
	TotalMemory       uint64
	AvailableMemory   uint64
	FreeDisk          uint64
	UserNamespaces    bool
	UserSystemd       bool
	LocalFilesystem   bool
	DockerGroupAbsent bool
	SELinuxEnforcing  bool
	SubordinateUIDs   uint32
	SubordinateGIDs   uint32
	MachineDigest     runtimeinstall.Hash
}

// NewHostEvidence validates a complete read-only observation.
func NewHostEvidence(input HostEvidenceInput) (HostEvidence, error) {
	if !validOSReleaseToken(input.Distribution) || !validOSReleaseToken(input.VersionID) ||
		!validKernel(input.Kernel) || input.Architecture != runtimeinstall.ArchitectureAMD64 &&
		input.Architecture != runtimeinstall.ArchitectureARM64 || input.UID == 0 || input.GID == 0 ||
		input.CPUs == 0 || input.TotalMemory == 0 || input.AvailableMemory > input.TotalMemory ||
		input.FreeDisk == 0 || input.MachineDigest.IsZero() {
		return HostEvidence{}, ErrProbeFailed
	}
	evidence := HostEvidence{
		distribution: input.Distribution, versionID: input.VersionID, kernel: input.Kernel,
		architecture: input.Architecture, uid: input.UID, gid: input.GID, cpus: input.CPUs,
		totalMemory: input.TotalMemory, availableMemory: input.AvailableMemory, freeDisk: input.FreeDisk,
		userNamespaces: input.UserNamespaces, userSystemd: input.UserSystemd,
		localFilesystem: input.LocalFilesystem, dockerGroupAbsent: input.DockerGroupAbsent,
		selinuxEnforcing: input.SELinuxEnforcing,
		subordinateUIDs:  input.SubordinateUIDs, subordinateGIDs: input.SubordinateGIDs,
		machineDigest: input.MachineDigest,
	}
	evidence.digest = evidence.computeDigest()
	return evidence, nil
}

func (e HostEvidence) computeDigest() runtimeinstall.Hash {
	encoded, _ := json.Marshal(struct {
		Architecture    string `json:"architecture"`
		AvailableMemory uint64 `json:"available_memory"`
		CPUs            uint16 `json:"cpus"`
		Distribution    string `json:"distribution"`
		DockerGroupFree bool   `json:"docker_group_absent"`
		FreeDisk        uint64 `json:"free_disk"`
		GID             uint32 `json:"gid"`
		Kernel          string `json:"kernel"`
		LocalFilesystem bool   `json:"local_filesystem"`
		Machine         string `json:"machine_digest"`
		SELinux         bool   `json:"selinux_enforcing"`
		SubGIDs         uint32 `json:"subordinate_gids"`
		SubUIDs         uint32 `json:"subordinate_uids"`
		Systemd         bool   `json:"user_systemd"`
		TotalMemory     uint64 `json:"total_memory"`
		UID             uint32 `json:"uid"`
		UserNamespaces  bool   `json:"user_namespaces"`
		VersionID       string `json:"version_id"`
	}{
		Architecture: e.architecture.String(), AvailableMemory: e.availableMemory, CPUs: e.cpus,
		Distribution: e.distribution, DockerGroupFree: e.dockerGroupAbsent,
		FreeDisk: e.freeDisk, GID: e.gid, Kernel: e.kernel,
		LocalFilesystem: e.localFilesystem, Machine: e.machineDigest.String(),
		SELinux: e.selinuxEnforcing, SubGIDs: e.subordinateGIDs, SubUIDs: e.subordinateUIDs,
		Systemd: e.userSystemd, TotalMemory: e.totalMemory, UID: e.uid,
		UserNamespaces: e.userNamespaces, VersionID: e.versionID,
	})
	return runtimeinstall.Sum(encoded)
}

// Digest returns the complete non-secret host observation binding.
func (e HostEvidence) Digest() runtimeinstall.Hash { return e.digest }

// Supports proves exact platform identity, resource floors, local storage,
// rootless user namespaces/systemd, principal/machine, and SELinux policy.
func (e HostEvidence) Supports(authority runtimeport.LinuxAuthority) error {
	if !authority.Valid() || e.digest.IsZero() || e.distribution != authority.Distribution() ||
		e.versionID != authority.VersionID() || e.architecture != authority.Architecture() ||
		e.uid != authority.InvokingUID() || e.gid != authority.InvokingGID() ||
		e.machineDigest != authority.MachineDigest() || compareKernel(e.kernel, authority.MinimumKernel()) < 0 ||
		e.cpus < authority.MinimumCPUs() || e.totalMemory < authority.MinimumTotalMemory() ||
		e.availableMemory < authority.MinimumAvailableMemory() || e.freeDisk < authority.MinimumFreeDisk() ||
		!e.localFilesystem || !e.userNamespaces || !e.dockerGroupAbsent {
		return ErrUnsupportedHost
	}
	if !e.userSystemd || e.selinuxEnforcing && !authority.SELinuxEnforcingSupported() {
		return ErrAdministratorRequired
	}
	return nil
}

// HasSubordinateIDs reports whether both independently parsed allocations
// already meet the exact signed minimum. Missing ranges are repairable only by
// the typed privilege helper.
func (e HostEvidence) HasSubordinateIDs(authority runtimeport.LinuxAuthority) bool {
	return authority.Valid() && e.subordinateUIDs >= authority.SubordinateIDCount() &&
		e.subordinateGIDs >= authority.SubordinateIDCount()
}

// HostProbe is the read-only native host boundary used by the provisioner.
type HostProbe interface {
	ProbeLinuxHost(context.Context, runtimeport.LinuxAuthority) (HostEvidence, error)
}
