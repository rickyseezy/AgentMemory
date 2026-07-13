// Package installapp orchestrates the PF-001 local installation saga.
//
// It depends only on the install domain and narrow inward ports. Platform,
// process, container-runtime, and filesystem behavior belongs in adapters.
package installapp

import (
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

// ErrOperationNotFound is returned by OperationRepository.Load when no durable
// operation exists for the requested identifier.
var ErrOperationNotFound = errors.New("installation operation not found")

// ErrOperationIntegrity is returned by OperationRepository.Load or Save when
// durable bytes exist but authentication, decoding, or domain rehydration
// cannot prove a valid aggregate. Callers must not retry or replace that state
// implicitly.
var ErrOperationIntegrity = errors.New("installation operation integrity violation")

// ErrOperationConflict is returned by OperationRepository.Save when the
// durable revision changed after the aggregate was loaded. The caller must
// reload before deciding whether to retry; it must never overwrite the newer
// state implicitly.
var ErrOperationConflict = errors.New("installation operation revision conflict")

// OperationRepository is the aggregate persistence boundary. Save must return
// only after the complete snapshot is durable. Implementations must restore and
// integrity-check an aggregate before returning it from Load.
type OperationRepository interface {
	Load(context.Context, install.OperationID) (*install.Operation, error)
	Save(context.Context, install.OperationSnapshot) error
}

// InstallationLock serializes one host installation operation. Release must be
// idempotent because callers may invoke it during failure unwinding.
type InstallationLock interface {
	Release(context.Context) error
}

// InstallationLockPort prevents any two launchers on the machine from
// executing installation side effects concurrently. The lock is deliberately
// not parameterized by caller-controlled operation identity: PF-001 mutates
// machine-global runtime, network, volume, and agent configuration state.
type InstallationLockPort interface {
	Acquire(context.Context) (InstallationLock, error)
}

// HostVerificationPort proves the host platform and resource prerequisites.
type HostVerificationPort interface {
	VerifyHost(context.Context, PhaseRequest) (PhaseOutput, error)
}

// ContainerRuntimePort reuses or provisions a compatible container runtime.
type ContainerRuntimePort interface {
	EnsureContainerRuntime(context.Context, PhaseRequest) (PhaseOutput, error)
}

// ReleaseVerificationPort verifies release signatures, digests, and policy.
type ReleaseVerificationPort interface {
	VerifyRelease(context.Context, PhaseRequest) (PhaseOutput, error)
}

// SpaceReservationPort reserves enough local capacity for safe installation.
type SpaceReservationPort interface {
	ReserveSpace(context.Context, PhaseRequest) (PhaseOutput, error)
}

// DirectoryPort creates and verifies owner-controlled local directories.
type DirectoryPort interface {
	EnsureDirectories(context.Context, PhaseRequest) (PhaseOutput, error)
}

// KeyProvisioningPort creates or recovers local cryptographic key material.
type KeyProvisioningPort interface {
	EnsureKeys(context.Context, PhaseRequest) (PhaseOutput, error)
}

// ComposeBundlePort installs the verified, immutable Compose release bundle.
type ComposeBundlePort interface {
	EnsureComposeBundle(context.Context, PhaseRequest) (PhaseOutput, error)
}

// NetworkVolumePort creates isolated local networks and durable volumes.
type NetworkVolumePort interface {
	EnsureNetworkAndVolumes(context.Context, PhaseRequest) (PhaseOutput, error)
}

// MigrationPort applies restart-safe schema and data migrations.
type MigrationPort interface {
	RunMigrations(context.Context, PhaseRequest) (PhaseOutput, error)
}

// CoreGraphPort starts and verifies AgentMemory Core and Neo4j.
type CoreGraphPort interface {
	EnsureCoreAndGraph(context.Context, PhaseRequest) (PhaseOutput, error)
}

// BrainBootstrapPort creates the initial local Brain and system metadata.
type BrainBootstrapPort interface {
	BootstrapLocalBrain(context.Context, PhaseRequest) (PhaseOutput, error)
}

// AgentConfigurationPort merges MCP configuration without destroying unrelated
// user configuration.
type AgentConfigurationPort interface {
	MergeAgentConfiguration(context.Context, PhaseRequest) (PhaseOutput, error)
}

// ReadinessPort verifies the installed system through its public health and
// memory-status contracts.
type ReadinessPort interface {
	VerifyReadiness(context.Context, PhaseRequest) (PhaseOutput, error)
}

// ActiveReleasePort atomically makes the verified release active.
type ActiveReleasePort interface {
	CommitActiveRelease(context.Context, PhaseRequest) (PhaseOutput, error)
}
