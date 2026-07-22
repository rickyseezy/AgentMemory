// Package provideradapterapp orchestrates verified PRO-002 adapter installation.
package provideradapterapp

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

var (
	operationPattern         = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	instancePattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	providerAdapterIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	installationPattern      = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// ErrInvalidCommand is a safe validation failure.
	ErrInvalidCommand = errors.New("custom provider adapter install command is invalid")
	// ErrUnauthorized is a safe role-policy failure.
	ErrUnauthorized = errors.New("custom provider adapter install is not authorized")
	// ErrConflict is a safe immutable-replay conflict.
	ErrConflict = errors.New("custom provider adapter install conflicts with immutable history")
	// ErrVerification is a safe supply-chain failure.
	ErrVerification = errors.New("custom provider adapter supply chain was rejected")
	// ErrPolicy is a safe permission-policy failure.
	ErrPolicy = errors.New("custom provider adapter permission policy was rejected")
	// ErrRuntime is a safe container lifecycle failure.
	ErrRuntime = errors.New("custom provider adapter runtime failed")
	// ErrConformance is a safe protocol certification failure.
	ErrConformance = errors.New("custom provider adapter conformance failed")
	// ErrStorage is a safe canonical journal failure.
	ErrStorage = errors.New("custom provider adapter install journal failed")
)

// Role is the closed administrator authority vocabulary.
type Role string

const (
	// RoleOwner has installation authority.
	RoleOwner Role = "owner"
	// RoleAdmin has delegated installation authority.
	RoleAdmin Role = "admin"
	// RoleReader has no installation authority.
	RoleReader Role = "reader"
)

// Status is the closed adapter activation state.
type Status string

// StatusActive means conformance passed and canonical persistence committed.
const StatusActive Status = "active"

// InstallProviderAdapterCommand is the immutable host-side installation request.
type InstallProviderAdapterCommand struct {
	OperationID, InstallationID string
	Role                        Role
	Manifest                    provideradapter.Manifest
	RequestedAt                 time.Time
}

func (c InstallProviderAdapterCommand) valid() bool {
	return operationPattern.MatchString(c.OperationID) && installationPattern.MatchString(c.InstallationID) &&
		(c.Role == RoleOwner || c.Role == RoleAdmin || c.Role == RoleReader) &&
		!c.Manifest.Digest().IsZero() && !c.RequestedAt.IsZero() && c.RequestedAt.Location() == time.UTC
}

// RuntimeHandle is opaque cleanup authority bound to one deployment plan.
type RuntimeHandle struct {
	instanceID string
	planDigest provideradapter.Digest
}

// NewRuntimeHandle validates a runtime identity and its exact plan binding.
func NewRuntimeHandle(instanceID string, planDigest provideradapter.Digest) RuntimeHandle {
	if !instancePattern.MatchString(instanceID) || planDigest.IsZero() {
		return RuntimeHandle{}
	}
	return RuntimeHandle{instanceID: instanceID, planDigest: planDigest}
}

// Valid reports whether the handle came through the constructor.
func (h RuntimeHandle) Valid() bool { return h.instanceID != "" && !h.planDigest.IsZero() }

// InstanceID returns the opaque runtime identity.
func (h RuntimeHandle) InstanceID() string { return h.instanceID }

// PlanDigest returns the immutable deployment binding.
func (h RuntimeHandle) PlanDigest() provideradapter.Digest { return h.planDigest }

// CapabilityAttestation is immutable evidence from live conformance.
type CapabilityAttestation struct {
	manifestDigest, planDigest, imageDigest, digest provideradapter.Digest
	protocol                                        uint16
	operations                                      []provideradapter.Operation
	health, cancellation, shutdown                  bool
	verifiedAt                                      time.Time
}

// NewCapabilityAttestation validates and hashes live protocol evidence.
func NewCapabilityAttestation(
	manifestDigest, planDigest, imageDigest provideradapter.Digest,
	protocol uint16,
	operations []provideradapter.Operation,
	health, cancellation, shutdown bool,
	verifiedAt time.Time,
) CapabilityAttestation {
	copyOperations := slices.Clone(operations)
	slices.Sort(copyOperations)
	document := struct {
		Manifest, Plan, Image          string
		Protocol                       uint16
		Operations                     []provideradapter.Operation
		Health, Cancellation, Shutdown bool
		VerifiedAt                     int64
	}{manifestDigest.Hex(), planDigest.Hex(), imageDigest.Hex(), protocol, copyOperations, health, cancellation, shutdown, verifiedAt.UnixMicro()}
	canonical, err := json.Marshal(document)
	if err != nil || manifestDigest.IsZero() || planDigest.IsZero() || imageDigest.IsZero() ||
		protocol != provideradapter.SupportedProtocolMajor || len(copyOperations) == 0 ||
		!health || !cancellation || !shutdown || verifiedAt.IsZero() || verifiedAt.Location() != time.UTC {
		return CapabilityAttestation{}
	}
	return CapabilityAttestation{manifestDigest, planDigest, imageDigest, provideradapter.DigestBytes(canonical), protocol, copyOperations, health, cancellation, shutdown, verifiedAt}
}

// ValidFor proves the attestation belongs to the exact manifest and deployment.
func (a CapabilityAttestation) ValidFor(manifest provideradapter.Manifest, plan provideradapter.DeploymentPlan) bool {
	if a.digest.IsZero() || !a.manifestDigest.Equal(manifest.Digest()) || !a.planDigest.Equal(plan.Digest()) ||
		!a.imageDigest.Equal(manifest.ImageDigest()) || a.protocol != provideradapter.SupportedProtocolMajor ||
		!a.health || !a.cancellation || !a.shutdown {
		return false
	}
	return slices.Equal(a.operations, manifest.Operations())
}

// Digest returns the canonical attestation identity.
func (a CapabilityAttestation) Digest() provideradapter.Digest { return a.digest }

// ManifestDigest returns the certified manifest identity.
func (a CapabilityAttestation) ManifestDigest() provideradapter.Digest { return a.manifestDigest }

// PlanDigest returns the certified deployment identity.
func (a CapabilityAttestation) PlanDigest() provideradapter.Digest { return a.planDigest }

// ImageDigest returns the live image identity.
func (a CapabilityAttestation) ImageDigest() provideradapter.Digest { return a.imageDigest }

// ProtocolVersion returns the negotiated major version.
func (a CapabilityAttestation) ProtocolVersion() uint16 { return a.protocol }

// Operations returns a caller-owned ordered capability list.
func (a CapabilityAttestation) Operations() []provideradapter.Operation {
	return slices.Clone(a.operations)
}

// VerifiedAt returns the canonical UTC certification time.
func (a CapabilityAttestation) VerifiedAt() time.Time { return a.verifiedAt }

// InstallResult is the canonical idempotent activation receipt.
type InstallResult struct {
	operationID, adapterID, runtimeID                            string
	requestDigest, manifestDigest, planDigest, attestationDigest provideradapter.Digest
	status                                                       Status
}

// RestoreInstallResult revalidates a persisted activation receipt.
func RestoreInstallResult(
	operationID, adapterID, runtimeID string,
	requestDigest, manifestDigest, planDigest, attestationDigest provideradapter.Digest,
	status Status,
) (InstallResult, error) {
	if !operationPattern.MatchString(operationID) || !providerAdapterIDPattern.MatchString(adapterID) ||
		!instancePattern.MatchString(runtimeID) || requestDigest.IsZero() || manifestDigest.IsZero() ||
		planDigest.IsZero() || attestationDigest.IsZero() || status != StatusActive {
		return InstallResult{}, ErrStorage
	}
	return InstallResult{operationID, adapterID, runtimeID, requestDigest, manifestDigest, planDigest, attestationDigest, status}, nil
}

func newResult(command InstallProviderAdapterCommand, manifest provideradapter.Manifest, plan provideradapter.DeploymentPlan, handle RuntimeHandle, attestation CapabilityAttestation) (InstallResult, error) {
	request := provideradapter.DigestBytes([]byte(command.InstallationID + "\x00" + manifest.Digest().Hex()))
	if !handle.Valid() || !handle.PlanDigest().Equal(plan.Digest()) || !attestation.ValidFor(manifest, plan) {
		return InstallResult{}, ErrConformance
	}
	return InstallResult{command.OperationID, manifest.AdapterID(), handle.InstanceID(), request, manifest.Digest(), plan.Digest(), attestation.Digest(), StatusActive}, nil
}

func (r InstallResult) matches(command InstallProviderAdapterCommand) bool {
	want := provideradapter.DigestBytes([]byte(command.InstallationID + "\x00" + command.Manifest.Digest().Hex()))
	return r.status == StatusActive && r.operationID == command.OperationID && r.requestDigest.Equal(want)
}

// OperationID returns the idempotency identity.
func (r InstallResult) OperationID() string { return r.operationID }

// AdapterID returns the activated adapter identity.
func (r InstallResult) AdapterID() string { return r.adapterID }

// RuntimeID returns the exact sidecar identity.
func (r InstallResult) RuntimeID() string { return r.runtimeID }

// Status returns the canonical activation state.
func (r InstallResult) Status() Status { return r.status }

// AttestationDigest returns the live-conformance identity.
func (r InstallResult) AttestationDigest() provideradapter.Digest { return r.attestationDigest }

// RequestDigest returns the immutable replay binding.
func (r InstallResult) RequestDigest() provideradapter.Digest { return r.requestDigest }

// ManifestDigest returns the activated manifest identity.
func (r InstallResult) ManifestDigest() provideradapter.Digest { return r.manifestDigest }

// PlanDigest returns the activated deployment identity.
func (r InstallResult) PlanDigest() provideradapter.Digest { return r.planDigest }

// SupplyChainVerifier verifies image and evidence trust before runtime access.
type SupplyChainVerifier interface {
	Verify(context.Context, provideradapter.Manifest) error
}

// PermissionPolicy applies installation-owned resource and gateway policy.
type PermissionPolicy interface {
	Authorize(context.Context, provideradapter.Manifest) error
}

// Runtime owns the narrow custom-sidecar start and cleanup lifecycle.
type Runtime interface {
	Start(context.Context, provideradapter.DeploymentPlan) (RuntimeHandle, error)
	Stop(context.Context, RuntimeHandle) error
}

// Conformance certifies the live protocol and declared operations.
type Conformance interface {
	Certify(context.Context, RuntimeHandle, provideradapter.Manifest) (CapabilityAttestation, error)
}

// Repository provides canonical idempotent activation persistence.
type Repository interface {
	Find(context.Context, string) (InstallResult, bool, error)
	Commit(context.Context, InstallResult) error
}

// Dependencies contains every outbound clean-architecture port.
type Dependencies struct {
	Verifier    SupplyChainVerifier
	Policy      PermissionPolicy
	Runtime     Runtime
	Conformance Conformance
	Repository  Repository
}

// Application coordinates one fail-closed custom adapter installation.
type Application struct{ dependencies Dependencies }

// ProviderInstallApplication names the host-launcher use case described by PRO-002.
type ProviderInstallApplication = Application

// New validates all required ports and constructs the use case.
func New(dependencies Dependencies) (Application, error) {
	if dependencies.Verifier == nil || dependencies.Policy == nil || dependencies.Runtime == nil ||
		dependencies.Conformance == nil || dependencies.Repository == nil {
		return Application{}, ErrInvalidCommand
	}
	return Application{dependencies: dependencies}, nil
}

// NewProviderInstallApplication constructs the explicit host-side install use case.
func NewProviderInstallApplication(dependencies Dependencies) (ProviderInstallApplication, error) {
	return New(dependencies)
}

// Execute verifies, authorizes, starts, certifies, and atomically records an adapter.
func (a Application) Execute(ctx context.Context, command InstallProviderAdapterCommand) (result InstallResult, resultErr error) {
	if ctx == nil || !command.valid() {
		return InstallResult{}, ErrInvalidCommand
	}
	if command.Role != RoleOwner && command.Role != RoleAdmin {
		return InstallResult{}, ErrUnauthorized
	}
	replay, found, err := a.dependencies.Repository.Find(ctx, command.OperationID)
	if err != nil {
		return InstallResult{}, errors.Join(ErrStorage, err)
	}
	if found {
		if !replay.matches(command) {
			return InstallResult{}, ErrConflict
		}
		return replay, nil
	}
	if err := a.dependencies.Verifier.Verify(ctx, command.Manifest); err != nil {
		return InstallResult{}, errors.Join(ErrVerification, err)
	}
	if err := a.dependencies.Policy.Authorize(ctx, command.Manifest); err != nil {
		return InstallResult{}, errors.Join(ErrPolicy, err)
	}
	plan, err := command.Manifest.DeploymentPlan(command.InstallationID)
	if err != nil {
		return InstallResult{}, errors.Join(ErrPolicy, err)
	}
	handle, err := a.dependencies.Runtime.Start(ctx, plan)
	if err != nil {
		if handle.Valid() {
			if cleanupErr := a.dependencies.Runtime.Stop(context.WithoutCancel(ctx), handle); cleanupErr != nil {
				return InstallResult{}, errors.Join(ErrRuntime, err, cleanupErr)
			}
		}
		return InstallResult{}, errors.Join(ErrRuntime, err)
	}
	committed := false
	defer func() {
		if !committed {
			if cleanupErr := a.dependencies.Runtime.Stop(context.WithoutCancel(ctx), handle); cleanupErr != nil {
				result = InstallResult{}
				resultErr = errors.Join(resultErr, ErrRuntime, cleanupErr)
			}
		}
	}()
	attestation, err := a.dependencies.Conformance.Certify(ctx, handle, command.Manifest)
	if err != nil {
		return InstallResult{}, errors.Join(ErrConformance, err)
	}
	result, err = newResult(command, command.Manifest, plan, handle, attestation)
	if err != nil {
		return InstallResult{}, err
	}
	if err := a.dependencies.Repository.Commit(ctx, result); err != nil {
		return InstallResult{}, errors.Join(ErrStorage, err)
	}
	committed = true
	return result, nil
}
