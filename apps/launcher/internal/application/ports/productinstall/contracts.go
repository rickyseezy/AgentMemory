// Package productinstall defines the narrow, plan-bound host product
// installation ports used by PF-001. It carries paths and protected references,
// never secret material, through the application boundary.
package productinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

const maximumProtectedPathBytes = 32 * 1024

var (
	// ErrIntegrity means an authorization, protected object, or receipt could
	// not be proven to match its immutable PF-001 binding.
	ErrIntegrity = errors.New("product installation integrity violation")
	// ErrUnavailable means a transient local platform boundary prevented an
	// otherwise authorized operation from completing.
	ErrUnavailable = errors.New("product installation capability unavailable")
	// ErrUnsupported means the host cannot provide the required security or
	// durability contract and must not be silently downgraded.
	ErrUnsupported = errors.New("product installation capability unsupported")
)

// DirectoryPurpose is the closed set of owner-controlled product directories.
type DirectoryPurpose string

const (
	// DirectoryRelease contains the immutable selected release generation.
	DirectoryRelease DirectoryPurpose = "release"
	// DirectoryConfiguration contains local owner configuration.
	DirectoryConfiguration DirectoryPurpose = "configuration"
	// DirectoryRuntime contains local runtime coordination material.
	DirectoryRuntime DirectoryPurpose = "runtime"
	// DirectorySecrets contains Docker-compatible protected secret references.
	DirectorySecrets DirectoryPurpose = "secrets"
	// DirectoryBackups contains encrypted local rollback and export material.
	DirectoryBackups DirectoryPurpose = "backups"
	// DirectoryComposeProject contains the immutable rendered Compose project.
	DirectoryComposeProject DirectoryPurpose = "compose-project"
)

var requiredDirectoryPurposes = []DirectoryPurpose{
	DirectoryBackups,
	DirectoryComposeProject,
	DirectoryConfiguration,
	DirectoryRelease,
	DirectoryRuntime,
	DirectorySecrets,
}

var requiredSecretPurposes = []installplan.SecretPurpose{
	installplan.SecretAPICredential,
	installplan.SecretAttestationHMACKey,
	installplan.SecretEmbeddingCapability,
	installplan.SecretExtractorCapability,
	installplan.SecretInstallationRootKey,
	installplan.SecretNeo4jPassword,
	installplan.SecretRerankerCapability,
}

// DirectorySpec binds one closed directory purpose to one plan-authorized path.
type DirectorySpec struct {
	purpose DirectoryPurpose
	path    string
}

// NewDirectorySpec validates one path-only directory authority.
func NewDirectorySpec(purpose DirectoryPurpose, path string) (DirectorySpec, error) {
	if !slices.Contains(requiredDirectoryPurposes, purpose) || !validProtectedPathReference(path) {
		return DirectorySpec{}, ErrIntegrity
	}
	return DirectorySpec{purpose: purpose, path: path}, nil
}

// Purpose returns the closed directory purpose.
func (s DirectorySpec) Purpose() DirectoryPurpose { return s.purpose }

// Path returns the exact parent-plan-authorized host path.
func (s DirectorySpec) Path() string { return s.path }

// SecretSpec binds one purpose-separated secret to one protected file path.
type SecretSpec struct {
	purpose installplan.SecretPurpose
	path    string
}

// NewSecretSpec validates one protected secret reference without accepting key bytes.
func NewSecretSpec(purpose installplan.SecretPurpose, path string) (SecretSpec, error) {
	if !slices.Contains(requiredSecretPurposes, purpose) || !validProtectedPathReference(path) {
		return SecretSpec{}, ErrIntegrity
	}
	return SecretSpec{purpose: purpose, path: path}, nil
}

// Purpose returns the exact key-separation purpose.
func (s SecretSpec) Purpose() installplan.SecretPurpose { return s.purpose }

// Path returns the parent-plan-authorized protected file reference.
func (s SecretSpec) Path() string { return s.path }

// DirectoryCommand is the immutable authorization for one EnsureDirectories attempt.
type DirectoryCommand struct {
	operationID      install.OperationID
	parentPlan       install.PlanDigest
	attempt          uint32
	runtimeOwnership install.RuntimeOwnership
	directories      []DirectorySpec
	bindingDigest    install.Digest
}

// NewDirectoryCommand constructs a complete purpose-sorted directory authorization.
func NewDirectoryCommand(
	operationID install.OperationID,
	parentPlan install.PlanDigest,
	attempt uint32,
	runtimeOwnership install.RuntimeOwnership,
	directories []DirectorySpec,
) (DirectoryCommand, error) {
	canonical, err := canonicalDirectories(directories)
	if operationID.IsZero() || parentPlan.IsZero() || attempt == 0 || !runtimeOwnership.Resolved() || err != nil {
		return DirectoryCommand{}, ErrIntegrity
	}
	command := DirectoryCommand{
		operationID: operationID, parentPlan: parentPlan, attempt: attempt,
		runtimeOwnership: runtimeOwnership, directories: canonical,
	}
	command.bindingDigest = digestDirectoryCommand(command)
	return command, nil
}

// OperationID returns the sole authorized installation operation.
func (c DirectoryCommand) OperationID() install.OperationID { return c.operationID }

// ParentPlanDigest returns the exact canonical installation-plan binding.
func (c DirectoryCommand) ParentPlanDigest() install.PlanDigest { return c.parentPlan }

// Attempt returns the one-based phase attempt.
func (c DirectoryCommand) Attempt() uint32 { return c.attempt }

// RuntimeOwnership returns the already resolved runtime disposition.
func (c DirectoryCommand) RuntimeOwnership() install.RuntimeOwnership { return c.runtimeOwnership }

// Directories returns a caller-owned purpose-sorted copy.
func (c DirectoryCommand) Directories() []DirectorySpec {
	return append([]DirectorySpec(nil), c.directories...)
}

// BindingDigest returns the canonical authorization digest.
func (c DirectoryCommand) BindingDigest() install.Digest { return c.bindingDigest }

// Valid reports whether the complete immutable command remains self-consistent.
func (c DirectoryCommand) Valid() bool {
	canonical, err := canonicalDirectories(c.directories)
	return err == nil && !c.operationID.IsZero() && !c.parentPlan.IsZero() && c.attempt > 0 &&
		c.runtimeOwnership.Resolved() && slices.Equal(canonical, c.directories) &&
		!c.bindingDigest.IsZero() && c.bindingDigest.Equal(digestDirectoryCommand(c))
}

// SecretCommand is the immutable authorization for one EnsureKeys attempt.
type SecretCommand struct {
	operationID      install.OperationID
	parentPlan       install.PlanDigest
	attempt          uint32
	runtimeOwnership install.RuntimeOwnership
	secretDirectory  string
	secrets          []SecretSpec
	bindingDigest    install.Digest
}

// NewSecretCommand constructs a complete purpose-sorted protected-key authorization.
func NewSecretCommand(
	operationID install.OperationID,
	parentPlan install.PlanDigest,
	attempt uint32,
	runtimeOwnership install.RuntimeOwnership,
	secretDirectory string,
	secrets []SecretSpec,
) (SecretCommand, error) {
	canonical, err := canonicalSecrets(secrets)
	if operationID.IsZero() || parentPlan.IsZero() || attempt == 0 || !runtimeOwnership.Resolved() ||
		!validProtectedPathReference(secretDirectory) || err != nil {
		return SecretCommand{}, ErrIntegrity
	}
	command := SecretCommand{
		operationID: operationID, parentPlan: parentPlan, attempt: attempt,
		runtimeOwnership: runtimeOwnership, secretDirectory: secretDirectory, secrets: canonical,
	}
	command.bindingDigest = digestSecretCommand(command)
	return command, nil
}

// OperationID returns the sole authorized installation operation.
func (c SecretCommand) OperationID() install.OperationID { return c.operationID }

// ParentPlanDigest returns the exact canonical installation-plan binding.
func (c SecretCommand) ParentPlanDigest() install.PlanDigest { return c.parentPlan }

// Attempt returns the one-based phase attempt.
func (c SecretCommand) Attempt() uint32 { return c.attempt }

// RuntimeOwnership returns the already resolved runtime disposition.
func (c SecretCommand) RuntimeOwnership() install.RuntimeOwnership { return c.runtimeOwnership }

// SecretDirectory returns the exact owner-protected materialization root.
func (c SecretCommand) SecretDirectory() string { return c.secretDirectory }

// Secrets returns a caller-owned purpose-sorted copy.
func (c SecretCommand) Secrets() []SecretSpec { return append([]SecretSpec(nil), c.secrets...) }

// BindingDigest returns the canonical authorization digest.
func (c SecretCommand) BindingDigest() install.Digest { return c.bindingDigest }

// Valid reports whether the complete immutable command remains self-consistent.
func (c SecretCommand) Valid() bool {
	canonical, err := canonicalSecrets(c.secrets)
	return err == nil && !c.operationID.IsZero() && !c.parentPlan.IsZero() && c.attempt > 0 &&
		c.runtimeOwnership.Resolved() && validProtectedPathReference(c.secretDirectory) &&
		slices.Equal(canonical, c.secrets) && !c.bindingDigest.IsZero() &&
		c.bindingDigest.Equal(digestSecretCommand(c))
}

// DirectoryReceipt is privacy-safe evidence that every authorized directory
// was created or re-verified through the native protected-path boundary.
type DirectoryReceipt struct {
	commandDigest install.Digest
	stateDigest   install.Digest
	outputDigest  install.Digest
	created       uint32
	reused        uint32
}

// NewDirectoryReceiptForAdapter constructs a receipt only for a complete result.
func NewDirectoryReceiptForAdapter(
	command DirectoryCommand,
	stateDigest install.Digest,
	created uint32,
	reused uint32,
) (DirectoryReceipt, error) {
	if !command.Valid() || stateDigest.IsZero() || uint64(created)+uint64(reused) != uint64(len(command.directories)) {
		return DirectoryReceipt{}, ErrIntegrity
	}
	receipt := DirectoryReceipt{
		commandDigest: command.bindingDigest, stateDigest: stateDigest, created: created, reused: reused,
	}
	receipt.outputDigest = digestDirectoryReceipt(receipt)
	return receipt, nil
}

// OutputDigest returns the complete receipt binding recorded by the saga.
func (r DirectoryReceipt) OutputDigest() install.Digest { return r.outputDigest }

// Created returns the exact number of newly created directories.
func (r DirectoryReceipt) Created() uint32 { return r.created }

// Reused returns the exact number of pre-existing, re-verified directories.
func (r DirectoryReceipt) Reused() uint32 { return r.reused }

// ValidFor prevents receipt replay across operation, plan, attempt, or layout.
func (r DirectoryReceipt) ValidFor(command DirectoryCommand) bool {
	return command.Valid() && !r.stateDigest.IsZero() && r.commandDigest.Equal(command.bindingDigest) &&
		uint64(r.created)+uint64(r.reused) == uint64(len(command.directories)) &&
		!r.outputDigest.IsZero() && r.outputDigest.Equal(digestDirectoryReceipt(r))
}

// SecretReceipt is privacy-safe HMAC-backed evidence that every exact secret
// reference contains one verified 256-bit purpose-separated value.
type SecretReceipt struct {
	commandDigest install.Digest
	stateDigest   install.Digest
	outputDigest  install.Digest
	created       uint32
	reused        uint32
}

// NewSecretReceiptForAdapter constructs a receipt only for a complete result.
func NewSecretReceiptForAdapter(
	command SecretCommand,
	stateDigest install.Digest,
	created uint32,
	reused uint32,
) (SecretReceipt, error) {
	if !command.Valid() || stateDigest.IsZero() || uint64(created)+uint64(reused) != uint64(len(command.secrets)) {
		return SecretReceipt{}, ErrIntegrity
	}
	receipt := SecretReceipt{
		commandDigest: command.bindingDigest, stateDigest: stateDigest, created: created, reused: reused,
	}
	receipt.outputDigest = digestSecretReceipt(receipt)
	return receipt, nil
}

// OutputDigest returns the complete receipt binding recorded by the saga.
func (r SecretReceipt) OutputDigest() install.Digest { return r.outputDigest }

// Created returns the exact number of newly generated secret values.
func (r SecretReceipt) Created() uint32 { return r.created }

// Reused returns the exact number of existing, re-verified secret values.
func (r SecretReceipt) Reused() uint32 { return r.reused }

// ValidFor prevents receipt replay across operation, plan, attempt, or key layout.
func (r SecretReceipt) ValidFor(command SecretCommand) bool {
	return command.Valid() && !r.stateDigest.IsZero() && r.commandDigest.Equal(command.bindingDigest) &&
		uint64(r.created)+uint64(r.reused) == uint64(len(command.secrets)) &&
		!r.outputDigest.IsZero() && r.outputDigest.Equal(digestSecretReceipt(r))
}

// DirectoryEnsurer is the native owner-protected directory boundary.
type DirectoryEnsurer interface {
	EnsureDirectories(context.Context, DirectoryCommand) (DirectoryReceipt, error)
}

// SecretEnsurer is the native purpose-separated secret materialization boundary.
type SecretEnsurer interface {
	EnsureSecrets(context.Context, SecretCommand) (SecretReceipt, error)
}

func canonicalDirectories(input []DirectorySpec) ([]DirectorySpec, error) {
	if len(input) != len(requiredDirectoryPurposes) {
		return nil, ErrIntegrity
	}
	result := append([]DirectorySpec(nil), input...)
	sort.Slice(result, func(left, right int) bool { return result[left].purpose < result[right].purpose })
	paths := make(map[string]struct{}, len(result))
	for index, spec := range result {
		if index >= len(requiredDirectoryPurposes) || spec.purpose != requiredDirectoryPurposes[index] ||
			!validProtectedPathReference(spec.path) {
			return nil, ErrIntegrity
		}
		if _, exists := paths[spec.path]; exists {
			return nil, ErrIntegrity
		}
		paths[spec.path] = struct{}{}
	}
	return result, nil
}

func canonicalSecrets(input []SecretSpec) ([]SecretSpec, error) {
	if len(input) != len(requiredSecretPurposes) {
		return nil, ErrIntegrity
	}
	result := append([]SecretSpec(nil), input...)
	sort.Slice(result, func(left, right int) bool { return result[left].purpose < result[right].purpose })
	paths := make(map[string]struct{}, len(result))
	for index, spec := range result {
		if index >= len(requiredSecretPurposes) || spec.purpose != requiredSecretPurposes[index] ||
			!validProtectedPathReference(spec.path) {
			return nil, ErrIntegrity
		}
		if _, exists := paths[spec.path]; exists {
			return nil, ErrIntegrity
		}
		paths[spec.path] = struct{}{}
	}
	return result, nil
}

func validProtectedPathReference(path string) bool {
	return path != "" && len(path) <= maximumProtectedPathBytes && path == strings.TrimSpace(path) &&
		!strings.ContainsRune(path, '\x00')
}

type canonicalSpec struct {
	Purpose string `json:"purpose"`
	Path    string `json:"path"`
}

type canonicalCommand struct {
	SchemaVersion    uint16          `json:"schema_version"`
	Kind             string          `json:"kind"`
	OperationID      string          `json:"operation_id"`
	ParentPlanDigest string          `json:"parent_plan_digest"`
	Attempt          uint32          `json:"attempt"`
	RuntimeOwnership string          `json:"runtime_ownership"`
	Root             string          `json:"root,omitempty"`
	Specifications   []canonicalSpec `json:"specifications"`
}

type canonicalReceipt struct {
	SchemaVersion uint16 `json:"schema_version"`
	Kind          string `json:"kind"`
	CommandDigest string `json:"command_digest"`
	StateDigest   string `json:"state_digest"`
}

func digestDirectoryCommand(command DirectoryCommand) install.Digest {
	specifications := make([]canonicalSpec, 0, len(command.directories))
	for _, spec := range command.directories {
		specifications = append(specifications, canonicalSpec{Purpose: string(spec.purpose), Path: spec.path})
	}
	return digestCanonical(canonicalCommand{
		SchemaVersion: 1, Kind: "ensure-directories", OperationID: command.operationID.String(),
		ParentPlanDigest: command.parentPlan.String(), Attempt: command.attempt,
		RuntimeOwnership: command.runtimeOwnership.String(), Specifications: specifications,
	})
}

func digestSecretCommand(command SecretCommand) install.Digest {
	specifications := make([]canonicalSpec, 0, len(command.secrets))
	for _, spec := range command.secrets {
		specifications = append(specifications, canonicalSpec{Purpose: string(spec.purpose), Path: spec.path})
	}
	return digestCanonical(canonicalCommand{
		SchemaVersion: 1, Kind: "ensure-secrets", OperationID: command.operationID.String(),
		ParentPlanDigest: command.parentPlan.String(), Attempt: command.attempt,
		RuntimeOwnership: command.runtimeOwnership.String(), Root: command.secretDirectory,
		Specifications: specifications,
	})
}

func digestDirectoryReceipt(receipt DirectoryReceipt) install.Digest {
	return digestCanonical(canonicalReceipt{
		SchemaVersion: 1, Kind: "directory-receipt", CommandDigest: receipt.commandDigest.String(),
		StateDigest: receipt.stateDigest.String(),
	})
}

func digestSecretReceipt(receipt SecretReceipt) install.Digest {
	return digestCanonical(canonicalReceipt{
		SchemaVersion: 1, Kind: "secret-receipt", CommandDigest: receipt.commandDigest.String(),
		StateDigest: receipt.stateDigest.String(),
	})
}

func digestCanonical(value any) install.Digest {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("marshal closed product-install contract: %v", err))
	}
	return install.DigestBytes(encoded)
}
