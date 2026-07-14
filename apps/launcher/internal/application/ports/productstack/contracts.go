// Package productstack defines the narrow, immutable PF-001 authority used to
// run release migrations and start the signed local Core/graph stack.
package productstack

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/containerengine"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

var (
	// ErrIntegrity rejects incomplete, contradictory, or replayed stack authority.
	ErrIntegrity = errors.New("product stack integrity violation")
	// ErrUnavailable reports a bounded Docker/Compose operation failure without
	// exposing command output or protected host paths.
	ErrUnavailable = errors.New("product stack unavailable")
)

// Operation is the closed set of mutating Compose operations authorized by
// PF-001 after the signed source has been materialized and verified.
type Operation string

const (
	// OperationMigrate runs only the signed one-shot migration service.
	OperationMigrate Operation = "migrate"
	// OperationStartCoreAndGraph starts the exact persistent production profile
	// and waits for Compose health without claiming application readiness.
	OperationStartCoreAndGraph Operation = "start-core-and-graph"
)

// Authorization binds one mutation to its operation, canonical installation
// plan, phase attempt, runtime ownership, and exact signed Compose source.
type Authorization struct {
	operation        Operation
	operationID      install.OperationID
	parentPlan       install.PlanDigest
	attempt          uint32
	runtimeOwnership install.RuntimeOwnership
	source           containerengine.ComposeReleaseSource
	bindingDigest    install.Digest
}

// NewAuthorization constructs one complete immutable stack authorization.
func NewAuthorization(
	operation Operation,
	operationID install.OperationID,
	parentPlan install.PlanDigest,
	attempt uint32,
	runtimeOwnership install.RuntimeOwnership,
	source containerengine.ComposeReleaseSource,
) (Authorization, error) {
	if !validOperation(operation) || operationID.IsZero() || parentPlan.IsZero() || attempt == 0 ||
		!runtimeOwnership.Resolved() || !validSource(source) {
		return Authorization{}, ErrIntegrity
	}
	authorization := Authorization{
		operation: operation, operationID: operationID, parentPlan: parentPlan, attempt: attempt,
		runtimeOwnership: runtimeOwnership, source: source,
	}
	authorization.bindingDigest = digestAuthorization(authorization)
	return authorization, nil
}

// Operation returns the sole permitted stack mutation.
func (a Authorization) Operation() Operation { return a.operation }

// OperationID returns the installation operation that owns the side effect.
func (a Authorization) OperationID() install.OperationID { return a.operationID }

// ParentPlanDigest returns the exact canonical installation-plan binding.
func (a Authorization) ParentPlanDigest() install.PlanDigest { return a.parentPlan }

// Attempt returns the one-based parent phase attempt.
func (a Authorization) Attempt() uint32 { return a.attempt }

// RuntimeOwnership returns the already resolved runtime disposition.
func (a Authorization) RuntimeOwnership() install.RuntimeOwnership { return a.runtimeOwnership }

// Source returns the exact signed, non-ambient Compose source authority.
func (a Authorization) Source() containerengine.ComposeReleaseSource { return a.source }

// BindingDigest returns the canonical operation authorization digest.
func (a Authorization) BindingDigest() install.Digest { return a.bindingDigest }

// Valid reports whether all immutable fields still match the digest.
func (a Authorization) Valid() bool {
	return validOperation(a.operation) && !a.operationID.IsZero() && !a.parentPlan.IsZero() &&
		a.attempt > 0 && a.runtimeOwnership.Resolved() && validSource(a.source) &&
		!a.bindingDigest.IsZero() && a.bindingDigest.Equal(digestAuthorization(a))
}

// Receipt is privacy-safe evidence that Docker re-derived and executed the
// exact signed source. It contains no path, command output, or secret value.
type Receipt struct {
	authorizationDigest install.Digest
	configurationDigest install.Digest
	outputDigest        install.Digest
}

// NewReceiptForAdapter constructs execution evidence from the normalized
// Compose configuration observed at the mutating adapter boundary.
func NewReceiptForAdapter(authorization Authorization, configurationDigest install.Digest) (Receipt, error) {
	if !authorization.Valid() || configurationDigest.IsZero() {
		return Receipt{}, ErrIntegrity
	}
	receipt := Receipt{
		authorizationDigest: authorization.bindingDigest,
		configurationDigest: configurationDigest,
	}
	receipt.outputDigest = digestReceipt(receipt)
	return receipt, nil
}

// ConfigurationDigest returns the normalized semantic Compose binding.
func (r Receipt) ConfigurationDigest() install.Digest { return r.configurationDigest }

// OutputDigest returns the complete operation receipt digest.
func (r Receipt) OutputDigest() install.Digest { return r.outputDigest }

// ValidFor rejects replay across operation, plan, attempt, ownership, or source.
func (r Receipt) ValidFor(authorization Authorization) bool {
	return authorization.Valid() && !r.configurationDigest.IsZero() &&
		r.authorizationDigest.Equal(authorization.bindingDigest) && !r.outputDigest.IsZero() &&
		r.outputDigest.Equal(digestReceipt(r))
}

// Ensurer is the application boundary used by the two PF-001 stack phases.
type Ensurer interface {
	RunMigrations(context.Context, Authorization) (Receipt, error)
	StartCoreAndGraph(context.Context, Authorization) (Receipt, error)
}

func validOperation(operation Operation) bool {
	return operation == OperationMigrate || operation == OperationStartCoreAndGraph
}

func validSource(source containerengine.ComposeReleaseSource) bool {
	identity := source.Identity()
	return source.Endpoint().String() != "" && identity.InstallationID() != "" &&
		identity.Generation() != "" && identity.ProjectName() != "" && source.Release() != "" &&
		source.ProjectDirectory() != "" && source.ConfigurationPath() != "" &&
		source.EmptyEnvironmentPath() != "" && !source.SourceDigest().IsZero() &&
		source.WaitTimeSeconds() > 0
}

type authorizationDocument struct {
	Operation        string `json:"operation"`
	OperationID      string `json:"operation_id"`
	ParentPlan       string `json:"parent_plan"`
	Attempt          uint32 `json:"attempt"`
	RuntimeOwnership string `json:"runtime_ownership"`
	Endpoint         string `json:"endpoint"`
	InstallationID   string `json:"installation_id"`
	GenerationID     string `json:"generation_id"`
	ProjectName      string `json:"project_name"`
	Release          string `json:"release"`
	ProjectDirectory string `json:"project_directory"`
	Configuration    string `json:"configuration"`
	EmptyEnvironment string `json:"empty_environment"`
	SourceDigest     string `json:"source_digest"`
	WaitSeconds      uint16 `json:"wait_seconds"`
}

func digestAuthorization(authorization Authorization) install.Digest {
	source := authorization.source
	identity := source.Identity()
	document := authorizationDocument{
		Operation: string(authorization.operation), OperationID: authorization.operationID.String(),
		ParentPlan: authorization.parentPlan.String(), Attempt: authorization.attempt,
		RuntimeOwnership: authorization.runtimeOwnership.String(), Endpoint: source.Endpoint().String(),
		InstallationID: identity.InstallationID(), GenerationID: identity.Generation(),
		ProjectName: identity.ProjectName(), Release: source.Release(),
		ProjectDirectory: source.ProjectDirectory(), Configuration: source.ConfigurationPath(),
		EmptyEnvironment: source.EmptyEnvironmentPath(), SourceDigest: source.SourceDigest().Hex(),
		WaitSeconds: source.WaitTimeSeconds(),
	}
	canonical, err := json.Marshal(document)
	if err != nil {
		return install.Digest{}
	}
	return install.DigestBytes(canonical)
}

func digestReceipt(receipt Receipt) install.Digest {
	canonical, err := json.Marshal(struct {
		Authorization string `json:"authorization"`
		Configuration string `json:"configuration"`
	}{
		Authorization: receipt.authorizationDigest.String(),
		Configuration: receipt.configurationDigest.String(),
	})
	if err != nil {
		return install.Digest{}
	}
	return install.DigestBytes(canonical)
}
