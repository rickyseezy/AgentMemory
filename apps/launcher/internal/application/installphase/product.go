package installphase

import (
	"context"
	"errors"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
)

// DirectoryPhase is the concrete EnsureDirectories phase adapter.
type DirectoryPhase struct {
	plans       DirectoryPlanQuery
	directories productinstall.DirectoryEnsurer
}

// NewDirectoryPhase requires canonical plan resolution and the native
// owner-protected filesystem use case.
func NewDirectoryPhase(
	plans DirectoryPlanQuery,
	directories productinstall.DirectoryEnsurer,
) (*DirectoryPhase, error) {
	if nilPort(plans) || nilPort(directories) {
		return nil, errors.New("directory phase capabilities are required")
	}
	return &DirectoryPhase{plans: plans, directories: directories}, nil
}

// EnsureDirectories creates or re-verifies only the six exact paths carried
// by the immutable plan and records no path-bearing evidence.
func (p *DirectoryPhase) EnsureDirectories(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	command, err := p.plans.ResolveDirectoryCommand(
		ctx, request.PlanDigest(), request.OperationID(), request.Attempt(),
	)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !validDirectoryCommand(command, request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	receipt, err := p.directories.EnsureDirectories(ctx, command)
	if err != nil {
		if errors.Is(err, productinstall.ErrIntegrity) {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return installapp.PhaseOutput{}, phaseError(ErrorCodeDirectoryUnavailable)
	}
	if !receipt.ValidFor(command) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedOutput(
		command.BindingDigest(),
		receipt.OutputDigest(),
		command.RuntimeOwnership(),
		"retain.owner_directories",
		"installation.continue",
		"directories_verified",
		strconv.Itoa(len(command.Directories())),
	)
}

// SecretPhase is the concrete EnsureKeys phase adapter.
type SecretPhase struct {
	plans   SecretPlanQuery
	secrets productinstall.SecretEnsurer
}

// NewSecretPhase requires canonical plan resolution and the native protected
// secret materialization use case.
func NewSecretPhase(
	plans SecretPlanQuery,
	secrets productinstall.SecretEnsurer,
) (*SecretPhase, error) {
	if nilPort(plans) || nilPort(secrets) {
		return nil, errors.New("secret phase capabilities are required")
	}
	return &SecretPhase{plans: plans, secrets: secrets}, nil
}

// EnsureKeys creates or re-verifies every purpose-separated 256-bit secret
// and persists only an HMAC-backed, non-secret receipt digest.
func (p *SecretPhase) EnsureKeys(
	ctx context.Context,
	request installapp.PhaseRequest,
) (installapp.PhaseOutput, error) {
	if !validRequest(request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	command, err := p.plans.ResolveSecretCommand(
		ctx, request.PlanDigest(), request.OperationID(), request.Attempt(),
	)
	if err != nil {
		return installapp.PhaseOutput{}, phaseError(ErrorCodePlanUnavailable)
	}
	if !validSecretCommand(command, request) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	receipt, err := p.secrets.EnsureSecrets(ctx, command)
	if err != nil {
		if errors.Is(err, productinstall.ErrIntegrity) {
			return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
		}
		return installapp.PhaseOutput{}, phaseError(ErrorCodeSecretUnavailable)
	}
	if !receipt.ValidFor(command) {
		return installapp.PhaseOutput{}, phaseError(ErrorCodeInvalidBinding)
	}
	return completedOutput(
		command.BindingDigest(),
		receipt.OutputDigest(),
		command.RuntimeOwnership(),
		"retain.protected_secrets",
		"installation.continue",
		"key_slots_verified",
		strconv.Itoa(len(command.Secrets())),
	)
}

func validDirectoryCommand(command productinstall.DirectoryCommand, request installapp.PhaseRequest) bool {
	return command.Valid() && command.OperationID() == request.OperationID() &&
		command.ParentPlanDigest().Equal(request.PlanDigest()) && command.Attempt() == request.Attempt() &&
		command.RuntimeOwnership().Resolved()
}

func validSecretCommand(command productinstall.SecretCommand, request installapp.PhaseRequest) bool {
	return command.Valid() && command.OperationID() == request.OperationID() &&
		command.ParentPlanDigest().Equal(request.PlanDigest()) && command.Attempt() == request.Attempt() &&
		command.RuntimeOwnership().Resolved()
}

var (
	_ installapp.DirectoryPort       = (*DirectoryPhase)(nil)
	_ installapp.KeyProvisioningPort = (*SecretPhase)(nil)
)
