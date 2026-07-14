package launcher

import (
	"bytes"
	"context"
	"errors"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

var (
	errNativeInstallerIntegrity   = errors.New("native installer authority integrity violation")
	errNativeInstallerUnavailable = errors.New("native installer authority unavailable")
)

// nativeInstallAuthority is the immutable command authority admitted to the
// operation-scoped production composition root. The caller-owned command is
// never passed to a phase constructor before these bindings are rechecked.
type nativeInstallAuthority struct {
	OperationID   install.OperationID
	PlanDigest    install.PlanDigest
	CanonicalPlan []byte
}

type nativeInstallApplication interface {
	Install(context.Context, installapp.InstallCommand) (installapp.InstallResult, error)
}

type nativeInstallApplicationFactory func(
	context.Context,
	nativeInstallAuthority,
) (nativeInstallApplication, error)

type nativeInstallAuthenticator func(installapp.InstallCommand) (nativeInstallAuthority, error)

// nativeCommandInstaller is the process-owned bridge between the reusable
// first-start supervisor and one operation-scoped fourteen-phase application.
type nativeCommandInstaller struct {
	applications nativeInstallApplicationFactory
	authenticate nativeInstallAuthenticator
}

func newNativeCommandInstaller(applications nativeInstallApplicationFactory) (*nativeCommandInstaller, error) {
	return newNativeCommandInstallerWithAuthenticator(applications, authenticateNativeInstallCommand)
}

func newNativeCommandInstallerWithAuthenticator(
	applications nativeInstallApplicationFactory,
	authenticate nativeInstallAuthenticator,
) (*nativeCommandInstaller, error) {
	if applications == nil || authenticate == nil {
		return nil, errNativeInstallerIntegrity
	}
	return &nativeCommandInstaller{applications: applications, authenticate: authenticate}, nil
}

func authenticateNativeInstallCommand(command installapp.InstallCommand) (nativeInstallAuthority, error) {
	operationID, err := install.NewOperationID(command.OperationID)
	if err != nil || len(command.CanonicalPlan) == 0 {
		return nativeInstallAuthority{}, errNativeInstallerIntegrity
	}
	plan, err := installplan.DecodeV1(command.CanonicalPlan)
	if err != nil || plan.OperationID() != operationID ||
		!bytes.Equal(plan.CanonicalBytes(), command.CanonicalPlan) {
		return nativeInstallAuthority{}, errNativeInstallerIntegrity
	}
	digest, err := install.BindPlan(command.CanonicalPlan)
	if err != nil || !digest.Equal(plan.Digest()) {
		return nativeInstallAuthority{}, errNativeInstallerIntegrity
	}
	return nativeInstallAuthority{
		OperationID: operationID, PlanDigest: digest,
		CanonicalPlan: append([]byte(nil), command.CanonicalPlan...),
	}, nil
}

func (i *nativeCommandInstaller) Install(
	ctx context.Context,
	command installapp.InstallCommand,
) (installapp.InstallResult, error) {
	if i == nil || ctx == nil || i.applications == nil || i.authenticate == nil {
		return installapp.InstallResult{}, errNativeInstallerIntegrity
	}
	if err := ctx.Err(); err != nil {
		return installapp.InstallResult{}, err
	}
	authority, err := i.authenticate(command)
	if err != nil || authority.OperationID.IsZero() || authority.PlanDigest.IsZero() ||
		len(authority.CanonicalPlan) == 0 {
		return installapp.InstallResult{}, errNativeInstallerIntegrity
	}
	application, err := i.applications(ctx, nativeInstallAuthority{
		OperationID: authority.OperationID, PlanDigest: authority.PlanDigest,
		CanonicalPlan: append([]byte(nil), authority.CanonicalPlan...),
	})
	if err != nil || nilAny(application) {
		return installapp.InstallResult{}, errNativeInstallerUnavailable
	}
	owned := installapp.InstallCommand{
		OperationID:   authority.OperationID.String(),
		CanonicalPlan: append([]byte(nil), authority.CanonicalPlan...),
	}
	if command.ResumeReceipt != nil {
		receipt := *command.ResumeReceipt
		owned.ResumeReceipt = &receipt
	}
	return application.Install(ctx, owned)
}

var _ interface {
	Install(context.Context, installapp.InstallCommand) (installapp.InstallResult, error)
} = (*nativeCommandInstaller)(nil)
