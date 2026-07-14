package installphase

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/productinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/installplan"
)

func TestDirectoryPhaseRecordsOnlyACompletePlanBoundReceipt(t *testing.T) {
	t.Parallel()
	request := productPhaseRequest(t, 2)
	command := productDirectoryCommand(t, request)
	phase, err := NewDirectoryPhase(
		directoryPlanQueryStub{resolve: func(
			context.Context, install.PlanDigest, install.OperationID, uint32,
		) (productinstall.DirectoryCommand, error) {
			return command, nil
		}},
		directoryEnsurerStub{ensure: func(
			_ context.Context, received productinstall.DirectoryCommand,
		) (productinstall.DirectoryReceipt, error) {
			return productinstall.NewDirectoryReceiptForAdapter(
				received, install.DigestBytes([]byte("verified-native-directory-identities")), 3, 3,
			)
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.EnsureDirectories(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if output.Outcome() != installapp.PhaseOutcomeCompleted || output.OutputDigest().IsZero() ||
		!output.InputDigest().Equal(command.BindingDigest()) ||
		output.RuntimeOwnership() != install.RuntimeOwnershipProvisionedByAgentMemory {
		t.Fatal("directory phase did not return complete privacy-safe evidence")
	}
}

func TestDirectoryPhaseRejectsCrossAttemptAuthorityAndReceipt(t *testing.T) {
	t.Parallel()
	request := productPhaseRequest(t, 2)
	wrongRequest := productPhaseRequest(t, 1)
	wrongCommand := productDirectoryCommand(t, wrongRequest)
	phase, err := NewDirectoryPhase(
		directoryPlanQueryStub{resolve: func(
			context.Context, install.PlanDigest, install.OperationID, uint32,
		) (productinstall.DirectoryCommand, error) {
			return wrongCommand, nil
		}},
		directoryEnsurerStub{ensure: func(
			_ context.Context, command productinstall.DirectoryCommand,
		) (productinstall.DirectoryReceipt, error) {
			return productinstall.NewDirectoryReceiptForAdapter(
				command, install.DigestBytes([]byte("state")), 6, 0,
			)
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = phase.EnsureDirectories(context.Background(), request)
	assertProductPhaseCode(t, err, ErrorCodeInvalidBinding)
}

func TestSecretPhaseRecordsOnlyACompleteHMACBackedReceipt(t *testing.T) {
	t.Parallel()
	request := productPhaseRequest(t, 1)
	command := productSecretCommand(t, request)
	phase, err := NewSecretPhase(
		secretPlanQueryStub{resolve: func(
			context.Context, install.PlanDigest, install.OperationID, uint32,
		) (productinstall.SecretCommand, error) {
			return command, nil
		}},
		secretEnsurerStub{ensure: func(
			_ context.Context, received productinstall.SecretCommand,
		) (productinstall.SecretReceipt, error) {
			return productinstall.NewSecretReceiptForAdapter(
				received, install.DigestBytes([]byte("hmac-over-all-purpose-separated-values")), 7, 0,
			)
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.EnsureKeys(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if output.Outcome() != installapp.PhaseOutcomeCompleted || output.OutputDigest().IsZero() ||
		!output.InputDigest().Equal(command.BindingDigest()) ||
		output.RuntimeOwnership() != install.RuntimeOwnershipProvisionedByAgentMemory {
		t.Fatal("secret phase did not return complete privacy-safe evidence")
	}
}

func TestProductPhasesMapPlatformFailuresWithoutLeakingDiagnostics(t *testing.T) {
	t.Parallel()
	request := productPhaseRequest(t, 1)
	directoryCommand := productDirectoryCommand(t, request)
	directoryPhase, err := NewDirectoryPhase(
		directoryPlanQueryStub{resolve: func(
			context.Context, install.PlanDigest, install.OperationID, uint32,
		) (productinstall.DirectoryCommand, error) {
			return directoryCommand, nil
		}},
		directoryEnsurerStub{ensure: func(
			context.Context, productinstall.DirectoryCommand,
		) (productinstall.DirectoryReceipt, error) {
			return productinstall.DirectoryReceipt{}, errors.New("private user path and native error")
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = directoryPhase.EnsureDirectories(context.Background(), request)
	assertProductPhaseCode(t, err, ErrorCodeDirectoryUnavailable)
	if err.Error() != string(ErrorCodeDirectoryUnavailable) {
		t.Fatal("directory phase leaked an adapter diagnostic")
	}

	secretCommand := productSecretCommand(t, request)
	secretPhase, err := NewSecretPhase(
		secretPlanQueryStub{resolve: func(
			context.Context, install.PlanDigest, install.OperationID, uint32,
		) (productinstall.SecretCommand, error) {
			return secretCommand, nil
		}},
		secretEnsurerStub{ensure: func(
			context.Context, productinstall.SecretCommand,
		) (productinstall.SecretReceipt, error) {
			return productinstall.SecretReceipt{}, productinstall.ErrIntegrity
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = secretPhase.EnsureKeys(context.Background(), request)
	assertProductPhaseCode(t, err, ErrorCodeInvalidBinding)
}

type directoryPlanQueryStub struct {
	resolve func(context.Context, install.PlanDigest, install.OperationID, uint32) (productinstall.DirectoryCommand, error)
}

func (s directoryPlanQueryStub) ResolveDirectoryCommand(
	ctx context.Context,
	plan install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
) (productinstall.DirectoryCommand, error) {
	return s.resolve(ctx, plan, operationID, attempt)
}

type secretPlanQueryStub struct {
	resolve func(context.Context, install.PlanDigest, install.OperationID, uint32) (productinstall.SecretCommand, error)
}

func (s secretPlanQueryStub) ResolveSecretCommand(
	ctx context.Context,
	plan install.PlanDigest,
	operationID install.OperationID,
	attempt uint32,
) (productinstall.SecretCommand, error) {
	return s.resolve(ctx, plan, operationID, attempt)
}

type directoryEnsurerStub struct {
	ensure func(context.Context, productinstall.DirectoryCommand) (productinstall.DirectoryReceipt, error)
}

func (s directoryEnsurerStub) EnsureDirectories(
	ctx context.Context,
	command productinstall.DirectoryCommand,
) (productinstall.DirectoryReceipt, error) {
	return s.ensure(ctx, command)
}

type secretEnsurerStub struct {
	ensure func(context.Context, productinstall.SecretCommand) (productinstall.SecretReceipt, error)
}

func (s secretEnsurerStub) EnsureSecrets(
	ctx context.Context,
	command productinstall.SecretCommand,
) (productinstall.SecretReceipt, error) {
	return s.ensure(ctx, command)
}

func productPhaseRequest(t testing.TB, attempt uint32) installapp.PhaseRequest {
	t.Helper()
	operationID, err := install.NewOperationID("pf001-product-phase")
	if err != nil {
		t.Fatal(err)
	}
	canonical := []byte("canonical-product-phase-plan")
	planDigest, err := install.BindPlan(canonical)
	if err != nil {
		t.Fatal(err)
	}
	request, err := installapp.NewPhaseRequestForIntegration(operationID, planDigest, attempt, canonical)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func productDirectoryCommand(t testing.TB, request installapp.PhaseRequest) productinstall.DirectoryCommand {
	t.Helper()
	inputs := []struct {
		purpose productinstall.DirectoryPurpose
		path    string
	}{
		{productinstall.DirectoryRelease, "/owner/.agentmemory/releases/v1"},
		{productinstall.DirectoryConfiguration, "/owner/.agentmemory/config"},
		{productinstall.DirectoryRuntime, "/owner/.agentmemory/runtime"},
		{productinstall.DirectorySecrets, "/owner/.agentmemory/secrets"},
		{productinstall.DirectoryBackups, "/owner/.agentmemory/backups"},
		{productinstall.DirectoryComposeProject, "/owner/.agentmemory/releases/v1/compose"},
	}
	specs := make([]productinstall.DirectorySpec, 0, len(inputs))
	for _, input := range inputs {
		spec, err := productinstall.NewDirectorySpec(input.purpose, input.path)
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, spec)
	}
	command, err := productinstall.NewDirectoryCommand(
		request.OperationID(), request.PlanDigest(), request.Attempt(),
		install.RuntimeOwnershipProvisionedByAgentMemory, specs,
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func productSecretCommand(t testing.TB, request installapp.PhaseRequest) productinstall.SecretCommand {
	t.Helper()
	purposes := []installplan.SecretPurpose{
		installplan.SecretInstallationRootKey,
		installplan.SecretAPICredential,
		installplan.SecretAttestationHMACKey,
		installplan.SecretNeo4jPassword,
		installplan.SecretEmbeddingCapability,
		installplan.SecretRerankerCapability,
		installplan.SecretExtractorCapability,
	}
	specs := make([]productinstall.SecretSpec, 0, len(purposes))
	for _, purpose := range purposes {
		spec, err := productinstall.NewSecretSpec(purpose, "/owner/.agentmemory/secrets/"+string(purpose))
		if err != nil {
			t.Fatal(err)
		}
		specs = append(specs, spec)
	}
	command, err := productinstall.NewSecretCommand(
		request.OperationID(), request.PlanDigest(), request.Attempt(),
		install.RuntimeOwnershipProvisionedByAgentMemory, "/owner/.agentmemory/secrets", specs,
	)
	if err != nil {
		t.Fatal(err)
	}
	return command
}

func assertProductPhaseCode(t testing.TB, err error, want ErrorCode) {
	t.Helper()
	var phaseFailure *Error
	if !errors.As(err, &phaseFailure) || phaseFailure.Code() != want {
		t.Fatalf("phase error = %v, want %s", err, want)
	}
}
