package installphase

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001ContainerRuntimePhaseBindsCompleteNestedAggregate(t *testing.T) {
	t.Parallel()

	for _, ownership := range []runtimeinstall.OwnershipDisposition{
		runtimeinstall.OwnershipReusedExternal,
		runtimeinstall.OwnershipProvisionedByAgentMemory,
	} {
		ownership := ownership
		t.Run(runtimeOwnershipName(ownership), func(t *testing.T) {
			t.Parallel()
			request, plan, query, ensurer := runtimePhaseFixture(t, ownership)
			phase, err := NewContainerRuntimePhase(query, ensurer)
			if err != nil {
				t.Fatal(err)
			}
			output, err := phase.EnsureContainerRuntime(context.Background(), request)
			if err != nil {
				t.Fatalf("EnsureContainerRuntime() error = %v", err)
			}
			receipt, ok := ensurer.result.CompletionReceipt()
			if !ok {
				t.Fatal("fixture has no completion receipt")
			}
			wantOutput, _ := install.ParseDigest(receipt.EvidenceDigest().String())
			wantArtifact, _ := install.ParseDigest(receipt.ArtifactDigest().String())
			wantOwnership, _ := installOwnership(ownership)
			if output.Outcome() != installapp.PhaseOutcomeCompleted ||
				!output.InputDigest().Equal(plan.ParentBindingDigest()) ||
				!output.OutputDigest().Equal(wantOutput) ||
				!output.VerifiedArtifactDigest().Equal(wantArtifact) ||
				output.RuntimeOwnership() != wantOwnership ||
				output.NextSafeAction() != "installation.continue" {
				t.Fatalf("EnsureContainerRuntime() output = %#v", output)
			}
			if ensurer.calls != 1 || ensurer.last.OperationID != request.OperationID().String() ||
				!bytes.Equal(ensurer.last.CanonicalPlan, plan.CanonicalPlan()) || ensurer.last.ResumeReceipt != nil {
				t.Fatalf("runtime command = %#v", ensurer.last)
			}
			if query.operation != request.OperationID() {
				t.Fatal("runtime plan query was not bound to the phase operation")
			}
		})
	}
}

func TestPF001ContainerRuntimePhaseTranslatesEveryDurableOutcome(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		state  runtimeinstall.OperationState
		want   installapp.PhaseOutcome
		action string
	}{
		{name: "recoverable", state: runtimeinstall.OperationStateFailedRecoverable, want: installapp.PhaseOutcomeFailedRecoverable, action: "installation.runtime_retry"},
		{name: "administrator", state: runtimeinstall.OperationStatePausedForAdministrator, want: installapp.PhaseOutcomeAdministratorRequired, action: "installation.runtime_administrator_required"},
		{name: "cancelled", state: runtimeinstall.OperationStateCancelled, want: installapp.PhaseOutcomeCancelled, action: "installation.runtime_cancelled"},
		{name: "unsupported", state: runtimeinstall.OperationStateUnsupportedHost, want: installapp.PhaseOutcomeUnsupportedHost, action: "installation.runtime_unsupported_host"},
		{name: "conflict", state: runtimeinstall.OperationStateRuntimeConflict, want: installapp.PhaseOutcomeRuntimeConflict, action: "installation.runtime_conflict"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimePausedResult(t, request.OperationID().String(), plan.PlanDigest(), test.state)
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			output, err := phase.EnsureContainerRuntime(context.Background(), request)
			if err != nil || output.Outcome() != test.want || output.NextSafeAction() != test.action {
				t.Fatalf("EnsureContainerRuntime() = %#v, %v", output, err)
			}
		})
	}
}

func TestPF001ContainerRuntimePhaseRoundTripsVerifiedRebootReceipt(t *testing.T) {
	t.Parallel()

	request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
	runtimeReceipt := runtimeinstall.Sum([]byte("one-use-runtime-reboot"))
	ensurer.result = runtimeRebootResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeReceipt)
	parentReceipt, err := install.ParseDigest(runtimeReceipt.String())
	if err != nil {
		t.Fatal(err)
	}
	request, err = installapp.NewPhaseRequestForIntegration(
		request.OperationID(), request.PlanDigest(), 2, request.CanonicalPlan(), parentReceipt,
	)
	if err != nil {
		t.Fatal(err)
	}
	phase, _ := NewContainerRuntimePhase(query, ensurer)
	output, err := phase.EnsureContainerRuntime(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeRebootRequired ||
		output.NextSafeAction() != "installation.resume_after_restart" {
		t.Fatalf("EnsureContainerRuntime() = %#v, %v", output, err)
	}
	actualReceipt, ok := output.ResumeReceipt()
	if !ok || !actualReceipt.Equal(parentReceipt) || ensurer.last.ResumeReceipt == nil ||
		*ensurer.last.ResumeReceipt != runtimeReceipt {
		t.Fatal("verified reboot receipt was not round-tripped exactly")
	}
}

func TestPF001ContainerRuntimePhaseTranslatesTypedRuntimeApplicationRetry(t *testing.T) {
	t.Parallel()

	request, _, query, _ := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
	capabilities := failingRuntimeCapabilities{}
	application, err := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
		Operations: runtimeOperationRepositoryStub{}, Host: capabilities, Detector: capabilities,
		Catalog: capabilities, Consent: capabilities, Fetcher: capabilities, Verifier: capabilities,
		Prerequisites: capabilities, Installer: capabilities, Terms: capabilities,
		Controller: capabilities, Capabilities: capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	phase, err := NewContainerRuntimePhase(query, application)
	if err != nil {
		t.Fatal(err)
	}
	output, err := phase.EnsureContainerRuntime(context.Background(), request)
	if err != nil || output.Outcome() != installapp.PhaseOutcomeFailedRecoverable ||
		output.NextSafeAction() != "installation.runtime_retry" {
		t.Fatalf("EnsureContainerRuntime() = %#v, %v", output, err)
	}
}

func TestPF001ContainerRuntimePhaseFailsClosedOnInvalidAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want ErrorCode
		run  func(*testing.T) error
	}{
		{name: "invalid request", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			_, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), installapp.PhaseRequest{})
			return err
		}},
		{name: "plan unavailable", want: ErrorCodePlanUnavailable, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			query.err = errors.New("private signed catalog path")
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "foreign parent plan", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			foreign, _ := install.BindPlan([]byte("foreign parent"))
			query.plan, _ = NewRuntimePlan(foreign, runtimePhaseCanonicalPlan(t), install.DigestBytes([]byte("signed evidence")))
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "generic runtime failure", want: ErrorCodeRuntimeUnavailable, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimeinstallapp.Result{OperationID: request.OperationID().String()}
			ensurer.err = errors.New("private platform path")
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "generic failure with foreign operation", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimeinstallapp.Result{OperationID: "foreign-operation"}
			ensurer.err = errors.New("private platform path")
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "foreign nested result", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimeReadyResult(t, request.OperationID().String(), runtimeinstall.Sum([]byte("foreign nested")), runtimeinstall.OwnershipReusedExternal)
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "foreign operation result", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimeReadyResult(t, "foreign-operation", plan.PlanDigest(), runtimeinstall.OwnershipReusedExternal)
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "zero result attempt", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result.Attempt = 0
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "contradictory completed state", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result.State = runtimeinstall.OperationStateRunning
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "contradictory completed code", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result.ErrorCode = runtimeinstallapp.ErrorCodeInternal
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "contradictory recoverable state", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimePausedResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.OperationStateFailedRecoverable)
			ensurer.result.State = runtimeinstall.OperationStateRunning
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "generic recoverable error", want: ErrorCodeRuntimeUnavailable, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimePausedResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.OperationStateFailedRecoverable)
			ensurer.err = errors.New("raw runtime failure")
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "contradictory recoverable code", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimePausedResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.OperationStateFailedRecoverable)
			ensurer.result.ErrorCode = runtimeinstallapp.ErrorCodeCancelled
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "contradictory reboot code", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimeRebootResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.Sum([]byte("receipt")))
			ensurer.result.ErrorCode = runtimeinstallapp.ErrorCodeInternal
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "contradictory reboot phase", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimeRebootResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.Sum([]byte("receipt")))
			ensurer.result.CurrentPhase = runtimeinstall.PhaseDetectHost
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "error on terminal outcome", want: ErrorCodeInvalidBinding, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			ensurer.result = runtimePausedResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.OperationStateCancelled)
			ensurer.err = errors.New("contradictory error")
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
		{name: "running is not an outcome", want: ErrorCodeRuntimeUnavailable, run: func(t *testing.T) error {
			request, plan, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
			operation, _ := runtimeinstall.NewOperation(request.OperationID().String(), plan.PlanDigest())
			ensurer.result, _ = runtimeinstallapp.NewResultFromSnapshot(operation.Snapshot())
			phase, _ := NewContainerRuntimePhase(query, ensurer)
			_, err := phase.EnsureContainerRuntime(context.Background(), request)
			return err
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := test.run(t)
			var typed *Error
			if !errors.As(err, &typed) || typed.Code() != test.want || typed.Error() != string(test.want) {
				t.Fatalf("error = %#v, want %s", err, test.want)
			}
		})
	}
}

func TestPF001RuntimePlanAndPhaseConstructorsRejectIncompleteCapabilities(t *testing.T) {
	t.Parallel()

	parent, _ := install.BindPlan([]byte("parent"))
	evidence := install.DigestBytes([]byte("signed evidence"))
	source := runtimePhaseCanonicalPlan(t)
	plan, err := NewRuntimePlan(parent, source, evidence)
	if err != nil {
		t.Fatal(err)
	}
	source[0] = 'X'
	returned := plan.CanonicalPlan()
	returned[0] = 'Y'
	if !plan.validFor(parent) || bytes.Equal(source, plan.CanonicalPlan()) || bytes.Equal(returned, plan.CanonicalPlan()) {
		t.Fatal("runtime plan did not defensively snapshot canonical bytes")
	}
	if !plan.ParentPlanDigest().Equal(parent) || !plan.SignedCatalogEvidenceDigest().Equal(evidence) {
		t.Fatal("runtime plan lost an authenticated parent or signed-catalog binding")
	}
	if _, err := NewRuntimePlan(install.PlanDigest{}, runtimePhaseCanonicalPlan(t), evidence); err == nil {
		t.Fatal("NewRuntimePlan() accepted a zero parent")
	}
	if _, err := NewRuntimePlan(parent, nil, evidence); err == nil {
		t.Fatal("NewRuntimePlan() accepted an empty plan")
	}
	if _, err := NewRuntimePlan(parent, runtimePhaseCanonicalPlan(t), install.Digest{}); err == nil {
		t.Fatal("NewRuntimePlan() accepted missing signed evidence")
	}
	_, _, query, ensurer := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
	if _, err := NewContainerRuntimePhase(nil, ensurer); err == nil {
		t.Fatal("NewContainerRuntimePhase() accepted a nil plan query")
	}
	if _, err := NewContainerRuntimePhase(query, nil); err == nil {
		t.Fatal("NewContainerRuntimePhase() accepted a nil runtime use case")
	}
	var typedNil *runtimeEnsurerStub
	if _, err := NewContainerRuntimePhase(query, typedNil); err == nil {
		t.Fatal("NewContainerRuntimePhase() accepted a typed-nil runtime use case")
	}
	if _, ok := installOwnership(runtimeinstall.OwnershipUnknown); ok {
		t.Fatal("unknown runtime ownership was mapped")
	}
	if _, ok := installOwnership(runtimeinstall.OwnershipDisposition(255)); ok {
		t.Fatal("out-of-vocabulary runtime ownership was mapped")
	}
	converted, err := runtimeHashFromInstallDigest(evidence)
	if err != nil || converted.String() != evidence.String() {
		t.Fatalf("runtimeHashFromInstallDigest() = %s, %v", converted, err)
	}
	if _, err := runtimeHashFromInstallDigest(install.Digest{}); err == nil {
		t.Fatal("runtimeHashFromInstallDigest() accepted zero")
	}
	request, plan, _, _ := runtimePhaseFixture(t, runtimeinstall.OwnershipReusedExternal)
	phase := &ContainerRuntimePhase{}
	paused := runtimePausedResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.OperationStateCancelled)
	if _, err := phase.completedOutput(request, plan, paused); err == nil {
		t.Fatal("completedOutput() accepted a paused aggregate")
	}
	ready := runtimeReadyResult(t, request.OperationID().String(), plan.PlanDigest(), runtimeinstall.OwnershipReusedExternal)
	ready.Version++
	if _, err := phase.completedOutput(request, plan, ready); err == nil {
		t.Fatal("completedOutput() accepted a mismatched aggregate version")
	}
}

func runtimePhaseCanonicalPlan(t testing.TB) []byte {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "6.8.0", true, true, true, true,
		8, 32*1024*1024*1024, 24*1024*1024*1024, 100*1024*1024*1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "docker-engine", "28.0.0", "stable", 42,
		runtimeinstall.Sum([]byte("catalog")), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerEngineTermsID, Version: "apache-2.0", URL: "https://docs.docker.com/engine/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemory,
		}, 1024, 4096,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil {
		t.Fatal(err)
	}
	return plan.CanonicalBytes()
}

func runtimePhaseFixture(
	t *testing.T,
	ownership runtimeinstall.OwnershipDisposition,
) (installapp.PhaseRequest, RuntimePlan, *runtimePlanQueryStub, *runtimeEnsurerStub) {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	if err != nil {
		t.Fatal(err)
	}
	parentBytes := []byte("canonical parent installation plan")
	parent, _ := install.BindPlan(parentBytes)
	request, err := installapp.NewPhaseRequestForIntegration(operationID, parent, 1, parentBytes)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewRuntimePlan(parent, runtimePhaseCanonicalPlan(t), install.DigestBytes([]byte("verified signed runtime catalog")))
	if err != nil {
		t.Fatal(err)
	}
	result := runtimeReadyResult(t, operationID.String(), plan.PlanDigest(), ownership)
	return request, plan, &runtimePlanQueryStub{plan: plan}, &runtimeEnsurerStub{result: result}
}

type runtimePlanQueryStub struct {
	plan      RuntimePlan
	err       error
	operation install.OperationID
}

func (s *runtimePlanQueryStub) ResolveRuntimePlan(_ context.Context, _ install.PlanDigest, operation install.OperationID) (RuntimePlan, error) {
	s.operation = operation
	return s.plan, s.err
}

type runtimeEnsurerStub struct {
	result runtimeinstallapp.Result
	err    error
	last   runtimeinstallapp.Command
	calls  int
}

type runtimeOperationRepositoryStub struct{}

func (runtimeOperationRepositoryStub) Load(context.Context, string) (*runtimeinstall.Operation, error) {
	return nil, runtimeinstallapp.ErrOperationNotFound
}

func (runtimeOperationRepositoryStub) Save(context.Context, runtimeinstall.OperationSnapshot) error {
	return nil
}

type failingRuntimeCapabilities struct{}

func (failingRuntimeCapabilities) fail() (runtimeinstallapp.Output, error) {
	return runtimeinstallapp.Output{}, context.DeadlineExceeded
}

func (c failingRuntimeCapabilities) DetectHost(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) DetectRuntime(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) PlanRuntime(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) AwaitRuntimeConsent(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) AcquireRuntime(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) VerifyRuntimeArtifact(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) InstallPrerequisites(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) InstallRuntime(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) AwaitThirdPartyTerms(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) StartRuntime(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (c failingRuntimeCapabilities) VerifyRuntimeCapabilities(context.Context, runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.fail()
}

func (s *runtimeEnsurerStub) Ensure(
	_ context.Context,
	command runtimeinstallapp.Command,
) (runtimeinstallapp.Result, error) {
	s.calls++
	s.last = command
	s.last.CanonicalPlan = append([]byte(nil), command.CanonicalPlan...)
	if command.ResumeReceipt != nil {
		receipt := *command.ResumeReceipt
		s.last.ResumeReceipt = &receipt
	}
	return s.result, s.err
}

func runtimeReadyResult(
	t *testing.T,
	operationID string,
	plan runtimeinstall.Hash,
	ownership runtimeinstall.OwnershipDisposition,
) runtimeinstallapp.Result {
	t.Helper()
	operation, err := runtimeinstall.NewOperation(operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	advanceRuntimeOperation(t, operation, runtimeinstall.PhaseUnknown, ownership)
	result, err := runtimeinstallapp.NewResultFromSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func runtimePausedResult(
	t *testing.T,
	operationID string,
	plan runtimeinstall.Hash,
	state runtimeinstall.OperationState,
) runtimeinstallapp.Result {
	t.Helper()
	operation, err := runtimeinstall.NewOperation(operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := operation.Pause(state); err != nil {
		t.Fatal(err)
	}
	result, err := runtimeinstallapp.NewResultFromSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func runtimeRebootResult(
	t *testing.T,
	operationID string,
	plan runtimeinstall.Hash,
	receipt runtimeinstall.Hash,
) runtimeinstallapp.Result {
	t.Helper()
	operation, err := runtimeinstall.NewOperation(operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	advanceRuntimeOperation(t, operation, runtimeinstall.PhaseInstallPrerequisites, runtimeinstall.OwnershipUnknown)
	if err := operation.RequireReboot(receipt); err != nil {
		t.Fatal(err)
	}
	result, err := runtimeinstallapp.NewResultFromSnapshot(operation.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func advanceRuntimeOperation(
	t *testing.T,
	operation *runtimeinstall.Operation,
	stopBefore runtimeinstall.Phase,
	ownership runtimeinstall.OwnershipDisposition,
) {
	t.Helper()
	artifact := runtimeinstall.Sum([]byte("verified runtime artifact"))
	for _, phase := range runtimeinstall.OrderedPhases() {
		if phase == stopBefore {
			return
		}
		phaseArtifact := runtimeinstall.Hash{}
		if phase >= runtimeinstall.PhaseVerifyRuntimeArtifact {
			phaseArtifact = artifact
		}
		phaseOwnership := runtimeinstall.OwnershipUnknown
		if phase == runtimeinstall.PhaseVerifyRuntimeCapabilities {
			phaseOwnership = ownership
		}
		evidence, err := runtimeinstall.NewTransitionEvidence(
			phase,
			operation.Attempt(),
			operation.PlanDigest(),
			runtimeinstall.Sum([]byte("input:"+phase.String())),
			runtimeinstall.Sum([]byte("output:"+phase.String())),
			phaseArtifact,
			phaseOwnership,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := operation.Complete(phase, evidence); err != nil {
			t.Fatal(err)
		}
	}
}

func runtimeOwnershipName(value runtimeinstall.OwnershipDisposition) string {
	if value == runtimeinstall.OwnershipReusedExternal {
		return "reused_external"
	}
	return "provisioned_by_agentmemory"
}
