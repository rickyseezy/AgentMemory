package launcher

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeconsent"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeremovalapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeremoval"
)

func TestPF001NativeManagedRuntimeRemovalControllerBindsPrepareDecisionAndEffect(t *testing.T) {
	t.Parallel()
	digest := runtimeinstall.Sum([]byte("removal-plan"))
	useCase := &nativeRuntimeRemovalUseCaseStub{prepared: nativePreparedRuntimeRemoval{
		public: managedRuntimeRemovalPlan{
			OperationID: "removal", PlanDigest: digest.String(), Impact: "impact",
			Platform: "linux", Product: "docker-ce", Version: "29.6.1",
		},
		valid: true,
	}, result: runtimeremovalapp.Result{
		OperationID: "removal", PlanDigest: digest, Outcome: runtimeremovalapp.OutcomeRemoved,
	}}
	broker := &nativeRuntimeRemovalDecisionBrokerStub{}
	controller, err := newNativeManagedRuntimeRemovalController(
		runtimeremovalapp.Command{
			OperationID: "removal", SourceOperationID: "source", CanonicalRuntimePlan: []byte("runtime-plan"),
		},
		useCase,
		broker,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controller.PrepareManagedRuntimeRemoval(t.Context())
	if err != nil || plan != useCase.prepared.public || useCase.prepareCalls != 1 || broker.calls != 0 {
		t.Fatalf("Prepare()=%+v,%v useCase=%+v broker=%+v", plan, err, useCase, broker)
	}
	result, err := controller.DecideManagedRuntimeRemoval(t.Context(), managedRuntimeRemovalDecision{
		OperationID: plan.OperationID, PlanDigest: plan.PlanDigest, Impact: plan.Impact,
		Approved: true, ExplicitConfirmation: true,
	})
	if err != nil || result.Outcome != "removed" || broker.calls != 1 || broker.discards != 1 || useCase.removeCalls != 1 ||
		broker.input.OperationID != plan.OperationID || broker.input.PlanDigest != digest ||
		!broker.input.Approved || !broker.input.ExplicitConfirmation {
		t.Fatalf("Decide()=%+v,%v useCase=%+v broker=%+v", result, err, useCase, broker)
	}
}

func TestPF001NativeManagedRuntimeRemovalControllerRefusesImplicitSubstitutedAndPrivateFailures(t *testing.T) {
	t.Parallel()
	digest := runtimeinstall.Sum([]byte("removal-plan"))
	useCase := &nativeRuntimeRemovalUseCaseStub{prepared: nativePreparedRuntimeRemoval{
		public: managedRuntimeRemovalPlan{
			OperationID: "removal", PlanDigest: digest.String(), Impact: "impact",
			Platform: "linux", Product: "docker-ce", Version: "29.6.1",
		},
		valid: true,
	}}
	broker := &nativeRuntimeRemovalDecisionBrokerStub{}
	controller, _ := newNativeManagedRuntimeRemovalController(
		runtimeremovalapp.Command{OperationID: "removal", SourceOperationID: "source", CanonicalRuntimePlan: []byte("plan")},
		useCase, broker,
	)
	for name, input := range map[string]managedRuntimeRemovalDecision{
		"implicit approval": {OperationID: "removal", PlanDigest: digest.String(), Impact: "impact", Approved: true},
		"operation":         {OperationID: "other", PlanDigest: digest.String(), Impact: "impact"},
		"digest":            {OperationID: "removal", PlanDigest: runtimeinstall.Sum([]byte("other")).String(), Impact: "impact"},
		"impact":            {OperationID: "removal", PlanDigest: digest.String(), Impact: "other"},
	} {
		if result, err := controller.DecideManagedRuntimeRemoval(t.Context(), input); result != (managedRuntimeRemovalResult{}) || err == nil {
			t.Fatalf("%s result=%+v error=%v", name, result, err)
		}
	}
	if broker.calls != 0 || useCase.removeCalls != 0 {
		t.Fatalf("unsafe effects broker=%d remove=%d", broker.calls, useCase.removeCalls)
	}
	broker.err = errors.New("private")
	if _, err := controller.DecideManagedRuntimeRemoval(t.Context(), managedRuntimeRemovalDecision{
		OperationID: "removal", PlanDigest: digest.String(), Impact: "impact",
	}); err == nil || useCase.removeCalls != 0 {
		t.Fatalf("broker failure error=%v removes=%d", err, useCase.removeCalls)
	}
	broker.err = nil
	useCase.result = runtimeremovalapp.Result{
		OperationID: "removal", PlanDigest: digest, Outcome: runtimeremovalapp.OutcomeDeclined,
	}
	if result, err := controller.DecideManagedRuntimeRemoval(t.Context(), managedRuntimeRemovalDecision{
		OperationID: "removal", PlanDigest: digest.String(), Impact: "impact",
	}); err != nil || result.Outcome != "declined" {
		t.Fatalf("decline result=%+v error=%v", result, err)
	}
	useCase.result.Outcome = runtimeremovalapp.OutcomeUnknown
	if result, err := controller.DecideManagedRuntimeRemoval(t.Context(), managedRuntimeRemovalDecision{
		OperationID: "removal", PlanDigest: digest.String(), Impact: "impact",
	}); result != (managedRuntimeRemovalResult{}) || err == nil {
		t.Fatalf("unknown result=%+v error=%v", result, err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := controller.PrepareManagedRuntimeRemoval(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled prepare error=%v", err)
	}
	var absent *nativeManagedRuntimeRemovalController
	if _, err := absent.PrepareManagedRuntimeRemoval(t.Context()); err == nil {
		t.Fatal("nil controller prepared")
	}
	if _, err := absent.DecideManagedRuntimeRemoval(t.Context(), managedRuntimeRemovalDecision{}); err == nil {
		t.Fatal("nil controller decided")
	}
	for name, command := range map[string]runtimeremovalapp.Command{
		"empty":          {},
		"same operation": {OperationID: "same", SourceOperationID: "same", CanonicalRuntimePlan: []byte("plan")},
	} {
		if controller, err := newNativeManagedRuntimeRemovalController(command, useCase, broker); controller != nil || err == nil {
			t.Fatalf("%s controller=%+v error=%v", name, controller, err)
		}
	}
	if controller, err := newNativeManagedRuntimeRemovalController(
		runtimeremovalapp.Command{OperationID: "removal", SourceOperationID: "source", CanonicalRuntimePlan: []byte("plan")},
		(*nativeRuntimeRemovalUseCaseStub)(nil), broker,
	); controller != nil || err == nil {
		t.Fatalf("typed nil controller=%+v error=%v", controller, err)
	}
}

func TestPF001NativeRuntimeRemovalApplicationAdapterContainsInvalidAndMissingAuthority(t *testing.T) {
	t.Parallel()
	want := runtimeremovalapp.Result{
		OperationID: "removal", PlanDigest: runtimeinstall.Sum([]byte("plan")),
		Outcome: runtimeremovalapp.OutcomeRemoved,
	}
	port := &nativeRuntimeRemovalApplicationPortStub{result: want}
	adapter := nativeRuntimeRemovalApplication{application: port}
	if prepared, err := adapter.Prepare(t.Context(), runtimeremovalapp.Command{}); prepared.valid || err == nil ||
		port.prepareCalls != 1 {
		t.Fatalf("invalid prepare=%+v,%v calls=%d", prepared, err, port.prepareCalls)
	}
	if result, err := adapter.Remove(t.Context(), runtimeremovalapp.Command{}); err != nil || result != want ||
		port.removeCalls != 1 {
		t.Fatalf("remove=%+v,%v calls=%d", result, err, port.removeCalls)
	}
	var missing *nativeRuntimeRemovalApplicationPortStub
	adapter.application = missing
	if _, err := adapter.Prepare(t.Context(), runtimeremovalapp.Command{}); err == nil {
		t.Fatal("typed nil application prepared")
	}
	if _, err := adapter.Remove(t.Context(), runtimeremovalapp.Command{}); err == nil {
		t.Fatal("typed nil application removed")
	}
}

type nativeRuntimeRemovalUseCaseStub struct {
	prepared     nativePreparedRuntimeRemoval
	result       runtimeremovalapp.Result
	err          error
	prepareCalls int
	removeCalls  int
}

type nativeRuntimeRemovalApplicationPortStub struct {
	result       runtimeremovalapp.Result
	prepareCalls int
	removeCalls  int
}

func (s *nativeRuntimeRemovalApplicationPortStub) Prepare(
	context.Context,
	runtimeremovalapp.Command,
) (runtimeremovalapp.PreparedRemoval, error) {
	s.prepareCalls++
	return runtimeremovalapp.PreparedRemoval{}, nil
}

func (s *nativeRuntimeRemovalApplicationPortStub) Remove(
	context.Context,
	runtimeremovalapp.Command,
) (runtimeremovalapp.Result, error) {
	s.removeCalls++
	return s.result, nil
}

func (s *nativeRuntimeRemovalUseCaseStub) Prepare(
	context.Context,
	runtimeremovalapp.Command,
) (nativePreparedRuntimeRemoval, error) {
	s.prepareCalls++
	return s.prepared, s.err
}

func (s *nativeRuntimeRemovalUseCaseStub) Remove(
	context.Context,
	runtimeremovalapp.Command,
) (runtimeremovalapp.Result, error) {
	s.removeCalls++
	return s.result, s.err
}

type nativeRuntimeRemovalDecisionBrokerStub struct {
	input    runtimeconsent.ManagedRuntimeRemovalDecisionInput
	plan     runtimeremoval.Plan
	err      error
	calls    int
	discards int
}

func (s *nativeRuntimeRemovalDecisionBrokerStub) DiscardManagedRuntimeRemovalDecision(runtimeremoval.Plan) {
	s.discards++
}

func (s *nativeRuntimeRemovalDecisionBrokerStub) SubmitManagedRuntimeRemovalDecision(
	_ context.Context,
	plan runtimeremoval.Plan,
	input runtimeconsent.ManagedRuntimeRemovalDecisionInput,
) error {
	s.calls++
	s.plan = plan
	s.input = input
	return s.err
}
