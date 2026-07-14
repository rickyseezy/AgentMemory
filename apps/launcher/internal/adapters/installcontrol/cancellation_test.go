package installcontrol

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001InstallCancellerDelegatesOnlyExactBoundPlan(t *testing.T) {
	t.Parallel()
	canonical := []byte(`{"schema":1}`)
	operationID, plan := cancellationBinding(t, canonical)
	application := &cancelApplicationStub{result: installapp.InstallResult{
		OperationID: operationID.String(), State: install.StateRunning, CancellationRequested: true,
	}}
	canceller, err := NewInstallCanceller(application, installapp.CancelCommand{
		OperationID: operationID.String(), CanonicalPlan: canonical,
	}, operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	canonical[0] = 'x'
	if err := canceller.RequestCancellation(context.Background()); err != nil {
		t.Fatal(err)
	}
	if application.calls != 1 || application.command.OperationID != operationID.String() ||
		!bytes.Equal(application.command.CanonicalPlan, []byte(`{"schema":1}`)) {
		t.Fatalf("delegated command = %+v, calls=%d", application.command, application.calls)
	}
}

func TestPF001InstallCancellerAcceptsSettledOrAlreadyCancelledTruth(t *testing.T) {
	t.Parallel()
	canonical := []byte(`{"schema":1}`)
	operationID, plan := cancellationBinding(t, canonical)
	for name, result := range map[string]installapp.InstallResult{
		"settled": {
			OperationID: operationID.String(), State: install.StateCancelled,
			CancellationRequested: true, CancellationSettled: true,
		},
		"phase cancelled": {OperationID: operationID.String(), State: install.StateCancelled},
	} {
		result := result
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			application := &cancelApplicationStub{result: result}
			canceller, err := NewInstallCanceller(application, installapp.CancelCommand{
				OperationID: operationID.String(), CanonicalPlan: canonical,
			}, operationID, plan)
			if err != nil || canceller.RequestCancellation(context.Background()) != nil {
				t.Fatalf("cancel settled construction/use error = %v", err)
			}
		})
	}
}

func TestPF001InstallCancellerRejectsBindingAndResultSubstitution(t *testing.T) {
	t.Parallel()
	canonical := []byte(`{"schema":1}`)
	operationID, plan := cancellationBinding(t, canonical)
	foreignID, _ := install.NewOperationID("019f5f20-1234-7abc-8123-0123456789ad")
	foreignPlan, _ := install.BindPlan([]byte(`{"schema":2}`))
	application := &cancelApplicationStub{}
	var nilApplication *cancelApplicationStub
	for _, input := range []struct {
		application InstallCancellationApplication
		command     installapp.CancelCommand
		operation   install.OperationID
		plan        install.PlanDigest
	}{
		{application: nilApplication, command: installapp.CancelCommand{OperationID: operationID.String(), CanonicalPlan: canonical}, operation: operationID, plan: plan},
		{application: application, command: installapp.CancelCommand{OperationID: foreignID.String(), CanonicalPlan: canonical}, operation: operationID, plan: plan},
		{application: application, command: installapp.CancelCommand{OperationID: operationID.String(), CanonicalPlan: nil}, operation: operationID, plan: plan},
		{application: application, command: installapp.CancelCommand{OperationID: operationID.String(), CanonicalPlan: canonical}, operation: install.OperationID{}, plan: plan},
		{application: application, command: installapp.CancelCommand{OperationID: operationID.String(), CanonicalPlan: canonical}, operation: operationID, plan: foreignPlan},
	} {
		if result, err := NewInstallCanceller(input.application, input.command, input.operation, input.plan); result != nil || err == nil {
			t.Fatalf("invalid canceller = %#v, %v", result, err)
		}
	}

	for _, result := range []installapp.InstallResult{
		{OperationID: foreignID.String(), CancellationRequested: true},
		{OperationID: operationID.String(), State: install.StateRunning},
	} {
		application.result = result
		canceller, err := NewInstallCanceller(application, installapp.CancelCommand{
			OperationID: operationID.String(), CanonicalPlan: canonical,
		}, operationID, plan)
		if err != nil {
			t.Fatal(err)
		}
		if err := canceller.RequestCancellation(context.Background()); err == nil {
			t.Fatalf("substituted result accepted: %+v", result)
		}
	}
}

func TestPF001InstallCancellerPropagatesDeadlineAndSafeApplicationFailure(t *testing.T) {
	t.Parallel()
	canonical := []byte(`{"schema":1}`)
	operationID, plan := cancellationBinding(t, canonical)
	want := errors.New("safe application failure")
	application := &cancelApplicationStub{err: want}
	canceller, err := NewInstallCanceller(application, installapp.CancelCommand{
		OperationID: operationID.String(), CanonicalPlan: canonical,
	}, operationID, plan)
	if err != nil {
		t.Fatal(err)
	}
	if err := canceller.RequestCancellation(context.Background()); !errors.Is(err, want) {
		t.Fatalf("RequestCancellation error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := canceller.RequestCancellation(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled RequestCancellation error = %v", err)
	}
	var nilContext context.Context
	if err := canceller.RequestCancellation(nilContext); err == nil {
		t.Fatal("nil context was accepted")
	}
	var nilCanceller *InstallCanceller
	if err := nilCanceller.RequestCancellation(context.Background()); err == nil {
		t.Fatal("nil canceller was accepted")
	}
}

func cancellationBinding(t testing.TB, canonical []byte) (install.OperationID, install.PlanDigest) {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f20-1234-7abc-8123-0123456789ac")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan(canonical)
	if err != nil {
		t.Fatal(err)
	}
	return operationID, plan
}

type cancelApplicationStub struct {
	result  installapp.InstallResult
	err     error
	command installapp.CancelCommand
	calls   int
}

func (a *cancelApplicationStub) Cancel(_ context.Context, command installapp.CancelCommand) (installapp.InstallResult, error) {
	a.calls++
	a.command = command
	return a.result, a.err
}
