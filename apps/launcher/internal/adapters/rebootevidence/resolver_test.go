package rebootevidence

import (
	"context"
	"errors"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/rebootapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001RebootEvidenceResolverAuthenticatesExactPendingJournal(t *testing.T) {
	operation, binding := pendingOperationFixture(t)
	operations := &operationRepositoryStub{operation: operation}
	locator := &journalLocatorStub{path: "/home/owner/.config/AgentMemory/install-operation.json"}
	verifier := &objectVerifierStub{
		launcher: VerifiedObject{Path: "/opt/AgentMemory/bin/agentmemory", Digest: install.DigestBytes([]byte("launcher"))},
		journal:  VerifiedObject{Path: locator.path, Digest: install.DigestBytes([]byte("journal"))},
	}
	resolver, err := New(operations, locator, verifier)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := resolver.Resolve(t.Context(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.Binding != binding || evidence.Verification.OperationID != binding.OperationID ||
		evidence.Verification.LauncherPath != verifier.launcher.Path ||
		!evidence.Verification.LauncherDigest.Equal(verifier.launcher.Digest) ||
		evidence.Verification.JournalPath != locator.path ||
		!evidence.Verification.JournalDigest.Equal(verifier.journal.Digest) {
		t.Fatalf("evidence = %+v", evidence)
	}
}

func TestPF001RebootEvidenceResolverRejectsEveryAggregateSubstitution(t *testing.T) {
	operation, binding := pendingOperationFixture(t)
	foreignOperation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	foreignPlan, _ := install.BindPlan([]byte("foreign plan"))
	tests := map[string]func(*rebootapp.Binding, *operationRepositoryStub){
		"operation": func(value *rebootapp.Binding, _ *operationRepositoryStub) { value.OperationID = foreignOperation },
		"plan":      func(value *rebootapp.Binding, _ *operationRepositoryStub) { value.PlanDigest = foreignPlan },
		"version":   func(value *rebootapp.Binding, _ *operationRepositoryStub) { value.AggregateVersion++ },
		"receipt": func(value *rebootapp.Binding, _ *operationRepositoryStub) {
			value.ResumeReceipt = install.DigestBytes([]byte("foreign receipt"))
		},
		"repository nil": func(_ *rebootapp.Binding, repository *operationRepositoryStub) { repository.operation = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			repository := &operationRepositoryStub{operation: operation}
			candidate := binding
			mutate(&candidate, repository)
			verifier := &objectVerifierStub{}
			resolver, _ := New(repository, &journalLocatorStub{path: "/journal"}, verifier)
			if _, err := resolver.Resolve(t.Context(), candidate); !errors.Is(err, rebootapp.ErrIntegrity) {
				t.Fatalf("Resolve() error = %v", err)
			}
			if verifier.launcherCalls != 0 || verifier.journalCalls != 0 {
				t.Fatal("substituted aggregate crossed the file verification boundary")
			}
		})
	}
}

func TestPF001RebootEvidenceResolverMapsBoundariesAndRejectsPartialComposition(t *testing.T) {
	operation, binding := pendingOperationFixture(t)
	operations := &operationRepositoryStub{operation: operation}
	locator := &journalLocatorStub{path: "/journal"}
	verifier := &objectVerifierStub{launcher: VerifiedObject{Path: "/launcher", Digest: install.DigestBytes([]byte("launcher"))},
		journal: VerifiedObject{Path: "/journal", Digest: install.DigestBytes([]byte("journal"))}}
	if resolver, err := New(nil, locator, verifier); resolver != nil || !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("nil repository constructor = (%v, %v)", resolver, err)
	}
	if resolver, err := New(operations, nil, verifier); resolver != nil || !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("nil locator constructor = (%v, %v)", resolver, err)
	}
	if resolver, err := New(operations, locator, nil); resolver != nil || !errors.Is(err, rebootapp.ErrIntegrity) {
		t.Fatalf("nil verifier constructor = (%v, %v)", resolver, err)
	}
	resolver, _ := New(operations, locator, verifier)
	for _, boundary := range []error{context.Canceled, context.DeadlineExceeded, installapp.ErrOperationIntegrity, errors.New("private")} {
		operations.err = boundary
		_, err := resolver.Resolve(t.Context(), binding)
		switch {
		case errors.Is(boundary, context.Canceled) && !errors.Is(err, context.Canceled):
			t.Fatalf("cancelled mapped to %v", err)
		case errors.Is(boundary, context.DeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded):
			t.Fatalf("deadline mapped to %v", err)
		case errors.Is(boundary, installapp.ErrOperationIntegrity) && !errors.Is(err, rebootapp.ErrIntegrity):
			t.Fatalf("integrity mapped to %v", err)
		case !errors.Is(boundary, context.Canceled) && !errors.Is(boundary, context.DeadlineExceeded) &&
			!errors.Is(boundary, installapp.ErrOperationIntegrity) && !errors.Is(err, rebootapp.ErrUnavailable):
			t.Fatalf("private mapped to %v", err)
		}
	}
	operations.err = nil
	locator.err = errors.New("private")
	if _, err := resolver.Resolve(t.Context(), binding); !errors.Is(err, rebootapp.ErrUnavailable) {
		t.Fatalf("locator error = %v", err)
	}
	locator.err = nil
	verifier.launcherErr = errors.New("private")
	if _, err := resolver.Resolve(t.Context(), binding); !errors.Is(err, rebootapp.ErrUnavailable) {
		t.Fatalf("launcher error = %v", err)
	}
	verifier.launcherErr = nil
	verifier.journalErr = errors.New("private")
	if _, err := resolver.Resolve(t.Context(), binding); !errors.Is(err, rebootapp.ErrUnavailable) {
		t.Fatalf("journal error = %v", err)
	}
}

func pendingOperationFixture(t testing.TB) (*install.Operation, rebootapp.Binding) {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	operation, _ := install.NewOperation(operationID, plan)
	fact, _ := install.NewNonSecretFact("probe_status", "verified")
	boundary, _ := install.NewCompensationBoundary("remove_agentmemory_owned_partial")
	action, _ := install.NewSafeAction("setup.continue")
	evidence, _ := install.NewStepEvidence(install.StepEvidenceInput{
		Phase: install.PhaseVerifyHost, Attempt: 1, PlanDigest: plan,
		InputDigest: install.DigestBytes([]byte("input")), OutputDigest: install.DigestBytes([]byte("output")),
		Facts: []install.NonSecretFact{fact}, RuntimeOwnership: install.RuntimeOwnershipUndetermined,
		CompensationBoundary: boundary, NextSafeAction: action,
	})
	if err := operation.CompleteStep(evidence); err != nil {
		t.Fatal(err)
	}
	receipt := install.DigestBytes([]byte("resume receipt"))
	resumeAction, _ := install.NewSafeAction("setup.resume_after_restart")
	checkpoint, _ := install.NewRebootCheckpoint(plan, install.PhaseEnsureContainerRuntime, 1, receipt, resumeAction)
	if err := operation.MarkRebootPending(plan, checkpoint); err != nil {
		t.Fatal(err)
	}
	return operation, rebootapp.Binding{OperationID: operationID, PlanDigest: plan,
		AggregateVersion: operation.AggregateVersion(), ResumeReceipt: receipt}
}

type operationRepositoryStub struct {
	operation *install.Operation
	err       error
}

func (r *operationRepositoryStub) Load(context.Context, install.OperationID) (*install.Operation, error) {
	return r.operation, r.err
}

type journalLocatorStub struct {
	path string
	err  error
}

func (l *journalLocatorStub) JournalPath(install.OperationID) (string, error) { return l.path, l.err }

type objectVerifierStub struct {
	launcher      VerifiedObject
	journal       VerifiedObject
	launcherErr   error
	journalErr    error
	launcherCalls int
	journalCalls  int
}

func (v *objectVerifierStub) VerifyLauncher(context.Context) (VerifiedObject, error) {
	v.launcherCalls++
	return v.launcher, v.launcherErr
}
func (v *objectVerifierStub) VerifyJournal(_ context.Context, path string) (VerifiedObject, error) {
	v.journalCalls++
	if v.journal.Path == "" {
		v.journal.Path = path
		v.journal.Digest = install.DigestBytes([]byte("journal"))
	}
	return v.journal, v.journalErr
}
