package runtimeconsent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001RuntimeConsentHubDeliversExactBoundDecision(t *testing.T) {
	t.Parallel()
	hub, binding, pending := hubFixture(t)
	result := make(chan Decision, 1)
	errResult := make(chan error, 1)
	go func() {
		decision, err := hub.Await(context.Background(), pending)
		result <- decision
		errResult <- err
	}()

	if err := submitConsent(context.Background(), hub, binding, setupprogressapp.DecisionAccept); err != nil {
		t.Fatal(err)
	}
	if decision, err := <-result, <-errResult; decision != DecisionAccept || err != nil {
		t.Fatalf("Await()=%q,%v", decision, err)
	}
}

func TestPF001RuntimeConsentHubWaitsForWorkerRegistration(t *testing.T) {
	t.Parallel()
	hub, binding, pending := hubFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	submitted := make(chan error, 1)
	go func() {
		submitted <- submitConsent(ctx, hub, binding, setupprogressapp.DecisionDecline)
	}()
	time.Sleep(time.Millisecond)
	decision, err := hub.Await(ctx, pending)
	if err != nil || decision != DecisionDecline {
		t.Fatalf("Await()=%q,%v", decision, err)
	}
	if err := <-submitted; err != nil {
		t.Fatalf("SubmitRuntimeConsent()=%v", err)
	}
}

func TestPF001RuntimeConsentHubRejectsSubstitutionReplayAndInvalidState(t *testing.T) {
	t.Parallel()
	hub, binding, pending := hubFixture(t)
	foreignDigest, _ := install.BindPlan([]byte("foreign"))
	foreign, _ := setupprogressapp.NewBinding(binding.OperationID(), foreignDigest)
	if err := hub.Bind(foreign); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("foreign Bind()=%v", err)
	}
	if _, err := hub.Await(context.Background(), Pending{}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("invalid Await()=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := hub.Await(ctx, pending); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Await()=%v", err)
	}
	if err := submitConsent(ctx, hub, binding, setupprogressapp.DecisionAccept); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Submit()=%v", err)
	}
	if err := submitConsent(context.Background(), hub, binding, setupprogressapp.DecisionRetry); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("retry Submit()=%v", err)
	}

	winner := make(chan error, 1)
	go func() {
		_, err := hub.Await(context.Background(), pending)
		winner <- err
	}()
	deadline, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	for {
		hub.mu.Lock()
		registered := hub.entries[binding.OperationID().String()].pending != nil
		hub.mu.Unlock()
		if registered {
			break
		}
		select {
		case <-deadline.Done():
			t.Fatal("pending consent did not register")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if _, err := hub.Await(deadline, pending); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate Await()=%v", err)
	}
	if err := submitConsent(deadline, hub, binding, setupprogressapp.DecisionAccept); err != nil {
		t.Fatal(err)
	}
	if err := <-winner; err != nil {
		t.Fatal(err)
	}
	if err := submitConsent(deadline, hub, binding, setupprogressapp.DecisionAccept); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("replayed Submit()=%v", err)
	}
}

func hubFixture(t testing.TB) (*Hub, setupprogressapp.Binding, Pending) {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f29-1234-7abc-8123-0123456789ab")
	parent, _ := install.BindPlan([]byte("parent"))
	binding, _ := setupprogressapp.NewBinding(operationID, parent)
	hub, err := NewHub()
	if err != nil {
		t.Fatal(err)
	}
	if err := hub.Bind(binding); err != nil {
		t.Fatal(err)
	}
	return hub, binding, Pending{
		OperationID:       operationID.String(),
		RuntimePlanDigest: runtimeinstall.Sum([]byte("runtime-plan")),
		TermsDigest:       runtimeinstall.Sum([]byte("terms")),
	}
}

func submitConsent(
	ctx context.Context,
	hub *Hub,
	binding setupprogressapp.Binding,
	decision setupprogressapp.Decision,
) error {
	return hub.SubmitRuntimeConsent(
		ctx, binding, decision, "019f5f2a-1234-7abc-8123-0123456789ab",
	)
}
