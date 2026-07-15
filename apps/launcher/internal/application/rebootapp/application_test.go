package rebootapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/rebootcontinuation"
)

func TestPF001RebootCoordinatorRegistersReplaysAndConsumesOneExactContinuation(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	if err := fixture.application.Register(t.Context(), fixture.binding); err != nil {
		t.Fatal(err)
	}
	if fixture.repository.publishCalls != 1 || fixture.registrar.registerCalls != 1 ||
		fixture.repository.record.OperationID() != fixture.binding.OperationID {
		t.Fatalf("first registration did not publish one exact continuation: %+v", fixture)
	}
	firstNonce := fixture.repository.record.Nonce()
	if err := fixture.application.Register(t.Context(), fixture.binding); err != nil {
		t.Fatal(err)
	}
	if fixture.repository.publishCalls != 1 || fixture.repository.record.Nonce() != firstNonce ||
		fixture.registrar.registerCalls != 2 {
		t.Fatal("registration replay replaced the record or skipped platform reconciliation")
	}
	if err := fixture.application.Consume(t.Context(), fixture.binding); err != nil {
		t.Fatal(err)
	}
	if fixture.repository.claimCalls != 1 || fixture.registrar.removeCalls != 0 {
		t.Fatal("continuation claim removed the crash-recovery login registration too early")
	}
	// A process crash after the durable claim but before the aggregate leaves
	// RebootPending may re-enter the same claim. The install lock serializes it,
	// and fresh journal evidence is required again.
	if err := fixture.application.Consume(t.Context(), fixture.binding); err != nil {
		t.Fatalf("same pending claim could not recover after process interruption: %v", err)
	}
	if fixture.repository.claimCalls != 2 || fixture.registrar.removeCalls != 0 {
		t.Fatal("claim recovery did not preserve the login registration until durable aggregate progress")
	}
}

func TestPF001RebootCoordinatorRotatesExpiredRecordAndRemovesTerminalState(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	expired, err := rebootcontinuation.NewRecord(rebootcontinuation.RecordInput{
		LauncherPath:   fixture.evidence.Verification.LauncherPath,
		LauncherDigest: fixture.evidence.Verification.LauncherDigest,
		OperationID:    fixture.binding.OperationID,
		JournalPath:    fixture.evidence.Verification.JournalPath,
		JournalDigest:  fixture.evidence.Verification.JournalDigest,
		ExpiresAt:      fixture.clock.now.Add(time.Minute), Nonce: rebootcontinuation.NonceBytes([]byte("expired")),
	}, fixture.clock.now)
	if err != nil {
		t.Fatal(err)
	}
	fixture.repository.record, fixture.repository.present = expired, true
	fixture.clock.now = fixture.clock.now.Add(time.Minute)
	if err := fixture.application.Register(t.Context(), fixture.binding); err != nil {
		t.Fatal(err)
	}
	if fixture.repository.deleteCalls != 1 || fixture.registrar.removeCalls != 1 ||
		fixture.repository.publishCalls != 1 || fixture.repository.record.Nonce() == expired.Nonce() {
		t.Fatal("expired continuation was not removed and safely rotated")
	}
	if err := fixture.application.Remove(t.Context(), fixture.binding.OperationID); err != nil {
		t.Fatal(err)
	}
	if fixture.repository.present || fixture.repository.deleteCalls != 2 || fixture.registrar.removeCalls != 2 {
		t.Fatal("terminal continuation cleanup was incomplete")
	}
	if err := fixture.application.Remove(t.Context(), fixture.binding.OperationID); err != nil {
		t.Fatalf("terminal cleanup was not idempotent: %v", err)
	}
}

func TestPF001RebootCoordinatorRejectsEveryAuthoritySubstitution(t *testing.T) {
	foreignOperation, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012399")
	foreignPlan, _ := install.BindPlan([]byte("foreign plan"))
	tests := map[string]func(*Binding, *Evidence){
		"operation": func(binding *Binding, _ *Evidence) { binding.OperationID = foreignOperation },
		"plan":      func(binding *Binding, _ *Evidence) { binding.PlanDigest = foreignPlan },
		"version":   func(binding *Binding, _ *Evidence) { binding.AggregateVersion++ },
		"receipt": func(binding *Binding, _ *Evidence) {
			binding.ResumeReceipt = install.DigestBytes([]byte("foreign receipt"))
		},
		"resolved operation": func(_ *Binding, evidence *Evidence) { evidence.Binding.OperationID = foreignOperation },
		"resolved plan": func(_ *Binding, evidence *Evidence) {
			evidence.Binding.PlanDigest = foreignPlan
		},
		"resolved version": func(_ *Binding, evidence *Evidence) { evidence.Binding.AggregateVersion++ },
		"resolved receipt": func(_ *Binding, evidence *Evidence) {
			evidence.Binding.ResumeReceipt = install.DigestBytes([]byte("foreign receipt"))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := newCoordinatorFixture(t)
			mutate(&candidate.binding, &candidate.evidence)
			candidate.resolver.evidence = candidate.evidence
			if err := candidate.application.Register(t.Context(), candidate.binding); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Register() error = %v, want integrity", err)
			}
			if candidate.repository.publishCalls != 0 || candidate.registrar.registerCalls != 0 {
				t.Fatal("substitution crossed a side-effect boundary")
			}
		})
	}
}

func TestPF001RebootCoordinatorMapsBoundariesAndRejectsPartialComposition(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	dependencies := fixture.dependencies
	tests := map[string]func(*Dependencies){
		"clock":     func(value *Dependencies) { value.Clock = nil },
		"entropy":   func(value *Dependencies) { value.Entropy = nil },
		"evidence":  func(value *Dependencies) { value.Evidence = nil },
		"records":   func(value *Dependencies) { value.Records = nil },
		"registrar": func(value *Dependencies) { value.Registrar = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := dependencies
			mutate(&candidate)
			if application, err := New(candidate); application != nil || !errors.Is(err, ErrIntegrity) {
				t.Fatalf("New() = (%v, %v)", application, err)
			}
		})
	}
	for _, boundary := range []error{context.Canceled, context.DeadlineExceeded, errors.New("private")} {
		candidate := newCoordinatorFixture(t)
		candidate.resolver.err = boundary
		err := candidate.application.Register(t.Context(), candidate.binding)
		if (errors.Is(boundary, context.Canceled) && !errors.Is(err, context.Canceled)) ||
			(errors.Is(boundary, context.DeadlineExceeded) && !errors.Is(err, context.DeadlineExceeded)) ||
			(!errors.Is(boundary, context.Canceled) && !errors.Is(boundary, context.DeadlineExceeded) && !errors.Is(err, ErrUnavailable)) {
			t.Fatalf("boundary %v mapped to %v", boundary, err)
		}
	}
	//lint:ignore SA1012 Deliberate nil-context application-boundary regression fixture.
	if err := fixture.application.Register(nil, fixture.binding); !errors.Is(err, ErrIntegrity) { //nolint:staticcheck // SA1012: owner=security expiry=2027-07-15.
		t.Fatalf("nil context error = %v", err)
	}
	invalid := fixture.binding
	invalid.ResumeReceipt = install.Digest{}
	if err := fixture.application.Consume(t.Context(), invalid); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("invalid binding error = %v", err)
	}
}

func TestPF001RebootCoordinatorFailsClosedAtEveryRecordBoundary(t *testing.T) {
	tests := map[string]struct {
		configure func(*coordinatorFixture)
		consume   bool
		want      error
	}{
		"load integrity":   {configure: func(value *coordinatorFixture) { value.repository.loadErr = ErrRecordIntegrity }, want: ErrIntegrity},
		"load unavailable": {configure: func(value *coordinatorFixture) { value.repository.loadErr = errors.New("private") }, want: ErrUnavailable},
		"entropy": {configure: func(value *coordinatorFixture) {
			value.dependencies.Entropy = entropyErrorStub{}
			value.application, _ = New(value.dependencies)
		}, want: ErrUnavailable},
		"zero entropy": {configure: func(value *coordinatorFixture) {
			value.dependencies.Entropy = zeroEntropyStub{}
			value.application, _ = New(value.dependencies)
		}, want: ErrIntegrity},
		"publish conflict": {configure: func(value *coordinatorFixture) { value.repository.publishErr = ErrRecordConflict }, want: ErrConflict},
		"registrar":        {configure: func(value *coordinatorFixture) { value.registrar.registerErr = errors.New("private") }, want: ErrUnavailable},
		"consume absent":   {consume: true, configure: func(*coordinatorFixture) {}, want: ErrUnavailable},
		"consume claim conflict": {consume: true, configure: func(value *coordinatorFixture) {
			mustRegisterFixture(t, value)
			value.repository.claimErr = ErrRecordConflict
		}, want: ErrConflict},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newCoordinatorFixture(t)
			test.configure(&fixture)
			var err error
			if test.consume {
				err = fixture.application.Consume(t.Context(), fixture.binding)
			} else {
				err = fixture.application.Register(t.Context(), fixture.binding)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestPF001RebootCoordinatorRejectsStaleObjectsAndCleansExpiredConsume(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	mustRegisterFixture(t, &fixture)
	fixture.evidence.Verification.JournalDigest = install.DigestBytes([]byte("changed journal"))
	fixture.resolver.evidence = fixture.evidence
	if err := fixture.application.Register(t.Context(), fixture.binding); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("stale existing registration error = %v", err)
	}
	if fixture.repository.publishCalls != 1 {
		t.Fatal("stale unexpired record was replaced")
	}

	expired := newCoordinatorFixture(t)
	mustRegisterFixture(t, &expired)
	expired.clock.now = expired.repository.record.ExpiresAt()
	if err := expired.application.Consume(t.Context(), expired.binding); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("expired consume error = %v", err)
	}
	if expired.repository.present || expired.repository.deleteCalls != 1 || expired.registrar.removeCalls != 1 {
		t.Fatal("expired consume did not remove record and native entry")
	}
}

func TestPF001RebootCoordinatorRejectsInvalidClockContextAndCleanupFailures(t *testing.T) {
	fixture := newCoordinatorFixture(t)
	fixture.clock.now = time.Time{}
	if err := fixture.application.Register(t.Context(), fixture.binding); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("zero clock error = %v", err)
	}
	fixture.clock.now = time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	mustRegisterFixture(t, &fixture)
	fixture.clock.now = time.Date(2026, time.July, 15, 8, 0, 0, 0, time.FixedZone("foreign", 4*60*60))
	if err := fixture.application.Consume(t.Context(), fixture.binding); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("non-UTC consume clock error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := fixture.application.Remove(cancelled, fixture.binding.OperationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled cleanup error = %v", err)
	}
	for name, configure := range map[string]func(*coordinatorFixture){
		"record":    func(value *coordinatorFixture) { value.repository.deleteErr = ErrRecordIntegrity },
		"registrar": func(value *coordinatorFixture) { value.registrar.removeErr = errors.New("private") },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := newCoordinatorFixture(t)
			configure(&candidate)
			err := candidate.application.Remove(t.Context(), candidate.binding.OperationID)
			if name == "record" && !errors.Is(err, ErrIntegrity) {
				t.Fatalf("cleanup error = %v", err)
			}
			if name == "registrar" && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("cleanup error = %v", err)
			}
		})
	}
	var absent *Application
	if err := absent.Remove(t.Context(), fixture.binding.OperationID); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("nil application error = %v", err)
	}
	if err := fixture.application.Remove(t.Context(), install.OperationID{}); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("zero operation error = %v", err)
	}
}

func mustRegisterFixture(t testing.TB, fixture *coordinatorFixture) {
	t.Helper()
	if err := fixture.application.Register(context.Background(), fixture.binding); err != nil {
		t.Fatal(err)
	}
}

type coordinatorFixture struct {
	application  *Application
	dependencies Dependencies
	binding      Binding
	evidence     Evidence
	clock        *clockStub
	repository   *recordRepositoryStub
	registrar    *registrarStub
	resolver     *evidenceResolverStub
}

func newCoordinatorFixture(t testing.TB) coordinatorFixture {
	t.Helper()
	now := time.Date(2026, time.July, 15, 4, 0, 0, 0, time.UTC)
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	planDigest, _ := install.BindPlan([]byte("plan"))
	binding := Binding{OperationID: operationID, PlanDigest: planDigest,
		AggregateVersion: 8, ResumeReceipt: install.DigestBytes([]byte("resume receipt"))}
	evidence := Evidence{Binding: binding, Verification: rebootcontinuation.Verification{
		OperationID: operationID, LauncherPath: "/opt/agentmemory/bin/agentmemory",
		LauncherDigest: install.DigestBytes([]byte("launcher")),
		JournalPath:    "/home/owner/.config/AgentMemory/install-operation.json",
		JournalDigest:  install.DigestBytes([]byte("journal")),
	}}
	clock := &clockStub{now: now}
	repository := &recordRepositoryStub{}
	registrar := &registrarStub{}
	resolver := &evidenceResolverStub{evidence: evidence}
	dependencies := Dependencies{Clock: clock, Entropy: entropyStub{}, Evidence: resolver,
		Records: repository, Registrar: registrar}
	application, err := New(dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return coordinatorFixture{application: application, dependencies: dependencies, binding: binding,
		evidence: evidence, clock: clock, repository: repository, registrar: registrar, resolver: resolver}
}

type clockStub struct{ now time.Time }

func (c *clockStub) Now() time.Time { return c.now }

type entropyStub struct{}

func (entropyStub) Bytes(context.Context, int) ([]byte, error) {
	value := make([]byte, 32)
	value[31] = 9
	return value, nil
}

type entropyErrorStub struct{}

func (entropyErrorStub) Bytes(context.Context, int) ([]byte, error) {
	return nil, errors.New("private entropy failure")
}

type zeroEntropyStub struct{}

func (zeroEntropyStub) Bytes(context.Context, int) ([]byte, error) { return make([]byte, 32), nil }

type evidenceResolverStub struct {
	evidence Evidence
	err      error
}

func (r *evidenceResolverStub) Resolve(context.Context, Binding) (Evidence, error) {
	return r.evidence, r.err
}

type recordRepositoryStub struct {
	record       rebootcontinuation.Record
	present      bool
	claimed      bool
	publishCalls int
	claimCalls   int
	deleteCalls  int
	loadErr      error
	publishErr   error
	claimErr     error
	deleteErr    error
}

func (r *recordRepositoryStub) Load(context.Context, install.OperationID) (rebootcontinuation.Record, error) {
	if r.loadErr != nil {
		return rebootcontinuation.Record{}, r.loadErr
	}
	if !r.present {
		return rebootcontinuation.Record{}, ErrRecordNotFound
	}
	return r.record, nil
}
func (r *recordRepositoryStub) Publish(_ context.Context, record rebootcontinuation.Record) error {
	r.publishCalls++
	if r.publishErr != nil {
		return r.publishErr
	}
	if r.present {
		return ErrRecordConflict
	}
	r.record, r.present, r.claimed = record, true, false
	return nil
}
func (r *recordRepositoryStub) Claim(_ context.Context, record rebootcontinuation.Record) error {
	r.claimCalls++
	if r.claimErr != nil {
		return r.claimErr
	}
	if !r.present || r.record.Nonce() != record.Nonce() {
		return ErrRecordConflict
	}
	r.claimed = true
	return nil
}
func (r *recordRepositoryStub) Delete(context.Context, install.OperationID) error {
	r.deleteCalls++
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.present, r.claimed = false, false
	return nil
}

type registrarStub struct {
	registerCalls int
	removeCalls   int
	registerErr   error
	removeErr     error
}

func (r *registrarStub) Register(context.Context, rebootcontinuation.Record) error {
	r.registerCalls++
	return r.registerErr
}
func (r *registrarStub) Remove(context.Context, install.OperationID) error {
	r.removeCalls++
	return r.removeErr
}
