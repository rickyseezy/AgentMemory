package readinessapp

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

func TestPF001ReadinessApplicationPersistsOnlyCompleteProof(t *testing.T) {
	t.Parallel()

	command := readinessCommand(t)
	ports := newReadinessPorts(t, command)
	application := mustReadinessApplication(t, ports)
	verification, err := application.Verify(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	if !verification.Ready() || verification.Receipt().IsZero() || len(verification.Failures()) != 0 ||
		ports.saved.IsZero() || !ports.saved.Digest().Equal(verification.Receipt().Digest()) {
		t.Fatalf("verification/saved = %+v/%+v", verification, ports.saved)
	}
	if !reflect.DeepEqual(ports.calls, readiness.RequiredProbes()) {
		t.Fatalf("probe order = %v, want %v", ports.calls, readiness.RequiredProbes())
	}
	for _, request := range ports.requests {
		if request.OperationID() != command.OperationID || !request.PlanDigest().Equal(command.PlanDigest) ||
			request.ReleaseID() != command.ReleaseID || request.GenerationID() != command.GenerationID ||
			!request.ManifestDigest().Equal(command.ManifestDigest) || !request.ComposeDigest().Equal(command.ComposeDigest) ||
			request.StartedAt().IsZero() {
			t.Fatal("probe request lost a release binding")
		}
	}
}

func TestPF001ReadinessApplicationDoesNotPersistPartialOrCrossBoundEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*readinessPorts, Command)
		code      readiness.FailureCode
	}{
		{name: "negative probe", configure: func(ports *readinessPorts, command Command) {
			ports.results[readiness.ProbeGraphCompatibility] = probeResult(t, command, readiness.ProbeGraphCompatibility, readiness.StatusFailed, ports.now)
		}, code: readiness.FailureProbeFailed},
		{name: "wrong probe", configure: func(ports *readinessPorts, command Command) {
			ports.results[readiness.ProbeGraphCompatibility] = probeResult(t, command, readiness.ProbeSQLiteIntegrity, readiness.StatusPassed, ports.now)
		}, code: readiness.FailureDuplicateProbe},
		{name: "cross release", configure: func(ports *readinessPorts, command Command) {
			foreign := command
			foreign.ReleaseID = "other"
			ports.results[readiness.ProbeGraphCompatibility] = probeResult(t, foreign, readiness.ProbeGraphCompatibility, readiness.StatusPassed, ports.now)
		}, code: readiness.FailureBindingMismatch},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := readinessCommand(t)
			ports := newReadinessPorts(t, command)
			test.configure(ports, command)
			verification, err := mustReadinessApplication(t, ports).Verify(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			if verification.Ready() || !verification.Receipt().IsZero() || !containsReadinessFailure(verification.Failures(), test.code) || !ports.saved.IsZero() {
				t.Fatalf("verification/saved = %+v/%+v, want %s", verification, ports.saved, test.code)
			}
		})
	}
}

func TestPF001ReadinessApplicationStopsAndSanitizesEveryBoundaryFailure(t *testing.T) {
	t.Parallel()

	for _, probe := range readiness.RequiredProbes() {
		probe := probe
		t.Run(probe.String(), func(t *testing.T) {
			t.Parallel()
			command := readinessCommand(t)
			ports := newReadinessPorts(t, command)
			ports.failProbe = probe
			ports.probeError = errors.New("raw host path and secret must not escape")
			_, err := mustReadinessApplication(t, ports).Verify(context.Background(), command)
			assertReadinessError(t, err, ErrorCodeDependencyUnavailable, true)
			if !ports.saved.IsZero() {
				t.Fatal("probe failure persisted a receipt")
			}
			if len(ports.calls) == 0 || ports.calls[len(ports.calls)-1] != probe {
				t.Fatalf("probe failure call order = %v", ports.calls)
			}
		})
	}
}

func TestPF001ReadinessApplicationMapsCancellationAndReceiptFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*readinessPorts)
		code      ErrorCode
		retryable bool
	}{
		{name: "probe deadline", configure: func(ports *readinessPorts) {
			ports.failProbe = readiness.ProbeSQLiteIntegrity
			ports.probeError = context.DeadlineExceeded
		}, code: ErrorCodeDeadlineExceeded, retryable: true},
		{name: "receipt deadline", configure: func(ports *readinessPorts) { ports.saveError = context.Canceled }, code: ErrorCodeDeadlineExceeded, retryable: true},
		{name: "receipt conflict", configure: func(ports *readinessPorts) { ports.saveError = ErrReceiptConflict }, code: ErrorCodeConflict, retryable: true},
		{name: "receipt integrity", configure: func(ports *readinessPorts) { ports.saveError = ErrReceiptIntegrity }, code: ErrorCodeIntegrityViolation, retryable: false},
		{name: "receipt unknown", configure: func(ports *readinessPorts) { ports.saveError = errors.New("secret") }, code: ErrorCodeInternal, retryable: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			command := readinessCommand(t)
			ports := newReadinessPorts(t, command)
			test.configure(ports)
			_, err := mustReadinessApplication(t, ports).Verify(context.Background(), command)
			assertReadinessError(t, err, test.code, test.retryable)
		})
	}

	command := readinessCommand(t)
	ports := newReadinessPorts(t, command)
	application := mustReadinessApplication(t, ports)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := application.Verify(ctx, command)
	assertReadinessError(t, err, ErrorCodeDeadlineExceeded, true)
}

func TestPF001ReadinessApplicationRejectsInvalidCompositionAndCommand(t *testing.T) {
	t.Parallel()

	command := readinessCommand(t)
	ports := newReadinessPorts(t, command)
	base := readinessDependencies(ports)
	removals := []func(*Dependencies){
		func(value *Dependencies) { value.Clock = nil },
		func(value *Dependencies) { value.SQLiteIntegrity = nil },
		func(value *Dependencies) { value.MigrationHead = nil },
		func(value *Dependencies) { value.WritableVolumes = nil },
		func(value *Dependencies) { value.GraphCompatibility = nil },
		func(value *Dependencies) { value.KeyAccess = nil },
		func(value *Dependencies) { value.AuditAppend = nil },
		func(value *Dependencies) { value.DeletionGuard = nil },
		func(value *Dependencies) { value.ExpiredLeaseRecovery = nil },
		func(value *Dependencies) { value.LocalProviders = nil },
		func(value *Dependencies) { value.SemanticWriteIndexRecall = nil },
		func(value *Dependencies) { value.DefaultEgressDenied = nil },
		func(value *Dependencies) { value.Receipts = nil },
	}
	for _, remove := range removals {
		dependencies := base
		remove(&dependencies)
		if _, err := NewApplication(dependencies); err == nil {
			t.Fatal("NewApplication() accepted a missing dependency")
		}
	}
	var typedNil *readinessPorts
	dependencies := base
	dependencies.Clock = typedNil
	if _, err := NewApplication(dependencies); err == nil {
		t.Fatal("NewApplication() accepted a typed-nil dependency")
	}

	invalidCommands := []Command{
		{},
		withCommandMutation(command, func(value *Command) { value.OperationID = install.OperationID{} }),
		withCommandMutation(command, func(value *Command) { value.PlanDigest = install.PlanDigest{} }),
		withCommandMutation(command, func(value *Command) { value.ReleaseID = "" }),
		withCommandMutation(command, func(value *Command) { value.GenerationID = "" }),
		withCommandMutation(command, func(value *Command) { value.ManifestDigest = install.Digest{} }),
		withCommandMutation(command, func(value *Command) { value.ComposeDigest = install.Digest{} }),
	}
	application := mustReadinessApplication(t, ports)
	for _, invalid := range invalidCommands {
		_, err := application.Verify(context.Background(), invalid)
		assertReadinessError(t, err, ErrorCodeInvalidArgument, false)
	}
	ports.zeroClock = true
	_, err := application.Verify(context.Background(), command)
	assertReadinessError(t, err, ErrorCodeInvalidArgument, false)
}

func TestPF001ReadinessVerificationConstructorsPreserveOnlyValidProof(t *testing.T) {
	t.Parallel()

	command := readinessCommand(t)
	ports := newReadinessPorts(t, command)
	verified, err := mustReadinessApplication(t, ports).Verify(context.Background(), command)
	if err != nil || !verified.Ready() {
		t.Fatalf("Verify() = %+v, %v", verified, err)
	}
	ready := NewReadyVerification(verified.Receipt())
	if !ready.Ready() || ready.Receipt().IsZero() || len(ready.Failures()) != 0 {
		t.Fatalf("NewReadyVerification() = %+v", ready)
	}
	if NewReadyVerification(readiness.Receipt{}).Ready() {
		t.Fatal("NewReadyVerification() accepted a zero receipt")
	}
	failures := []readiness.Failure{{Probe: readiness.ProbeAuditAppend, Code: readiness.FailureProbeFailed}}
	notReady := NewNotReadyVerification(failures)
	failures[0].Probe = readiness.ProbeSQLiteIntegrity
	returned := notReady.Failures()
	returned[0].Probe = readiness.ProbeMigrationHead
	if notReady.Ready() || len(notReady.Failures()) != 1 ||
		notReady.Failures()[0].Probe != readiness.ProbeAuditAppend || !notReady.Receipt().IsZero() {
		t.Fatalf("NewNotReadyVerification() exposed mutable or successful state: %+v", notReady)
	}
	if len(NewNotReadyVerification(nil).Failures()) != 0 || nilCapability(1) || !nilCapability(nil) {
		t.Fatal("empty negative verification or dependency nil policy changed")
	}
}

type readinessPorts struct {
	now        time.Time
	results    map[readiness.Probe]readiness.Result
	calls      []readiness.Probe
	requests   []ProbeRequest
	failProbe  readiness.Probe
	probeError error
	saveError  error
	saved      readiness.Receipt
	zeroClock  bool
}

func newReadinessPorts(t testing.TB, command Command) *readinessPorts {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
	ports := &readinessPorts{now: now, results: make(map[readiness.Probe]readiness.Result)}
	for _, probe := range readiness.RequiredProbes() {
		ports.results[probe] = probeResult(t, command, probe, readiness.StatusPassed, now)
	}
	return ports
}

func (p *readinessPorts) Now() time.Time {
	if p.zeroClock {
		return time.Time{}
	}
	return p.now
}

func (p *readinessPorts) execute(probe readiness.Probe, request ProbeRequest) (readiness.Result, error) {
	p.calls = append(p.calls, probe)
	p.requests = append(p.requests, request)
	if p.failProbe == probe {
		return readiness.Result{}, p.probeError
	}
	return p.results[probe], nil
}

func (p *readinessPorts) ProbeSQLiteIntegrity(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeSQLiteIntegrity, request)
}
func (p *readinessPorts) ProbeMigrationHead(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeMigrationHead, request)
}
func (p *readinessPorts) ProbeWritableVolumes(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeWritableVolumes, request)
}
func (p *readinessPorts) ProbeGraphCompatibility(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeGraphCompatibility, request)
}
func (p *readinessPorts) ProbeKeyAccess(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeKeyAccess, request)
}
func (p *readinessPorts) ProbeAuditAppend(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeAuditAppend, request)
}
func (p *readinessPorts) ProbeDeletionGuard(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeDeletionGuard, request)
}
func (p *readinessPorts) ProbeExpiredLeaseRecovery(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeExpiredLeaseRecovery, request)
}
func (p *readinessPorts) ProbeLocalProviders(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeLocalProviders, request)
}
func (p *readinessPorts) ProbeSemanticWriteIndexRecall(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeSemanticWriteIndexRecall, request)
}
func (p *readinessPorts) ProbeDefaultEgressDenied(_ context.Context, request ProbeRequest) (readiness.Result, error) {
	return p.execute(readiness.ProbeDefaultEgressDenied, request)
}
func (p *readinessPorts) SaveReadinessReceipt(_ context.Context, receipt readiness.Receipt) error {
	if p.saveError != nil {
		return p.saveError
	}
	p.saved = receipt
	return nil
}

func readinessDependencies(ports *readinessPorts) Dependencies {
	return Dependencies{
		Clock:                    ports,
		SQLiteIntegrity:          ports,
		MigrationHead:            ports,
		WritableVolumes:          ports,
		GraphCompatibility:       ports,
		KeyAccess:                ports,
		AuditAppend:              ports,
		DeletionGuard:            ports,
		ExpiredLeaseRecovery:     ports,
		LocalProviders:           ports,
		SemanticWriteIndexRecall: ports,
		DefaultEgressDenied:      ports,
		Receipts:                 ports,
	}
}

func mustReadinessApplication(t testing.TB, ports *readinessPorts) *Application {
	t.Helper()
	application, err := NewApplication(readinessDependencies(ports))
	if err != nil {
		t.Fatal(err)
	}
	return application
}

func readinessCommand(t testing.TB) Command {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f20-1234-7abc-8123-0123456789ab")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := install.BindPlan([]byte("canonical-plan"))
	if err != nil {
		t.Fatal(err)
	}
	return Command{
		OperationID:    operationID,
		PlanDigest:     plan,
		ReleaseID:      "agentmemory-1.0.0",
		GenerationID:   "019f5f21-5678-7def-9123-abcdef012345",
		ManifestDigest: install.DigestBytes([]byte("manifest")),
		ComposeDigest:  install.DigestBytes([]byte("compose")),
	}
}

func probeResult(t testing.TB, command Command, probe readiness.Probe, status readiness.Status, observedAt time.Time) readiness.Result {
	t.Helper()
	result, err := readiness.NewResult(readiness.ResultInput{
		Probe:          probe,
		Status:         status,
		OperationID:    command.OperationID,
		PlanDigest:     command.PlanDigest,
		ReleaseID:      command.ReleaseID,
		GenerationID:   command.GenerationID,
		ManifestDigest: command.ManifestDigest,
		ComposeDigest:  command.ComposeDigest,
		EvidenceDigest: install.DigestBytes([]byte(probe.String())),
		ObservedAt:     observedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func assertReadinessError(t testing.TB, err error, code ErrorCode, retryable bool) {
	t.Helper()
	var applicationError *ApplicationError
	if !errors.As(err, &applicationError) || applicationError.Code() != code || applicationError.Retryable() != retryable || err.Error() != string(code) {
		t.Fatalf("error = %#v, want %s retryable=%v", err, code, retryable)
	}
}

func containsReadinessFailure(failures []readiness.Failure, code readiness.FailureCode) bool {
	for _, failure := range failures {
		if failure.Code == code {
			return true
		}
	}
	return false
}

func withCommandMutation(command Command, mutate func(*Command)) Command {
	mutate(&command)
	return command
}
