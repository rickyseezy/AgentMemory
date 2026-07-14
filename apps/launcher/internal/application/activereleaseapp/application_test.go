package activereleaseapp

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/readiness"
)

func TestPF001CommitActiveReleaseStagesHostAndCoreInDurableOrder(t *testing.T) {
	t.Parallel()

	fixture := newActivationFixture(t)
	result, err := fixture.application().Commit(context.Background(), fixture.command)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != StatusCommitted || result.AlreadyActive || result.PointerDigest.IsZero() ||
		!fixture.host.current.Digest().Equal(result.PointerDigest) || !fixture.core.committed {
		t.Fatalf("result = %+v", result)
	}
	wantCalls := []string{"receipt.load", "activation.load", "host.load", "activation.save.created", "core.stage", "activation.save.core_prepared", "host.load", "host.cas", "host.confirm", "activation.save.host_committed", "core.commit", "activation.save.committed", "host.load", "core.matches"}
	if !reflect.DeepEqual(fixture.calls, wantCalls) {
		t.Fatalf("calls = %v, want %v", fixture.calls, wantCalls)
	}
	for _, snapshot := range fixture.activation.saved {
		if snapshot.State == activerelease.StateCreated && snapshot.Version != 0 ||
			snapshot.State == activerelease.StateCorePrepared && snapshot.Version != 1 ||
			snapshot.State == activerelease.StateHostCommitted && snapshot.Version != 2 ||
			snapshot.State == activerelease.StateCommitted && snapshot.Version != 3 {
			t.Fatalf("invalid saved cursor: %+v", snapshot)
		}
	}
}

func TestPF001CommitActiveReleaseReconcilesEverySaveAfterSideEffectCrashWindow(t *testing.T) {
	t.Parallel()

	for _, failState := range []activerelease.State{
		activerelease.StateCorePrepared,
		activerelease.StateHostCommitted,
		activerelease.StateCommitted,
	} {
		failState := failState
		t.Run(stateName(failState), func(t *testing.T) {
			t.Parallel()
			fixture := newActivationFixture(t)
			fixture.activation.failOnceState = failState
			_, firstError := fixture.application().Commit(context.Background(), fixture.command)
			assertActivationError(t, firstError, ErrorCodePersistence, true)

			result, retryError := fixture.application().Commit(context.Background(), fixture.command)
			if retryError != nil || result.Status != StatusCommitted || !fixture.core.committed || fixture.host.current.IsZero() {
				t.Fatalf("retry = %+v, %v", result, retryError)
			}
			if fixture.core.stageTargets != 1 {
				t.Fatalf("Core staged %d distinct targets", fixture.core.stageTargets)
			}
		})
	}
}

func TestPF001CommitActiveReleaseRequiresExactPersistedFreshReadinessReceipt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*activationFixture)
		code      ErrorCode
	}{
		{name: "missing", configure: func(value *activationFixture) { value.receipts.err = ErrReadinessReceiptNotFound }, code: ErrorCodeReadinessRequired},
		{name: "integrity", configure: func(value *activationFixture) { value.receipts.err = ErrReadinessReceiptIntegrity }, code: ErrorCodeIntegrityViolation},
		{name: "wrong digest", configure: func(value *activationFixture) {
			value.command.ReadinessReceiptDigest = install.DigestBytes([]byte("wrong"))
		}, code: ErrorCodeReadinessRequired},
		{name: "wrong release", configure: func(value *activationFixture) { value.command.ReleaseID = "other" }, code: ErrorCodeReadinessRequired},
		{name: "wrong generation", configure: func(value *activationFixture) { value.command.GenerationID = "019f5f22-5678-7def-9123-abcdef012346" }, code: ErrorCodeReadinessRequired},
		{name: "stale", configure: func(value *activationFixture) {
			value.clock.now = value.receipts.receipt.EvaluatedAt().Add(5*time.Minute + time.Microsecond)
		}, code: ErrorCodeReadinessRequired},
		{name: "future", configure: func(value *activationFixture) {
			value.clock.now = value.receipts.receipt.EvaluatedAt().Add(-time.Microsecond)
		}, code: ErrorCodeReadinessRequired},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newActivationFixture(t)
			test.configure(fixture)
			_, err := fixture.application().Commit(context.Background(), fixture.command)
			assertActivationError(t, err, test.code, false)
			if len(fixture.activation.saved) != 0 || !fixture.host.current.IsZero() || fixture.core.committed {
				t.Fatal("invalid readiness caused an activation side effect")
			}
		})
	}
}

func TestPF001CommitActiveReleaseRejectsRollbackForeignStateAndAmbiguousCAS(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		configure func(*activationFixture)
		code      ErrorCode
	}{
		{name: "release rollback", configure: func(value *activationFixture) {
			current := value.pointerInput()
			current.ReleaseSequence++
			value.host.current = mustActivePointer(t, current)
		}, code: ErrorCodeConflict},
		{name: "foreign installation", configure: func(value *activationFixture) {
			current := value.pointerInput()
			current.InstallationID = "019f5f20-1234-7abc-9123-0123456789ac"
			value.host.current = mustActivePointer(t, current)
		}, code: ErrorCodeConflict},
		{name: "CAS conflict", configure: func(value *activationFixture) { value.host.casError = ErrPointerConflict }, code: ErrorCodeConflict},
		{name: "host integrity", configure: func(value *activationFixture) { value.host.loadError = ErrPointerIntegrity }, code: ErrorCodeIntegrityViolation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newActivationFixture(t)
			test.configure(fixture)
			_, err := fixture.application().Commit(context.Background(), fixture.command)
			assertActivationError(t, err, test.code, false)
			if fixture.core.committed {
				t.Fatal("conflicting host state was committed in Core")
			}
		})
	}
}

func TestPF001CommitActiveReleaseIsIdempotentOnlyAfterHostAndCoreMatch(t *testing.T) {
	t.Parallel()

	fixture := newActivationFixture(t)
	first, err := fixture.application().Commit(context.Background(), fixture.command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := fixture.application().Commit(context.Background(), fixture.command)
	if err != nil || second.Status != StatusCommitted || !second.AlreadyActive || !second.PointerDigest.Equal(first.PointerDigest) {
		t.Fatalf("second = %+v, %v", second, err)
	}
	fixture.core.matches = false
	if _, err := fixture.application().Commit(context.Background(), fixture.command); err == nil {
		t.Fatal("Commit accepted host/Core pointer disagreement")
	}
}

func TestPF001CommitActiveReleaseSanitizesBoundariesAndRejectsInvalidComposition(t *testing.T) {
	t.Parallel()

	fixture := newActivationFixture(t)
	dependencies := fixture.dependencies()
	removals := []func(*Dependencies){
		func(value *Dependencies) { value.Clock = nil },
		func(value *Dependencies) { value.ReadinessReceipts = nil },
		func(value *Dependencies) { value.Activations = nil },
		func(value *Dependencies) { value.HostPointers = nil },
		func(value *Dependencies) { value.CorePointers = nil },
	}
	for _, remove := range removals {
		candidate := dependencies
		remove(&candidate)
		if _, err := New(candidate); err == nil {
			t.Fatal("New() accepted a missing dependency")
		}
	}
	var typedNil *activationRepository
	dependencies.Activations = typedNil
	if _, err := New(dependencies); err == nil {
		t.Fatal("New() accepted a typed-nil dependency")
	}

	fixture = newActivationFixture(t)
	fixture.core.stageError = errors.New("/raw/path secret")
	_, err := fixture.application().Commit(context.Background(), fixture.command)
	assertActivationError(t, err, ErrorCodeDependencyUnavailable, true)
	if err != nil && (contains(err.Error(), "/raw/path") || contains(err.Error(), "secret")) {
		t.Fatal("raw boundary error escaped")
	}

	fixture = newActivationFixture(t)
	fixture.command.InstallationID = "bad"
	_, err = fixture.application().Commit(context.Background(), fixture.command)
	assertActivationError(t, err, ErrorCodeInvalidArgument, false)

	fixture = newActivationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = fixture.application().Commit(ctx, fixture.command)
	assertActivationError(t, err, ErrorCodeDeadlineExceeded, true)
}

func TestPF001CommitActiveReleaseCoversRecoveryAndAgreementFailures(t *testing.T) {
	t.Parallel()

	t.Run("expected predecessor disappears", func(t *testing.T) {
		t.Parallel()
		fixture := newActivationFixture(t)
		oldInput := fixture.pointerInput()
		oldInput.ReleaseID = "release-v0"
		oldInput.ReleaseSequence--
		old := mustActivePointer(t, oldInput)
		target := mustActivePointer(t, fixture.pointerInput())
		activation, err := activerelease.NewActivation(fixture.command.OperationID, fixture.command.PlanDigest, old.Digest(), target)
		if err != nil {
			t.Fatal(err)
		}
		stage := install.DigestBytes([]byte("stage:" + target.Digest().String()))
		if err := activation.RecordCorePrepared(stage); err != nil {
			t.Fatal(err)
		}
		fixture.activation.current = activation
		fixture.core.stageDigest = stage
		_, err = fixture.application().Commit(context.Background(), fixture.command)
		assertActivationError(t, err, ErrorCodeConflict, false)
	})

	t.Run("existing predecessor is replaced", func(t *testing.T) {
		t.Parallel()
		fixture := newActivationFixture(t)
		oldInput := fixture.pointerInput()
		oldInput.ReleaseID = "release-v0"
		oldInput.ReleaseSequence--
		old := mustActivePointer(t, oldInput)
		target := mustActivePointer(t, fixture.pointerInput())
		activation, _ := activerelease.NewActivation(fixture.command.OperationID, fixture.command.PlanDigest, old.Digest(), target)
		stage := install.DigestBytes([]byte("stage:" + target.Digest().String()))
		_ = activation.RecordCorePrepared(stage)
		fixture.activation.current = activation
		fixture.host.current = old
		fixture.core.stageDigest = stage
		result, err := fixture.application().Commit(context.Background(), fixture.command)
		if err != nil || result.Status != StatusCommitted {
			t.Fatalf("Commit() = %+v, %v", result, err)
		}
	})

	tests := []struct {
		name      string
		configure func(*activationFixture)
		code      ErrorCode
		retryable bool
	}{
		{name: "nil aggregate", configure: func(value *activationFixture) { value.activation.returnNil = true }, code: ErrorCodeIntegrityViolation},
		{name: "activation integrity", configure: func(value *activationFixture) { value.activation.loadError = ErrActivationIntegrity }, code: ErrorCodeIntegrityViolation},
		{name: "activation conflict", configure: func(value *activationFixture) { value.activation.loadError = ErrActivationConflict }, code: ErrorCodeConflict, retryable: true},
		{name: "activation unavailable", configure: func(value *activationFixture) { value.activation.loadError = errors.New("private") }, code: ErrorCodePersistence, retryable: true},
		{name: "host confirm", configure: func(value *activationFixture) { value.host.confirmError = errors.New("private") }, code: ErrorCodePersistence, retryable: true},
		{name: "empty stage", configure: func(value *activationFixture) { value.core.emptyStage = true }, code: ErrorCodeInternal},
		{name: "foreign Core commit", configure: func(value *activationFixture) { value.core.foreignCommit = true }, code: ErrorCodeIntegrityViolation},
		{name: "Core agreement error", configure: func(value *activationFixture) { value.core.matchesError = errors.New("private") }, code: ErrorCodeDependencyUnavailable, retryable: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fixture := newActivationFixture(t)
			test.configure(fixture)
			_, err := fixture.application().Commit(context.Background(), fixture.command)
			assertActivationError(t, err, test.code, test.retryable)
		})
	}
}

func TestPF001ActivationBoundaryErrorMappingIsClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mapped    *ApplicationError
		code      ErrorCode
		retryable bool
	}{
		{name: "receipt canceled", mapped: mapReceiptError(context.Canceled), code: ErrorCodeDeadlineExceeded, retryable: true},
		{name: "receipt unknown", mapped: mapReceiptError(errors.New("raw")), code: ErrorCodePersistence, retryable: true},
		{name: "activation deadline", mapped: mapActivationRepositoryError(context.DeadlineExceeded), code: ErrorCodeDeadlineExceeded, retryable: true},
		{name: "pointer deadline", mapped: mapPointerError(context.DeadlineExceeded), code: ErrorCodeDeadlineExceeded, retryable: true},
		{name: "pointer not found", mapped: mapPointerError(ErrPointerNotFound), code: ErrorCodeIntegrityViolation},
		{name: "dependency deadline", mapped: mapDependencyError(context.DeadlineExceeded), code: ErrorCodeDeadlineExceeded, retryable: true},
	}
	for _, test := range tests {
		if test.mapped.Code() != test.code || test.mapped.Retryable() != test.retryable || test.mapped.Error() != string(test.code) {
			t.Fatalf("%s = %#v", test.name, test.mapped)
		}
	}
}

func TestPF001CommitActiveReleaseRejectsNilContextAndReconcilesOrphanHostCommit(t *testing.T) {
	t.Parallel()

	fixture := newActivationFixture(t)
	var nilContext context.Context
	if _, err := fixture.application().Commit(nilContext, fixture.command); err == nil {
		t.Fatal("Commit() accepted a nil context")
	} else {
		assertActivationError(t, err, ErrorCodeInvalidArgument, false)
	}
	if nilDependency(1) || !nilDependency(nil) {
		t.Fatal("dependency nil detection changed")
	}

	fixture = newActivationFixture(t)
	fixture.host.current = mustActivePointer(t, fixture.pointerInput())
	result, err := fixture.application().Commit(context.Background(), fixture.command)
	if err != nil || result.Status != StatusCommitted || !fixture.core.committed {
		t.Fatalf("Commit(orphan host pointer) = %+v, %v", result, err)
	}

	fixture = newActivationFixture(t)
	if _, err := fixture.application().Commit(context.Background(), fixture.command); err != nil {
		t.Fatal(err)
	}
	fixture.host.loadError = errors.New("private final host failure")
	_, err = fixture.application().Commit(context.Background(), fixture.command)
	assertActivationError(t, err, ErrorCodePersistence, true)
}

type activationFixture struct {
	t             *testing.T
	command       Command
	clock         *activationClock
	receipts      *receiptRepository
	activation    *activationRepository
	host          *hostPointerRepository
	core          *corePointerPort
	calls         []string
	releaseID     string
	generationID  string
	manifest      install.Digest
	compose       install.Digest
	inventory     install.Digest
	releaseSeq    uint64
	inventoryVers uint64
	securityEpoch uint64
}

func newActivationFixture(t *testing.T) *activationFixture {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	plan, _ := install.BindPlan([]byte("canonical plan"))
	now := time.Date(2026, 7, 13, 10, 11, 12, 123456000, time.UTC)
	fixture := &activationFixture{
		t:             t,
		clock:         &activationClock{now: now},
		releaseID:     "release-v1",
		generationID:  "019f5f21-5678-7def-9123-abcdef012345",
		manifest:      install.DigestBytes([]byte("manifest")),
		compose:       install.DigestBytes([]byte("compose")),
		inventory:     install.DigestBytes([]byte("inventory")),
		releaseSeq:    7,
		inventoryVers: 9,
		securityEpoch: 3,
	}
	fixture.receipts = &receiptRepository{calls: &fixture.calls}
	fixture.activation = &activationRepository{calls: &fixture.calls}
	fixture.host = &hostPointerRepository{calls: &fixture.calls}
	fixture.core = &corePointerPort{calls: &fixture.calls, matches: true}
	fixture.receipts.receipt = completeReadinessReceipt(t, operationID, plan, fixture.releaseID, fixture.generationID, fixture.manifest, fixture.compose, now)
	fixture.command = Command{
		OperationID:              operationID,
		PlanDigest:               plan,
		InstallationID:           "019f5f20-1234-7abc-8123-0123456789ab",
		ReleaseID:                fixture.releaseID,
		GenerationID:             fixture.generationID,
		ManifestDigest:           fixture.manifest,
		ComposeDigest:            fixture.compose,
		ReadinessReceiptDigest:   fixture.receipts.receipt.Digest(),
		RuntimeEndpoint:          "unix:///var/run/docker.sock",
		ReleaseSequence:          fixture.releaseSeq,
		ResourceInventoryVersion: fixture.inventoryVers,
		ResourceInventoryDigest:  fixture.inventory,
		SecurityEpoch:            fixture.securityEpoch,
	}
	return fixture
}

func (f *activationFixture) dependencies() Dependencies {
	return Dependencies{Clock: f.clock, ReadinessReceipts: f.receipts, Activations: f.activation, HostPointers: f.host, CorePointers: f.core}
}

func (f *activationFixture) application() *Application {
	f.t.Helper()
	application, err := New(f.dependencies())
	if err != nil {
		f.t.Fatal(err)
	}
	return application
}

func (f *activationFixture) pointerInput() activerelease.PointerInput {
	return activerelease.PointerInput{
		InstallationID: f.command.InstallationID, ReleaseID: f.command.ReleaseID, GenerationID: f.command.GenerationID,
		ManifestDigest: f.command.ManifestDigest, ComposeDigest: f.command.ComposeDigest,
		ReadinessReceiptDigest: f.command.ReadinessReceiptDigest, RuntimeEndpoint: f.command.RuntimeEndpoint,
		ReleaseSequence: f.command.ReleaseSequence, ResourceInventoryVersion: f.command.ResourceInventoryVersion,
		ResourceInventoryDigest: f.command.ResourceInventoryDigest, SecurityEpoch: f.command.SecurityEpoch,
		ActivatedAt: f.clock.now,
	}
}

type activationClock struct{ now time.Time }

func (c *activationClock) Now() time.Time { return c.now }

type receiptRepository struct {
	receipt readiness.Receipt
	err     error
	calls   *[]string
}

func (r *receiptRepository) LoadReadinessReceipt(context.Context, install.Digest) (readiness.Receipt, error) {
	*r.calls = append(*r.calls, "receipt.load")
	return r.receipt, r.err
}

type activationRepository struct {
	current       *activerelease.Activation
	saved         []activerelease.ActivationSnapshot
	failOnceState activerelease.State
	loadError     error
	returnNil     bool
	calls         *[]string
}

func (r *activationRepository) Load(context.Context, install.OperationID) (*activerelease.Activation, error) {
	*r.calls = append(*r.calls, "activation.load")
	if r.loadError != nil {
		return nil, r.loadError
	}
	if r.returnNil {
		return nil, nil
	}
	if r.current == nil {
		return nil, ErrActivationNotFound
	}
	restored, err := activerelease.RestoreActivation(r.current.Snapshot())
	return restored, err
}

func (r *activationRepository) Save(_ context.Context, snapshot activerelease.ActivationSnapshot) error {
	*r.calls = append(*r.calls, "activation.save."+stateName(snapshot.State))
	if r.failOnceState == snapshot.State {
		r.failOnceState = activerelease.StateUnknown
		return errors.New("simulated durable save failure")
	}
	restored, err := activerelease.RestoreActivation(snapshot)
	if err != nil {
		return err
	}
	r.current = restored
	r.saved = append(r.saved, snapshot)
	return nil
}

type hostPointerRepository struct {
	current      activerelease.Pointer
	loadError    error
	casError     error
	confirmError error
	calls        *[]string
}

func (r *hostPointerRepository) Load(context.Context, string) (activerelease.Pointer, error) {
	*r.calls = append(*r.calls, "host.load")
	if r.loadError != nil {
		return activerelease.Pointer{}, r.loadError
	}
	if r.current.IsZero() {
		return activerelease.Pointer{}, ErrPointerNotFound
	}
	return r.current, nil
}

func (r *hostPointerRepository) CompareAndSwap(_ context.Context, expected install.Digest, target activerelease.Pointer) error {
	*r.calls = append(*r.calls, "host.cas")
	if r.casError != nil {
		return r.casError
	}
	if r.current.IsZero() && !expected.IsZero() || !r.current.IsZero() && !r.current.Digest().Equal(expected) {
		return ErrPointerConflict
	}
	r.current = target
	return nil
}

func (r *hostPointerRepository) ConfirmDurable(context.Context, activerelease.Pointer) error {
	*r.calls = append(*r.calls, "host.confirm")
	return r.confirmError
}

type corePointerPort struct {
	stageDigest   install.Digest
	stageError    error
	commitError   error
	committed     bool
	matches       bool
	emptyStage    bool
	foreignCommit bool
	matchesError  error
	stageTargets  int
	calls         *[]string
}

func (p *corePointerPort) Stage(_ context.Context, _ install.OperationID, pointer activerelease.Pointer, _ readiness.Receipt) (install.Digest, error) {
	*p.calls = append(*p.calls, "core.stage")
	if p.stageError != nil {
		return install.Digest{}, p.stageError
	}
	if p.emptyStage {
		return install.Digest{}, nil
	}
	if p.stageDigest.IsZero() {
		p.stageDigest = install.DigestBytes([]byte("stage:" + pointer.Digest().String()))
		p.stageTargets++
	}
	return p.stageDigest, nil
}

func (p *corePointerPort) Commit(
	_ context.Context,
	_ install.OperationID,
	_ install.Digest,
	pointer activerelease.Pointer,
) (install.Digest, error) {
	*p.calls = append(*p.calls, "core.commit")
	if p.commitError != nil {
		return install.Digest{}, p.commitError
	}
	p.committed = true
	if p.foreignCommit {
		return install.DigestBytes([]byte("foreign")), nil
	}
	return pointer.Digest(), nil
}

func (p *corePointerPort) Matches(context.Context, activerelease.Pointer) (bool, error) {
	*p.calls = append(*p.calls, "core.matches")
	return p.matches, p.matchesError
}

func completeReadinessReceipt(
	t *testing.T,
	operationID install.OperationID,
	plan install.PlanDigest,
	release string,
	generation string,
	manifest install.Digest,
	compose install.Digest,
	now time.Time,
) readiness.Receipt {
	t.Helper()
	results := make([]readiness.Result, 0, len(readiness.RequiredProbes()))
	for _, probe := range readiness.RequiredProbes() {
		result, err := readiness.NewResult(readiness.ResultInput{
			Probe: probe, Status: readiness.StatusPassed, OperationID: operationID, PlanDigest: plan,
			ReleaseID: release, GenerationID: generation, ManifestDigest: manifest, ComposeDigest: compose,
			EvidenceDigest: install.DigestBytes([]byte(probe.String())), ObservedAt: now,
		})
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	receipt, failures := readiness.NewGate().Evaluate(readiness.GateInput{
		OperationID: operationID, PlanDigest: plan, ReleaseID: release, GenerationID: generation,
		ManifestDigest: manifest, ComposeDigest: compose, EvaluatedAt: now, Results: results,
	})
	if len(failures) != 0 {
		t.Fatalf("readiness failures = %v", failures)
	}
	return receipt
}

func mustActivePointer(t *testing.T, input activerelease.PointerInput) activerelease.Pointer {
	t.Helper()
	pointer, err := activerelease.NewPointer(input)
	if err != nil {
		t.Fatal(err)
	}
	return pointer
}

func stateName(state activerelease.State) string {
	switch state {
	case activerelease.StateCreated:
		return "created"
	case activerelease.StateCorePrepared:
		return "core_prepared"
	case activerelease.StateHostCommitted:
		return "host_committed"
	case activerelease.StateCommitted:
		return "committed"
	case activerelease.StateUnknown:
		return "unknown"
	}
	return "unknown"
}

func assertActivationError(t *testing.T, err error, code ErrorCode, retryable bool) {
	t.Helper()
	var typed *ApplicationError
	if !errors.As(err, &typed) || typed.Code() != code || typed.Retryable() != retryable {
		t.Fatalf("error = %#v, want %s retryable=%v", err, code, retryable)
	}
}

func contains(value string, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}
