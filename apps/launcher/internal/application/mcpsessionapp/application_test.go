package mcpsessionapp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/activerelease"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/mcpsession"
)

const (
	applicationSessionID = "019d2b4e-7a10-7def-8abc-0123456789ab"
	applicationInstallID = "019d2b4e-7a11-7def-8abc-0123456789ab"
	applicationBrainID   = "019d2b4e-7a13-7def-8abc-0123456789ab"
	applicationActorID   = "019d2b4e-7a14-7def-8abc-0123456789ab"
	applicationGrantID   = "019d2b4e-7a15-7def-8abc-0123456789ab"
	applicationImage     = "registry.local/agentmemory/mcp-session@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	applicationHash      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	credentialHash       = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

var applicationNow = time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

func TestPF005StartRunsExactSessionAndCompletesOnlyAfterCheckpoint(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.child.delay = 30 * time.Millisecond

	result, err := fixture.application.Start(context.Background(), fixture.command())

	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if result.SessionID != applicationSessionID || result.Status != StatusCompleted {
		t.Fatalf("Start() result = %#v", result)
	}
	if fixture.child.plan.SessionID() != applicationSessionID ||
		fixture.child.plan.WorkspaceMount().Source() != fixture.paths.realPath ||
		fixture.child.plan.Network() != fixture.release.Network() ||
		fixture.child.plan.Image() != fixture.release.Image() {
		t.Fatalf("child plan = %#v", fixture.child.plan)
	}
	if !fixture.child.lockReleasedAtRun {
		t.Fatal("child started while startup lock remained held")
	}
	if fixture.sessions.heartbeats == 0 {
		t.Fatal("session emitted no heartbeat")
	}
	if fixture.checkpoints.begins != 1 || fixture.checkpoints.calls != 1 || fixture.credentials.revocations != 1 ||
		fixture.child.removals != 1 || fixture.sessions.finished != StatusCompleted {
		t.Fatalf(
			"cleanup checkpoint=%d revoke=%d remove=%d finish=%s",
			fixture.checkpoints.calls, fixture.credentials.revocations,
			fixture.child.removals, fixture.sessions.finished,
		)
	}
	if fixture.output.String() != "mcp-frame\n" || fixture.diagnostics.String() != "diagnostic\n" {
		t.Fatalf("stdio output=%q diagnostics=%q", fixture.output.String(), fixture.diagnostics.String())
	}
}

func TestPF005FailedCheckpointMarksSessionInterrupted(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.checkpoints.err = errors.New("private checkpoint failure")

	result, err := fixture.application.Start(context.Background(), fixture.command())

	if !IsUnavailable(err) || result.Status != StatusInterrupted {
		t.Fatalf("Start() result=%#v error=%v", result, err)
	}
	if fixture.sessions.finished != StatusInterrupted || fixture.credentials.revocations != 1 ||
		fixture.child.removals != 1 {
		t.Fatalf("interrupted cleanup = %#v", fixture)
	}
}

func TestPF005CancellationRevokesCredentialRemovesContainerAndInterrupts(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.child.block = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := fixture.application.Start(ctx, fixture.command())
		done <- err
	}()
	<-fixture.child.started
	cancel()

	err := <-done
	if !IsDeadline(err) || fixture.sessions.finished != StatusInterrupted ||
		fixture.credentials.revocations != 1 || fixture.child.removals != 1 {
		t.Fatalf("cancel error=%v fixture=%#v", err, fixture)
	}
}

func TestPF005StartupFailureNeverRunsChildAndRevokesMintedCredential(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.sessions.beginError = errors.New("private persistence failure")

	_, err := fixture.application.Start(context.Background(), fixture.command())

	if !IsUnavailable(err) || fixture.child.runs != 0 || fixture.credentials.revocations != 1 ||
		fixture.lock.releases != 1 {
		t.Fatalf("startup error=%v fixture=%#v", err, fixture)
	}
}

func TestPF005BaselineFailureNeverRunsChildAndSettlesBegunSession(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.checkpoints.beginErr = errors.New("private baseline failure")

	_, err := fixture.application.Start(context.Background(), fixture.command())

	if !IsUnavailable(err) || fixture.child.runs != 0 || fixture.credentials.revocations != 1 ||
		fixture.lock.releases != 1 || fixture.sessions.finished != StatusInterrupted {
		t.Fatalf("baseline error=%v fixture=%#v", err, fixture)
	}
}

func TestPF005RuntimeAndIdentityResolutionRemainInsideStartupLock(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.runtime.lock = fixture.lock
	fixture.paths.lock = fixture.lock
	fixture.git.lock = fixture.lock
	fixture.credentials.lock = fixture.lock
	fixture.sessions.lock = fixture.lock

	if _, err := fixture.application.Start(context.Background(), fixture.command()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if fixture.runtime.calledWithoutLock || fixture.paths.calledWithoutLock ||
		fixture.git.calledWithoutLock || fixture.credentials.mintedWithoutLock ||
		fixture.sessions.beganWithoutLock {
		t.Fatalf("startup capability escaped lock: %#v", fixture)
	}
}

func TestPF005RejectsPartialCompositionAndInvalidCommand(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	dependencies := fixture.dependencies
	dependencies.Child = nil
	if _, err := New(dependencies, testPolicy()); !IsIntegrity(err) {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := fixture.application.Start(context.Background(), Command{}); !IsInvalidArgument(err) {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestPF005ProductionPolicyAndTypedErrorsAreClosed(t *testing.T) {
	t.Parallel()
	if !ProductionPolicy().valid() {
		t.Fatal("ProductionPolicy() is invalid")
	}
	err := newError(errorIntegrity)
	if err.Error() != "AM_SESSION_INTEGRITY" || err.Code() != errorIntegrity ||
		!IsIntegrity(err) || IsUnavailable(err) {
		t.Fatalf("application error = %#v", err)
	}
	if _, releaseError := NewSessionRelease(activerelease.Pointer{}, applicationImage, "bridge"); !IsIntegrity(releaseError) {
		t.Fatalf("NewSessionRelease(invalid) error = %v", releaseError)
	}
}

func TestPF005LockReleaseFailureSettlesUnstartedSession(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.lock.releaseError = errors.New("private release failure")

	result, err := fixture.application.Start(context.Background(), fixture.command())

	if !IsUnavailable(err) || result.Status != StatusInterrupted || fixture.child.runs != 0 ||
		fixture.child.removals != 1 || fixture.credentials.revocations != 1 ||
		fixture.sessions.finished != StatusInterrupted {
		t.Fatalf("release failure result=%#v error=%v fixture=%#v", result, err, fixture)
	}
}

func TestPF005HeartbeatFailureCancelsChildAndReturnsUnavailable(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	fixture.child.block = true
	fixture.sessions.heartbeatError = errors.New("private heartbeat failure")

	result, err := fixture.application.Start(context.Background(), fixture.command())

	if !IsUnavailable(err) || result.Status != StatusInterrupted ||
		fixture.sessions.heartbeats != 1 || fixture.credentials.revocations != 1 ||
		fixture.child.removals != 1 {
		t.Fatalf("heartbeat result=%#v error=%v fixture=%#v", result, err, fixture)
	}
}

func TestPF005CancelledContextStopsBeforeLockAcquisition(t *testing.T) {
	t.Parallel()
	fixture := newApplicationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := fixture.application.Start(ctx, fixture.command())

	if !IsDeadline(err) || fixture.lock.acquisitions != 0 {
		t.Fatalf("Start(cancelled) error=%v acquisitions=%d", err, fixture.lock.acquisitions)
	}
}

func TestPF005ConcurrentDirectoriesSerializeStartupAndRunDistinctSessions(t *testing.T) {
	t.Parallel()
	first := newApplicationFixture(t)
	second := newApplicationFixture(t)
	second.ids.id = "019d2b4e-7a10-7def-8abc-0123456789ac"
	second.paths.logicalPath = "/Users/ricky/Second β"
	second.paths.realPath = "/Users/ricky/Second β"
	lock := newSerialLockPort()
	for _, fixture := range []*applicationFixture{first, second} {
		fixture.dependencies.Lock = lock
		fixture.child.lock = nil
		fixture.child.delay = 40 * time.Millisecond
		application, err := New(fixture.dependencies, testPolicy())
		if err != nil {
			t.Fatal(err)
		}
		fixture.application = application
	}
	results := make(chan Result, 2)
	errors := make(chan error, 2)
	for _, fixture := range []*applicationFixture{first, second} {
		go func(current *applicationFixture) {
			result, err := current.application.Start(t.Context(), current.command())
			results <- result
			errors <- err
		}(fixture)
	}
	for range 2 {
		if err := <-errors; err != nil {
			t.Fatalf("concurrent Start() error=%v", err)
		}
	}
	one, two := <-results, <-results
	if one.SessionID == two.SessionID || one.Status != StatusCompleted || two.Status != StatusCompleted {
		t.Fatalf("results=%+v/%+v", one, two)
	}
	if lock.maximum() != 1 || first.child.plan.WorkspaceMount().Source() ==
		second.child.plan.WorkspaceMount().Source() {
		t.Fatalf("lock maximum=%d plans=%+v/%+v", lock.maximum(), first.child.plan, second.child.plan)
	}
}

func TestPF005CleanupFailureNeverReportsOrPersistsCompleted(t *testing.T) {
	t.Parallel()
	for _, scenario := range []string{"credential_revoke", "container_remove", "session_finish"} {
		scenario := scenario
		t.Run(scenario, func(t *testing.T) {
			t.Parallel()
			fixture := newApplicationFixture(t)
			switch scenario {
			case "credential_revoke":
				fixture.credentials.revokeError = errors.New("private revoke failure")
			case "container_remove":
				fixture.child.removeError = errors.New("private remove failure")
			case "session_finish":
				fixture.sessions.finishError = errors.New("private finish failure")
			default:
				t.Fatal("unknown scenario")
			}

			result, err := fixture.application.Start(t.Context(), fixture.command())

			if !IsUnavailable(err) || result.Status != StatusInterrupted ||
				fixture.credentials.revocations != 1 || fixture.child.removals != 1 {
				t.Fatalf("result=%+v error=%v fixture=%+v", result, err, fixture)
			}
			if scenario != "session_finish" && fixture.sessions.finished != StatusInterrupted {
				t.Fatalf("durable status=%s", fixture.sessions.finished)
			}
		})
	}
}

func TestPF005StartupCancellationMatrixReleasesAuthorityAndNeverRunsChild(t *testing.T) {
	t.Parallel()
	for _, stage := range []string{
		"active_release", "runtime", "path", "git", "session_id", "credential", "begin", "baseline",
	} {
		stage := stage
		t.Run(stage, func(t *testing.T) {
			t.Parallel()
			fixture := newApplicationFixture(t)
			switch stage {
			case "active_release":
				fixture.releases.err = context.Canceled
			case "runtime":
				fixture.runtime.err = context.Canceled
			case "path":
				fixture.paths.err = context.Canceled
			case "git":
				fixture.git.err = context.Canceled
			case "session_id":
				fixture.ids.err = context.Canceled
			case "credential":
				fixture.credentials.mintError = context.Canceled
			case "begin":
				fixture.sessions.beginError = context.Canceled
			case "baseline":
				fixture.checkpoints.beginErr = context.Canceled
			default:
				t.Fatal("unknown stage")
			}

			_, err := fixture.application.Start(t.Context(), fixture.command())

			if !IsDeadline(err) || fixture.child.runs != 0 || fixture.lock.releases != 1 {
				t.Fatalf("stage=%s error=%v fixture=%+v", stage, err, fixture)
			}
			minted := stage == "begin" || stage == "baseline"
			if (fixture.credentials.revocations == 1) != minted {
				t.Fatalf("stage=%s revocations=%d", stage, fixture.credentials.revocations)
			}
			if stage == "baseline" && fixture.sessions.finished != StatusInterrupted {
				t.Fatalf("baseline durable status=%s", fixture.sessions.finished)
			}
		})
	}
}

type applicationFixture struct {
	application  *Application
	dependencies Dependencies
	lock         *lockPort
	releases     *activeReleasePort
	runtime      *runtimeController
	paths        *pathIdentityPort
	git          *gitIdentityPort
	ids          *sessionIDPort
	credentials  *credentialPort
	sessions     *sessionRepository
	child        *childProcessPort
	checkpoints  *checkpointPort
	output       bytes.Buffer
	diagnostics  bytes.Buffer
	release      SessionRelease
}

type serialLockPort struct {
	semaphore chan struct{}
	mu        sync.Mutex
	holders   int
	max       int
}

func newSerialLockPort() *serialLockPort {
	return &serialLockPort{semaphore: make(chan struct{}, 1)}
}

func (p *serialLockPort) Acquire(ctx context.Context) (InstallationLock, error) {
	select {
	case p.semaphore <- struct{}{}:
		p.mu.Lock()
		p.holders++
		if p.holders > p.max {
			p.max = p.holders
		}
		p.mu.Unlock()
		return &serialHeldLock{owner: p}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *serialLockPort) maximum() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.max
}

type serialHeldLock struct {
	owner *serialLockPort
	once  sync.Once
}

func (l *serialHeldLock) Release(context.Context) error {
	l.once.Do(func() {
		l.owner.mu.Lock()
		l.owner.holders--
		l.owner.mu.Unlock()
		<-l.owner.semaphore
	})
	return nil
}

func newApplicationFixture(t testing.TB) *applicationFixture {
	t.Helper()
	pointer := activePointer(t)
	release, err := NewSessionRelease(
		pointer, applicationImage, "agentmemory_019d2b4e7a117def8abc0123456789ab_internal",
	)
	if err != nil {
		t.Fatalf("NewSessionRelease() error = %v", err)
	}
	fixture := &applicationFixture{
		lock:        &lockPort{},
		releases:    &activeReleasePort{pointer: pointer},
		runtime:     &runtimeController{release: release},
		paths:       &pathIdentityPort{logicalPath: "/Users/ricky/Project α", realPath: "/Users/ricky/Project α"},
		git:         &gitIdentityPort{},
		ids:         &sessionIDPort{id: applicationSessionID},
		credentials: &credentialPort{},
		sessions:    &sessionRepository{},
		child:       &childProcessPort{started: make(chan struct{})},
		checkpoints: &checkpointPort{},
		release:     release,
	}
	fixture.dependencies = Dependencies{
		Authority: SessionAuthorityScope{
			BrainID: applicationBrainID, ActorID: applicationActorID, GrantID: applicationGrantID,
		},
		Lock: fixture.lock, ActiveRelease: fixture.releases, Runtime: fixture.runtime,
		Paths: fixture.paths, Git: fixture.git, IDs: fixture.ids, Credentials: fixture.credentials,
		Sessions: fixture.sessions, Child: fixture.child, Checkpoints: fixture.checkpoints,
		Clock: fixedClock{value: applicationNow},
	}
	fixture.child.lock = fixture.lock
	application, err := New(fixture.dependencies, testPolicy())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	fixture.application = application
	return fixture
}

func (f *applicationFixture) command() Command {
	return Command{
		AgentID: "codex", WorkingDirectory: f.paths.logicalPath,
		Input: bytes.NewBufferString("request\n"), Output: &f.output, Diagnostics: &f.diagnostics,
	}
}

func testPolicy() Policy {
	return Policy{
		HeartbeatInterval: 5 * time.Millisecond,
		LeaseTimeout:      50 * time.Millisecond,
		CredentialTTL:     12 * time.Hour,
		CheckpointTimeout: 100 * time.Millisecond,
		CleanupTimeout:    100 * time.Millisecond,
	}
}

func activePointer(t testing.TB) activerelease.Pointer {
	t.Helper()
	digest := func(value string) install.Digest {
		result, err := install.ParseDigest(value)
		if err != nil {
			t.Fatalf("ParseDigest() error = %v", err)
		}
		return result
	}
	pointer, err := activerelease.NewPointer(activerelease.PointerInput{
		InstallationID: applicationInstallID,
		ReleaseID:      "v1.0.0",
		GenerationID:   "019d2b4e-7a12-7def-8abc-0123456789ab",
		ManifestDigest: digest("1111111111111111111111111111111111111111111111111111111111111111"),
		ComposeDigest:  digest("2222222222222222222222222222222222222222222222222222222222222222"),
		ReadinessReceiptDigest: digest(
			"3333333333333333333333333333333333333333333333333333333333333333",
		),
		RuntimeEndpoint:          "unix:///var/run/docker.sock",
		ReleaseSequence:          1,
		ResourceInventoryVersion: 1,
		ResourceInventoryDigest:  digest("4444444444444444444444444444444444444444444444444444444444444444"),
		SecurityEpoch:            1,
		ActivatedAt:              applicationNow.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("NewPointer() error = %v", err)
	}
	return pointer
}

type heldLock struct {
	owner    *lockPort
	released bool
}

func (l *heldLock) Release(context.Context) error {
	l.owner.mu.Lock()
	defer l.owner.mu.Unlock()
	if !l.released {
		l.released = true
		l.owner.held = false
		l.owner.releases++
	}
	return l.owner.releaseError
}

type lockPort struct {
	mu           sync.Mutex
	held         bool
	acquisitions int
	releases     int
	releaseError error
}

func (p *lockPort) Acquire(context.Context) (InstallationLock, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.held {
		return nil, errors.New("lock already held")
	}
	p.held = true
	p.acquisitions++
	return &heldLock{owner: p}, nil
}

func (p *lockPort) isHeld() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.held
}

type activeReleasePort struct {
	pointer activerelease.Pointer
	err     error
}

func (p *activeReleasePort) LoadActive(context.Context) (activerelease.Pointer, error) {
	return p.pointer, p.err
}

type runtimeController struct {
	release           SessionRelease
	lock              *lockPort
	calledWithoutLock bool
	err               error
}

func (c *runtimeController) EnsureReady(_ context.Context, pointer activerelease.Pointer) (SessionRelease, error) {
	if c.lock != nil && !c.lock.isHeld() {
		c.calledWithoutLock = true
	}
	if c.err != nil {
		return SessionRelease{}, c.err
	}
	if !pointer.Digest().Equal(c.release.Pointer().Digest()) {
		return SessionRelease{}, errors.New("pointer mismatch")
	}
	return c.release, nil
}

type pathIdentityPort struct {
	logicalPath       string
	realPath          string
	lock              *lockPort
	calledWithoutLock bool
	err               error
}

func (p *pathIdentityPort) Resolve(_ context.Context, logicalPath string) (PathIdentity, error) {
	if p.lock != nil && !p.lock.isHeld() {
		p.calledWithoutLock = true
	}
	if p.err != nil {
		return PathIdentity{}, p.err
	}
	if logicalPath != p.logicalPath {
		return PathIdentity{}, errors.New("path mismatch")
	}
	return PathIdentity{
		LogicalPath: logicalPath, RealPath: p.realPath,
		DeviceIdentity: "dev:1", PathFingerprint: applicationHash,
	}, nil
}

type gitIdentityPort struct {
	lock              *lockPort
	calledWithoutLock bool
	err               error
}

func (p *gitIdentityPort) Resolve(_ context.Context, _ PathIdentity) (GitIdentity, error) {
	if p.lock != nil && !p.lock.isHeld() {
		p.calledWithoutLock = true
	}
	if p.err != nil {
		return GitIdentity{}, p.err
	}
	return GitIdentity{Coverage: mcpsession.GitCoverageNone}, nil
}

type sessionIDPort struct {
	id  string
	err error
}

func (p *sessionIDPort) NewSessionID(context.Context) (string, error) { return p.id, p.err }

type credentialPort struct {
	lock              *lockPort
	mintedWithoutLock bool
	revocations       int
	mintError         error
	revokeError       error
}

func (p *credentialPort) Mint(_ context.Context, scope CredentialScope) (mcpsession.CredentialLease, error) {
	if p.lock != nil && !p.lock.isHeld() {
		p.mintedWithoutLock = true
	}
	if p.mintError != nil {
		return mcpsession.CredentialLease{}, p.mintError
	}
	return mcpsession.NewCredentialLease(
		credentialHash, "/owner/session.key", applicationNow,
		applicationNow.Add(scope.TTL),
	)
}

func (p *credentialPort) Revoke(context.Context, mcpsession.CredentialLease) error {
	p.revocations++
	return p.revokeError
}

type sessionRepository struct {
	lock             *lockPort
	beganWithoutLock bool
	beginError       error
	heartbeats       int
	heartbeatError   error
	finished         Status
	finishError      error
}

func (r *sessionRepository) Begin(_ context.Context, _ mcpsession.ExecutionPlan, _ time.Duration) error {
	if r.lock != nil && !r.lock.isHeld() {
		r.beganWithoutLock = true
	}
	return r.beginError
}

func (r *sessionRepository) Heartbeat(context.Context, string, time.Time) error {
	r.heartbeats++
	return r.heartbeatError
}

func (r *sessionRepository) Finish(_ context.Context, _ string, status Status, _ time.Time) error {
	r.finished = status
	return r.finishError
}

type childProcessPort struct {
	lock              *lockPort
	started           chan struct{}
	delay             time.Duration
	block             bool
	runs              int
	removals          int
	plan              mcpsession.ExecutionPlan
	lockReleasedAtRun bool
	runError          error
	removeError       error
}

func (p *childProcessPort) Run(ctx context.Context, plan mcpsession.ExecutionPlan, streams Streams) error {
	p.runs++
	p.plan = plan
	p.lockReleasedAtRun = p.lock == nil || !p.lock.isHeld()
	close(p.started)
	if _, err := io.WriteString(streams.Output, "mcp-frame\n"); err != nil {
		return err
	}
	if _, err := io.WriteString(streams.Diagnostics, "diagnostic\n"); err != nil {
		return err
	}
	if p.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if p.runError != nil {
		return p.runError
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(p.delay):
		return nil
	}
}

func (p *childProcessPort) Remove(context.Context, mcpsession.ExecutionPlan) error {
	p.removals++
	return p.removeError
}

type checkpointPort struct {
	begins   int
	calls    int
	beginErr error
	err      error
}

func (p *checkpointPort) Begin(context.Context, mcpsession.ExecutionPlan) error {
	p.begins++
	return p.beginErr
}

func (p *checkpointPort) Checkpoint(context.Context, mcpsession.ExecutionPlan) error {
	p.calls++
	return p.err
}

type fixedClock struct{ value time.Time }

func (c fixedClock) Now() time.Time { return c.value }
