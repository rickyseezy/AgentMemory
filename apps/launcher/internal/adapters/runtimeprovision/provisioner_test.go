package runtimeprovision

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxProvisionerCompletesCertifiedRootlessInstallThroughExactTypedEffects(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	clock := &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)}
	broker := &fakePrivilegeBroker{}
	replay := &fakeReplayLedger{consumed: make(map[runtimeport.Nonce]runtimeinstall.Hash)}
	rootless := &fakeRunner{authority: rootlessAuthority(t, authority)}
	consent := newFakeLinuxConsent()
	provisioner, err := NewLinuxProvisioner(Dependencies{
		Authority: staticAuthorityResolver{authority: authority}, Host: staticHostProbe{evidence: supportedHost(t, authority)},
		Runtime: &installRuntimeInspector{authority: authority}, Capabilities: completeCapabilityProbe{},
		Consent: consent, ConsentAuth: consent, ConsentStore: consent,
		Privilege: broker, Authenticator: acceptingAuthenticator{}, Replay: replay,
		Nonces: &incrementingNonces{}, Clock: clock, RootlessTool: rootless,
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := &memoryRuntimeRepository{}
	otherPhases := completeOtherPhases{artifact: authority.ArtifactDigest()}
	application, err := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
		Operations: repository, Host: provisioner, Detector: provisioner,
		Catalog: provisioner, Consent: provisioner, Fetcher: otherPhases, Verifier: otherPhases,
		Prerequisites: provisioner, Installer: provisioner, Terms: provisioner,
		Controller: provisioner, Capabilities: provisioner,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := application.Ensure(context.Background(), runtimeinstallapp.Command{
		OperationID: "install-linux-1", CanonicalPlan: plan.CanonicalBytes(),
	})
	if err != nil || result.State != runtimeinstall.OperationStateReady || result.ErrorCode != runtimeinstallapp.ErrorCodeNone {
		t.Fatalf("Ensure() = state:%s code:%s error:%v", result.State, result.ErrorCode, err)
	}
	if _, present := result.CompletionReceipt(); !present {
		t.Fatal("ready Linux provisioning omitted aggregate completion evidence")
	}
	wantedOperations := []runtimeport.PrivilegeOperation{
		runtimeport.PrivilegeConfigureRepository,
		runtimeport.PrivilegeConfigureSubordinateIDs,
		runtimeport.PrivilegeInstallPackages,
		runtimeport.PrivilegeEnableUserService,
		runtimeport.PrivilegeVerifyManagedState,
	}
	if !slices.Equal(broker.operations, wantedOperations) {
		t.Fatalf("privilege operations = %v, want %v", broker.operations, wantedOperations)
	}
	if rootless.calls != 1 || len(replay.consumed) != len(wantedOperations) {
		t.Fatalf("rootless calls = %d, consumed receipts = %d", rootless.calls, len(replay.consumed))
	}
	if !rootless.sawSanitizedRootlessEnvironment {
		t.Fatal("rootless tool did not receive the closed sanitized environment profile")
	}
}

func TestLinuxProvisionerMapsPrivilegeAndAuthorityFailuresWithoutRootfulFallback(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	tests := []struct {
		name       string
		resolver   runtimeport.AuthorityResolver
		consentErr error
		brokerErr  error
		state      runtimeinstall.OperationState
	}{
		{name: "unsigned execution projection", resolver: staticAuthorityResolver{err: runtimeport.ErrAuthorityUnavailable}, state: runtimeinstall.OperationStatePausedForAdministrator},
		{name: "consent surface unavailable", resolver: staticAuthorityResolver{authority: authority}, consentErr: runtimeport.ErrLinuxConsentUnavailable, state: runtimeinstall.OperationStatePausedForAdministrator},
		{name: "consent declined", resolver: staticAuthorityResolver{authority: authority}, consentErr: runtimeport.ErrLinuxConsentDeclined, state: runtimeinstall.OperationStateCancelled},
		{name: "native prompt unavailable", resolver: staticAuthorityResolver{authority: authority}, brokerErr: runtimeport.ErrPrivilegeUnavailable, state: runtimeinstall.OperationStatePausedForAdministrator},
		{name: "native prompt declined", resolver: staticAuthorityResolver{authority: authority}, brokerErr: runtimeport.ErrPrivilegeDenied, state: runtimeinstall.OperationStateCancelled},
		{name: "policy blocked", resolver: staticAuthorityResolver{authority: authority}, brokerErr: runtimeport.ErrPrivilegePolicy, state: runtimeinstall.OperationStatePausedForAdministrator},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			broker := &fakePrivilegeBroker{err: test.brokerErr}
			consent := newFakeLinuxConsent()
			consent.awaitErr = test.consentErr
			rootless := &fakeRunner{authority: rootlessAuthority(t, authority)}
			provisioner, err := NewLinuxProvisioner(Dependencies{
				Authority: test.resolver, Host: staticHostProbe{evidence: supportedHost(t, authority)},
				Runtime: &installRuntimeInspector{authority: authority}, Capabilities: completeCapabilityProbe{},
				Consent: consent, ConsentAuth: consent, ConsentStore: consent,
				Privilege: broker, Authenticator: acceptingAuthenticator{},
				Replay: &fakeReplayLedger{consumed: make(map[runtimeport.Nonce]runtimeinstall.Hash)},
				Nonces: &incrementingNonces{}, Clock: &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)},
				RootlessTool: rootless,
			})
			if err != nil {
				t.Fatal(err)
			}
			other := completeOtherPhases{artifact: authority.ArtifactDigest()}
			application, _ := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
				Operations: &memoryRuntimeRepository{}, Host: provisioner, Detector: provisioner,
				Catalog: provisioner, Consent: provisioner, Fetcher: other, Verifier: other,
				Prerequisites: provisioner, Installer: provisioner, Terms: provisioner,
				Controller: provisioner, Capabilities: provisioner,
			})
			result, ensureError := application.Ensure(context.Background(), runtimeinstallapp.Command{
				OperationID: "failure-case", CanonicalPlan: plan.CanonicalBytes(),
			})
			if ensureError != nil || result.State != test.state {
				t.Fatalf("Ensure() = state:%s error:%v, want %s", result.State, ensureError, test.state)
			}
			if rootless.calls != 0 {
				t.Fatal("rootless tool ran after authority or privilege denial")
			}
		})
	}
}

func TestLinuxProvisionerRejectsForgedExpiredAndReplayedPrivilegeReceipts(t *testing.T) {
	t.Parallel()
	plan, authority := adapterAuthority(t)
	tests := []struct {
		name   string
		broker *fakePrivilegeBroker
		replay *fakeReplayLedger
	}{
		{name: "forged state", broker: &fakePrivilegeBroker{forgeState: true}, replay: &fakeReplayLedger{consumed: make(map[runtimeport.Nonce]runtimeinstall.Hash)}},
		{name: "bad signature", broker: &fakePrivilegeBroker{}, replay: &fakeReplayLedger{consumed: make(map[runtimeport.Nonce]runtimeinstall.Hash)}},
		{name: "replayed nonce", broker: &fakePrivilegeBroker{}, replay: &fakeReplayLedger{err: runtimeport.ErrPrivilegeIntegrity, consumed: make(map[runtimeport.Nonce]runtimeinstall.Hash)}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authenticator := runtimeport.ReceiptAuthenticator(acceptingAuthenticator{})
			consent := newFakeLinuxConsent()
			if test.name == "bad signature" {
				authenticator = rejectingAuthenticator{}
			}
			provisioner, err := NewLinuxProvisioner(Dependencies{
				Authority: staticAuthorityResolver{authority: authority}, Host: staticHostProbe{evidence: supportedHost(t, authority)},
				Runtime: &installRuntimeInspector{authority: authority}, Capabilities: completeCapabilityProbe{},
				Consent: consent, ConsentAuth: consent, ConsentStore: consent,
				Privilege: test.broker, Authenticator: authenticator, Replay: test.replay,
				Nonces: &incrementingNonces{}, Clock: &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)},
				RootlessTool: &fakeRunner{authority: rootlessAuthority(t, authority)},
			})
			if err != nil {
				t.Fatal(err)
			}
			other := completeOtherPhases{artifact: authority.ArtifactDigest()}
			application, _ := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
				Operations: &memoryRuntimeRepository{}, Host: provisioner, Detector: provisioner,
				Catalog: provisioner, Consent: provisioner, Fetcher: other, Verifier: other,
				Prerequisites: provisioner, Installer: provisioner, Terms: provisioner,
				Controller: provisioner, Capabilities: provisioner,
			})
			result, ensureError := application.Ensure(context.Background(), runtimeinstallapp.Command{
				OperationID: "integrity-case", CanonicalPlan: plan.CanonicalBytes(),
			})
			if ensureError == nil || result.State != runtimeinstall.OperationStateFailedRecoverable {
				t.Fatalf("Ensure() = state:%s error:%v", result.State, ensureError)
			}
		})
	}
}

func TestLinuxProvisionerConsentAuthorityFailsClosedBeforeHostMutation(t *testing.T) {
	t.Parallel()
	plan, authority := adapterPlanForAction(t, runtimeinstall.PlanActionInstallCertified)
	request := captureRequest(t, plan)
	newProvisioner := func() (*LinuxProvisioner, *fakeLinuxConsent, *fakePrivilegeBroker) {
		broker := &fakePrivilegeBroker{}
		provisioner := edgeProvisioner(
			t, authority, &edgeRuntimeInspector{}, &edgeCapabilityProbe{}, broker,
			&edgeRunner{authority: rootlessAuthority(t, authority)},
		)
		consent, ok := provisioner.consent.(*fakeLinuxConsent)
		if !ok {
			t.Fatal("test provisioner did not retain its consent authority")
		}
		return provisioner, consent, broker
	}

	for _, mutate := range []func(*LinuxProvisioner, *fakeLinuxConsent){
		func(_ *LinuxProvisioner, consent *fakeLinuxConsent) { consent.authErr = errors.New("bad signature") },
		func(_ *LinuxProvisioner, consent *fakeLinuxConsent) { consent.storeErr = errors.New("storage failed") },
		func(provisioner *LinuxProvisioner, _ *fakeLinuxConsent) {
			provisioner.clock = &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.FixedZone("offset", 3600))}
		},
	} {
		provisioner, consent, broker := newProvisioner()
		mutate(provisioner, consent)
		if _, err := provisioner.AwaitRuntimeConsent(context.Background(), request); !errors.Is(err, ErrProvisionIntegrity) {
			t.Fatalf("unsafe consent authority error = %v", err)
		}
		if len(broker.operations) != 0 {
			t.Fatal("privileged mutation ran after unsafe consent authority")
		}
	}

	provisioner, consent, broker := newProvisioner()
	consent.loadErr = errors.New("load failed")
	if _, err := provisioner.InstallPrerequisites(context.Background(), request); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("missing stored consent error = %v", err)
	}
	if len(broker.operations) != 0 {
		t.Fatal("privileged mutation ran without reauthenticated stored consent")
	}
}

type staticAuthorityResolver struct {
	authority runtimeport.LinuxAuthority
	err       error
}

func (r staticAuthorityResolver) ResolveLinuxAuthority(context.Context, []byte) (runtimeport.LinuxAuthority, error) {
	return r.authority, r.err
}

type staticHostProbe struct{ evidence HostEvidence }

func (p staticHostProbe) ProbeLinuxHost(context.Context, runtimeport.LinuxAuthority) (HostEvidence, error) {
	return p.evidence, nil
}

func supportedHost(t *testing.T, authority runtimeport.LinuxAuthority) HostEvidence {
	t.Helper()
	evidence, err := NewHostEvidence(HostEvidenceInput{
		Distribution: authority.Distribution(), VersionID: authority.VersionID(), Kernel: authority.MinimumKernel(),
		Architecture: authority.Architecture(), UID: authority.InvokingUID(), GID: authority.InvokingGID(),
		CPUs: authority.MinimumCPUs(), TotalMemory: authority.MinimumTotalMemory(),
		AvailableMemory: authority.MinimumAvailableMemory(), FreeDisk: authority.MinimumFreeDisk(),
		UserNamespaces: true, UserSystemd: true, LocalFilesystem: true, DockerGroupAbsent: true,
		SELinuxEnforcing: authority.SELinuxEnforcingSupported(), SubordinateUIDs: authority.SubordinateIDCount(),
		SubordinateGIDs: authority.SubordinateIDCount(), MachineDigest: authority.MachineDigest(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

type installRuntimeInspector struct {
	mu        sync.Mutex
	calls     uint64
	authority runtimeport.LinuxAuthority
}

func (i *installRuntimeInspector) Inspect(
	context.Context,
	runtimeinstall.Plan,
	runtimeport.LinuxAuthority,
) (RuntimeEvidence, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls++
	if i.calls == 1 {
		endpoint, _ := NewEndpointEvidence(false, 0, 0, false)
		return NewRuntimeEvidence(RuntimeEvidenceInput{
			Condition: runtimeinstall.RuntimeConditionAbsent, Endpoint: endpoint,
		})
	}
	endpoint, _ := NewEndpointEvidence(true, i.calls, 0o660, true)
	return NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: i.authority.RuntimeVersion(), ComposeVersion: i.authority.ComposeVersion(),
		Architecture: i.authority.Architecture(), Rootless: true, LinuxContainers: true,
		Workloads: i.authority.UnrelatedWorkloads(),
	})
}

type completeCapabilityProbe struct{}

func (completeCapabilityProbe) VerifyLinuxCapabilities(
	context.Context,
	runtimeport.LinuxAuthority,
	RuntimeEvidence,
	runtimeinstall.Hash,
) (CapabilityEvidence, error) {
	return NewCapabilityEvidence(CapabilityEvidenceInput{
		EngineAPI: true, Compose: true, Architecture: true, LinuxContainers: true, Rootless: true,
		NoTCPListener: true, BindReadOnly: true, NetworkIsolation: true, VolumePersistence: true,
		LoopbackPublish: true, WorkloadsPreserved: true, LocalExecution: true,
		ManagedStateDigest: runtimeinstall.Sum([]byte("managed-state")),
		PolicyDigest:       runtimeinstall.Sum([]byte("capability")),
	})
}

type fakePrivilegeBroker struct {
	operations []runtimeport.PrivilegeOperation
	err        error
	forgeState bool
}

func (b *fakePrivilegeBroker) Execute(
	_ context.Context,
	request runtimeport.PrivilegeRequest,
) (runtimeport.PrivilegeReceipt, error) {
	b.operations = append(b.operations, request.Operation())
	if b.err != nil {
		return runtimeport.PrivilegeReceipt{}, b.err
	}
	authority := request.Authority()
	packages, _ := runtimeport.ExpectedPackageStateDigest(authority)
	repository, _ := runtimeport.ExpectedRepositoryStateDigest(authority)
	input := runtimeport.PrivilegeReceiptInput{
		RequestDigest: request.Digest(), OperationKey: request.OperationKey(), PlanDigest: authority.PlanDigest(),
		AuthorityDigest: authority.Digest(), Operation: request.Operation(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), Nonce: request.Nonce(), ExpiresAt: request.ExpiresAt(),
		Result: runtimeport.PrivilegeResultCompleted, ObservedState: request.ExpectedState(),
		HelperDigest: runtimeinstall.Sum([]byte("helper")), Signature: make([]byte, 64),
	}
	switch request.Operation() {
	case runtimeport.PrivilegeConfigureRepository:
		input.RepositoryDigest = repository
	case runtimeport.PrivilegeInstallPackages:
		input.RepositoryDigest, input.PackageStateDigest = repository, packages
	case runtimeport.PrivilegeConfigureSubordinateIDs:
		input.SubordinateIDs = authority.SubordinateIDCount()
		input.SubordinateUIDStart, input.SubordinateGIDStart = 100000, 200000
		input.SubordinateStateDigest = runtimeinstall.Sum([]byte("subordinate-state"))
	case runtimeport.PrivilegeEnableUserService:
		input.ServiceUnitDigest = authority.ServiceUnitDigest()
		input.ServiceEnabled, input.ServiceActive, input.UserLingerEnabled = true, true, true
	case runtimeport.PrivilegeVerifyManagedState:
		input.RepositoryDigest, input.PackageStateDigest = repository, packages
		input.ServiceUnitDigest, input.SubordinateIDs = authority.ServiceUnitDigest(), authority.SubordinateIDCount()
		input.ServiceEnabled, input.ServiceActive, input.UserLingerEnabled = true, true, true
		input.SubordinateUIDStart, input.SubordinateGIDStart = 100000, 200000
		input.SubordinateStateDigest = runtimeinstall.Sum([]byte("subordinate-state"))
	}
	if b.forgeState {
		input.ObservedState = runtimeinstall.Sum([]byte("forged"))
	}
	return runtimeport.NewPrivilegeReceipt(input)
}

type acceptingAuthenticator struct{}

func (acceptingAuthenticator) VerifyPrivilegeReceipt(
	context.Context,
	runtimeport.PrivilegeRequest,
	runtimeport.PrivilegeReceipt,
) error {
	return nil
}

type rejectingAuthenticator struct{}

func (rejectingAuthenticator) VerifyPrivilegeReceipt(
	context.Context,
	runtimeport.PrivilegeRequest,
	runtimeport.PrivilegeReceipt,
) error {
	return runtimeport.ErrPrivilegeIntegrity
}

type fakeReplayLedger struct {
	mu       sync.Mutex
	err      error
	consumed map[runtimeport.Nonce]runtimeinstall.Hash
}

func (l *fakeReplayLedger) ConsumePrivilegeReceipt(
	_ context.Context,
	nonce runtimeport.Nonce,
	digest runtimeinstall.Hash,
) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		return l.err
	}
	if _, duplicate := l.consumed[nonce]; duplicate {
		return runtimeport.ErrPrivilegeIntegrity
	}
	l.consumed[nonce] = digest
	return nil
}

type incrementingNonces struct {
	mu   sync.Mutex
	next byte
}

func (s *incrementingNonces) NewPrivilegeNonce(context.Context) (runtimeport.Nonce, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next++
	return runtimeport.Nonce{s.next}, nil
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type fakeLinuxConsent struct {
	mu       sync.Mutex
	grants   map[string]runtimeport.LinuxConsentGrant
	awaitErr error
	authErr  error
	storeErr error
	loadErr  error
}

func newFakeLinuxConsent() *fakeLinuxConsent {
	return &fakeLinuxConsent{grants: make(map[string]runtimeport.LinuxConsentGrant)}
}

func (c *fakeLinuxConsent) AwaitLinuxConsent(
	_ context.Context,
	request runtimeport.LinuxConsentRequest,
) (runtimeport.LinuxConsentReceipt, error) {
	if c.awaitErr != nil {
		return runtimeport.LinuxConsentReceipt{}, c.awaitErr
	}
	authority := request.Authority()
	signature := make([]byte, 64)
	return runtimeport.NewLinuxConsentReceipt(runtimeport.LinuxConsentReceiptInput{
		RequestDigest: request.Digest(), PlanDigest: authority.PlanDigest(), AuthorityDigest: authority.Digest(),
		CatalogDigest: authority.CatalogDigest(), ArtifactDigest: authority.ArtifactDigest(),
		TermsDigest: authority.TermsDigest(), PrincipalID: authority.PrincipalID(),
		MachineDigest: authority.MachineDigest(), Nonce: request.Nonce(),
		AcceptedAt: request.IssuedAt(), ExpiresAt: request.IssuedAt().Add(24 * time.Hour),
		Signature: signature, SignatureDigest: runtimeinstall.Sum(signature),
	})
}

func (c *fakeLinuxConsent) VerifyLinuxConsent(
	context.Context,
	runtimeport.LinuxConsentRequest,
	runtimeport.LinuxConsentReceipt,
) error {
	return c.authErr
}

func (c *fakeLinuxConsent) VerifyStoredLinuxConsent(
	context.Context,
	runtimeport.LinuxAuthority,
	runtimeport.LinuxConsentReceipt,
) error {
	return c.authErr
}

func (c *fakeLinuxConsent) StoreLinuxConsent(
	_ context.Context,
	operationID string,
	grant runtimeport.LinuxConsentGrant,
) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.storeErr != nil {
		return c.storeErr
	}
	c.grants[operationID] = grant
	return nil
}

func (c *fakeLinuxConsent) LoadLinuxConsent(
	_ context.Context,
	operationID string,
	planDigest runtimeinstall.Hash,
) (runtimeport.LinuxConsentGrant, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.loadErr != nil {
		return runtimeport.LinuxConsentGrant{}, c.loadErr
	}
	grant, present := c.grants[operationID]
	if !present || grant.Request().Authority().PlanDigest() != planDigest {
		return runtimeport.LinuxConsentGrant{}, runtimeport.ErrLinuxConsentIntegrity
	}
	return grant, nil
}

func seedLinuxConsent(
	t *testing.T,
	store *fakeLinuxConsent,
	operationID string,
	authority runtimeport.LinuxAuthority,
	now time.Time,
) {
	t.Helper()
	request, err := runtimeport.NewLinuxConsentRequest(
		operationID, 1, authority, runtimeport.Nonce{1}, now, now.Add(2*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := store.AwaitLinuxConsent(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := runtimeport.NewLinuxConsentGrant(request, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.StoreLinuxConsent(context.Background(), operationID, grant); err != nil {
		t.Fatal(err)
	}
}

type fakeRunner struct {
	authority                       argvprocess.ExecutableAuthority
	calls                           int
	sawSanitizedRootlessEnvironment bool
}

func (r *fakeRunner) ExecutableAuthority() argvprocess.ExecutableAuthority { return r.authority }

func (r *fakeRunner) Run(_ context.Context, invocation argvprocess.Invocation) (argvprocess.Result, error) {
	r.calls++
	r.sawSanitizedRootlessEnvironment = invocation.EnvironmentProfile() == argvprocess.EnvironmentProfileRootlessSetup &&
		len(invocation.Environment()) == 8 &&
		slices.Contains(invocation.Environment(), "DOCKER_CONFIG=/run/user/1000/agentmemory-docker-cli") &&
		slices.Equal(invocation.Arguments(), []string{"install"})
	return argvprocess.Result{ExitCode: 0}, nil
}

func rootlessAuthority(t *testing.T, authority runtimeport.LinuxAuthority) argvprocess.ExecutableAuthority {
	t.Helper()
	result, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "docker-rootless-setup", CanonicalPath: authority.RootlessToolPath(),
		SHA256: [32]byte(authority.RootlessToolDigest()), OwnerIdentity: "uid:0",
		PublisherIdentity: "docker-linux-packages", PublisherPolicyID: "linux-package-signature-v1",
		ReleaseManifestDigest: [32]byte(runtimeinstall.Sum([]byte("release"))),
		RuntimePlanDigest:     [32]byte(authority.PlanDigest()), Role: argvprocess.ExecutableRoleRootlessSetup,
		Platform: "linux", Architecture: authority.Architecture().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type memoryRuntimeRepository struct {
	mu       sync.Mutex
	snapshot *runtimeinstall.OperationSnapshot
}

func (r *memoryRuntimeRepository) Load(context.Context, string) (*runtimeinstall.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.snapshot == nil {
		return nil, runtimeinstallapp.ErrOperationNotFound
	}
	return runtimeinstall.RestoreOperation(*r.snapshot)
}

func (r *memoryRuntimeRepository) Save(_ context.Context, snapshot runtimeinstall.OperationSnapshot) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	copyOfSnapshot := snapshot
	r.snapshot = &copyOfSnapshot
	return nil
}

type completeOtherPhases struct{ artifact runtimeinstall.Hash }

func (p completeOtherPhases) complete(request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	artifact := runtimeinstall.Hash{}
	if request.Phase() >= runtimeinstall.PhaseVerifyRuntimeArtifact {
		artifact = p.artifact
	}
	return runtimeinstallapp.NewCompletedOutput(runtimeinstallapp.Completion{
		InputDigest:    runtimeinstall.Sum([]byte("input-" + request.Phase().String())),
		OutputDigest:   runtimeinstall.Sum([]byte("output-" + request.Phase().String())),
		ArtifactDigest: artifact,
	})
}

func (p completeOtherPhases) PlanRuntime(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return p.complete(request)
}

func (p completeOtherPhases) AwaitRuntimeConsent(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return p.complete(request)
}

func (p completeOtherPhases) AcquireRuntime(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return p.complete(request)
}

func (p completeOtherPhases) VerifyRuntimeArtifact(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return p.complete(request)
}

func (p completeOtherPhases) AwaitThirdPartyTerms(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return p.complete(request)
}
