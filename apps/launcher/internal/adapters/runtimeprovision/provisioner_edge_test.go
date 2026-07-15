package runtimeprovision

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimeinstallapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestLinuxProvisionerExecutesEveryClosedPlanAction(t *testing.T) {
	t.Parallel()
	for _, action := range []runtimeinstall.PlanAction{
		runtimeinstall.PlanActionAdoptCompatible,
		runtimeinstall.PlanActionStartCompatible,
		runtimeinstall.PlanActionInstallCertified,
		runtimeinstall.PlanActionRepairManaged,
		runtimeinstall.PlanActionBlock,
	} {
		action := action
		t.Run(action.String(), func(t *testing.T) {
			t.Parallel()
			plan, authority := adapterPlanForAction(t, action)
			request := captureRequest(t, plan)
			runtimeEvidence := runtimeEvidenceForAction(t, action, authority)
			inspector := &edgeRuntimeInspector{sequence: []RuntimeEvidence{
				runtimeEvidence,
				runningRuntimeEvidence(t, authority),
				runningRuntimeEvidence(t, authority),
			}}
			broker := &fakePrivilegeBroker{}
			capability := &edgeCapabilityProbe{}
			provisioner := edgeProvisioner(t, authority, inspector, capability, broker, &edgeRunner{
				authority: rootlessAuthority(t, authority),
			})

			if _, err := provisioner.DetectRuntime(context.Background(), request); err != nil {
				t.Fatalf("DetectRuntime(%s) error = %v", action, err)
			}
			if _, err := provisioner.InstallPrerequisites(context.Background(), request); err != nil {
				t.Fatalf("InstallPrerequisites(%s) error = %v", action, err)
			}
			if _, err := provisioner.InstallRuntime(context.Background(), request); err != nil {
				t.Fatalf("InstallRuntime(%s) error = %v", action, err)
			}
			if action == runtimeinstall.PlanActionBlock {
				if _, err := provisioner.StartRuntime(context.Background(), request); err != nil {
					t.Fatalf("StartRuntime(block) error = %v", err)
				}
				if _, err := provisioner.VerifyRuntimeCapabilities(context.Background(), request); err != nil {
					t.Fatalf("VerifyRuntimeCapabilities(block) error = %v", err)
				}
				return
			}
			if _, err := provisioner.StartRuntime(context.Background(), request); err != nil {
				t.Fatalf("StartRuntime(%s) error = %v", action, err)
			}
			if _, err := provisioner.VerifyRuntimeCapabilities(context.Background(), request); err != nil {
				t.Fatalf("VerifyRuntimeCapabilities(%s) error = %v", action, err)
			}
			if capability.managed.IsZero() {
				t.Fatal("capability probe did not receive authenticated managed-state evidence")
			}
		})
	}
}

func TestLinuxProvisionerFailsClosedAcrossRunnerRuntimeAndCapabilityBoundaries(t *testing.T) {
	t.Parallel()
	plan, authority := adapterPlanForAction(t, runtimeinstall.PlanActionInstallCertified)
	request := captureRequest(t, plan)
	running := runningRuntimeEvidence(t, authority)
	tests := []struct {
		name          string
		runtime       *edgeRuntimeInspector
		capability    *edgeCapabilityProbe
		rootless      *edgeRunner
		invoke        func(*LinuxProvisioner) error
		want          error
		broker        *fakePrivilegeBroker
		authenticator runtimeport.ReceiptAuthenticator
	}{
		{
			name: "rootless executable substitution", runtime: &edgeRuntimeInspector{evidence: running},
			capability: &edgeCapabilityProbe{}, rootless: &edgeRunner{authority: rootlessAuthority(t, authority)},
			broker: &fakePrivilegeBroker{}, want: ErrProvisionIntegrity,
			invoke: func(provisioner *LinuxProvisioner) error {
				provisioner.rootlessTool = &edgeRunner{authority: dockerAuthorityForEdge(t, authority)}
				_, err := provisioner.InstallRuntime(context.Background(), request)
				return err
			},
		},
		{
			name: "rootless setup execution", runtime: &edgeRuntimeInspector{evidence: running},
			capability: &edgeCapabilityProbe{}, rootless: &edgeRunner{authority: rootlessAuthority(t, authority), err: errors.New("failed")},
			broker: &fakePrivilegeBroker{}, want: ErrProbeFailed,
			invoke: func(provisioner *LinuxProvisioner) error {
				_, err := provisioner.InstallRuntime(context.Background(), request)
				return err
			},
		},
		{
			name: "rootless output truncation", runtime: &edgeRuntimeInspector{evidence: running},
			capability: &edgeCapabilityProbe{}, rootless: &edgeRunner{
				authority: rootlessAuthority(t, authority), result: argvprocess.Result{OutputTruncated: true},
			},
			broker: &fakePrivilegeBroker{}, want: ErrProbeFailed,
			invoke: func(provisioner *LinuxProvisioner) error {
				_, err := provisioner.InstallRuntime(context.Background(), request)
				return err
			},
		},
		{
			name: "runtime re-probe conflict", runtime: &edgeRuntimeInspector{evidence: runtimeEvidenceForAction(t, runtimeinstall.PlanActionInstallCertified, authority)},
			capability: &edgeCapabilityProbe{}, rootless: &edgeRunner{authority: rootlessAuthority(t, authority)},
			broker: &fakePrivilegeBroker{}, want: nil,
			invoke: func(provisioner *LinuxProvisioner) error {
				_, err := provisioner.VerifyRuntimeCapabilities(context.Background(), request)
				return err
			},
		},
		{
			name: "active capability failure", runtime: &edgeRuntimeInspector{evidence: running},
			capability: &edgeCapabilityProbe{err: ErrProbeFailed}, rootless: &edgeRunner{authority: rootlessAuthority(t, authority)},
			broker: &fakePrivilegeBroker{}, want: ErrProbeFailed,
			invoke: func(provisioner *LinuxProvisioner) error {
				_, err := provisioner.VerifyRuntimeCapabilities(context.Background(), request)
				return err
			},
		},
		{
			name: "receipt authentication", runtime: &edgeRuntimeInspector{evidence: running},
			capability: &edgeCapabilityProbe{}, rootless: &edgeRunner{authority: rootlessAuthority(t, authority)},
			broker: &fakePrivilegeBroker{}, authenticator: rejectingAuthenticator{}, want: ErrProvisionIntegrity,
			invoke: func(provisioner *LinuxProvisioner) error {
				_, err := provisioner.InstallPrerequisites(context.Background(), request)
				return err
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authenticator := test.authenticator
			if authenticator == nil {
				authenticator = acceptingAuthenticator{}
			}
			provisioner := edgeProvisionerWithAuthenticator(
				t, authority, test.runtime, test.capability, test.broker, test.rootless, authenticator,
			)
			if err := test.invoke(provisioner); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestLinuxProvisionerRejectsReceiptThatExpiresDuringDurableReplayCommit(t *testing.T) {
	t.Parallel()
	plan, authority := adapterPlanForAction(t, runtimeinstall.PlanActionInstallCertified)
	request := captureRequest(t, plan)
	broker := &fakePrivilegeBroker{}
	provisioner := edgeProvisioner(
		t, authority, &edgeRuntimeInspector{}, &edgeCapabilityProbe{}, broker,
		&edgeRunner{authority: rootlessAuthority(t, authority)},
	)
	issued := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	provisioner.clock = &sequenceClock{values: []time.Time{
		issued, issued.Add(time.Second), issued.Add(2 * time.Second), issued.Add(3 * time.Minute),
	}}
	if _, err := provisioner.InstallPrerequisites(context.Background(), request); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("expired post-replay receipt error = %v", err)
	}
	if len(broker.operations) != 1 {
		t.Fatalf("expired receipt executed %d privilege operations", len(broker.operations))
	}
}

func TestLinuxProvisionerPreservesCancellationAndSanitizesAuthorityFailures(t *testing.T) {
	t.Parallel()
	plan, authority := adapterPlanForAction(t, runtimeinstall.PlanActionInstallCertified)
	request := captureRequest(t, plan)
	provisioner := edgeProvisioner(t, authority, &edgeRuntimeInspector{err: errors.New("secret host detail")},
		&edgeCapabilityProbe{}, &fakePrivilegeBroker{}, &edgeRunner{authority: rootlessAuthority(t, authority)})
	if _, err := provisioner.DetectRuntime(context.Background(), request); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("sanitized runtime error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provisioner.DetectHost(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled host error = %v", err)
	}
	var nilContext context.Context
	if _, err := provisioner.DetectHost(nilContext, request); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("nil context error = %v", err)
	}
	provisioner.authority = staticAuthorityResolver{err: errors.New("signature detail")}
	if _, err := provisioner.DetectHost(context.Background(), request); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("authority error = %v", err)
	}
}

func TestLinuxProvisionerHostAndStartEdgeOutcomesRemainTyped(t *testing.T) {
	t.Parallel()
	installPlan, installAuthority := adapterPlanForAction(t, runtimeinstall.PlanActionInstallCertified)
	request := captureRequest(t, installPlan)
	provisioner := edgeProvisioner(t, installAuthority, &edgeRuntimeInspector{evidence: runningRuntimeEvidence(t, installAuthority)},
		&edgeCapabilityProbe{}, &fakePrivilegeBroker{}, &edgeRunner{authority: rootlessAuthority(t, installAuthority)})
	provisioner.host = edgeHostProbe{err: errors.New("sensitive native probe detail")}
	if _, err := provisioner.DetectHost(context.Background(), request); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("host probe error = %v", err)
	}
	incompatible := supportedHost(t, installAuthority)
	incompatible.availableMemory--
	incompatible.digest = incompatible.computeDigest()
	provisioner.host = edgeHostProbe{evidence: incompatible}
	if _, err := provisioner.DetectHost(context.Background(), request); err != nil {
		t.Fatalf("unsupported host outcome error = %v", err)
	}

	_, catalog := adapterBaseHostCatalog(t)
	blockedHost, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04", true, true, true, true,
		1, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	blockedPlan, err := runtimeinstall.NewPlanV1(blockedHost, runtimeinstall.NewAbsentRuntimeDiscovery(), catalog)
	if err != nil || blockedPlan.Action() != runtimeinstall.PlanActionBlock {
		t.Fatalf("blocked plan = %s/%v", blockedPlan.Action(), err)
	}
	blockedAuthority := adapterLinuxAuthority(t, blockedPlan, 0)
	blocked := edgeProvisioner(t, blockedAuthority, &edgeRuntimeInspector{}, &edgeCapabilityProbe{},
		&fakePrivilegeBroker{}, &edgeRunner{authority: rootlessAuthority(t, blockedAuthority)})
	if _, err := blocked.DetectHost(context.Background(), captureRequest(t, blockedPlan)); err != nil {
		t.Fatalf("blocked host outcome error = %v", err)
	}

	startPlan, startAuthority := adapterPlanForAction(t, runtimeinstall.PlanActionStartCompatible)
	startRequest := captureRequest(t, startPlan)
	failedStart := edgeProvisioner(t, startAuthority, &edgeRuntimeInspector{err: errors.New("daemon detail")},
		&edgeCapabilityProbe{}, &fakePrivilegeBroker{}, &edgeRunner{authority: rootlessAuthority(t, startAuthority)})
	if _, err := failedStart.StartRuntime(context.Background(), startRequest); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("failed start error = %v", err)
	}
	deadlineStart := edgeProvisioner(t, startAuthority, &edgeRuntimeInspector{err: ErrRuntimeConflict},
		&edgeCapabilityProbe{}, &fakePrivilegeBroker{}, &edgeRunner{authority: rootlessAuthority(t, startAuthority)})
	deadlineContext, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := deadlineStart.StartRuntime(deadlineContext, startRequest); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline start error = %v", err)
	}
}

func adapterPlanForAction(
	t *testing.T,
	action runtimeinstall.PlanAction,
) (runtimeinstall.Plan, runtimeport.LinuxAuthority) {
	t.Helper()
	host, catalog := adapterBaseHostCatalog(t)
	var discovery runtimeinstall.RuntimeDiscovery
	var err error
	switch action {
	case runtimeinstall.PlanActionInstallCertified:
		discovery = runtimeinstall.NewAbsentRuntimeDiscovery()
	case runtimeinstall.PlanActionAdoptCompatible:
		discovery, err = runtimeinstall.NewRuntimeDiscovery(
			runtimeinstall.RuntimeConditionRunning, "docker_engine", "29.6.1",
			"unix:///run/user/1000/docker.sock", true, true, true,
			runtimeinstall.OwnershipReusedExternal, 0,
		)
	case runtimeinstall.PlanActionStartCompatible:
		discovery, err = runtimeinstall.NewRuntimeDiscovery(
			runtimeinstall.RuntimeConditionStopped, "docker_engine", "29.6.1",
			"unix:///run/user/1000/docker.sock", true, true, true,
			runtimeinstall.OwnershipReusedExternal, 0,
		)
	case runtimeinstall.PlanActionRepairManaged:
		discovery, err = runtimeinstall.NewRuntimeDiscovery(
			runtimeinstall.RuntimeConditionDamaged, "docker_engine", "29.6.1",
			"unix:///run/user/1000/docker.sock", true, true, false,
			runtimeinstall.OwnershipProvisionedByAgentMemory, 0,
		)
	case runtimeinstall.PlanActionBlock:
		discovery, err = runtimeinstall.NewRuntimeDiscovery(
			runtimeinstall.RuntimeConditionRunning, "docker_engine", "29.6.1",
			"tcp://127.0.0.1:2375", false, true, true,
			runtimeinstall.OwnershipReusedExternal, 0,
		)
	case runtimeinstall.PlanActionUnknown:
		t.Fatalf("unsupported test action %s", action)
	default:
		t.Fatalf("out-of-vocabulary test action %d", action)
	}
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(host, discovery, catalog)
	if err != nil || plan.Action() != action {
		t.Fatalf("plan action/error = %s/%v, want %s", plan.Action(), err, action)
	}
	return plan, adapterLinuxAuthority(t, plan, 0)
}

func runtimeEvidenceForAction(
	t *testing.T,
	action runtimeinstall.PlanAction,
	authority runtimeport.LinuxAuthority,
) RuntimeEvidence {
	t.Helper()
	switch action {
	case runtimeinstall.PlanActionAdoptCompatible, runtimeinstall.PlanActionStartCompatible:
		return runningRuntimeEvidence(t, authority)
	case runtimeinstall.PlanActionInstallCertified:
		endpoint, _ := NewEndpointEvidence(false, 0, 0, false)
		evidence, err := NewRuntimeEvidence(RuntimeEvidenceInput{
			Condition: runtimeinstall.RuntimeConditionAbsent, Endpoint: endpoint,
		})
		if err != nil {
			t.Fatal(err)
		}
		return evidence
	case runtimeinstall.PlanActionRepairManaged:
		endpoint, _ := NewEndpointEvidence(false, 0, 0, false)
		evidence, err := NewRuntimeEvidence(RuntimeEvidenceInput{
			Condition: runtimeinstall.RuntimeConditionDamaged, Endpoint: endpoint,
		})
		if err != nil {
			t.Fatal(err)
		}
		return evidence
	case runtimeinstall.PlanActionBlock:
		return RuntimeEvidence{}
	case runtimeinstall.PlanActionUnknown:
		t.Fatalf("unsupported runtime evidence action %s", action)
		return RuntimeEvidence{}
	default:
		t.Fatalf("out-of-vocabulary runtime evidence action %d", action)
		return RuntimeEvidence{}
	}
}

func runningRuntimeEvidence(t *testing.T, authority runtimeport.LinuxAuthority) RuntimeEvidence {
	t.Helper()
	endpoint, err := NewEndpointEvidence(true, 42, 0o660, true)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := NewRuntimeEvidence(RuntimeEvidenceInput{
		Condition: runtimeinstall.RuntimeConditionRunning, Endpoint: endpoint,
		RuntimeVersion: authority.RuntimeVersion(), ComposeVersion: authority.ComposeVersion(),
		Architecture: authority.Architecture(), Rootless: true, LinuxContainers: true,
		Workloads: authority.UnrelatedWorkloads(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func edgeProvisioner(
	t *testing.T,
	authority runtimeport.LinuxAuthority,
	runtimeInspector RuntimeInspector,
	capability CapabilityProbe,
	broker runtimeport.PrivilegeBroker,
	rootless argvprocess.Runner,
) *LinuxProvisioner {
	t.Helper()
	return edgeProvisionerWithAuthenticator(
		t, authority, runtimeInspector, capability, broker, rootless, acceptingAuthenticator{},
	)
}

func edgeProvisionerWithAuthenticator(
	t *testing.T,
	authority runtimeport.LinuxAuthority,
	runtimeInspector RuntimeInspector,
	capability CapabilityProbe,
	broker runtimeport.PrivilegeBroker,
	rootless argvprocess.Runner,
	authenticator runtimeport.ReceiptAuthenticator,
) *LinuxProvisioner {
	t.Helper()
	consent := newFakeLinuxConsent()
	artifacts := &fakeLinuxArtifacts{}
	seedLinuxConsent(
		t, consent, "capture-request", authority, time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC),
	)
	provisioner, err := NewLinuxProvisioner(Dependencies{
		Authority: staticAuthorityResolver{authority: authority},
		Host:      staticHostProbe{evidence: supportedHost(t, authority)},
		Runtime:   runtimeInspector, Capabilities: capability, Privilege: broker,
		Consent: consent, ConsentAuth: consent, ConsentStore: consent,
		Artifacts: artifacts, ArtifactTrust: artifacts,
		Authenticator: authenticator,
		Replay:        &fakeReplayLedger{consumed: make(map[runtimeport.Nonce]runtimeinstall.Hash)},
		Nonces:        &incrementingNonces{}, Clock: &fakeClock{now: time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)},
		RootlessTool: rootless,
	})
	if err != nil {
		t.Fatal(err)
	}
	return provisioner
}

type edgeRuntimeInspector struct {
	evidence RuntimeEvidence
	sequence []RuntimeEvidence
	calls    int
	err      error
}

type edgeHostProbe struct {
	evidence HostEvidence
	err      error
}

func (p edgeHostProbe) ProbeLinuxHost(
	context.Context,
	runtimeport.LinuxAuthority,
) (HostEvidence, error) {
	return p.evidence, p.err
}

func (i *edgeRuntimeInspector) Inspect(
	context.Context,
	runtimeinstall.Plan,
	runtimeport.LinuxAuthority,
) (RuntimeEvidence, error) {
	if len(i.sequence) != 0 {
		index := i.calls
		if index >= len(i.sequence) {
			index = len(i.sequence) - 1
		}
		i.calls++
		return i.sequence[index], i.err
	}
	return i.evidence, i.err
}

type edgeCapabilityProbe struct {
	managed runtimeinstall.Hash
	err     error
}

func (p *edgeCapabilityProbe) VerifyLinuxCapabilities(
	_ context.Context,
	authority runtimeport.LinuxAuthority,
	_ RuntimeEvidence,
	managed runtimeinstall.Hash,
) (CapabilityEvidence, error) {
	p.managed = managed
	if p.err != nil {
		return CapabilityEvidence{}, p.err
	}
	return NewCapabilityEvidence(CapabilityEvidenceInput{
		EngineAPI: true, Compose: true, Architecture: true, LinuxContainers: true,
		Rootless: true, NoTCPListener: true, BindReadOnly: true, NetworkIsolation: true,
		VolumePersistence: true, LoopbackPublish: true, WorkloadsPreserved: true,
		LocalExecution: true, ManagedStateDigest: managed, PolicyDigest: authority.CapabilityPolicyDigest(),
	})
}

type edgeRunner struct {
	authority argvprocess.ExecutableAuthority
	result    argvprocess.Result
	err       error
}

type sequenceClock struct {
	values []time.Time
	index  int
}

func (c *sequenceClock) Now() time.Time {
	if c.index >= len(c.values) {
		return c.values[len(c.values)-1]
	}
	value := c.values[c.index]
	c.index++
	return value
}

func (r *edgeRunner) ExecutableAuthority() argvprocess.ExecutableAuthority { return r.authority }

func (r *edgeRunner) Run(context.Context, argvprocess.Invocation) (argvprocess.Result, error) {
	return r.result, r.err
}

func dockerAuthorityForEdge(
	t *testing.T,
	authority runtimeport.LinuxAuthority,
) argvprocess.ExecutableAuthority {
	t.Helper()
	result, err := argvprocess.NewExecutableAuthority(argvprocess.ExecutableAuthorityInput{
		CanonicalID: "docker-cli", CanonicalPath: "/usr/bin/docker",
		SHA256: [32]byte(runtimeinstall.Sum([]byte("docker-cli"))), OwnerIdentity: "uid:0",
		PublisherIdentity: "docker-linux-packages", PublisherPolicyID: "linux-package-signature-v1",
		PublisherTrustDigest:  [32]byte(runtimeinstall.Sum([]byte("docker-linux-package-trust"))),
		ReleaseManifestDigest: [32]byte(runtimeinstall.Sum([]byte("release"))),
		RuntimePlanDigest:     [32]byte(authority.PlanDigest()), Role: argvprocess.ExecutableRoleDockerCLI,
		Platform: "linux", Architecture: authority.Architecture().String(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

var errCaptureRequest = errors.New("capture runtime request")

type requestCapturer struct{ request runtimeinstallapp.Request }

func (c *requestCapturer) capture(request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	c.request = request
	return runtimeinstallapp.Output{}, errCaptureRequest
}

func (c *requestCapturer) DetectHost(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) DetectRuntime(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) PlanRuntime(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) AwaitRuntimeConsent(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) AcquireRuntime(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) VerifyRuntimeArtifact(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) InstallPrerequisites(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) InstallRuntime(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) AwaitThirdPartyTerms(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) StartRuntime(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func (c *requestCapturer) VerifyRuntimeCapabilities(_ context.Context, request runtimeinstallapp.Request) (runtimeinstallapp.Output, error) {
	return c.capture(request)
}

func captureRequest(t *testing.T, plan runtimeinstall.Plan) runtimeinstallapp.Request {
	t.Helper()
	capturer := &requestCapturer{}
	application, err := runtimeinstallapp.New(runtimeinstallapp.Dependencies{
		Operations: &memoryRuntimeRepository{}, OwnershipAuthorities: discardOwnership{}, OwnershipRecords: discardOwnership{},
		Compensation: discardOwnership{},
		Host:         capturer, Detector: capturer,
		Catalog: capturer, Consent: capturer, Fetcher: capturer, Verifier: capturer,
		Prerequisites: capturer, Installer: capturer, Terms: capturer,
		Controller: capturer, Capabilities: capturer,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, ensureError := application.Ensure(context.Background(), runtimeinstallapp.Command{
		OperationID: "capture-request", CanonicalPlan: plan.CanonicalBytes(),
	})
	if ensureError == nil || capturer.request.OperationID() == "" {
		t.Fatalf("capture request error/request = %v/%s", ensureError, capturer.request.OperationID())
	}
	return capturer.request
}
