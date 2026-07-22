package provideradapterapp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/provideradapter"
)

var errInjected = errors.New("injected safe port failure")

func TestPRO002InstallVerifiesPlansStartsProbesAndCommitsInOrder(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	result, err := fixture.application.Execute(context.Background(), fixture.command)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Status() != StatusActive || result.AdapterID() != "python-reference" ||
		result.RuntimeID() != "adapter-runtime-1" || result.AttestationDigest().IsZero() {
		t.Fatalf("incomplete result: %#v", result)
	}
	want := make([]string, 0, 7)
	want = append(want, "find", "verify", "authorize", "start", "conformance", "commit")
	if !sameStrings(fixture.calls, want) || fixture.runtime.stopCalls != 0 {
		t.Fatalf("unexpected lifecycle: got %v want %v", fixture.calls, want)
	}
	if !fixture.runtime.plan.ReadOnlyRootFS() || fixture.runtime.plan.Privileged() ||
		fixture.runtime.plan.HostNetwork() || fixture.runtime.plan.PublishPort() {
		t.Fatal("application did not pass the closed sandbox plan")
	}

	replay, err := fixture.application.Execute(context.Background(), fixture.command)
	if err != nil || replay != result {
		t.Fatalf("exact replay failed: %#v %v", replay, err)
	}
	if !sameStrings(fixture.calls, append(want, "find")) {
		t.Fatalf("replay performed another side effect: %v", fixture.calls)
	}
}

func TestPRO002InstallFailsClosedAndCleansEveryStartedRuntime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		configure  func(*fixture)
		wantStarts int
		wantStops  int
	}{
		{"verification", func(value *fixture) { value.verifier.err = errInjected }, 0, 0},
		{"policy", func(value *fixture) { value.policy.err = errInjected }, 0, 0},
		{"runtime", func(value *fixture) { value.runtime.err = errInjected }, 1, 1},
		{"conformance", func(value *fixture) { value.conformance.err = errInjected }, 1, 1},
		{"commit", func(value *fixture) { value.repository.commitErr = errInjected }, 1, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := newFixture(t)
			test.configure(value)
			if _, err := value.application.Execute(context.Background(), value.command); err == nil {
				t.Fatal("failed installation reported success")
			}
			if value.runtime.startCalls != test.wantStarts || value.runtime.stopCalls != test.wantStops {
				t.Fatalf("runtime lifecycle start=%d stop=%d", value.runtime.startCalls, value.runtime.stopCalls)
			}
			if len(value.repository.results) != 0 {
				t.Fatal("failed installation became canonical")
			}
		})
	}
}

func TestPRO002InstallRejectsAuthorizationReplayMismatchAndAttestationMismatch(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	denied := fixture.command
	denied.Role = RoleReader
	if _, err := fixture.application.Execute(context.Background(), denied); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("reader was not denied: %v", err)
	}

	existing, err := newResult(fixture.command, fixture.manifest, fixture.plan, fixture.runtime.handle, fixture.conformance.attestation)
	if err != nil {
		t.Fatalf("result fixture: %v", err)
	}
	fixture.repository.results[fixture.command.OperationID] = existing
	changed := fixture.command
	changed.InstallationID = "018f0000-0000-7000-8000-000000000799"
	if _, err := fixture.application.Execute(context.Background(), changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed replay did not conflict: %v", err)
	}

	delete(fixture.repository.results, fixture.command.OperationID)
	fixture.conformance.attestation.planDigest = provideradapter.DigestBytes([]byte("wrong plan"))
	if _, err := fixture.application.Execute(context.Background(), fixture.command); !errors.Is(err, ErrConformance) {
		t.Fatalf("foreign attestation accepted: %v", err)
	}
	if fixture.runtime.stopCalls != 1 {
		t.Fatal("foreign attestation runtime was not stopped")
	}
}

func TestPRO002InstallReportsCleanupFailureAndNeverCommits(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	fixture.conformance.err = errInjected
	fixture.runtime.stopErr = errors.New("cleanup failed")
	if _, err := fixture.application.Execute(context.Background(), fixture.command); !errors.Is(err, ErrConformance) || !errors.Is(err, ErrRuntime) {
		t.Fatalf("cleanup failure was hidden: %v", err)
	}
	if len(fixture.repository.results) != 0 || fixture.runtime.stopCalls != 1 {
		t.Fatal("cleanup failure committed or retried unexpectedly")
	}
}

func TestPRO002CommandRejectsInvalidAuthorityIdentityTimeAndOperation(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	tests := []InstallProviderAdapterCommand{
		{OperationID: "bad operation", InstallationID: fixture.command.InstallationID, Role: RoleOwner, Manifest: fixture.manifest, RequestedAt: fixture.command.RequestedAt},
		{OperationID: "install-1", InstallationID: "bad", Role: RoleOwner, Manifest: fixture.manifest, RequestedAt: fixture.command.RequestedAt},
		{OperationID: "install-1", InstallationID: fixture.command.InstallationID, Role: "root", Manifest: fixture.manifest, RequestedAt: fixture.command.RequestedAt},
		{OperationID: "install-1", InstallationID: fixture.command.InstallationID, Role: RoleOwner, Manifest: fixture.manifest, RequestedAt: time.Time{}},
	}
	for _, command := range tests {
		if _, err := fixture.application.Execute(context.Background(), command); !errors.Is(err, ErrInvalidCommand) {
			t.Fatalf("invalid command accepted: %#v %v", command, err)
		}
	}
	var nilContext context.Context
	if _, err := fixture.application.Execute(nilContext, fixture.command); !errors.Is(err, ErrInvalidCommand) {
		t.Fatalf("nil context accepted: %v", err)
	}
}

type fixture struct {
	manifest    provideradapter.Manifest
	plan        provideradapter.DeploymentPlan
	command     InstallProviderAdapterCommand
	calls       []string
	verifier    *verifierStub
	policy      *policyStub
	runtime     *runtimeStub
	conformance *conformanceStub
	repository  *repositoryStub
	application Application
}

func newFixture(t testing.TB) *fixture {
	t.Helper()
	manifest, err := provideradapter.NewManifest(manifestInput())
	if err != nil {
		t.Fatalf("manifest: %v", err)
	}
	installationID := "018f0000-0000-7000-8000-000000000711"
	plan, err := manifest.DeploymentPlan(installationID)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	value := &fixture{manifest: manifest, plan: plan}
	value.verifier = &verifierStub{calls: &value.calls}
	value.policy = &policyStub{calls: &value.calls}
	value.runtime = &runtimeStub{calls: &value.calls, handle: NewRuntimeHandle("adapter-runtime-1", plan.Digest())}
	value.conformance = &conformanceStub{calls: &value.calls, attestation: NewCapabilityAttestation(
		manifest.Digest(), plan.Digest(), manifest.ImageDigest(), provideradapter.SupportedProtocolMajor,
		manifest.Operations(), true, true, true, time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC),
	)}
	value.repository = &repositoryStub{calls: &value.calls, results: map[string]InstallResult{}}
	value.application, err = New(Dependencies{
		Verifier: value.verifier, Policy: value.policy, Runtime: value.runtime,
		Conformance: value.conformance, Repository: value.repository,
	})
	if err != nil {
		t.Fatalf("application: %v", err)
	}
	value.command = InstallProviderAdapterCommand{
		OperationID: "install-provider-1", InstallationID: installationID, Role: RoleOwner,
		Manifest: manifest, RequestedAt: time.Date(2026, 7, 22, 8, 0, 0, 0, time.UTC),
	}
	return value
}

func manifestInput() provideradapter.ManifestInput {
	image := provideradapter.DigestBytes([]byte("python-reference-image"))
	digest := func(value string) provideradapter.Digest { return provideradapter.DigestBytes([]byte(value)) }
	return provideradapter.ManifestInput{
		AdapterID: "python-reference", Image: "registry.example/custom/python@sha256:" + image.Hex(),
		ImageDigest: image, Protocol: provideradapter.ProtocolRangeInput{Minimum: 1, Maximum: 1},
		Transport: provideradapter.TransportAuthenticatedHTTP,
		Operations: []provideradapter.Operation{
			provideradapter.OperationGetManifest, provideradapter.OperationValidateConfiguration,
			provideradapter.OperationProbe, provideradapter.OperationHealth,
			provideradapter.OperationEmbedDocuments, provideradapter.OperationEmbedQueries,
			provideradapter.OperationRerank, provideradapter.OperationEstimateCost,
			provideradapter.OperationCancel, provideradapter.OperationShutdown,
		},
		Permissions: provideradapter.PermissionInput{GatewayAccess: true},
		Limits:      provideradapter.LimitInput{CPUsMilli: 500, MemoryBytes: 536870912, PIDs: 64, TimeoutMilliseconds: 30000, ScratchBytes: 67108864},
		Evidence: provideradapter.EvidenceInput{
			SignatureBundle: digest("signature"), CycloneDXSBOM: digest("cyclonedx"),
			SPDXSBOM: digest("spdx"), Provenance: digest("provenance"),
			License: digest("license"), Vulnerability: digest("vulnerability"),
		},
	}
}

type verifierStub struct {
	calls *[]string
	err   error
}

func (s *verifierStub) Verify(_ context.Context, _ provideradapter.Manifest) error {
	*s.calls = append(*s.calls, "verify")
	return s.err
}

type policyStub struct {
	calls *[]string
	err   error
}

func (s *policyStub) Authorize(_ context.Context, _ provideradapter.Manifest) error {
	*s.calls = append(*s.calls, "authorize")
	return s.err
}

type runtimeStub struct {
	calls                 *[]string
	handle                RuntimeHandle
	err                   error
	stopErr               error
	startCalls, stopCalls int
	plan                  provideradapter.DeploymentPlan
}

func (s *runtimeStub) Start(_ context.Context, plan provideradapter.DeploymentPlan) (RuntimeHandle, error) {
	s.startCalls++
	s.plan = plan
	*s.calls = append(*s.calls, "start")
	return s.handle, s.err
}
func (s *runtimeStub) Stop(_ context.Context, _ RuntimeHandle) error {
	s.stopCalls++
	*s.calls = append(*s.calls, "stop")
	return s.stopErr
}

type conformanceStub struct {
	calls       *[]string
	attestation CapabilityAttestation
	err         error
}

func (s *conformanceStub) Certify(_ context.Context, _ RuntimeHandle, _ provideradapter.Manifest) (CapabilityAttestation, error) {
	*s.calls = append(*s.calls, "conformance")
	return s.attestation, s.err
}

type repositoryStub struct {
	calls     *[]string
	results   map[string]InstallResult
	commitErr error
}

func (s *repositoryStub) Find(_ context.Context, operationID string) (InstallResult, bool, error) {
	*s.calls = append(*s.calls, "find")
	result, found := s.results[operationID]
	return result, found, nil
}
func (s *repositoryStub) Commit(_ context.Context, result InstallResult) error {
	*s.calls = append(*s.calls, "commit")
	if s.commitErr == nil {
		s.results[result.OperationID()] = result
	}
	return s.commitErr
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
