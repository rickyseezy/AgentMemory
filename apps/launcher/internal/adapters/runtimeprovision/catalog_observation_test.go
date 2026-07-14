package runtimeprovision

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestNativeCatalogObserverBindsVerifiedCatalogPublisherAndNativeEvidence(t *testing.T) {
	t.Parallel()
	catalog := verifiedObservationCatalog(t)
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	publisher := catalog.Manifest().Artifact().Publisher()
	trust := runtimecatalog.DigestBytes([]byte("docker certificate"))
	publishers, err := NewRuntimePublisherPolicyVerifier([]RuntimePublisherPolicyInput{{
		Verification: publisher.Verification(), Identity: publisher.Identity(),
		SigningKeyIdentity: publisher.SigningKeyIdentity(), PackageIdentity: publisher.PackageIdentity(),
		NativeTrustSHA256: trust.Hex(),
	}})
	if err != nil {
		t.Fatal(err)
	}
	backend := &catalogObservationBackendStub{
		result: CatalogObservationResult{
			Host: observationHost(t), Discovery: runtimeinstall.NewAbsentRuntimeDiscovery(),
			Evidence: runtimeinstall.Sum([]byte("native observation")),
		},
	}
	hostAttestor := &catalogHostReattestorStub{}
	observer, err := newNativeCatalogObserver(publishers, hostAttestor, backend)
	if err != nil {
		t.Fatal(err)
	}
	host, discovery, evidence, err := observer.ObserveRuntime(t.Context(), observationRequest(t), catalog, certified)
	if err != nil || hostAttestor.calls != 1 || backend.calls != 1 || backend.input.NativePublisherTrust != trust ||
		host.Platform() != runtimeinstall.PlatformDarwin ||
		discovery != runtimeinstall.NewAbsentRuntimeDiscovery() || evidence.IsZero() {
		t.Fatalf("observation=%+v/%+v/%s error=%v backend=%+v", host, discovery, evidence, err, backend)
	}
}

func TestNativeCatalogObserverFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()
	catalog := verifiedObservationCatalog(t)
	certified, _ := catalog.CertifiedRuntime()
	publisher := catalog.Manifest().Artifact().Publisher()
	publishers, _ := NewRuntimePublisherPolicyVerifier([]RuntimePublisherPolicyInput{{
		Verification: publisher.Verification(), Identity: publisher.Identity(),
		SigningKeyIdentity: publisher.SigningKeyIdentity(), PackageIdentity: publisher.PackageIdentity(),
		NativeTrustSHA256: runtimecatalog.DigestBytes([]byte("trust")).Hex(),
	}})
	validBackend := &catalogObservationBackendStub{result: CatalogObservationResult{
		Host: observationHost(t), Discovery: runtimeinstall.NewAbsentRuntimeDiscovery(),
		Evidence: runtimeinstall.Sum([]byte("evidence")),
	}}
	validHost := &catalogHostReattestorStub{}
	for name, test := range map[string]struct {
		publishers CatalogPublisherTrustResolver
		host       HostEvidenceReattestor
		backend    catalogObservationBackend
		mutate     func(*installplanapp.RuntimeEvidenceRequest)
	}{
		"publisher": {host: validHost, backend: validBackend},
		"host":      {publishers: publishers, backend: validBackend},
		"backend":   {publishers: publishers, host: validHost},
		"host plan": {publishers: publishers, host: validHost, backend: validBackend, mutate: func(value *installplanapp.RuntimeEvidenceRequest) {
			value.SignedHostPlan = hostverification.SignedPlan{}
		}},
		"storage": {publishers: publishers, host: validHost, backend: validBackend, mutate: func(value *installplanapp.RuntimeEvidenceRequest) {
			value.HostStorageTarget = ""
		}},
	} {
		request := observationRequest(t)
		if test.mutate != nil {
			test.mutate(&request)
		}
		observer, constructError := newNativeCatalogObserver(test.publishers, test.host, test.backend)
		if name == "publisher" || name == "host" || name == "backend" {
			if observer != nil || constructError == nil {
				t.Fatalf("%s accepted: observer=%+v error=%v", name, observer, constructError)
			}
			continue
		}
		if constructError != nil {
			t.Fatal(constructError)
		}
		if _, _, _, err := observer.ObserveRuntime(t.Context(), request, catalog, certified); !errors.Is(err, ErrProvisionIntegrity) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	for name, attestor := range map[string]*catalogHostReattestorStub{
		"failure":   {err: errors.New("private")},
		"cancelled": {err: context.Canceled},
	} {
		observer, _ := newNativeCatalogObserver(publishers, attestor, validBackend)
		_, _, _, err := observer.ObserveRuntime(t.Context(), observationRequest(t), catalog, certified)
		if name == "cancelled" && !errors.Is(err, context.Canceled) || name == "failure" && !errors.Is(err, ErrProbeFailed) {
			t.Fatalf("host %s error=%v", name, err)
		}
	}
	for name, backend := range map[string]*catalogObservationBackendStub{
		"failure": {err: errors.New("private")},
		"empty evidence": {result: CatalogObservationResult{
			Host: observationHost(t), Discovery: runtimeinstall.NewAbsentRuntimeDiscovery(),
		}},
		"invalid host": {result: CatalogObservationResult{
			Discovery: runtimeinstall.NewAbsentRuntimeDiscovery(), Evidence: runtimeinstall.Sum([]byte("evidence")),
		}},
	} {
		observer, _ := newNativeCatalogObserver(publishers, validHost, backend)
		if _, _, _, err := observer.ObserveRuntime(t.Context(), observationRequest(t), catalog, certified); !errors.Is(err, ErrProbeFailed) {
			t.Fatalf("%s error=%v", name, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	observer, _ := newNativeCatalogObserver(publishers, validHost, validBackend)
	if _, _, _, err := observer.ObserveRuntime(cancelled, observationRequest(t), catalog, certified); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

func verifiedObservationCatalog(t testing.TB) runtimecatalogapp.VerifiedCatalog {
	t.Helper()
	manifest := catalogSignatureManifest(t)
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindMacOS, Architecture: runtimecatalog.ArchitectureARM64,
		Edition: "desktop", Distribution: "macos", OSVersion: "15.5.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 32 << 30, FreeDiskBytes: 100 << 30, Virtualization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ports := &observationCatalogPorts{host: host, now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC)}
	application, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: ports, Host: ports, Signature: ports, NativePublisher: ports, AntiRollback: ports,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := runtimecatalog.NewSignedManifest(manifest, manifest.SigningKeyID(), []byte("detached signature"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := application.Verify(t.Context(), runtimecatalogapp.Request{
		SignedManifest: signed, ExpectedManifestDigest: manifest.Digest(), SourceMode: runtimecatalog.SourceModeOfflineBundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

func observationRequest(t testing.TB) installplanapp.RuntimeEvidenceRequest {
	t.Helper()
	operationID, _ := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	parent, _ := install.BindPlan([]byte("parent plan"))
	return installplanapp.RuntimeEvidenceRequest{
		OperationID: operationID, ParentPlanDigest: parent,
		SignedHostPlan: signedCatalogHostPlan(t, hostverification.PlatformTuple{
			OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos",
			Architecture: hostverification.ArchitectureARM64, Version: "15.5", Build: "24F74",
		}, 8, 32<<30, 100<<30),
		HostEvidenceDigest: install.DigestBytes([]byte("host evidence")),
		HostStorageTarget:  "/Users/agentmemory/Library/Application Support/AgentMemory",
		RuntimeEndpoint:    "unix:///Users/agentmemory/.docker/run/docker.sock",
	}
}

func observationHost(t testing.TB) runtimeinstall.HostCapabilities {
	t.Helper()
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64, "15.5.0",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	return host
}

type catalogObservationBackendStub struct {
	result CatalogObservationResult
	input  CatalogObservationInput
	err    error
	calls  int
}

type catalogHostReattestorStub struct {
	err   error
	calls int
}

func (s *catalogHostReattestorStub) ReattestHost(context.Context, installplanapp.RuntimeEvidenceRequest) error {
	s.calls++
	return s.err
}

func (s *catalogObservationBackendStub) ObserveCatalogRuntime(_ context.Context, input CatalogObservationInput) (CatalogObservationResult, error) {
	s.calls++
	s.input = input
	return s.result, s.err
}

type observationCatalogPorts struct {
	host runtimecatalog.Host
	now  time.Time
}

func (p *observationCatalogPorts) Now() time.Time { return p.now }
func (p *observationCatalogPorts) CurrentHost(context.Context) (runtimecatalog.Host, error) {
	return p.host, nil
}
func (*observationCatalogPorts) VerifyManifestSignature(context.Context, runtimecatalog.SignedManifest) error {
	return nil
}
func (*observationCatalogPorts) VerifyNativePublisherPolicy(context.Context, runtimecatalog.PublisherPolicy) error {
	return nil
}
func (*observationCatalogPorts) LoadCatalogAnchor(context.Context, string) (runtimecatalogapp.CatalogAnchor, error) {
	return runtimecatalogapp.CatalogAnchor{}, runtimecatalogapp.ErrCatalogAnchorNotFound
}
func (*observationCatalogPorts) CompareAndSwapCatalogAnchor(context.Context, *runtimecatalogapp.CatalogAnchor, runtimecatalogapp.CatalogAnchor) error {
	return nil
}
