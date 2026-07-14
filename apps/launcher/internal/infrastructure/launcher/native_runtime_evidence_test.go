package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/installplanapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001NativeRuntimeEvidenceResolverBindsEveryIndependentReceipt(t *testing.T) {
	t.Parallel()
	request := nativeRuntimeEvidenceRequest(t)
	catalog := nativeRuntimeCertifiedCatalog(t)
	manifestDigest := runtimecatalog.Digest(catalog.CatalogDigest())
	resourceDigest := install.DigestBytes([]byte("outer signed catalog envelope"))
	discoveryDigest := install.DigestBytes([]byte("native runtime observation"))
	loader := &runtimeEnvelopeLoaderStub{envelope: nativeRuntimeCatalogEnvelope{ResourceDigest: resourceDigest}}
	policy := &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{runtime: catalog, manifestDigest: manifestDigest}}
	observer := &runtimeObservationStub{
		host: nativeRuntimeHost(t), discovery: runtimeinstall.NewAbsentRuntimeDiscovery(), digest: discoveryDigest,
	}
	resolver, err := newNativeRuntimeEvidenceResolver(loader, policy, observer)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := resolver.ResolveRuntimeEvidence(t.Context(), request)
	wantManifestDigest, parseError := install.ParseDigest(manifestDigest.Hex())
	if parseError != nil {
		t.Fatal(parseError)
	}
	if err != nil || loader.calls != 1 || policy.calls != 1 || observer.calls != 1 ||
		!evidence.HostEvidenceDigest().Equal(request.HostEvidenceDigest) ||
		!evidence.DiscoveryEvidenceDigest().Equal(discoveryDigest) ||
		!evidence.CatalogResourceEvidenceDigest().Equal(resourceDigest) ||
		!evidence.SignedCatalogEvidenceDigest().Equal(wantManifestDigest) {
		t.Fatalf("evidence=%+v error=%v calls=%d/%d/%d", evidence, err, loader.calls, policy.calls, observer.calls)
	}
}

func TestPF001NativeRuntimeEvidenceResolverFailsClosedAtEveryBoundary(t *testing.T) {
	t.Parallel()
	request := nativeRuntimeEvidenceRequest(t)
	catalog := nativeRuntimeCertifiedCatalog(t)
	validLoader := &runtimeEnvelopeLoaderStub{envelope: nativeRuntimeCatalogEnvelope{ResourceDigest: install.DigestBytes([]byte("outer"))}}
	validPolicy := &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{
		runtime: catalog, manifestDigest: runtimecatalog.Digest(catalog.CatalogDigest()),
	}}
	validObserver := &runtimeObservationStub{
		host: nativeRuntimeHost(t), discovery: runtimeinstall.NewAbsentRuntimeDiscovery(),
		digest: install.DigestBytes([]byte("discovery")),
	}
	for name, test := range map[string]struct {
		loader   nativeRuntimeCatalogEnvelopeLoader
		policy   nativeRuntimeCatalogPolicyVerifier
		observer nativeRuntimeObservationResolver
		mutate   func(*installplanapp.RuntimeEvidenceRequest)
	}{
		"loader error":   {loader: &runtimeEnvelopeLoaderStub{err: errors.New("private")}, policy: validPolicy, observer: validObserver},
		"empty envelope": {loader: &runtimeEnvelopeLoaderStub{}, policy: validPolicy, observer: validObserver},
		"policy error":   {loader: validLoader, policy: &runtimeCatalogPolicyStub{err: errors.New("private")}, observer: validObserver},
		"catalog contradiction": {loader: validLoader, policy: &runtimeCatalogPolicyStub{verified: nativeVerifiedRuntimeCatalog{
			runtime: catalog, manifestDigest: runtimecatalog.DigestBytes([]byte("foreign")),
		}}, observer: validObserver},
		"observation error": {loader: validLoader, policy: validPolicy, observer: &runtimeObservationStub{err: errors.New("private")}},
		"empty observation": {loader: validLoader, policy: validPolicy, observer: &runtimeObservationStub{host: nativeRuntimeHost(t), discovery: runtimeinstall.NewAbsentRuntimeDiscovery()}},
		"invalid observed host": {loader: validLoader, policy: validPolicy, observer: &runtimeObservationStub{
			discovery: runtimeinstall.NewAbsentRuntimeDiscovery(), digest: install.DigestBytes([]byte("discovery")),
		}},
		"host plan": {loader: validLoader, policy: validPolicy, observer: validObserver, mutate: func(value *installplanapp.RuntimeEvidenceRequest) {
			value.SignedHostPlan = hostverification.SignedPlan{}
		}},
		"host evidence": {loader: validLoader, policy: validPolicy, observer: validObserver, mutate: func(value *installplanapp.RuntimeEvidenceRequest) {
			value.HostEvidenceDigest = install.Digest{}
		}},
		"storage target": {loader: validLoader, policy: validPolicy, observer: validObserver, mutate: func(value *installplanapp.RuntimeEvidenceRequest) {
			value.HostStorageTarget = ""
		}},
		"runtime endpoint": {loader: validLoader, policy: validPolicy, observer: validObserver, mutate: func(value *installplanapp.RuntimeEvidenceRequest) {
			value.RuntimeEndpoint = ""
		}},
	} {
		candidate := request
		if test.mutate != nil {
			test.mutate(&candidate)
		}
		resolver, constructError := newNativeRuntimeEvidenceResolver(test.loader, test.policy, test.observer)
		if constructError != nil {
			t.Fatalf("%s construct: %v", name, constructError)
		}
		if evidence, resolveError := resolver.ResolveRuntimeEvidence(t.Context(), candidate); !errors.Is(resolveError, installplanapp.ErrRuntimeEvidenceUnavailable) || !evidence.HostEvidenceDigest().IsZero() {
			t.Fatalf("%s evidence=%+v error=%v", name, evidence, resolveError)
		}
	}
	for name, dependencies := range map[string][]any{
		"loader": {nil, validPolicy, validObserver}, "policy": {validLoader, nil, validObserver},
		"observer": {validLoader, validPolicy, nil},
	} {
		resolver, err := newNativeRuntimeEvidenceResolver(
			asRuntimeLoader(dependencies[0]), asRuntimePolicy(dependencies[1]), asRuntimeObserver(dependencies[2]),
		)
		if resolver != nil || err == nil {
			t.Fatalf("%s dependency accepted: resolver=%+v error=%v", name, resolver, err)
		}
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	resolver, _ := newNativeRuntimeEvidenceResolver(validLoader, validPolicy, validObserver)
	//lint:ignore SA1012 Deliberate nil-context trust-boundary regression fixture.
	if _, err := resolver.ResolveRuntimeEvidence(nil, request); !errors.Is(err, installplanapp.ErrRuntimeEvidenceUnavailable) { //nolint:staticcheck
		t.Fatalf("nil context error=%v", err)
	}
	var absent *nativeRuntimeEvidenceResolver
	if _, err := absent.ResolveRuntimeEvidence(t.Context(), request); !errors.Is(err, installplanapp.ErrRuntimeEvidenceUnavailable) {
		t.Fatalf("nil resolver error=%v", err)
	}
	if _, err := resolver.ResolveRuntimeEvidence(cancelled, request); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error=%v", err)
	}
}

func TestPF001NativeRuntimeCatalogPolicyRejectsIncompleteCompositionAndInvocation(t *testing.T) {
	t.Parallel()
	for _, dependencies := range [][]any{
		{nil, &catalogSignatureStub{}, &catalogPublisherStub{}, &catalogAnchorStub{}},
		{catalogClockStub{}, nil, &catalogPublisherStub{}, &catalogAnchorStub{}},
		{catalogClockStub{}, &catalogSignatureStub{}, nil, &catalogAnchorStub{}},
		{catalogClockStub{}, &catalogSignatureStub{}, &catalogPublisherStub{}, nil},
	} {
		policy, err := newNativeRuntimeCatalogPolicy(
			asCatalogClock(dependencies[0]), asCatalogSignature(dependencies[1]),
			asCatalogPublisher(dependencies[2]), asCatalogAnchor(dependencies[3]),
		)
		if policy != nil || err == nil {
			t.Fatalf("incomplete policy accepted: policy=%+v error=%v", policy, err)
		}
	}
	policy, err := newNativeRuntimeCatalogPolicy(
		catalogClockStub{}, &catalogSignatureStub{}, &catalogPublisherStub{}, &catalogAnchorStub{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified, err := policy.VerifyRuntimeCatalog(t.Context(), installplanapp.RuntimeEvidenceRequest{}, nativeRuntimeCatalogEnvelope{}); !errors.Is(err, installplanapp.ErrRuntimeEvidenceUnavailable) || !verified.runtime.CatalogDigest().IsZero() {
		t.Fatalf("invalid invocation=%+v error=%v", verified, err)
	}
	var absent *nativeRuntimeCatalogPolicy
	if _, err := absent.VerifyRuntimeCatalog(t.Context(), nativeRuntimeEvidenceRequest(t), nativeRuntimeCatalogEnvelope{}); !errors.Is(err, installplanapp.ErrRuntimeEvidenceUnavailable) {
		t.Fatalf("nil policy error=%v", err)
	}
	if mode, source, err := nativeRuntimeCatalogSourceSelection(runtimecatalog.Manifest{}); mode != runtimecatalog.SourceModeUnknown || source != (runtimecatalog.SourceLocation{}) || err == nil {
		t.Fatalf("invalid source selection=%s/%+v/%v", mode, source, err)
	}
}

func TestPF001NativeRuntimeCatalogSourceSelectionHonorsRedistributionPolicy(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/runtime-catalog-macos.json")
	if err != nil {
		t.Fatal(err)
	}
	bundled, err := runtimecatalog.DecodeManifestV1(bytes.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	mode, source, err := nativeRuntimeCatalogSourceSelection(bundled)
	if err != nil || mode != runtimecatalog.SourceModeOfflineBundle || source != (runtimecatalog.SourceLocation{}) {
		t.Fatalf("bundled selection=%s/%+v/%v", mode, source, err)
	}
	onlineRaw := bytes.Replace(raw, []byte(`"offline_policy":"bundled"`), []byte(`"offline_policy":"user_selected_official"`), 1)
	onlineRaw = bytes.Replace(onlineRaw, []byte(`"redistribution_permitted":true`), []byte(`"redistribution_permitted":false`), 1)
	online, err := runtimecatalog.DecodeManifestV1(bytes.TrimSpace(onlineRaw))
	if err != nil {
		t.Fatal(err)
	}
	mode, source, err = nativeRuntimeCatalogSourceSelection(online)
	if err != nil || mode != runtimecatalog.SourceModeOnline || source == (runtimecatalog.SourceLocation{}) {
		t.Fatalf("online selection=%s/%+v/%v", mode, source, err)
	}
}

func nativeRuntimeEvidenceRequest(t testing.TB) installplanapp.RuntimeEvidenceRequest {
	t.Helper()
	operationID, err := install.NewOperationID("019f5f23-5678-7def-9123-abcdef012347")
	if err != nil {
		t.Fatal(err)
	}
	parent, err := install.BindPlan([]byte("canonical parent plan"))
	if err != nil {
		t.Fatal(err)
	}
	hostPlan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "agentmemory-host-policy", SigningKeyID: "host-policy-root",
		Platform: hostverification.PlatformTuple{
			OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos",
			Architecture: hostverification.ArchitectureARM64, Version: "15.5", Build: "24F74",
		},
		MinimumCPUCores: 8, MinimumMemoryBytes: 32 << 30, MinimumFreeDiskBytes: 100 << 30,
		StorageTargetMode: hostverification.StorageTargetOwnerSelected,
		RequiredPorts:     []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 7474}},
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(hostPlan, "host-policy-root", []byte("detached signature"))
	if err != nil {
		t.Fatal(err)
	}
	return installplanapp.RuntimeEvidenceRequest{
		OperationID: operationID, ParentPlanDigest: parent,
		SignedHostPlan: signed, HostEvidenceDigest: install.DigestBytes([]byte("host receipt")),
		HostStorageTarget: "/Users/agentmemory/Library/Application Support/AgentMemory",
		RuntimeEndpoint:   "unix:///Users/agentmemory/.docker/run/docker.sock",
	}
}

func nativeRuntimeCertifiedCatalog(t testing.TB) runtimeinstall.CertifiedRuntime {
	t.Helper()
	catalog, err := runtimeinstall.NewCertifiedRuntime(
		runtimeinstall.PlatformDarwin, runtimeinstall.ArchitectureARM64, "docker_desktop", "28.3.2", "stable", 42,
		runtimeinstall.Sum([]byte("inner manifest")), runtimeinstall.RuntimeTermsInput{
			ID: runtimeinstall.DockerDesktopTermsID, Version: "2025.07.02",
			URL:    "https://www.docker.com/legal/docker-subscription-service-agreement/",
			Digest: runtimeinstall.Sum([]byte("terms")), Presentation: runtimeinstall.TermsPresentationAgentMemoryThenNative,
		}, 700_000_000, 2_000_000_000,
	)
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

func nativeRuntimeHost(t testing.TB) runtimeinstall.HostCapabilities {
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

type runtimeEnvelopeLoaderStub struct {
	envelope nativeRuntimeCatalogEnvelope
	err      error
	calls    int
}

func (s *runtimeEnvelopeLoaderStub) Load(context.Context, installplanapp.RuntimeEvidenceRequest) (nativeRuntimeCatalogEnvelope, error) {
	s.calls++
	return s.envelope, s.err
}

type runtimeCatalogPolicyStub struct {
	verified nativeVerifiedRuntimeCatalog
	err      error
	calls    int
}

func (s *runtimeCatalogPolicyStub) VerifyRuntimeCatalog(context.Context, installplanapp.RuntimeEvidenceRequest, nativeRuntimeCatalogEnvelope) (nativeVerifiedRuntimeCatalog, error) {
	s.calls++
	return s.verified, s.err
}

type runtimeObservationStub struct {
	host      runtimeinstall.HostCapabilities
	discovery runtimeinstall.RuntimeDiscovery
	digest    install.Digest
	err       error
	calls     int
}

func (s *runtimeObservationStub) ObserveRuntime(
	context.Context,
	installplanapp.RuntimeEvidenceRequest,
	runtimecatalogapp.VerifiedCatalog,
	runtimeinstall.CertifiedRuntime,
) (runtimeinstall.HostCapabilities, runtimeinstall.RuntimeDiscovery, install.Digest, error) {
	s.calls++
	return s.host, s.discovery, s.digest, s.err
}

type catalogSignatureStub struct{}

func (*catalogSignatureStub) VerifyManifestSignature(context.Context, runtimecatalog.SignedManifest) error {
	return nil
}

type catalogPublisherStub struct{}

func (*catalogPublisherStub) VerifyNativePublisherPolicy(context.Context, runtimecatalog.PublisherPolicy) error {
	return nil
}

type catalogAnchorStub struct{}

func (*catalogAnchorStub) LoadCatalogAnchor(context.Context, string) (runtimecatalogapp.CatalogAnchor, error) {
	return runtimecatalogapp.CatalogAnchor{}, runtimecatalogapp.ErrCatalogAnchorNotFound
}
func (*catalogAnchorStub) CompareAndSwapCatalogAnchor(context.Context, *runtimecatalogapp.CatalogAnchor, runtimecatalogapp.CatalogAnchor) error {
	return nil
}

type catalogClockStub struct{}

func (catalogClockStub) Now() time.Time { return time.Unix(1, 0).UTC() }

func asRuntimeLoader(value any) nativeRuntimeCatalogEnvelopeLoader {
	result, _ := value.(nativeRuntimeCatalogEnvelopeLoader)
	return result
}
func asRuntimePolicy(value any) nativeRuntimeCatalogPolicyVerifier {
	result, _ := value.(nativeRuntimeCatalogPolicyVerifier)
	return result
}
func asRuntimeObserver(value any) nativeRuntimeObservationResolver {
	result, _ := value.(nativeRuntimeObservationResolver)
	return result
}
func asCatalogClock(value any) runtimecatalogapp.Clock {
	result, _ := value.(runtimecatalogapp.Clock)
	return result
}
func asCatalogSignature(value any) runtimecatalogapp.ManifestSignatureVerifier {
	result, _ := value.(runtimecatalogapp.ManifestSignatureVerifier)
	return result
}
func asCatalogPublisher(value any) runtimecatalogapp.NativePublisherVerifier {
	result, _ := value.(runtimecatalogapp.NativePublisherVerifier)
	return result
}
func asCatalogAnchor(value any) runtimecatalogapp.AntiRollbackRepository {
	result, _ := value.(runtimecatalogapp.AntiRollbackRepository)
	return result
}
