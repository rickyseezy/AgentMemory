//go:build linux

package runtimeprovision

import (
	"context"
	"errors"
	"testing"
	"time"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF001LinuxDesktopNativeBoundariesFailClosed(t *testing.T) {
	t.Parallel()
	probe, err := NewNativeDesktopHostProbe(DesktopHostProbeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewNativeDesktopArtifactVerifier(DesktopArtifactVerifierDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	installed, err := NewNativeDesktopInstalledApplicationProbe(DesktopInstalledApplicationProbeDependencies{})
	if err != nil {
		t.Fatal(err)
	}
	launcher, err := NewNativeDesktopRuntimeLauncher()
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var nilContext context.Context
	if _, err := probe.ProbeDesktopHost(ctx, runtimeport.DesktopAuthority{}); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("desktop host probe error = %v", err)
	}
	if _, err := verifier.VerifyDesktopArtifact(ctx, runtimeport.DesktopAuthority{}); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("desktop artifact verification error = %v", err)
	}
	if _, err := installed.ProbeDesktopInstalledApplication(ctx, runtimeport.DesktopAuthority{}); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("desktop installed-app probe error = %v", err)
	}
	if _, err := launcher.LaunchDesktopRuntime(ctx, runtimeport.DesktopAuthority{}); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("desktop runtime launch error = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := probe.ProbeDesktopHost(cancelled, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled desktop host error = %v", err)
	}
	if _, err := verifier.VerifyDesktopArtifact(nilContext, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context desktop artifact error = %v", err)
	}
	if _, err := installed.ProbeDesktopInstalledApplication(cancelled, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled installed-app error = %v", err)
	}
	if _, err := launcher.LaunchDesktopRuntime(nilContext, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context desktop launcher error = %v", err)
	}
	if _, err := prepareNativeDesktopProbeWorkspace(ctx, runtimeport.DesktopAuthority{}); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("desktop workspace error = %v", err)
	}
	if _, err := prepareNativeDesktopProbeWorkspace(nilContext, runtimeport.DesktopAuthority{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context desktop workspace error = %v", err)
	}
}

func TestPF001LinuxDesktopMutationBrokerAndExchangeFailClosed(t *testing.T) {
	t.Parallel()
	if _, err := NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{}); !errors.Is(err, ErrProvisionIntegrity) {
		t.Fatalf("empty desktop mutation broker error = %v", err)
	}
	var typedNil *desktopMutationAuthorityStub
	if !desktopMutationNil(nil) || !desktopMutationNil(typedNil) || desktopMutationNil(struct{}{}) {
		t.Fatal("desktop mutation dependency nil detector drifted")
	}
	ctx := context.Background()
	var nilContext context.Context
	if _, err := createNativeDesktopMutationExchange(ctx, runtimeport.DesktopHelperAuthority{}, runtimeport.DesktopMutationRequest{}, []byte(`{}`)); !errors.Is(err, runtimeport.ErrDesktopMutationUnavailable) {
		t.Fatalf("desktop mutation exchange error = %v", err)
	}
	if _, err := createNativeDesktopMutationExchange(nilContext, runtimeport.DesktopHelperAuthority{}, runtimeport.DesktopMutationRequest{}, []byte(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context mutation exchange error = %v", err)
	}
	if err := executeNativeDesktopHelper(ctx, runtimeport.DesktopHelperAuthority{}, "request", runtimeport.DesktopMutationInstallRuntime); !errors.Is(err, runtimeport.ErrDesktopMutationUnavailable) {
		t.Fatalf("desktop helper execution error = %v", err)
	}
	if err := executeNativeDesktopHelper(nilContext, runtimeport.DesktopHelperAuthority{}, "request", runtimeport.DesktopMutationInstallRuntime); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil-context desktop helper error = %v", err)
	}
	exchange := nativeDesktopMutationExchange{}
	if _, err := exchange.readReceipt(ctx); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("empty mutation receipt error = %v", err)
	}
	removed := 0
	exchange = nativeDesktopMutationExchange{
		requestPath: "request", receiptPath: "receipt",
		read:   func(context.Context, string) ([]byte, error) { return []byte("receipt"), nil },
		remove: func(string) error { removed++; return nil },
	}
	if raw, err := exchange.readReceipt(ctx); err != nil || string(raw) != "receipt" {
		t.Fatalf("mutation receipt = %q/%v", raw, err)
	}
	exchange.cleanup()
	if removed != 2 {
		t.Fatalf("mutation exchange removed %d paths", removed)
	}
	(nativeDesktopMutationExchange{}).cleanup()
	if _, err := (*nativeDesktopMutationBroker)(nil).ExecuteDesktopMutation(ctx, runtimeport.DesktopMutationRequest{}); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("nil mutation broker error = %v", err)
	}
	_, authority := desktopAdapterAuthority(t, runtimeinstall.PlatformDarwin)
	helper, err := runtimeport.NewDesktopHelperAuthority(runtimeport.DesktopHelperAuthorityInput{
		Platform: authority.Platform(), Architecture: authority.Architecture(), PlanDigest: authority.PlanDigest(),
		PrincipalID: authority.PrincipalID(), MachineDigest: authority.MachineDigest(),
		CanonicalPath: "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
		SHA256:        runtimeinstall.Sum([]byte("helper")), PublisherIdentity: "agentmemory-helper",
		PublisherCertificate:  runtimeinstall.Sum([]byte("certificate")),
		ReleaseManifestDigest: runtimeinstall.Sum([]byte("manifest")),
		ExchangeDirectory:     "/Users/agentmemory/Library/Application Support/AgentMemory/bootstrap/test/native",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	request, err := runtimeport.NewDesktopMutationRequest(
		"linux-closed-desktop-1", 1, runtimeport.DesktopMutationInstallRuntime, authority,
		runtimeinstall.Sum([]byte("consent")), authority.ArtifactSHA256(), runtimeport.Nonce{1}, now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	broker, err := NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{
		Authority: &desktopMutationAuthorityStub{helper: helper}, Publisher: desktopMutationPublisherStub{}, Encoder: &desktopMutationEncoderStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecuteDesktopMutation(ctx, request); !errors.Is(err, runtimeport.ErrDesktopMutationUnavailable) {
		t.Fatalf("unavailable native mutation execution error = %v", err)
	}
	publisherFailure := errors.New("publisher unavailable")
	broker, err = NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{
		Authority: &desktopMutationAuthorityStub{helper: helper}, Publisher: desktopMutationPublisherStub{err: publisherFailure}, Encoder: &desktopMutationEncoderStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecuteDesktopMutation(ctx, request); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("untrusted helper publisher error = %v", err)
	}
	resolverFailure := errors.New("resolver unavailable")
	broker, err = NewNativeDesktopMutationBroker(NativeDesktopMutationDependencies{
		Authority: &desktopMutationAuthorityStub{err: resolverFailure}, Publisher: desktopMutationPublisherStub{}, Encoder: &desktopMutationEncoderStub{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := broker.ExecuteDesktopMutation(ctx, request); !errors.Is(err, resolverFailure) ||
		!errors.Is(err, runtimeport.ErrDesktopMutationUnavailable) {
		t.Fatalf("resolver mutation error = %v", err)
	}
}

type desktopMutationAuthorityStub struct {
	helper runtimeport.DesktopHelperAuthority
	err    error
}

func (s *desktopMutationAuthorityStub) ResolveDesktopHelperAuthority(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopHelperAuthority, error) {
	return s.helper, s.err
}

type desktopMutationPublisherStub struct{ err error }

func (s desktopMutationPublisherStub) VerifyDesktopHelperPublisher(
	context.Context,
	runtimeport.DesktopHelperAuthority,
) error {
	return s.err
}
