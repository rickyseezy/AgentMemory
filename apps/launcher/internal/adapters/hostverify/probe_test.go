package hostverify

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/hostverifyapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/hostverification"
)

func TestPF001NativeProbeReturnsOnlyValidatedEvidenceOrClosedFailure(t *testing.T) {
	t.Parallel()
	plan, observation := adapterFixture(t)
	observed, _ := hostverification.NewObservedResult(observation)
	rejected, _ := hostverification.NewRejectedResult(hostverification.FailureEncryptionUnavailable)
	tests := []struct {
		name      string
		collector collector
		want      hostverification.FailureReason
		observed  bool
	}{
		{name: "observed", collector: fixedCollector{input: observationInput(observation), reason: hostverification.FailureNone}, want: hostverification.FailureNone, observed: true},
		{name: "rejected", collector: fixedCollector{reason: hostverification.FailureEncryptionUnavailable}, want: hostverification.FailureEncryptionUnavailable},
		{name: "invalid observation", collector: fixedCollector{reason: hostverification.FailureNone}, want: hostverification.FailurePlatformProofUnavailable},
	}
	_ = observed
	_ = rejected
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			probe := &NativeProbe{collector: test.collector}
			result, err := probe.ProbeHost(context.Background(), plan)
			if err != nil || !result.Valid() || result.Failure() != test.want {
				t.Fatalf("ProbeHost() = %+v, %v", result, err)
			}
			_, gotObservation := result.Observation()
			if gotObservation != test.observed {
				t.Fatalf("observed = %v", gotObservation)
			}
		})
	}

	if _, err := (&NativeProbe{}).ProbeHost(context.Background(), plan); err == nil {
		t.Fatal("uninitialized probe succeeded")
	}
	if _, err := (*NativeProbe)(nil).ProbeHost(context.Background(), plan); err == nil {
		t.Fatal("nil probe succeeded")
	}
	var absentContext context.Context
	if _, err := (&NativeProbe{collector: fixedCollector{}}).ProbeHost(absentContext, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := (&NativeProbe{collector: fixedCollector{}}).ProbeHost(cancelled, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	native := NewNativeProbe()
	if native == nil {
		t.Fatal("NewNativeProbe() returned nil")
	}
	closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := native.Close(closeCtx); err != nil {
		t.Fatalf("native probe close = %v", err)
	}
}

func TestPF001NativeProbeClosesOwnedPlatformResources(t *testing.T) {
	t.Parallel()
	collector := &closingCollector{}
	probe := &NativeProbe{collector: collector}
	if err := probe.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !collector.closed {
		t.Fatal("collector was not closed")
	}
	if err := (&NativeProbe{collector: fixedCollector{}}).Close(context.Background()); err != nil {
		t.Fatalf("stateless collector close = %v", err)
	}
	if err := (&NativeProbe{collector: fixedCollector{}}).Close(cancelledContext()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled stateless close error = %v", err)
	}
	var absent context.Context
	if err := probe.Close(absent); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil context close error = %v", err)
	}
	if err := (*NativeProbe)(nil).Close(context.Background()); err == nil {
		t.Fatal("nil probe close succeeded")
	}
}

func TestPF001HostPolicyEd25519VerifierUsesCopiedClosedTrustRoots(t *testing.T) {
	t.Parallel()
	plan, _ := adapterFixture(t)
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := hostverification.NewSignedPlan(plan, plan.SigningKeyID(), ed25519.Sign(privateKey, plan.CanonicalBytes()))
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]ed25519.PublicKey{plan.SigningKeyID(): publicKey}
	verifier, err := NewEd25519Verifier(keys)
	if err != nil {
		t.Fatal(err)
	}
	clear(publicKey)
	delete(keys, plan.SigningKeyID())
	if err := verifier.VerifyHostPlanSignature(context.Background(), signed); err != nil {
		t.Fatalf("VerifyHostPlanSignature() = %v", err)
	}

	otherPublic, _, _ := ed25519.GenerateKey(nil)
	untrusted, _ := NewEd25519Verifier(map[string]ed25519.PublicKey{"other-root": otherPublic})
	if err := untrusted.VerifyHostPlanSignature(context.Background(), signed); !errors.Is(err, hostverifyapp.ErrUntrustedSigner) {
		t.Fatalf("untrusted error = %v", err)
	}
	badSignature, _ := hostverification.NewSignedPlan(plan, plan.SigningKeyID(), make([]byte, ed25519.SignatureSize))
	if err := verifier.VerifyHostPlanSignature(context.Background(), badSignature); !errors.Is(err, hostverifyapp.ErrSignatureInvalid) {
		t.Fatalf("signature error = %v", err)
	}
	if err := verifier.VerifyHostPlanSignature(context.Background(), hostverification.SignedPlan{}); !errors.Is(err, hostverifyapp.ErrSignatureInvalid) {
		t.Fatalf("invalid envelope error = %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := verifier.VerifyHostPlanSignature(cancelled, signed); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled error = %v", err)
	}
	for _, roots := range []map[string]ed25519.PublicKey{
		nil,
		{"": otherPublic},
		{"root": []byte("short")},
	} {
		if _, err := NewEd25519Verifier(roots); err == nil {
			t.Fatalf("NewEd25519Verifier(%v) succeeded", roots)
		}
	}
}

func TestPF001LoopbackAttestationUsesExactAddressFamilyAndRejectsOccupiedPort(t *testing.T) {
	t.Parallel()
	if network, address, err := loopbackAddress(hostverification.LoopbackEndpoint{Family: hostverification.LoopbackIPv4, Port: 4317}); err != nil || network != "tcp4" || address != "127.0.0.1:4317" {
		t.Fatalf("IPv4 address = %q, %q, %v", network, address, err)
	}
	if network, address, err := loopbackAddress(hostverification.LoopbackEndpoint{Family: hostverification.LoopbackIPv6, Port: 4318}); err != nil || network != "tcp6" || address != "[::1]:4318" {
		t.Fatalf("IPv6 address = %q, %q, %v", network, address, err)
	}
	if _, _, err := loopbackAddress(hostverification.LoopbackEndpoint{Family: "wildcard", Port: 1}); err == nil {
		t.Fatal("wildcard address family was accepted")
	}

	occupied, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = occupied.Close() }()
	port := checkedTestPort(t, occupied)
	endpoint := hostverification.LoopbackEndpoint{Family: hostverification.LoopbackIPv4, Port: port}
	if attestLoopback(context.Background(), []hostverification.LoopbackEndpoint{endpoint}) {
		t.Fatal("occupied loopback port was attested as available")
	}
	if attestLoopback(cancelledContext(), []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 1}}) {
		t.Fatal("cancelled loopback attestation succeeded")
	}

	available, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	availablePort := checkedTestPort(t, available)
	_ = available.Close()
	if !attestLoopback(context.Background(), []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: availablePort}}) {
		t.Fatal("available loopback port was rejected")
	}
}

func checkedTestPort(t *testing.T, listener net.Listener) uint16 {
	t.Helper()
	port := listener.Addr().(*net.TCPAddr).Port
	if port <= 0 || port > 65535 {
		t.Fatalf("invalid OS-assigned port %d", port)
	}
	return uint16(port) // #nosec G115 -- range is proved immediately above.
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func adapterFixture(t *testing.T) (hostverification.Plan, hostverification.Observation) {
	t.Helper()
	plan, err := hostverification.NewPlan(hostverification.Input{
		PolicyID: "host-policy-1", SigningKeyID: "host-root-1",
		Platform:        hostverification.PlatformTuple{OperatingSystem: hostverification.OperatingSystemMacOS, Product: "macos", Architecture: hostverification.ArchitectureARM64, Version: "15.5", Build: "24F74"},
		MinimumCPUCores: 4, MinimumMemoryBytes: 8 << 30, MinimumFreeDiskBytes: 1 << 30,
		StorageTarget: "/Users/user/Library/Application Support/AgentMemory",
		RequiredPorts: []hostverification.LoopbackEndpoint{{Family: hostverification.LoopbackIPv4, Port: 4317}},
	})
	if err != nil {
		t.Fatal(err)
	}
	observation, err := hostverification.NewObservation(hostverification.ObservationInput{
		Platform: plan.Platform(), CPUCores: 8, MemoryBytes: 16 << 30, FreeDiskBytes: 100 << 30,
		StorageTarget: plan.StorageTarget(), Virtualization: hostverification.VirtualizationHypervisorFramework,
		Encryption: hostverification.EncryptionFileVault, AvailablePorts: plan.RequiredPorts(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan, observation
}

func observationInput(observation hostverification.Observation) hostverification.ObservationInput {
	return hostverification.ObservationInput{
		Platform: observation.Platform(), CPUCores: observation.CPUCores(), MemoryBytes: observation.MemoryBytes(),
		FreeDiskBytes: observation.FreeDiskBytes(), StorageTarget: observation.StorageTarget(),
		Virtualization: observation.Virtualization(), Encryption: observation.Encryption(), AvailablePorts: observation.AvailablePorts(),
	}
}

type fixedCollector struct {
	input  hostverification.ObservationInput
	reason hostverification.FailureReason
}

func (c fixedCollector) collect(context.Context, hostverification.Plan) (hostverification.ObservationInput, hostverification.FailureReason) {
	return c.input, c.reason
}

type closingCollector struct {
	closed bool
}

func (*closingCollector) collect(context.Context, hostverification.Plan) (hostverification.ObservationInput, hostverification.FailureReason) {
	return hostverification.ObservationInput{}, hostverification.FailureEncryptionUnavailable
}

func (c *closingCollector) close(ctx context.Context) error {
	c.closed = true
	return ctx.Err()
}
