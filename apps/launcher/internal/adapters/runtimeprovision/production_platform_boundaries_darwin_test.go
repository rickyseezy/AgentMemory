//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
)

func TestPF001DarwinProductionConstructorsBindNativeDesktopAndRejectLinuxElevation(t *testing.T) {
	t.Parallel()
	provider := NewNativeDesktopHostBindingProvider()
	binding, err := provider.CurrentDesktopHostBinding(
		t.Context(), runtimecatalog.DigestBytes([]byte("catalog")), "Docker.dmg",
	)
	if err != nil || binding.HomeDirectory() == "" {
		t.Fatalf("native binding home=%q error=%v", binding.HomeDirectory(), err)
	}
	if candidate, constructError := NewPrivilegedDesktopHostBindingProvider("uid:501"); os.Geteuid() != 0 &&
		(candidate != nil || !errors.Is(constructError, ErrUnsupportedHost)) {
		t.Fatalf("unelevated binding=%T error=%v", candidate, constructError)
	}
	if candidate, constructError := NewPrivilegedDesktopCatalogHostProvider(nil); candidate != nil ||
		!errors.Is(constructError, ErrUnsupportedHost) {
		t.Fatalf("nil privileged host=%T error=%v", candidate, constructError)
	}
	privileged, err := NewPrivilegedDesktopCatalogHostProvider(desktopDarwinBindingProviderFixture())
	if err != nil {
		t.Fatal(err)
	}
	if host, hostError := privileged.CurrentHost(t.Context()); os.Geteuid() != 0 &&
		(host.OperatingSystem() != runtimecatalog.OSKind("") || !errors.Is(hostError, runtimecatalogappDependencyUnavailable())) {
		t.Fatalf("unelevated catalog host os=%q error=%v", host.OperatingSystem(), hostError)
	}
	if candidate, constructError := NewPrivilegedLinuxHostBindingProvider(); candidate != nil ||
		!errors.Is(constructError, ErrUnsupportedHost) {
		t.Fatalf("Darwin Linux binding=%T error=%v", candidate, constructError)
	}
	if candidate, constructError := NewPrivilegedLinuxCatalogHostProvider(nil); candidate != nil ||
		!errors.Is(constructError, ErrUnsupportedHost) {
		t.Fatalf("Darwin Linux host=%T error=%v", candidate, constructError)
	}
}

func TestPF006DarwinProductionHelperFallbacksRemainUnavailable(t *testing.T) {
	t.Parallel()
	publicKeys := NewRootPrivilegeReceiptPublicKeySource()
	if key, err := publicKeys.LoadPrivilegeReceiptPublicKey(t.Context()); len(key) != 0 ||
		!errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Darwin privilege public key=%x error=%v", key, err)
	}
	if key, err := (unavailablePrivilegeReceiptSigningKeySource{}).LoadPrivilegeReceiptSigningKey(t.Context()); len(key) != 0 || !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Darwin privilege signing key=%x error=%v", key, err)
	}
	if signer, err := NewRootPrivilegeReceiptSigner(); signer == nil || err != nil {
		t.Fatalf("fail-closed signer=%T error=%v", signer, err)
	}
	copier := newNativePrivilegeArtifactCopier()
	if err := copier.CopyPrivilegeArtifacts(t.Context(), "/tmp/transaction", 1000, 1000, nil); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Darwin privilege copier error=%v", err)
	}
	if store, err := NewRootPrivilegeArtifactStore(); store == nil || err != nil {
		t.Fatalf("fail-closed artifact store=%T error=%v", store, err)
	}
	for name, construct := range map[string]func() error{
		"protected writer": func() error { _, err := NewNativePrivilegeProtectedFileWriter(); return err },
		"repository probe": func() error { _, err := NewNativePrivilegeRepositoryStateProbe(); return err },
		"subordinate IDs":  func() error { _, err := NewNativePrivilegeSubordinateIDManager(); return err },
	} {
		if err := construct(); !errors.Is(err, ErrUnsupportedHost) {
			t.Fatalf("Darwin %s error=%v", name, err)
		}
	}
	if lock, err := openDarwinDesktopMutationKeyLock(); lock != nil || err == nil {
		t.Fatalf("unelevated production key lock=%v error=%v", lock, err)
	}
	if key, err := loadOrCreateDarwinDesktopMutationPrivateKey(); len(key) != 0 || err == nil {
		t.Fatalf("unelevated production private key bytes=%d error=%v", len(key), err)
	}
	if err := ensureDarwinDesktopMutationPublicKey(make(ed25519.PublicKey, ed25519.PublicKeySize)); err == nil {
		t.Fatal("unelevated production public key was published")
	}
	if _, err := (CanonicalPrivilegeRequestDecoder{}).DecodePrivilegeRequest(nil); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("empty privilege request error=%v", err)
	}
	if _, err := (&CanonicalPrivilegeTransportCodec{}).DecodePrivilegeReceipt(nil); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("empty privilege receipt error=%v", err)
	}
}

func TestPF006DarwinRendersDNFRepositoryFromClosedAuthority(t *testing.T) {
	t.Parallel()
	_, apt := adapterAuthority(t)
	dnf := privilegeDNFAuthority(t, apt)
	configurationPath, keyPath, configuration, err := renderPrivilegeRepository(dnf)
	if err != nil || configurationPath != "/etc/yum.repos.d/agentmemory-docker-stable.repo" ||
		keyPath != "/etc/pki/rpm-gpg/RPM-GPG-KEY-agentmemory-docker-stable" || len(configuration) == 0 {
		t.Fatalf("DNF paths=%q/%q bytes=%d error=%v", configurationPath, keyPath, len(configuration), err)
	}
	if direct, err := renderDNFPrivilegeRepository(dnf, keyPath); err != nil || string(direct) != string(configuration) {
		t.Fatalf("direct DNF bytes=%q error=%v", direct, err)
	}
}

func TestPF001DarwinProductionCatalogObserverSelectsNativeBackend(t *testing.T) {
	t.Parallel()
	observer, err := NewNativeCatalogObserver(productionCatalogPublisherStub{}, &catalogHostReattestorStub{})
	if err != nil || observer == nil || observer.backend == nil {
		t.Fatalf("observer=%T backend=%T error=%v", observer, observer.backend, err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := privilegedDesktopCatalogContextOrUnavailable(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled privileged catalog error=%v", err)
	}
	if err := privilegedDesktopCatalogContextOrUnavailable(t.Context()); !errors.Is(err, runtimecatalogappDependencyUnavailable()) {
		t.Fatalf("privileged catalog fallback error=%v", err)
	}
}

// This helper keeps the platform test's dependency assertion readable while
// preserving the application layer's public sentinel identity.
func runtimecatalogappDependencyUnavailable() error {
	return runtimecatalogapp.ErrDependencyUnavailable
}

type productionCatalogPublisherStub struct{}

func (productionCatalogPublisherStub) NativeTrustDigest(runtimecatalog.PublisherPolicy) (runtimecatalog.Digest, error) {
	return runtimecatalog.DigestBytes([]byte("publisher")), nil
}
