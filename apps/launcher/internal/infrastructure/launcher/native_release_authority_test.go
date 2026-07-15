package launcher

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/firststartapp"
)

func TestPF001NativeReleaseAuthorityOwnsExactBundleAndCompleteTrustStack(t *testing.T) {
	t.Parallel()
	root := nativeReleaseAuthorityBundleRoot(t)
	fixture := nativeReleaseStackFixture(t)
	authority, err := newNativeReleaseAuthority(t.Context(), nativeReleaseAuthorityDependencies{
		BundleRoot: func() (string, error) { return root, nil },
		Trust:      func() (nativeReleaseTrustMaterial, error) { return fixture.Trust, nil },
		Clock:      fixture.Clock, AntiRollback: fixture.AntiRollback,
	})
	if err != nil || authority.templates() == nil || authority.verifier() == nil ||
		authority.hostVerification() == nil || authority.releaseVerification() == nil ||
		authority.runtimeCatalogLoader() == nil || authority.runtimeCatalogSignatureVerifier() == nil ||
		authority.runtimeCatalogPublisherVerifier() == nil ||
		len(authority.runtimeHelperAuthenticationKey()) != ed25519.PublicKeySize {
		t.Fatalf("authority=%#v error=%v", authority, err)
	}
	helperKey := authority.runtimeHelperAuthenticationKey()
	helperKey[0] ^= 0xff
	if authority.runtimeHelperAuthenticationKey()[0] == helperKey[0] {
		t.Fatal("runtime helper authentication key aliases caller memory")
	}
	if authority.runtimeHelperPublisherCertificateDigest("runtime-helper-darwin-arm64").IsZero() ||
		authority.runtimeHelperPublisherCertificateDigest("runtime-helper-windows-amd64").IsZero() ||
		!authority.runtimeHelperPublisherCertificateDigest("foreign").IsZero() {
		t.Fatal("runtime helper publisher certificate is unavailable")
	}
	if authority.nativePublisherCertificateDigest("runtime-helper-windows-amd64").IsZero() ||
		!(*nativeReleaseAuthority)(nil).nativePublisherCertificateDigest("launcher").IsZero() {
		t.Fatal("native publisher certificate binding is unavailable")
	}
	if err := authority.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := authority.Close(t.Context()); err != nil {
		t.Fatalf("idempotent close error=%v", err)
	}
}

func TestPF001NativeReleaseAuthorityFailsClosedBeforePublishingCapability(t *testing.T) {
	t.Parallel()
	root := nativeReleaseAuthorityBundleRoot(t)
	fixture := nativeReleaseStackFixture(t)
	valid := nativeReleaseAuthorityDependencies{
		BundleRoot: func() (string, error) { return root, nil },
		Trust:      func() (nativeReleaseTrustMaterial, error) { return fixture.Trust, nil },
		Clock:      fixture.Clock, AntiRollback: fixture.AntiRollback,
	}
	var nilClock *nativeReleaseClock
	var nilAnchor *nativeReleasePorts
	for _, test := range []struct {
		name   string
		mutate func(*nativeReleaseAuthorityDependencies)
		want   error
	}{
		{name: "bundle resolver", mutate: func(d *nativeReleaseAuthorityDependencies) { d.BundleRoot = nil }, want: firststartapp.ErrIntegrity},
		{name: "trust loader", mutate: func(d *nativeReleaseAuthorityDependencies) { d.Trust = nil }, want: firststartapp.ErrIntegrity},
		{name: "clock", mutate: func(d *nativeReleaseAuthorityDependencies) { d.Clock = nilClock }, want: firststartapp.ErrIntegrity},
		{name: "anchor", mutate: func(d *nativeReleaseAuthorityDependencies) { d.AntiRollback = nilAnchor }, want: firststartapp.ErrIntegrity},
		{name: "bundle failure", mutate: func(d *nativeReleaseAuthorityDependencies) {
			d.BundleRoot = func() (string, error) { return "", errors.New("private path") }
		}, want: firststartapp.ErrUnavailable},
		{name: "unsafe bundle", mutate: func(d *nativeReleaseAuthorityDependencies) {
			d.BundleRoot = func() (string, error) { return "relative", nil }
		}, want: firststartapp.ErrUnavailable},
		{name: "trust failure", mutate: func(d *nativeReleaseAuthorityDependencies) {
			d.Trust = func() (nativeReleaseTrustMaterial, error) {
				return nativeReleaseTrustMaterial{}, errors.New("private trust")
			}
		}, want: firststartapp.ErrIntegrity},
		{name: "invalid trust", mutate: func(d *nativeReleaseAuthorityDependencies) {
			d.Trust = func() (nativeReleaseTrustMaterial, error) { return nativeReleaseTrustMaterial{}, nil }
		}, want: firststartapp.ErrIntegrity},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			authority, err := newNativeReleaseAuthority(t.Context(), candidate)
			if authority != nil || !errors.Is(err, test.want) {
				t.Fatalf("authority=%#v error=%v want=%v", authority, err, test.want)
			}
		})
	}
	//lint:ignore SA1012 Deliberate absent-context production boundary.
	if authority, err := newNativeReleaseAuthority(nil, valid); authority != nil || !errors.Is(err, firststartapp.ErrIntegrity) { //nolint:staticcheck
		t.Fatalf("nil context authority=%#v error=%v", authority, err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if authority, err := newNativeReleaseAuthority(canceled, valid); authority != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled authority=%#v error=%v", authority, err)
	}
	var absent *nativeReleaseAuthority
	if absent.templates() != nil || absent.verifier() != nil || absent.hostVerification() != nil ||
		absent.releaseVerification() != nil || absent.runtimeCatalogLoader() != nil ||
		absent.runtimeCatalogSignatureVerifier() != nil || absent.runtimeCatalogPublisherVerifier() != nil ||
		len(absent.runtimeHelperAuthenticationKey()) != 0 ||
		!absent.runtimeHelperPublisherCertificateDigest("resource").IsZero() {
		t.Fatal("absent release authority exposed a capability")
	}
	if err := absent.Close(t.Context()); err != nil {
		t.Fatalf("absent release close error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context release boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := (&nativeReleaseAuthority{}).Close(nil); err == nil {
		t.Fatal("release authority accepted a nil close context")
	}
}

func nativeReleaseAuthorityBundleRoot(t testing.TB) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "bundle")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}
