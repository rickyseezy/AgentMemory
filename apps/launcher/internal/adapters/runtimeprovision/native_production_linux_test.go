//go:build linux

package runtimeprovision

import (
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/unix"
)

func TestPF006LinuxCatalogObservationBackendBindsCurrentCertifiedHost(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("the rootless catalog principal deliberately rejects uid/gid zero")
	}
	catalog, _, _, _ := verifiedLinuxCatalogProjectionFixture(t)
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid()) // #nosec G115 -- positive native IDs are bounded by the kernel ABI.
	endpoint := "/run/user/" + strconv.Itoa(os.Geteuid()) + "/docker.sock"
	input := CatalogObservationInput{
		Catalog: catalog, CertifiedRuntime: certified, HostStorageTarget: t.TempDir(),
		RuntimeEndpoint:      "unix://" + endpoint,
		NativePublisherTrust: runtimecatalog.DigestBytes([]byte("native package authority")),
	}
	host, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	hostVersion := "ubuntu:24.04:6.8.0"
	backend := nativeCatalogObservationBackend{
		host: func(observed CatalogObservationInput, observedUID uint32) (runtimeinstall.HostCapabilities, string, error) {
			if observed.RuntimeEndpoint != input.RuntimeEndpoint || observedUID != uid {
				return runtimeinstall.HostCapabilities{}, "", ErrProbeFailed
			}
			return host, hostVersion, nil
		},
		runtime: func(
			_ context.Context,
			observed CatalogObservationInput,
			observedUID uint32,
			observedGID uint32,
			observedEndpoint string,
		) (runtimeinstall.RuntimeDiscovery, bool, error) {
			if observed.RuntimeEndpoint != input.RuntimeEndpoint || observedUID != uid || observedGID != gid ||
				observedEndpoint != endpoint {
				return runtimeinstall.RuntimeDiscovery{}, false, ErrProbeFailed
			}
			return runtimeinstall.NewAbsentRuntimeDiscovery(), false, nil
		},
	}
	result, err := backend.ObserveCatalogRuntime(t.Context(), input)
	if err != nil || result.Evidence.IsZero() || result.Host.Platform() != runtimeinstall.PlatformLinux ||
		result.Discovery != runtimeinstall.NewAbsentRuntimeDiscovery() {
		t.Fatalf("catalog observation=%+v error=%v", result, err)
	}
	if result, err := (nativeCatalogObservationBackend{}).ObserveCatalogRuntime(
		t.Context(), CatalogObservationInput{},
	); !errors.Is(err, ErrProvisionIntegrity) || !result.Evidence.IsZero() {
		t.Fatalf("invalid catalog observation=%+v error=%v", result, err)
	}
	if architecture, err := linuxCatalogArchitecture(runtimecatalog.Architecture("")); architecture != runtimeinstall.ArchitectureUnknown ||
		!errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("unknown catalog architecture=%s error=%v", architecture, err)
	}
	distribution, version, releaseError := linuxOSRelease()
	if releaseError != nil || distribution != "ubuntu" || version != "24.04" {
		t.Logf("native certified-host probe is reserved for Ubuntu 24.04 (host=%s:%s error=%v)", distribution, version, releaseError)
		return
	}
	observed, observedVersion, err := observeLinuxCatalogHost(input, uid)
	if runtime.GOARCH != "amd64" {
		if !errors.Is(err, ErrUnsupportedHost) || observedVersion != "" ||
			observed != (runtimeinstall.HostCapabilities{}) {
			t.Fatalf("foreign-architecture catalog host=%+v version=%q error=%v", observed, observedVersion, err)
		}
		return
	}
	if err != nil || observed.Platform() != runtimeinstall.PlatformLinux || observedVersion == "" {
		t.Fatalf("certified Linux host=%+v version=%q error=%v", observed, observedVersion, err)
	}
}

func TestPF006LinuxCatalogRuntimeObservationUsesOnlyCertifiedSurfaces(t *testing.T) {
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		t.Skip("the rootless catalog principal deliberately rejects uid/gid zero")
	}
	catalog, _, _, _ := verifiedLinuxCatalogProjectionFixture(t)
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid()) // #nosec G115 -- positive native IDs are bounded by the kernel ABI.
	endpoint := "/run/user/" + strconv.Itoa(os.Geteuid()) + "/docker.sock"
	input := CatalogObservationInput{
		Catalog: catalog, CertifiedRuntime: certified, HostStorageTarget: t.TempDir(),
		RuntimeEndpoint:      "unix://" + endpoint,
		NativePublisherTrust: runtimecatalog.DigestBytes([]byte("native package authority")),
	}
	discovery, candidate, err := observeLinuxCatalogRuntime(t.Context(), input, uid, gid, endpoint)
	if errors.Is(err, ErrRuntimeConflict) {
		if !candidate || discovery != (runtimeinstall.RuntimeDiscovery{}) {
			t.Fatalf("conflicting runtime discovery=%+v candidate=%t", discovery, candidate)
		}
		return
	}
	if err != nil {
		t.Fatalf("catalog runtime discovery=%+v candidate=%t error=%v", discovery, candidate, err)
	}
	if candidate && discovery == runtimeinstall.NewAbsentRuntimeDiscovery() {
		t.Fatalf("candidate runtime discovery=%+v", discovery)
	}
	if !candidate && discovery != runtimeinstall.NewAbsentRuntimeDiscovery() {
		t.Fatalf("absent runtime discovery=%+v", discovery)
	}
}

func TestPF006LinuxCertifiedHostObservationEvaluatesEveryNativeFact(t *testing.T) {
	t.Parallel()
	catalog, _, _, _ := verifiedLinuxCatalogProjectionFixture(t)
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	uid := uint32(os.Geteuid()) // #nosec G115 -- native IDs are bounded by the kernel ABI.
	observations := linuxCatalogHostObservations{
		osRelease: func() (string, string, error) { return "ubuntu", "24.04", nil },
		kernel: func() (string, runtimeinstall.Architecture, error) {
			return "6.8.0", certified.Architecture(), nil
		},
		resources: func() (uint16, uint64, uint64, error) { return 8, 32 << 30, 24 << 30, nil },
		filesystem: func(path string) (uint64, bool, error) {
			if path != target {
				t.Fatalf("filesystem target=%q", path)
			}
			return 100 << 30, true, nil
		},
		namespaces: func() (bool, error) { return true, nil },
		selinux:    func() (bool, error) { return false, nil },
		currentUser: func() (*user.User, error) {
			return &user.User{Uid: strconv.FormatUint(uint64(uid), 10), Gid: strconv.Itoa(os.Getegid())}, nil
		},
		validateOwner: func(path string, owner uint32, runtimeDirectory bool) error {
			if path != target || owner != uid || runtimeDirectory {
				t.Fatalf("owner validation=%q/%d/%t", path, owner, runtimeDirectory)
			}
			return nil
		},
	}
	input := CatalogObservationInput{Catalog: catalog, CertifiedRuntime: certified, HostStorageTarget: target}
	if backend := newNativeCatalogObservationBackend(); backend == nil {
		t.Fatal("native catalog observation backend is absent")
	}
	host, version, err := observeLinuxCatalogHostUsing(input, uid, observations)
	if err != nil || host.Platform() != runtimeinstall.PlatformLinux ||
		host.Architecture() != certified.Architecture() || version != "ubuntu:24.04:6.8.0" {
		t.Fatalf("certified host=%+v version=%q error=%v", host, version, err)
	}
	if host, version, err := observeLinuxCatalogHostUsing(input, uid, linuxCatalogHostObservations{}); !errors.Is(err, ErrProbeFailed) ||
		version != "" || host.Platform() != runtimeinstall.PlatformUnknown {
		t.Fatalf("missing observations host=%+v version=%q error=%v", host, version, err)
	}

	rejected := observations
	rejected.osRelease = func() (string, string, error) { return "fedora", "42", nil }
	if _, _, err := observeLinuxCatalogHostUsing(input, uid, rejected); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("substituted distribution error=%v", err)
	}
	rejected = observations
	rejected.kernel = func() (string, runtimeinstall.Architecture, error) {
		if certified.Architecture() == runtimeinstall.ArchitectureAMD64 {
			return "6.8.0", runtimeinstall.ArchitectureARM64, nil
		}
		return "6.8.0", runtimeinstall.ArchitectureAMD64, nil
	}
	if _, _, err := observeLinuxCatalogHostUsing(input, uid, rejected); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("substituted architecture error=%v", err)
	}
	rejected = observations
	rejected.resources = func() (uint16, uint64, uint64, error) { return 0, 32 << 30, 24 << 30, nil }
	if _, _, err := observeLinuxCatalogHostUsing(input, uid, rejected); !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("invalid host capability error=%v", err)
	}
	nativeHost, nativeVersion, nativeError := observeLinuxCatalogHost(input, uid)
	if nativeError == nil {
		if nativeHost.Platform() != runtimeinstall.PlatformLinux || nativeVersion == "" {
			t.Fatalf("native host=%+v version=%q", nativeHost, nativeVersion)
		}
	} else if !errors.Is(nativeError, ErrUnsupportedHost) && !errors.Is(nativeError, ErrProbeFailed) {
		t.Fatalf("native certified-host observation error=%v", nativeError)
	}
}

func TestPF006LinuxPrivilegeArtifactTransactionCopiesOnlyExactOwnedBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(t.TempDir(), "package.deb")
	contents := []byte("exact signed package bytes")
	if err := os.WriteFile(source, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "package.deb")
	artifact := PrivilegeTransactionArtifact{
		artifactID: "package", sourcePath: source, targetPath: target,
		sha256: runtimeinstall.Sum(contents), size: uint64(len(contents)),
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid()) // #nosec G115 -- native IDs are bounded by the kernel ABI.
	if err := copyPrivilegeArtifact(t.Context(), root, uid, gid, artifact); err != nil {
		t.Fatal(err)
	}
	published, err := os.ReadFile(target)
	if err != nil || string(published) != string(contents) {
		t.Fatalf("published bytes=%q error=%v", published, err)
	}
	if !existingPrivilegeArtifactMatches(target, uid, gid, artifact.sha256, artifact.size) ||
		existingPrivilegeArtifactMatches(target, uid, gid, runtimeinstall.Sum([]byte("foreign")), artifact.size) {
		t.Fatal("existing privilege artifact did not bind exact owner, size, and digest")
	}
	descriptor, err := unix.Open(source, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !privilegeArtifactDescriptorMatches(descriptor, uid, gid, artifact.size) {
		_ = unix.Close(descriptor)
		t.Fatal("exact source descriptor rejected")
	}
	if err := unix.Close(descriptor); err != nil {
		t.Fatal(err)
	}
	if privilegeArtifactDescriptorMatches(descriptor, uid, gid, artifact.size) {
		t.Fatal("closed source descriptor accepted")
	}
	if err := syncPrivilegeDirectory(root); err != nil {
		t.Fatal(err)
	}

	for name, comparison := range map[string]struct{ got, want int }{
		"less":  {comparePrivilegeArtifactID("a", "b"), -1},
		"equal": {comparePrivilegeArtifactID("a", "a"), 0},
		"more":  {comparePrivilegeArtifactID("b", "a"), 1},
	} {
		if comparison.got != comparison.want {
			t.Fatalf("%s comparison=%d want=%d", name, comparison.got, comparison.want)
		}
	}
	if !canonicalLowerSHA256ForTransaction(artifact.sha256.String()) ||
		canonicalLowerSHA256ForTransaction("not-a-digest") {
		t.Fatal("transaction digest canonicality mismatch")
	}
	if !nonNegativeInt64EqualsUint64(int64(len(contents)), uint64(len(contents))) ||
		nonNegativeInt64EqualsUint64(-1, 0) {
		t.Fatal("signed transaction size conversion mismatch")
	}
	if copier := newNativePrivilegeArtifactCopier(); copier == nil {
		t.Fatal("native privilege artifact copier is absent")
	}
	if os.Geteuid() != 0 {
		if err := (nativePrivilegeArtifactCopier{}).CopyPrivilegeArtifacts(
			t.Context(), root, uid, gid, []PrivilegeTransactionArtifact{artifact},
		); !errors.Is(err, ErrProvisionIntegrity) {
			t.Fatalf("unprivileged transaction error=%v", err)
		}
		if err := ensureRootPrivilegeDirectory(filepath.Join(root, "root-owned"), 0o700); !errors.Is(err, ErrProvisionIntegrity) {
			t.Fatalf("unprivileged root directory error=%v", err)
		}
	}
}

func TestPF006LinuxProtectedReceiptAndPrivilegedHostSourcesFailClosed(t *testing.T) {
	publicKeys := NewRootPrivilegeReceiptPublicKeySource()
	if publicKeys == nil {
		t.Fatal("root privilege public-key source is absent")
	}
	if key, err := publicKeys.LoadPrivilegeReceiptPublicKey(t.Context()); key != nil || !errors.Is(err, ErrProvisionIntegrity) {
		clear(key)
		t.Fatalf("unprovisioned public key=%x error=%v", key, err)
	}
	if signer, err := NewRootPrivilegeReceiptSigner(); signer == nil || err != nil {
		t.Fatalf("protected root signer=%T error=%v", signer, err)
	}
	keySource := rootPrivilegeReceiptSigningKeySource{}
	//lint:ignore SA1012 Deliberate nil-context protected-key boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-15.
	if key, err := keySource.LoadPrivilegeReceiptSigningKey(nil); key != nil || !errors.Is(err, ErrProvisionIntegrity) {
		clear(key)
		t.Fatalf("nil-context signing key=%x error=%v", key, err)
	}
	if os.Geteuid() != 0 {
		if key, err := keySource.LoadPrivilegeReceiptSigningKey(t.Context()); key != nil || !errors.Is(err, ErrProvisionIntegrity) {
			clear(key)
			t.Fatalf("unprivileged signing key=%x error=%v", key, err)
		}
	}

	keyPath := filepath.Join(t.TempDir(), "receipt.key")
	if err := os.WriteFile(keyPath, make([]byte, ed25519.PublicKeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, err := readExactRootPrivilegeKey(keyPath, ed25519.PublicKeySize, 0o600); os.Geteuid() != 0 &&
		(key != nil || !errors.Is(err, ErrProvisionIntegrity)) {
		clear(key)
		t.Fatalf("non-root protected key=%x error=%v", key, err)
	}
	createPath := filepath.Join(t.TempDir(), "created.key")
	if err := writeExactRootPrivilegeKey(createPath, make([]byte, ed25519.PublicKeySize), 0o600); err == nil {
		t.Fatal("key outside the protected receipt directory committed")
	}

	binding, err := NewPrivilegedLinuxHostBindingProvider()
	if err != nil || binding == nil {
		t.Fatalf("privileged host binding=%T error=%v", binding, err)
	}
	source := &nativePrivilegedLinuxIdentitySource{}
	version, machine, err := source.CurrentPrivilegedLinuxMachine(t.Context())
	if err != nil && !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("privileged machine=%q/%s error=%v", version, machine, err)
	}
	if err == nil && (version == "" || machine.IsZero()) {
		t.Fatalf("incomplete privileged machine=%q/%s", version, machine)
	}
	//lint:ignore SA1012 Deliberate nil-context protected-principal boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-15.
	if _, err := source.CurrentPrivilegedLinuxIdentity(nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("nil privileged identity error=%v", err)
	}
	if os.Geteuid() != 0 {
		t.Setenv(polkitOriginalUIDEnvironment, strconv.Itoa(os.Geteuid()))
		if _, err := source.CurrentPrivilegedLinuxIdentity(t.Context()); !errors.Is(err, ErrUnsupportedHost) {
			t.Fatalf("unprivileged original identity error=%v", err)
		}
	}
	host, err := NewPrivilegedLinuxCatalogHostProvider(binding)
	if err != nil || host == nil {
		t.Fatalf("privileged catalog host=%T error=%v", host, err)
	}
	if os.Geteuid() != 0 {
		if current, err := host.CurrentHost(t.Context()); !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) ||
			current.OperatingSystem() != runtimecatalog.OSKind("") {
			t.Fatalf("unprivileged catalog host=%+v error=%v", current, err)
		}
	}
	if _, err := privilegedLinuxVirtualizationAvailable(); err != nil && !errors.Is(err, ErrProbeFailed) {
		t.Fatalf("native virtualization observation error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := privilegedCatalogContextOrUnavailable(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled catalog context error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context privileged-catalog boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-15.
	if err := privilegedCatalogContextOrUnavailable(nil); !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) {
		t.Fatalf("nil catalog context error=%v", err)
	}
}

func TestPF006LinuxRejectsEveryDesktopProductionBoundary(t *testing.T) {
	t.Parallel()
	provider := NewNativeDesktopHostBindingProvider()
	if provider == nil {
		t.Fatal("unsupported desktop binding provider is absent")
	}
	if binding, err := provider.CurrentDesktopHostBinding(
		t.Context(), runtimecatalog.DigestBytes([]byte("catalog")), "Docker.dmg",
	); binding != (runtimecatalogapp.DesktopHostBinding{}) || !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux desktop binding=%+v error=%v", binding, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.CurrentDesktopHostBinding(
		cancelled, runtimecatalog.DigestBytes([]byte("catalog")), "Docker.dmg",
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled desktop binding error=%v", err)
	}
	//lint:ignore SA1012 Deliberate nil-context desktop-binding boundary attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-15.
	if _, err := provider.CurrentDesktopHostBinding(nil, runtimecatalog.Digest{}, ""); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("nil-context desktop binding error=%v", err)
	}

	copier := newNativeDesktopMutationArtifactCopier()
	if copier == nil {
		t.Fatal("unsupported desktop artifact copier is absent")
	}
	if err := copier.CopyDesktopMutationArtifact(
		t.Context(), runtimeport.DesktopMutationRequest{}, DesktopMutationTransactionArtifact{},
	); !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux desktop artifact copy error=%v", err)
	}
	backend := newNativeDesktopMutationBackend(nil, nil)
	if backend == nil {
		t.Fatal("unsupported desktop mutation backend is absent")
	}
	if exitCode, err := backend.ExecuteNativeDesktopMutation(
		t.Context(), runtimeport.DesktopMutationRequest{}, DesktopMutationArtifactBinding{}, false,
		DesktopMutationAuthorityEvidence{},
	); exitCode != 0 || !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux desktop mutation exit=%d error=%v", exitCode, err)
	}

	keys, err := NewProtectedDesktopMutationReceiptPublicKeySource("/tmp/helper")
	if err != nil || keys == nil {
		t.Fatalf("unsupported desktop key source=%T error=%v", keys, err)
	}
	if key, err := keys.LoadDesktopMutationPublicKey(t.Context(), runtimeinstall.Sum([]byte("helper"))); key != nil ||
		!errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux desktop public key=%x error=%v", key, err)
	}
	if signer, err := NewNativeDesktopMutationReceiptSigner(); signer == nil || err != nil {
		t.Fatalf("unsupported desktop signer=%T error=%v", signer, err)
	}
	if provider, err := NewPrivilegedDesktopHostBindingProvider("uid:1000"); provider != nil ||
		!errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux privileged desktop binding=%T error=%v", provider, err)
	}
	if host, err := NewPrivilegedDesktopCatalogHostProvider(nil); host != nil || !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux privileged desktop host=%T error=%v", host, err)
	}
	if host, err := (&PrivilegedDesktopCatalogHostProvider{}).CurrentHost(t.Context()); host.OperatingSystem() != runtimecatalog.OSKind("") || !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) {
		t.Fatalf("Linux privileged desktop observation=%+v error=%v", host, err)
	}
	if digest, err := (&NativeDesktopHelperExecutableVerifier{}).verifyDesktopHelperSelf(
		t.Context(), releaseinventory.Resource{}, runtimeport.DesktopAuthority{},
	); !digest.IsZero() || !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux desktop helper self digest=%s error=%v", digest, err)
	}
	if verifier, err := NewNativeDesktopHelperExecutableVerifier(nil); verifier != nil || err == nil {
		t.Fatalf("empty desktop helper verifier=%T error=%v", verifier, err)
	}
	certificate := releaseinventory.Digest(runtimeinstall.Sum([]byte("native certificate")))
	certificates := map[string]releaseinventory.Digest{"desktop-helper": certificate}
	verifier, err := NewNativeDesktopHelperExecutableVerifier(certificates)
	if err != nil || verifier == nil {
		t.Fatalf("desktop helper verifier=%T error=%v", verifier, err)
	}
	certificates["desktop-helper"] = releaseinventory.Digest{}
	if verifier.certificates["desktop-helper"] != certificate {
		t.Fatal("desktop helper verifier retained caller-owned certificate map")
	}
	if digest, err := verifier.expectedCertificate(releaseinventory.Resource{}, runtimeport.DesktopAuthority{}); !digest.IsZero() ||
		!errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("invalid desktop helper certificate digest=%s error=%v", digest, err)
	}
	if digest, err := verifier.VerifyDesktopHelperSelf(
		t.Context(), releaseinventory.Resource{}, runtimeport.DesktopAuthority{},
	); !digest.IsZero() || !errors.Is(err, ErrUnsupportedHost) {
		t.Fatalf("Linux desktop helper verification digest=%s error=%v", digest, err)
	}
	if err := privilegedDesktopCatalogContextOrUnavailable(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled privileged desktop catalog error=%v", err)
	}
	if err := privilegedDesktopCatalogContextOrUnavailable(t.Context()); !errors.Is(err, runtimecatalogapp.ErrDependencyUnavailable) {
		t.Fatalf("Linux privileged desktop catalog error=%v", err)
	}
}

func TestPF006LinuxProductionRepositoryAndCodecConstructorsAreClosed(t *testing.T) {
	t.Parallel()
	_, apt := adapterAuthority(t)
	dnf := privilegeDNFAuthority(t, apt)
	configurationPath, keyPath, configuration, err := renderPrivilegeRepository(dnf)
	if err != nil || configurationPath != "/etc/yum.repos.d/agentmemory-docker-stable.repo" ||
		keyPath != "/etc/pki/rpm-gpg/RPM-GPG-KEY-agentmemory-docker-stable" || len(configuration) == 0 {
		t.Fatalf("DNF repository=%q/%q bytes=%d error=%v", configurationPath, keyPath, len(configuration), err)
	}
	if direct, err := renderDNFPrivilegeRepository(dnf, keyPath); err != nil || string(direct) != string(configuration) {
		t.Fatalf("direct DNF repository bytes=%q error=%v", direct, err)
	}
	if _, err := (CanonicalPrivilegeRequestDecoder{}).DecodePrivilegeRequest(nil); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("empty privilege request error=%v", err)
	}
	if _, err := (&CanonicalPrivilegeTransportCodec{}).DecodePrivilegeReceipt(nil); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("empty privilege receipt error=%v", err)
	}
	for name, construct := range map[string]func() error{
		"protected writer": func() error { _, err := NewNativePrivilegeProtectedFileWriter(); return err },
		"repository probe": func() error { _, err := NewNativePrivilegeRepositoryStateProbe(); return err },
		"subordinate IDs":  func() error { _, err := NewNativePrivilegeSubordinateIDManager(); return err },
	} {
		if err := construct(); err != nil {
			t.Fatalf("Linux %s constructor error=%v", name, err)
		}
	}
}
