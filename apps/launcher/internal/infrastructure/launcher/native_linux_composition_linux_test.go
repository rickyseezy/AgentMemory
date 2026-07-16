//go:build linux

package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifactfs"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/dockercli"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/process"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeconsent"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeconsentjournal"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/argvprocess"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	appreleaseverify "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006LinuxProductionRunnerSetsBindEveryCatalogExecutableRole(t *testing.T) {
	t.Parallel()
	if runtime.GOARCH != "amd64" {
		t.Skip("the reviewed executable-authority fixture is the x86-64 certification cell")
	}
	release := releaseinventory.Digest(runtimeinstall.Sum([]byte("release manifest")))
	for _, manager := range []runtimeport.PackageManager{
		runtimeport.PackageManagerAPT,
		runtimeport.PackageManagerDNF,
	} {
		authority := launcherLinuxAuthority(t, manager)
		runtimeRunners, err := newNativeLinuxRunnerSet(authority, release)
		if err != nil || runtimeRunners.docker == nil || runtimeRunners.compose == nil ||
			runtimeRunners.rootless == nil || runtimeRunners.privilege == nil {
			t.Fatalf("manager=%s runtime runners=%+v error=%v", manager, runtimeRunners, err)
		}
		if manager == runtimeport.PackageManagerDNF && runtimeRunners.rpmkeys == nil {
			t.Fatal("DNF runtime runner set omitted rpmkeys")
		}
		if manager == runtimeport.PackageManagerAPT && runtimeRunners.rpmkeys != nil {
			t.Fatal("APT runtime runner set admitted rpmkeys")
		}

		privilegeRunners, err := newNativeLinuxPrivilegeRunnerSet(authority, release)
		if err != nil || privilegeRunners.transaction == nil || privilegeRunners.query == nil ||
			privilegeRunners.loginctl == nil || privilegeRunners.systemctl == nil {
			t.Fatalf("manager=%s privilege runners=%+v error=%v", manager, privilegeRunners, err)
		}
	}
	if runners, err := newNativeLinuxRunnerSet(runtimeport.LinuxAuthority{}, release); err == nil ||
		runners.docker != nil {
		t.Fatalf("invalid runtime authority runners=%+v error=%v", runners, err)
	}
	if runners, err := newNativeLinuxPrivilegeRunnerSet(runtimeport.LinuxAuthority{}, release); err == nil ||
		runners.transaction != nil {
		t.Fatalf("invalid privilege authority runners=%+v error=%v", runners, err)
	}
}

func TestPF006LinuxPrivilegeOperationCompositionReachesClosedExecutor(t *testing.T) {
	t.Parallel()
	if runtime.GOARCH != "amd64" {
		t.Skip("the reviewed executable-authority fixture is the x86-64 certification cell")
	}
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerAPT)
	expected, err := runtimeport.ExpectedPrivilegeState(authority, runtimeport.PrivilegeInstallPackages)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	request, err := runtimeport.NewPrivilegeRequest(runtimeport.PrivilegeRequestInput{
		OperationID: "runtime-install", Attempt: 1, Operation: runtimeport.PrivilegeInstallPackages,
		Authority: authority, Nonce: runtimeport.Nonce{1}, IssuedAt: now,
		ExpiresAt: now.Add(time.Minute), ExpectedState: expected,
	})
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := runtimeprovision.NewPrivilegeAuthorityEvidence(
		authority, runtimeinstall.Sum([]byte("helper")), runtimeinstall.Sum([]byte("release manifest")),
	)
	if err != nil {
		t.Fatal(err)
	}
	executor := &nativePrivilegeOperationExecutor{}
	observation, err := executor.ExecutePrivilegeOperation(t.Context(), request, nil, evidence)
	if !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) || !observation.ObservedState.IsZero() {
		t.Fatalf("closed executor observation=%+v error=%v", observation, err)
	}
	if observation, err := executor.ExecutePrivilegeOperation(
		t.Context(), runtimeport.PrivilegeRequest{}, nil, runtimeprovision.PrivilegeAuthorityEvidence{},
	); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) || !observation.ObservedState.IsZero() {
		t.Fatalf("invalid executor observation=%+v error=%v", observation, err)
	}
}

func TestPF006LinuxHelperCommandRejectsAmbientAndIncompleteAuthority(t *testing.T) {
	t.Parallel()
	for name, run := range map[string]func() error{
		"arguments": func() error {
			return RunNativeLinuxPrivilegeHelper(t.Context(), nil, bytes.NewReader([]byte("request")), &bytes.Buffer{})
		},
		"input": func() error {
			return RunNativeLinuxPrivilegeHelper(t.Context(), []string{"--request-stdin"}, nil, &bytes.Buffer{})
		},
		"output": func() error {
			return RunNativeLinuxPrivilegeHelper(t.Context(), []string{"--request-stdin"}, bytes.NewReader([]byte("request")), nil)
		},
	} {
		if err := run(); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
			t.Fatalf("%s helper boundary error=%v", name, err)
		}
	}
	//lint:ignore SA1012 Deliberate nil-context helper composition attack.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-15.
	if application, release, err := newNativeLinuxPrivilegeHelperApplication(nil); application != nil || release != nil ||
		!errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("nil helper composition=%T/%T error=%v", application, release, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := privilegeHelperCommandContextOrIntegrity(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled helper context error=%v", err)
	}
	if err := privilegeHelperCommandContextOrIntegrity(nil); !errors.Is(err, runtimeport.ErrPrivilegeIntegrity) {
		t.Fatalf("nil helper context error=%v", err)
	}
	if codec, helper, err := buildNativeLinuxPrivilegeCodec(
		t.Context(), nil, nativeVerifiedRuntimeExecution{}, runtimeport.LinuxAuthority{}, nil,
	); codec != nil || helper.ResourceID() != "" || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("incomplete privilege codec=%T/%+v error=%v", codec, helper, err)
	}
	if removal, err := newNativePlatformManagedRuntimeRemoval(
		t.Context(), nil, nil, nativeVerifiedRuntimeExecution{},
	); removal != nil || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("incomplete managed removal=%T error=%v", removal, err)
	}
}

func TestPF006InstalledLinuxLauncherReceiptBindsExactExecutableEvidence(t *testing.T) {
	t.Parallel()
	authority := launcherLinuxAuthority(t, runtimeport.PackageManagerAPT)
	release := releaseinventory.Digest(runtimeinstall.Sum([]byte("release manifest")))
	executable, err := newNativeLinuxExecutableAuthority(authority, release, argvprocess.ExecutableRoleDockerCLI)
	if err != nil {
		t.Fatal(err)
	}
	evidence := process.ExecutableEvidence{
		CanonicalID: executable.CanonicalID(), Digest: executable.SHA256(),
		OwnerIdentity: executable.OwnerIdentity(), ReleaseManifestDigest: executable.ReleaseManifestDigest(),
		RuntimePlanDigest: executable.RuntimePlanDigest(), Role: executable.Role(),
	}
	verifier := nativeLauncherPackageReceipt{authority: executable}
	if err := verifier.VerifyLinuxPackageReceipt(t.Context(), executable, evidence); err != nil {
		t.Fatalf("exact installed launcher receipt error=%v", err)
	}
	evidence.CanonicalID = "foreign"
	if err := verifier.VerifyLinuxPackageReceipt(t.Context(), executable, evidence); !errors.Is(err, argvprocess.ErrInvalidInvocation) {
		t.Fatalf("substituted installed launcher receipt error=%v", err)
	}
}

func TestPF006LinuxDesktopOnlyCompositionSurfacesRemainUnavailable(t *testing.T) {
	t.Parallel()
	if err := RunNativeDesktopMutationHelper(
		t.Context(), []string{"--execute-desktop-mutation", "/tmp/request"},
	); !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("desktop helper command error=%v", err)
	}
	if elevated := nativeDesktopHelperElevated(); elevated {
		t.Fatal("Linux reported desktop helper elevation")
	}
	if root, exchange, err := nativeDesktopHelperPlatformBoundaries("/tmp/request"); root != "" || exchange != nil ||
		!errors.Is(err, errNativeInstallerUnavailable) {
		t.Fatalf("desktop boundaries=%q/%T error=%v", root, exchange, err)
	}
	if root, err := nativeDesktopHelperReleaseBundleRoot(); root != "" || !errors.Is(err, errNativeInstallerUnavailable) {
		t.Fatalf("desktop release root=%q error=%v", root, err)
	}
	if security, err := newNativeDesktopPlatformSecurity(); !errors.Is(err, errNativeInstallerUnavailable) ||
		security.host.WindowsEncryption != nil || security.signer != nil || len(security.closers) != 0 {
		t.Fatalf("desktop security=%+v error=%v", security, err)
	}
	if application, release, closers, err := newNativeDesktopMutationHelperApplication(
		t.Context(), "/tmp/agentmemory", "linux:uid:1000",
	); application != nil || release != nil || len(closers) != 0 || !errors.Is(err, runtimeport.ErrDesktopMutationIntegrity) {
		t.Fatalf("desktop helper composition=%T/%T/%d error=%v", application, release, len(closers), err)
	}

	request, authority, certified := nativeRuntimeExecutionFixture(t)
	factory := &nativePlatformRuntimeFactory{
		composition: &nativeComposition{}, release: &nativeReleaseAuthority{}, artifacts: &artifactapp.Application{},
		desktopAuthority: buildNativeDesktopAuthority, desktopArtifacts: buildNativeDesktopArtifacts,
		desktopHelpers: buildNativeDesktopHelpers,
	}
	if application, err := factory.buildDesktopRuntimeApplication(t.Context(), nativeVerifiedRuntimeExecution{
		request: request, authority: authority, runtime: certified,
	}); application != nil || !errors.Is(err, errNativeInstallerUnavailable) {
		t.Fatalf("desktop runtime on Linux=%T error=%v", application, err)
	}
	verified := nativeVerifiedRuntimeExecution{request: request, authority: authority, runtime: certified}
	if _, err := buildNativeDesktopAuthority(t.Context(), verified, nil); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil desktop release error=%v", err)
	}
	if _, err := buildNativeDesktopArtifacts(
		verified, nil, nil, nativeDesktopPlatformSecurity{},
	); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil desktop artifacts error=%v", err)
	}
	if _, err := buildNativeDesktopHelpers(nil, verified); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil desktop helper trust error=%v", err)
	}
}

func TestPF006LinuxProductionCompositionReachesCryptographicHelperBoundary(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the reviewed Linux catalog fixture is the x86-64 certification cell")
	}
	verified, binding := launcherLinuxProductionExecution(t)
	codecBuilder := launcherLinuxTestPrivilegeCodecBuilder()
	composition := launcherLinuxTestComposition()
	release := &nativeReleaseAuthority{
		stack: nativeReleaseStack{application: &appreleaseverify.Application{}},
	}
	factory, err := newNativePlatformRuntimeFactory(composition, release, &artifactapp.Application{})
	if err != nil {
		t.Fatalf("Linux production runtime factory error=%v", err)
	}
	factory.linuxBindings = launcherLinuxBindingProvider{binding: binding}
	factory.linuxCodec = codecBuilder
	application, err := factory.BuildRuntimeApplication(t.Context(), verified)
	if err != nil || application == nil {
		t.Fatalf("Linux runtime application=%T error=%v", application, err)
	}
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if candidate, err := factory.BuildRuntimeApplication(cancelled, verified); candidate != nil ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Linux runtime application=%T error=%v", candidate, err)
	}
	closer, ok := application.(interface{ Close(context.Context) error })
	if !ok {
		t.Fatalf("Linux runtime application %T omitted lifecycle ownership", application)
	}
	if err := closer.Close(t.Context()); err != nil {
		t.Fatalf("close Linux runtime application: %v", err)
	}
	executors, err := factory.buildPlatformProductExecutors(t.Context(), verified)
	if err != nil || executors == (dockercli.Executors{}) {
		t.Fatalf("Linux product executors=%+v error=%v", executors, err)
	}
	if controller, err := newNativePlatformManagedRuntimeRemovalWithBindings(
		t.Context(), composition, release, verified,
		launcherLinuxBindingProvider{binding: binding}, codecBuilder,
	); controller == nil || err != nil {
		t.Fatalf("Linux removal controller=%T error=%v", controller, err)
	}
}

func TestPF006LinuxProductionCompositionFailsClosedAtEveryLateAuthority(t *testing.T) {
	if runtime.GOARCH != "amd64" {
		t.Skip("the reviewed Linux catalog fixture is the x86-64 certification cell")
	}
	verified, binding := launcherLinuxProductionExecution(t)
	privateFailure := errors.New("private Linux composition failure")
	codecBuilder := launcherLinuxTestPrivilegeCodecBuilder()
	release := &nativeReleaseAuthority{}
	bindingProvider := launcherLinuxBindingProvider{binding: binding}

	runtimeTests := map[string]func(*nativeComposition, *nativePlatformRuntimeFactory){
		"host binding": func(_ *nativeComposition, factory *nativePlatformRuntimeFactory) {
			factory.linuxBindings = launcherLinuxBindingProvider{err: privateFailure}
		},
		"artifact store": func(composition *nativeComposition, _ *nativePlatformRuntimeFactory) {
			composition.artifactStore = nil
		},
		"privilege codec": func(_ *nativeComposition, factory *nativePlatformRuntimeFactory) {
			factory.linuxCodec = launcherLinuxFailingPrivilegeCodecBuilder(privateFailure)
		},
		"replay journal": func(composition *nativeComposition, _ *nativePlatformRuntimeFactory) {
			composition.replayJournals = nil
		},
		"consent broker": func(composition *nativeComposition, _ *nativePlatformRuntimeFactory) {
			composition.consentBroker = nil
		},
		"runtime state": func(composition *nativeComposition, _ *nativePlatformRuntimeFactory) {
			composition.runtimeState = nil
		},
	}
	for name, mutate := range runtimeTests {
		t.Run("runtime "+name, func(t *testing.T) {
			composition := launcherLinuxTestComposition()
			factory := &nativePlatformRuntimeFactory{
				composition: composition, release: release, artifacts: &artifactapp.Application{},
				linuxBindings: bindingProvider, linuxCodec: codecBuilder,
			}
			mutate(composition, factory)
			if application, err := factory.buildLinuxRuntimeApplication(t.Context(), verified); application != nil ||
				!errors.Is(err, errNativeInstallerIntegrity) {
				t.Fatalf("runtime application=%T error=%v", application, err)
			}
		})
	}

	removalTests := map[string]func(
		*nativeComposition,
	) (runtimeprovision.LinuxHostBindingProvider, nativeLinuxPrivilegeCodecBuilder){
		"host binding": func(*nativeComposition) (
			runtimeprovision.LinuxHostBindingProvider,
			nativeLinuxPrivilegeCodecBuilder,
		) {
			return launcherLinuxBindingProvider{err: privateFailure}, codecBuilder
		},
		"artifact store": func(composition *nativeComposition) (
			runtimeprovision.LinuxHostBindingProvider,
			nativeLinuxPrivilegeCodecBuilder,
		) {
			composition.artifactStore = nil
			return bindingProvider, codecBuilder
		},
		"privilege codec": func(*nativeComposition) (
			runtimeprovision.LinuxHostBindingProvider,
			nativeLinuxPrivilegeCodecBuilder,
		) {
			return bindingProvider, launcherLinuxFailingPrivilegeCodecBuilder(privateFailure)
		},
		"replay journal": func(composition *nativeComposition) (
			runtimeprovision.LinuxHostBindingProvider,
			nativeLinuxPrivilegeCodecBuilder,
		) {
			composition.replayJournals = nil
			return bindingProvider, codecBuilder
		},
		"removal consent": func(composition *nativeComposition) (
			runtimeprovision.LinuxHostBindingProvider,
			nativeLinuxPrivilegeCodecBuilder,
		) {
			composition.removalConsentBroker = nil
			return bindingProvider, codecBuilder
		},
	}
	for name, mutate := range removalTests {
		t.Run("removal "+name, func(t *testing.T) {
			composition := launcherLinuxTestComposition()
			provider, builder := mutate(composition)
			if controller, err := newNativePlatformManagedRuntimeRemovalWithBindings(
				t.Context(), composition, release, verified, provider, builder,
			); controller != nil || !errors.Is(err, errNativeInstallerIntegrity) {
				t.Fatalf("removal controller=%T error=%v", controller, err)
			}
		})
	}
}

func launcherLinuxTestComposition() *nativeComposition {
	return &nativeComposition{
		artifactStore:        &artifactfs.Store{},
		replayJournals:       nativeMissingJournalProvider{},
		consentBroker:        &runtimeconsent.Broker{},
		consentRepository:    &runtimeconsentjournal.Repository{},
		runtimeState:         &filesystem.RuntimeOperationRepository{},
		runtimeOwnership:     &filesystem.RuntimeOwnershipRepository{},
		runtimeRemoval:       &filesystem.RuntimeRemovalOperationRepository{},
		removalConsentBroker: &runtimeconsent.RemovalBroker{},
	}
}

func launcherLinuxFailingPrivilegeCodecBuilder(failure error) nativeLinuxPrivilegeCodecBuilder {
	return func(
		context.Context,
		*nativeReleaseAuthority,
		nativeVerifiedRuntimeExecution,
		runtimeport.LinuxAuthority,
		runtimeprovision.PrivilegeArtifactStager,
	) (*runtimeprovision.CanonicalPrivilegeTransportCodec, nativeLinuxHelperAuthority, error) {
		return nil, nativeLinuxHelperAuthority{}, failure
	}
}

func launcherLinuxTestPrivilegeCodecBuilder() nativeLinuxPrivilegeCodecBuilder {
	return func(
		ctx context.Context,
		_ *nativeReleaseAuthority,
		verified nativeVerifiedRuntimeExecution,
		authority runtimeport.LinuxAuthority,
		artifactStager runtimeprovision.PrivilegeArtifactStager,
	) (*runtimeprovision.CanonicalPrivilegeTransportCodec, nativeLinuxHelperAuthority, error) {
		resolver, err := newNativeLinuxHelperAuthorityResolver(
			&nativeLinuxHelperReleaseStub{}, verified.request.SignedRelease,
			verified.request.SignedRelease.Manifest().Digest(),
			verified.request.SignedRelease.Manifest().Resources(),
		)
		if err != nil {
			return nil, nativeLinuxHelperAuthority{}, err
		}
		return buildNativeLinuxPrivilegeCodecWithEncoders(
			ctx, verified, authority, resolver, artifactStager,
			releaseinventory.EncodeSignedManifestV1, runtimecatalog.EncodeSignedManifestV1,
		)
	}
}

func launcherLinuxProductionExecution(
	t testing.TB,
) (nativeVerifiedRuntimeExecution, runtimecatalogapp.LinuxHostBinding) {
	t.Helper()
	raw, err := os.ReadFile("../../adapters/runtimeprovision/testdata/runtime-catalog-linux.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := runtimecatalog.DecodeManifestV1(bytes.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	signedCatalog, err := runtimecatalog.NewSignedManifest(
		manifest, manifest.SigningKeyID(), []byte("detached signature"),
	)
	if err != nil {
		t.Fatal(err)
	}
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindLinux, Architecture: runtimecatalog.ArchitectureX8664,
		Edition: "workstation", Distribution: "ubuntu", OSVersion: "24.4.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 32 << 30, FreeDiskBytes: 100 << 30, Virtualization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ports := &launcherLinuxCatalogPorts{
		host: host, now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
	application, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: ports, Host: ports, Signature: ports, NativePublisher: ports, AntiRollback: ports,
	})
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := application.Verify(t.Context(), runtimecatalogapp.Request{
		SignedManifest: signedCatalog, ExpectedManifestDigest: manifest.Digest(),
		SourceMode: runtimecatalog.SourceModeOfflineUserSelected,
	})
	if err != nil {
		t.Fatal(err)
	}
	certified, err := catalog.CertifiedRuntime()
	if err != nil {
		t.Fatal(err)
	}
	hostCapabilities, err := runtimeinstall.NewHostCapabilities(
		runtimeinstall.PlatformLinux, runtimeinstall.ArchitectureAMD64, "24.04",
		true, true, true, true, 8, 32<<30, 24<<30, 100<<30,
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeinstall.NewPlanV1(
		hostCapabilities, runtimeinstall.NewAbsentRuntimeDiscovery(), certified,
	)
	if err != nil {
		t.Fatal(err)
	}
	catalogRaw, err := runtimecatalog.EncodeSignedManifestV1(signedCatalog)
	if err != nil {
		t.Fatal(err)
	}
	verified := launcherLinuxVerifiedExecution(t, plan, catalogRaw)
	signedRelease, err := releaseinventory.DecodeSignedManifestV1(
		invalidlySignedReleaseEnvelope(t, time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)),
	)
	if err != nil {
		t.Fatal(err)
	}
	verified.request.SignedRelease = signedRelease
	verified.catalog = catalog
	verified.runtime = certified
	verified.manifestDigest = catalog.ManifestDigest()
	verified.signedCatalog = signedCatalog
	binding, err := runtimecatalogapp.NewLinuxHostBinding(runtimecatalogapp.LinuxHostBindingInput{
		VersionID: "24.04", InvokingUID: 1000, InvokingGID: 1000,
		AccountName: "agentmemory", PrincipalID: "linux:uid:1000",
		MachineDigest: runtimeinstall.Sum([]byte("machine")), HomeDirectory: "/home/agentmemory",
		RuntimeDirectory: "/run/user/1000", Endpoint: "unix:///run/user/1000/docker.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified, binding
}

type launcherLinuxBindingProvider struct {
	binding runtimecatalogapp.LinuxHostBinding
	err     error
}

func (p launcherLinuxBindingProvider) CurrentLinuxHostBinding(
	context.Context,
) (runtimecatalogapp.LinuxHostBinding, error) {
	return p.binding, p.err
}

type launcherLinuxCatalogPorts struct {
	host runtimecatalog.Host
	now  time.Time
}

func (p *launcherLinuxCatalogPorts) Now() time.Time { return p.now }
func (p *launcherLinuxCatalogPorts) CurrentHost(context.Context) (runtimecatalog.Host, error) {
	return p.host, nil
}
func (*launcherLinuxCatalogPorts) VerifyManifestSignature(context.Context, runtimecatalog.SignedManifest) error {
	return nil
}
func (*launcherLinuxCatalogPorts) VerifyNativePublisherPolicy(context.Context, runtimecatalog.PublisherPolicy) error {
	return nil
}
func (*launcherLinuxCatalogPorts) LoadCatalogAnchor(
	context.Context,
	string,
) (runtimecatalogapp.CatalogAnchor, error) {
	return runtimecatalogapp.CatalogAnchor{}, runtimecatalogapp.ErrCatalogAnchorNotFound
}
func (*launcherLinuxCatalogPorts) CompareAndSwapCatalogAnchor(
	context.Context,
	*runtimecatalogapp.CatalogAnchor,
	runtimecatalogapp.CatalogAnchor,
) error {
	return nil
}
