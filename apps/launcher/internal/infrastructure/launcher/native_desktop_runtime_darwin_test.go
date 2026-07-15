//go:build darwin

package launcher

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	bootstrapadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/bootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/filesystem"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

func TestPF006DarwinDesktopRuntimeInitializesOnlyNativeSecurityAdapters(t *testing.T) {
	t.Parallel()
	security, err := newNativeDesktopPlatformSecurity()
	if err != nil || security.host.WindowsEncryption != nil || security.signer != nil || len(security.closers) != 0 {
		t.Fatalf("security=%+v error=%v", security, err)
	}
	publisher, err := newNativeDesktopExecutablePublisherVerifier()
	if err != nil || publisher == nil {
		t.Fatalf("publisher=%T error=%v", publisher, err)
	}
}

func TestPF006DarwinDesktopRuntimeRejectsUnverifiedCatalogBeforeProvisioning(t *testing.T) {
	t.Parallel()
	request, authority, runtime := nativeRuntimeExecutionFixture(t)
	factory := &nativePlatformRuntimeFactory{
		release: &nativeReleaseAuthority{}, desktopAuthority: buildNativeDesktopAuthority,
		desktopArtifacts: buildNativeDesktopArtifacts, desktopHelpers: buildNativeDesktopHelpers,
	}
	application, err := factory.buildDesktopRuntimeApplication(t.Context(), nativeVerifiedRuntimeExecution{
		request: request, authority: authority, runtime: runtime,
	})
	if application != nil || !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("application=%T error=%v", application, err)
	}
}

func TestPF006DarwinDesktopRuntimeBuildsCompleteOperationScopedApplication(t *testing.T) {
	t.Parallel()
	composition, err := composeNative(
		t.Context(), nativeTestRoots(t.TempDir()),
		func(*bootstrapadapter.OperationLocator) (filesystem.OperationJournalProvider, error) {
			return nativeMissingJournalProvider{}, nil
		}, pendingReadySurface{},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = composition.resources.Close(context.Background()) })
	request, execution, certified := nativeRuntimeExecutionFixture(t)
	desktop := launcherDesktopAuthorityForDigests(
		t, runtimeinstall.PlatformDarwin, execution.Plan().Digest(), execution.Plan().CatalogDigest(),
	)
	resolver := &nativeDesktopAuthorityStub{authority: desktop}
	artifacts := &nativeDesktopArtifactStub{}
	helperAuthority, err := runtimeport.NewDesktopHelperAuthority(runtimeport.DesktopHelperAuthorityInput{
		Platform: desktop.Platform(), Architecture: desktop.Architecture(), PlanDigest: desktop.PlanDigest(),
		PrincipalID: desktop.PrincipalID(), MachineDigest: desktop.MachineDigest(),
		CanonicalPath: "/Library/PrivilegedHelperTools/com.rickyseezy.agentmemory.runtime-helper",
		SHA256:        runtimeinstall.Sum([]byte("helper")), PublisherIdentity: "agentmemory.publisher",
		PublisherCertificate:  runtimeinstall.Sum([]byte("certificate")),
		ReleaseManifestDigest: runtimeinstall.Sum([]byte("release")),
		ExchangeDirectory:     "/Users/agentmemory/Library/Application Support/AgentMemory/bootstrap/test/native",
	})
	if err != nil {
		t.Fatal(err)
	}
	helper := &nativeDesktopHelperStub{helper: helperAuthority}
	factory := &nativePlatformRuntimeFactory{
		composition: &composition,
		release:     &nativeReleaseAuthority{},
		artifacts:   &artifactapp.Application{},
		desktopAuthority: func(
			context.Context, nativeVerifiedRuntimeExecution, *nativeReleaseAuthority,
		) (nativeDesktopAuthoritySet, error) {
			return nativeDesktopAuthoritySet{resolver: resolver, authority: desktop}, nil
		},
		desktopArtifacts: func(
			nativeVerifiedRuntimeExecution, *artifactapp.Application, *nativeComposition, nativeDesktopPlatformSecurity,
		) (nativeDesktopArtifactSet, error) {
			return nativeDesktopArtifactSet{acquirer: artifacts, verifier: artifacts}, nil
		},
		desktopHelpers: func(
			*nativeReleaseAuthority, nativeVerifiedRuntimeExecution,
		) (nativeDesktopHelperSet, error) {
			return nativeDesktopHelperSet{authority: helper, publisher: helper, encoder: helper}, nil
		},
	}
	application, err := factory.buildDesktopRuntimeApplication(t.Context(), nativeVerifiedRuntimeExecution{
		request: request, authority: execution, runtime: certified,
		catalog: nativeDesktopRuntimeVerifiedCatalog(t),
	})
	if err != nil || application == nil {
		t.Fatalf("application=%T error=%v", application, err)
	}
	managed, ok := application.(*managedNativeRuntimeApplication)
	if !ok {
		t.Fatalf("application type=%T", application)
	}
	if err := managed.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	verified := nativeVerifiedRuntimeExecution{request: request, authority: execution, runtime: certified}
	if _, err := buildNativeDesktopAuthority(t.Context(), verified, nil); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil release authority error=%v", err)
	}
	if _, err := buildNativeDesktopAuthority(t.Context(), verified, &nativeReleaseAuthority{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("unverified catalog authority error=%v", err)
	}
	if _, err := buildNativeDesktopArtifacts(verified, nil, nil, nativeDesktopPlatformSecurity{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil artifact composition error=%v", err)
	}
	if _, err := buildNativeDesktopArtifacts(verified, nil, &composition, nativeDesktopPlatformSecurity{}); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("unverified artifact catalog error=%v", err)
	}
	if _, err := buildNativeDesktopHelpers(nil, verified); !errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("nil helper release error=%v", err)
	}

	missingAuthority := *factory
	missingAuthority.desktopAuthority = func(
		context.Context, nativeVerifiedRuntimeExecution, *nativeReleaseAuthority,
	) (nativeDesktopAuthoritySet, error) {
		return nativeDesktopAuthoritySet{}, nil
	}
	if candidate, err := missingAuthority.buildDesktopRuntimeApplication(t.Context(), verified); candidate != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("missing authority application=%T error=%v", candidate, err)
	}
	missingArtifacts := *factory
	missingArtifacts.desktopArtifacts = func(
		nativeVerifiedRuntimeExecution, *artifactapp.Application, *nativeComposition, nativeDesktopPlatformSecurity,
	) (nativeDesktopArtifactSet, error) {
		return nativeDesktopArtifactSet{}, nil
	}
	if candidate, err := missingArtifacts.buildDesktopRuntimeApplication(t.Context(), verified); candidate != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("missing artifacts application=%T error=%v", candidate, err)
	}
	missingHelpers := *factory
	missingHelpers.desktopHelpers = func(
		*nativeReleaseAuthority, nativeVerifiedRuntimeExecution,
	) (nativeDesktopHelperSet, error) {
		return nativeDesktopHelperSet{}, nil
	}
	if candidate, err := missingHelpers.buildDesktopRuntimeApplication(t.Context(), verified); candidate != nil ||
		!errors.Is(err, errNativeInstallerIntegrity) {
		t.Fatalf("missing helpers application=%T error=%v", candidate, err)
	}
}

func nativeDesktopRuntimeVerifiedCatalog(t *testing.T) runtimecatalogapp.VerifiedCatalog {
	t.Helper()
	raw, err := os.ReadFile("testdata/runtime-catalog-macos.json")
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := runtimecatalog.DecodeManifestV1(bytes.TrimSpace(raw))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := runtimecatalog.NewSignedManifest(manifest, manifest.SigningKeyID(), []byte("test-signature"))
	if err != nil {
		t.Fatal(err)
	}
	host, err := runtimecatalog.NewHost(runtimecatalog.HostInput{
		OperatingSystem: runtimecatalog.OSKindMacOS, Architecture: runtimecatalog.ArchitectureARM64,
		Edition: "desktop", Distribution: "macos", OSVersion: "15.5.0", Build: 24000,
		CPUCores: 8, MemoryBytes: 32 << 30, FreeDiskBytes: 100 << 30, Virtualization: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ports := &nativeDesktopVerifiedCatalogPorts{
		host: host, now: time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC),
	}
	application, err := runtimecatalogapp.NewApplication(runtimecatalogapp.Dependencies{
		Clock: ports, Host: ports, Signature: ports, NativePublisher: ports, AntiRollback: ports,
	})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := application.Verify(t.Context(), runtimecatalogapp.Request{
		SignedManifest: signed, ExpectedManifestDigest: manifest.Digest(),
		SourceMode: runtimecatalog.SourceModeOfflineBundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verified
}

type nativeDesktopAuthorityStub struct {
	authority runtimeport.DesktopAuthority
}

func (s *nativeDesktopAuthorityStub) ResolveDesktopAuthority(
	context.Context,
	[]byte,
) (runtimeport.DesktopAuthority, error) {
	return s.authority, nil
}

type nativeDesktopArtifactStub struct{}

func (*nativeDesktopArtifactStub) AcquireDesktopArtifact(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	return runtimeport.DesktopArtifactEvidence{}, nil
}

func (*nativeDesktopArtifactStub) VerifyDesktopArtifact(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopArtifactEvidence, error) {
	return runtimeport.DesktopArtifactEvidence{}, nil
}

type nativeDesktopHelperStub struct {
	helper runtimeport.DesktopHelperAuthority
}

func (s *nativeDesktopHelperStub) ResolveDesktopHelperAuthority(
	context.Context,
	runtimeport.DesktopAuthority,
) (runtimeport.DesktopHelperAuthority, error) {
	return s.helper, nil
}

func (*nativeDesktopHelperStub) VerifyDesktopHelperPublisher(
	context.Context,
	runtimeport.DesktopHelperAuthority,
) error {
	return nil
}

func (*nativeDesktopHelperStub) EncodeDesktopMutationRequest(
	context.Context,
	runtimeport.DesktopMutationRequest,
) ([]byte, error) {
	return []byte(`{"signed":"desktop-mutation"}`), nil
}
