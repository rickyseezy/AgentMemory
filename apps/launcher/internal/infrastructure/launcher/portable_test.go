package launcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/mcpbootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/nativepackage"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/portablebootstrap"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/nativepackageinstallapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

func TestPF001PortableFactoryServesBootstrapBeforeNativePackageSettles(t *testing.T) {
	t.Parallel()
	installer := &portableInstallerWaitStub{started: make(chan struct{})}
	factory := &PortableFactory{compose: func(
		context.Context,
		agentconfigdomain.AgentHost,
	) (portableComposition, error) {
		return portableComposition{installer: installer, surface: &portableSurfaceWaitStub{}}, nil
	}}
	runner, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostClaude)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-installer.started:
	case <-time.After(time.Second):
		t.Fatal("native package transaction did not start")
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runner.Run(ctx, serverTransport) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "portable-test", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	tools, err := session.ListTools(ctx, nil)
	if err != nil || len(tools.Tools) != 3 {
		t.Fatalf("portable tools = %+v, %v", tools, err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case runError := <-done:
		if runError != nil {
			t.Fatalf("portable runner error = %v", runError)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("portable runner did not settle")
	}
	if installer.calls.Load() != 1 {
		t.Fatalf("native package calls = %d", installer.calls.Load())
	}
}

func TestPF001PortableFactoryRejectsIncompleteComposition(t *testing.T) {
	t.Parallel()
	var absent *PortableFactory
	if runner, err := absent.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); runner != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil factory = %T, %v", runner, err)
	}
	factory := &PortableFactory{}
	if runner, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHost("unknown")); runner != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("invalid host = %T, %v", runner, err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	factory.compose = func(context.Context, agentconfigdomain.AgentHost) (portableComposition, error) {
		return portableComposition{}, nil
	}
	if runner, err := factory.BuildMCP(cancelled, agentconfigdomain.AgentHostCodex); runner != nil ||
		!errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled call = %T, %v", runner, err)
	}
	private := errors.New("private composition")
	factory.compose = func(context.Context, agentconfigdomain.AgentHost) (portableComposition, error) {
		return portableComposition{}, private
	}
	if runner, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); runner != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("failed composition = %T, %v", runner, err)
	}
	factory.compose = func(context.Context, agentconfigdomain.AgentHost) (portableComposition, error) {
		return portableComposition{}, nil
	}
	if runner, err := factory.BuildMCP(context.Background(), agentconfigdomain.AgentHostCodex); runner != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("empty composition = %T, %v", runner, err)
	}
	if !errors.Is(mcpbootstrapIntegrity(), mcpbootstrapapp.ErrBootstrapIntegrity) ||
		!errors.Is(mcpbootstrapUnavailable(), mcpbootstrapapp.ErrBootstrapUnavailable) ||
		(portableComposition{}).valid() {
		t.Fatal("portable error or validity classification failed")
	}
	if _, ok := NewPortableFactory().(*PortableFactory); !ok {
		t.Fatal("NewPortableFactory() returned a foreign implementation")
	}
}

func TestPF001PortableProductionCompositionBindsBothSigstoreIdentities(t *testing.T) {
	t.Parallel()
	layout := portableLayoutFixture(t)
	trust, err := decodeNativeReleaseTrust(encodeNativeReleaseTrust(t, nativeReleaseTrustFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	build := func(context.Context, agentconfigdomain.AgentHost) (bootstrapSurface, error) {
		return bootstrapSurface{}, errors.New("unused until package installation")
	}
	dependencies := portableProductionDependencies{
		layout:      func() (nativepackage.PortableLayout, error) { return layout, nil },
		format:      func() (releasepublication.Format, error) { return releasepublication.FormatDEB, nil },
		trust:       func() (nativeReleaseTrustMaterial, error) { return trust, nil },
		operatingOS: "linux", architecture: "amd64", buildSurface: build,
	}
	composition, err := composePortable(context.Background(), agentconfigdomain.AgentHostGemini, dependencies)
	if err != nil || !composition.valid() {
		t.Fatalf("composePortable() = %+v, %v", composition, err)
	}
	installer := composition.installer.(*portableNativeInstaller)
	if installer.request.OperatingSystem != "linux" || installer.request.Architecture != "amd64" ||
		installer.request.Format != releasepublication.FormatDEB || len(installer.request.PublicationJSON) == 0 ||
		len(installer.request.PublicationSigstoreBundle) == 0 {
		t.Fatalf("portable request = %+v", installer.request)
	}
	if surface := composition.surface.(*portableInstalledSurfaceFactory); surface.host != agentconfigdomain.AgentHostGemini {
		t.Fatalf("portable surface host = %q", surface.host)
	}
	if production, err := composeNativePortable(context.Background(), agentconfigdomain.AgentHostCodex); production.valid() ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
		t.Fatalf("unpackaged source composition = %+v, %v", production, err)
	}
}

func TestPF001PortableProductionCompositionRejectsEveryMissingAuthority(t *testing.T) {
	t.Parallel()
	layout := portableLayoutFixture(t)
	trust, err := decodeNativeReleaseTrust(encodeNativeReleaseTrust(t, nativeReleaseTrustFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	valid := portableProductionDependencies{
		layout:      func() (nativepackage.PortableLayout, error) { return layout, nil },
		format:      func() (releasepublication.Format, error) { return releasepublication.FormatDEB, nil },
		trust:       func() (nativeReleaseTrustMaterial, error) { return trust, nil },
		operatingOS: "linux", architecture: "amd64",
		buildSurface: func(context.Context, agentconfigdomain.AgentHost) (bootstrapSurface, error) {
			return bootstrapSurface{}, nil
		},
	}
	for name, mutate := range map[string]func(*portableProductionDependencies){
		"layout":       func(value *portableProductionDependencies) { value.layout = nil },
		"format":       func(value *portableProductionDependencies) { value.format = nil },
		"trust":        func(value *portableProductionDependencies) { value.trust = nil },
		"OS":           func(value *portableProductionDependencies) { value.operatingOS = "" },
		"architecture": func(value *portableProductionDependencies) { value.architecture = "" },
		"surface":      func(value *portableProductionDependencies) { value.buildSurface = nil },
	} {
		candidate := valid
		mutate(&candidate)
		if composition, err := composePortable(context.Background(), agentconfigdomain.AgentHostCodex, candidate); composition.valid() || !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s composition = %+v, %v", name, composition, err)
		}
	}
	private := errors.New("private")
	for name, mutate := range map[string]func(*portableProductionDependencies){
		"layout error": func(value *portableProductionDependencies) {
			value.layout = func() (nativepackage.PortableLayout, error) { return nativepackage.PortableLayout{}, private }
		},
		"format error": func(value *portableProductionDependencies) {
			value.format = func() (releasepublication.Format, error) { return "", private }
		},
	} {
		candidate := valid
		mutate(&candidate)
		if composition, err := composePortable(context.Background(), agentconfigdomain.AgentHostCodex, candidate); composition.valid() || !errors.Is(err, mcpbootstrapapp.ErrBootstrapUnavailable) {
			t.Fatalf("%s composition = %+v, %v", name, composition, err)
		}
	}
	candidate := valid
	candidate.trust = func() (nativeReleaseTrustMaterial, error) { return nativeReleaseTrustMaterial{}, private }
	if composition, err := composePortable(context.Background(), agentconfigdomain.AgentHostCodex, candidate); composition.valid() || !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("trust error composition = %+v, %v", composition, err)
	}
}

func TestPF001PortableAdaptersCopyRequestsAdoptSurfaceAndBoundAuthorityFiles(t *testing.T) {
	t.Parallel()
	application := &portablePackageApplicationStub{}
	installer := &portableNativeInstaller{application: application, request: nativepackageinstallapp.Request{
		PublicationJSON: []byte("publication"), PublicationSigstoreBundle: []byte("signature"),
		OperatingSystem: "linux", Architecture: "amd64", Format: releasepublication.FormatDEB,
	}}
	if err := installer.InstallNativePackage(context.Background()); err != nil {
		t.Fatal(err)
	}
	application.request.PublicationJSON[0] ^= 0xff
	if string(installer.request.PublicationJSON) != "publication" || application.calls.Load() != 1 {
		t.Fatal("portable installer exposed retained request storage")
	}
	var absentInstaller *portableNativeInstaller
	if err := absentInstaller.InstallNativePackage(context.Background()); !errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil installer error = %v", err)
	}

	resolved, runtime := launcherFixture(t)
	nativeFactory, err := NewFactory(&resolverStub{resolved: resolved}, &runtimeFactoryStub{runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	surfaceFactory := &portableInstalledSurfaceFactory{
		host: agentconfigdomain.AgentHostCodex, build: nativeFactory.buildBootstrapSurface,
	}
	surface, err := surfaceFactory.BuildInstalledSurface(context.Background())
	if err != nil || surface.Application == nil || surface.Ready == nil || surface.Lifecycle == nil {
		t.Fatalf("BuildInstalledSurface() = %+v, %v", surface, err)
	}
	_ = surface.Lifecycle.Close(context.Background())
	var absentSurface *portableInstalledSurfaceFactory
	if surface, err := absentSurface.BuildInstalledSurface(context.Background()); surface != (portablebootstrap.Surface{}) ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("nil surface factory = %+v, %v", surface, err)
	}

	root := t.TempDir()
	regular := filepath.Join(root, "authority.json")
	if err := os.WriteFile(regular, []byte("authority"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := readPortableAuthority(regular, 64)
	if err != nil || string(raw) != "authority" {
		t.Fatalf("readPortableAuthority() = %q, %v", raw, err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"empty": "", "link": link, "directory": root} {
		if raw, err := readPortableAuthority(path, 64); raw != nil ||
			!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
			t.Fatalf("%s authority = %q, %v", name, raw, err)
		}
	}
	if raw, err := readPortableAuthority(regular, 1); raw != nil ||
		!errors.Is(err, mcpbootstrapapp.ErrBootstrapIntegrity) {
		t.Fatalf("oversized authority = %q, %v", raw, err)
	}
}

func portableLayoutFixture(t testing.TB) nativepackage.PortableLayout {
	t.Helper()
	root := t.TempDir()
	release := filepath.Join(root, "release")
	objects := filepath.Join(release, "objects")
	evidence := filepath.Join(release, "evidence")
	for _, directory := range []string{objects, evidence} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	publication := filepath.Join(release, "agentmemory-release-publication.json")
	signature := filepath.Join(release, "agentmemory-release-publication.sigstore.json")
	for path, content := range map[string][]byte{publication: []byte("publication"), signature: []byte("signature")} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return nativepackage.PortableLayout{
		Root: root, Objects: objects, Evidence: evidence,
		Publication: publication, PublicationSigstore: signature,
	}
}

type portableInstallerWaitStub struct {
	started chan struct{}
	calls   atomic.Int32
}

func (s *portableInstallerWaitStub) InstallNativePackage(ctx context.Context) error {
	s.calls.Add(1)
	close(s.started)
	<-ctx.Done()
	return ctx.Err()
}

type portableSurfaceWaitStub struct{}

func (*portableSurfaceWaitStub) BuildInstalledSurface(context.Context) (portablebootstrap.Surface, error) {
	return portablebootstrap.Surface{}, errors.New("must not build after cancellation")
}

type portablePackageApplicationStub struct {
	request nativepackageinstallapp.Request
	calls   atomic.Int32
}

func (s *portablePackageApplicationStub) Install(
	_ context.Context,
	request nativepackageinstallapp.Request,
) (nativepackageinstallapp.Result, error) {
	s.calls.Add(1)
	s.request = request
	return nativepackageinstallapp.Result{}, nil
}

type portableApplicationStub struct{}

func (*portableApplicationStub) Status(context.Context) (mcpbootstrapapp.InstallationStatus, error) {
	return mcpbootstrapapp.InstallationStatus{Sequence: 1}, nil
}

func (*portableApplicationStub) WaitAfter(context.Context, uint64) (mcpbootstrapapp.InstallationStatus, error) {
	return mcpbootstrapapp.InstallationStatus{Sequence: 2}, nil
}

func (*portableApplicationStub) OpenSetup(context.Context) (mcpbootstrapapp.OpenSetupResult, error) {
	return mcpbootstrapapp.OpenSetupResult{}, nil
}

func (*portableApplicationStub) Cancel(context.Context) (mcpbootstrapapp.CancelResult, error) {
	return mcpbootstrapapp.CancelResult{}, nil
}

var _ mcpbootstrap.BootstrapApplication = (*portableApplicationStub)(nil)
