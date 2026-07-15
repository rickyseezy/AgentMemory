package launcher

import (
	"context"
	"io"
	"os"
	"runtime"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/nativepackage"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/portablebootstrap"
	releaseverifyadapter "github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/releaseverify"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/mcpbootstrapapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/nativepackageinstallapp"
	agentconfigdomain "github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/agentconfig"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releasepublication"
)

const (
	maximumPortablePublicationBytes = 32 * 1024 * 1024
	maximumPortableSignatureBytes   = 64 * 1024 * 1024
)

type portableComposition struct {
	installer portablebootstrap.Installer
	surface   portablebootstrap.SurfaceFactory
}

func (c portableComposition) valid() bool {
	return !nilCapability(c.installer) && !nilCapability(c.surface)
}

type portableComposer func(
	context.Context,
	agentconfigdomain.AgentHost,
) (portableComposition, error)

// PortableFactory is the signed agent-host package composition. It returns an
// MCP runner before the native package transaction completes.
type PortableFactory struct{ compose portableComposer }

// NewPortableFactory constructs the production host-package entry point.
func NewPortableFactory() MCPFactory {
	return &PortableFactory{compose: composeNativePortable}
}

// BuildMCP creates one live portable-to-native bridge for an exact host.
func (f *PortableFactory) BuildMCP(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (MCPRunner, error) {
	if f == nil || ctx == nil || !host.Valid() || f.compose == nil {
		return nil, mcpbootstrapIntegrity()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	composition, err := f.compose(ctx, host)
	if err != nil || !composition.valid() {
		return nil, mcpbootstrapUnavailable()
	}
	bridge, err := portablebootstrap.New(ctx, composition.installer, composition.surface)
	if err != nil {
		if contextError := ctx.Err(); contextError != nil {
			return nil, contextError
		}
		return nil, mcpbootstrapUnavailable()
	}
	return newManagedRunner(ctx, bootstrapSurface{
		application: bridge, ready: bridge, lifecycle: bridge,
	})
}

func mcpbootstrapIntegrity() error {
	return mcpbootstrapapp.ErrBootstrapIntegrity
}

func mcpbootstrapUnavailable() error {
	return mcpbootstrapapp.ErrBootstrapUnavailable
}

type portableProductionDependencies struct {
	layout       func() (nativepackage.PortableLayout, error)
	format       func() (releasepublication.Format, error)
	trust        nativeReleaseTrustLoader
	operatingOS  string
	architecture string
	buildSurface installedSurfaceBuilder
}

func composeNativePortable(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
) (portableComposition, error) {
	return composePortable(ctx, host, portableProductionDependencies{
		layout: nativepackage.NativePortableLayout, format: nativepackage.Format,
		trust: loadEmbeddedNativeReleaseTrust, operatingOS: runtime.GOOS, architecture: runtime.GOARCH,
		buildSurface: func(ctx context.Context, host agentconfigdomain.AgentHost) (bootstrapSurface, error) {
			return newInstalledNativeFactory().buildBootstrapSurface(ctx, host)
		},
	})
}

func composePortable(
	ctx context.Context,
	host agentconfigdomain.AgentHost,
	dependencies portableProductionDependencies,
) (portableComposition, error) {
	if ctx == nil || !host.Valid() || dependencies.layout == nil || dependencies.format == nil ||
		dependencies.trust == nil || dependencies.buildSurface == nil ||
		dependencies.operatingOS == "" || dependencies.architecture == "" {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	if err := ctx.Err(); err != nil {
		return portableComposition{}, err
	}
	layout, err := dependencies.layout()
	if err != nil {
		return portableComposition{}, mcpbootstrapUnavailable()
	}
	format, err := dependencies.format()
	if err != nil {
		return portableComposition{}, mcpbootstrapUnavailable()
	}
	trust, err := dependencies.trust()
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	publicationSignature, err := releaseverifyadapter.NewSigstoreCertificateTransparencyVerifier(
		trust.PublicationSigstore,
	)
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	objectSignature, err := releaseverifyadapter.NewSigstoreCertificateTransparencyVerifier(
		trust.ReleaseObjectSigstore,
	)
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	objectPublisher, err := nativepackage.NewObjectSignatureVerifier(layout.Evidence, objectSignature)
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	candidate, err := nativepackage.NewCandidateVerifier(layout.Objects, objectPublisher)
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	runner, err := nativepackage.NewNativeCommandRunner()
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	transaction, err := nativepackage.NewTransactionInstaller(
		layout.Objects, dependencies.operatingOS, dependencies.architecture, runner,
	)
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	installed, err := nativepackage.NewNativeInstalledProductVerifier()
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	application, err := nativepackageinstallapp.New(nativepackageinstallapp.Dependencies{
		Signature: publicationSignature, Candidate: candidate, Installer: transaction, Installed: installed,
	})
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	publication, err := readPortableAuthority(layout.Publication, maximumPortablePublicationBytes)
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	signature, err := readPortableAuthority(layout.PublicationSigstore, maximumPortableSignatureBytes)
	if err != nil {
		return portableComposition{}, mcpbootstrapIntegrity()
	}
	installer := &portableNativeInstaller{application: application, request: nativepackageinstallapp.Request{
		PublicationJSON: publication, PublicationSigstoreBundle: signature,
		OperatingSystem: dependencies.operatingOS, Architecture: dependencies.architecture, Format: format,
	}}
	surface := &portableInstalledSurfaceFactory{host: host, build: dependencies.buildSurface}
	return portableComposition{installer: installer, surface: surface}, nil
}

type nativePackageApplication interface {
	Install(context.Context, nativepackageinstallapp.Request) (nativepackageinstallapp.Result, error)
}

type portableNativeInstaller struct {
	application nativePackageApplication
	request     nativepackageinstallapp.Request
}

func (i *portableNativeInstaller) InstallNativePackage(ctx context.Context) error {
	if i == nil || ctx == nil || nilAny(i.application) {
		return mcpbootstrapIntegrity()
	}
	request := i.request
	request.PublicationJSON = append([]byte(nil), i.request.PublicationJSON...)
	request.PublicationSigstoreBundle = append([]byte(nil), i.request.PublicationSigstoreBundle...)
	_, err := i.application.Install(ctx, request)
	return err
}

type installedSurfaceBuilder func(
	context.Context,
	agentconfigdomain.AgentHost,
) (bootstrapSurface, error)

type portableInstalledSurfaceFactory struct {
	host  agentconfigdomain.AgentHost
	build installedSurfaceBuilder
}

func (f *portableInstalledSurfaceFactory) BuildInstalledSurface(
	ctx context.Context,
) (portablebootstrap.Surface, error) {
	if f == nil || ctx == nil || !f.host.Valid() || f.build == nil {
		return portablebootstrap.Surface{}, mcpbootstrapIntegrity()
	}
	surface, err := f.build(ctx, f.host)
	if err != nil || !surface.valid() {
		return portablebootstrap.Surface{}, mcpbootstrapUnavailable()
	}
	return portablebootstrap.Surface{
		Application: surface.application, Ready: surface.ready, Lifecycle: surface.lifecycle,
	}, nil
}

func readPortableAuthority(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, mcpbootstrapIntegrity()
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > maximum {
		return nil, mcpbootstrapIntegrity()
	}
	// #nosec G304 -- path is one closed leaf from NativePortableLayout.
	file, err := os.Open(path)
	if err != nil {
		return nil, mcpbootstrapIntegrity()
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, mcpbootstrapIntegrity()
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, mcpbootstrapIntegrity()
	}
	return raw, nil
}

var (
	_ MCPFactory                       = (*PortableFactory)(nil)
	_ portablebootstrap.Installer      = (*portableNativeInstaller)(nil)
	_ portablebootstrap.SurfaceFactory = (*portableInstalledSurfaceFactory)(nil)
)
