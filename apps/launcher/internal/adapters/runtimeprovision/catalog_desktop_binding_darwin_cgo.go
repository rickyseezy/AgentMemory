//go:build darwin && cgo

package runtimeprovision

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
)

// NativeDesktopHostBindingProvider derives catalog-addressed macOS authority
// from the actual non-root invoking user and platform UUID.
type NativeDesktopHostBindingProvider struct {
	uid          func() int
	currentUser  func() (*user.User, error)
	home         func() (string, error)
	machine      func() (runtimeinstall.Hash, error)
	architecture string
}

// NewNativeDesktopHostBindingProvider constructs the production native probe.
func NewNativeDesktopHostBindingProvider() *NativeDesktopHostBindingProvider {
	return &NativeDesktopHostBindingProvider{
		uid: os.Geteuid, currentUser: user.Current, home: os.UserHomeDir,
		machine: nativeDarwinMachineDigest, architecture: runtime.GOARCH,
	}
}

// CurrentDesktopHostBinding returns only native facts and a deterministic
// catalog-addressed owner cache path.
func (p *NativeDesktopHostBindingProvider) CurrentDesktopHostBinding(
	ctx context.Context,
	catalog runtimecatalog.Digest,
	artifact string,
) (runtimecatalogapp.DesktopHostBinding, error) {
	if ctx == nil {
		return runtimecatalogapp.DesktopHostBinding{}, ErrUnsupportedHost
	}
	if err := ctx.Err(); err != nil {
		return runtimecatalogapp.DesktopHostBinding{}, err
	}
	if p == nil || p.uid == nil || p.currentUser == nil || p.home == nil || p.machine == nil ||
		!validNativeDesktopBindingRequest(catalog, artifact, runtimeinstall.PlatformDarwin) ||
		(p.architecture != "amd64" && p.architecture != "arm64") {
		return runtimecatalogapp.DesktopHostBinding{}, ErrUnsupportedHost
	}
	uid := p.uid()
	current, currentError := p.currentUser()
	home, homeError := p.home()
	machine, machineError := p.machine()
	if uid <= 0 || currentError != nil || homeError != nil || machineError != nil ||
		current == nil || current.Uid != strconv.Itoa(uid) || current.Username == "" || current.HomeDir != home ||
		!filepath.IsAbs(home) || filepath.Clean(home) != home {
		return runtimecatalogapp.DesktopHostBinding{}, ErrUnsupportedHost
	}
	architecture := runtimeinstall.ArchitectureARM64
	if p.architecture == "amd64" {
		architecture = runtimeinstall.ArchitectureAMD64
	}
	return runtimecatalogapp.NewDesktopHostBinding(runtimecatalogapp.DesktopHostBindingInput{
		Platform: runtimeinstall.PlatformDarwin, Architecture: architecture,
		PrincipalID: "uid:" + strconv.Itoa(uid), UserName: current.Username, MachineDigest: machine,
		HomeDirectory: home,
		ArtifactPath:  filepath.Join(home, "Library", "Caches", "AgentMemory", "runtime", catalog.Hex(), artifact),
		Endpoint:      "unix://" + home + "/.docker/run/docker.sock",
	})
}

var _ DesktopHostBindingProvider = (*NativeDesktopHostBindingProvider)(nil)
