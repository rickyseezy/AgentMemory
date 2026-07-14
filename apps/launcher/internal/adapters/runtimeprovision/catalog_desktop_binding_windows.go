//go:build windows

package runtimeprovision

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/runtimecatalogapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimecatalog"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

const windowsNameSamCompatible = 2

// NativeDesktopHostBindingProvider derives catalog-addressed Windows authority
// from the actual process token SID and machine registry identity.
type NativeDesktopHostBindingProvider struct{}

// NewNativeDesktopHostBindingProvider constructs the production native probe.
func NewNativeDesktopHostBindingProvider() *NativeDesktopHostBindingProvider {
	return &NativeDesktopHostBindingProvider{}
}

// CurrentDesktopHostBinding returns only current native identity and a fixed
// catalog-addressed owner-local artifact path.
func (*NativeDesktopHostBindingProvider) CurrentDesktopHostBinding(
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
	if !validNativeDesktopBindingRequest(catalog, artifact, runtimeinstall.PlatformWindows) {
		return runtimecatalogapp.DesktopHostBinding{}, ErrUnsupportedHost
	}
	_, sid, sidError := windowssecurity.CurrentUserSID(ctx)
	machineGUID, machineError := windowssecurity.MachineGUID(ctx)
	home, homeError := os.UserHomeDir()
	userName, userError := currentWindowsAccountName()
	if sidError != nil || machineError != nil || homeError != nil || userError != nil ||
		!filepath.IsAbs(home) || filepath.Clean(home) != home {
		return runtimecatalogapp.DesktopHostBinding{}, ErrUnsupportedHost
	}
	return runtimecatalogapp.NewDesktopHostBinding(runtimecatalogapp.DesktopHostBindingInput{
		Platform: runtimeinstall.PlatformWindows, Architecture: runtimeinstall.ArchitectureAMD64,
		PrincipalID: "sid:" + sid, UserName: userName, MachineDigest: runtimeinstall.Sum([]byte(machineGUID)),
		HomeDirectory: home,
		ArtifactPath:  filepath.Join(home, "AppData", "Local", "AgentMemory", "runtime", catalog.Hex(), artifact),
		Endpoint:      "npipe:////./pipe/docker_engine",
	})
}

func currentWindowsAccountName() (string, error) {
	size := uint32(0)
	err := windows.GetUserNameEx(windowsNameSamCompatible, nil, &size)
	if !errorsIsWindowsMoreData(err) || size <= 1 || size > 256 {
		return "", ErrProbeFailed
	}
	buffer := make([]uint16, size)
	if err := windows.GetUserNameEx(windowsNameSamCompatible, &buffer[0], &size); err != nil {
		return "", ErrProbeFailed
	}
	qualified := windows.UTF16ToString(buffer)
	separator := strings.LastIndexByte(qualified, '\\')
	if separator < 0 || separator == len(qualified)-1 {
		return "", ErrProbeFailed
	}
	return qualified[separator+1:], nil
}

func errorsIsWindowsMoreData(err error) bool {
	return err == windows.ERROR_MORE_DATA || err == windows.ERROR_INSUFFICIENT_BUFFER
}

var _ DesktopHostBindingProvider = (*NativeDesktopHostBindingProvider)(nil)
