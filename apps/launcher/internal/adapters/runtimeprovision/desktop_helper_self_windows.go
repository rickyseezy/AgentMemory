//go:build windows

package runtimeprovision

import (
	"context"
	"io"
	"math"
	"os"
	"path/filepath"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/runtimeinstall"
	"golang.org/x/sys/windows"
)

func (v *NativeDesktopHelperExecutableVerifier) verifyDesktopHelperSelf(
	ctx context.Context,
	resource releaseinventory.Resource,
	authority runtimeport.DesktopAuthority,
) (runtimeinstall.Hash, error) {
	certificate, err := v.expectedCertificate(resource, authority)
	if err != nil || ctx == nil || authority.Platform() != runtimeinstall.PlatformWindows ||
		resource.Size() > math.MaxInt64 {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return runtimeinstall.Hash{}, err
	}
	path := `C:\Program Files\AgentMemory\bin\agentmemory-runtime-helper.exe`
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	handle, err := windows.CreateFile(
		pointer, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0,
	)
	if err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	file := os.NewFile(uintptr(handle), filepath.Base(path))
	if file == nil {
		_ = windows.CloseHandle(handle)
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = file.Close() }()
	var information windows.ByHandleFileInformation
	info, statError := file.Stat()
	if windows.GetFileInformationByHandle(handle, &information) != nil || statError != nil ||
		information.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|
			windows.FILE_ATTRIBUTE_DEVICE) != 0 || information.NumberOfLinks != 1 || info.Size() < 0 ||
		uint64(info.Size()) != resource.Size() {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	digest, read, err := digestWindowsDesktopArtifact(ctx, file, resource.Size())
	if err != nil || read != resource.Size() || releaseinventory.Digest(digest) != resource.Digest() ||
		!verifyWindowsAuthenticode(path) {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	leaf, err := windowssecurity.AuthenticodeLeafCertificateSHA256(ctx, path)
	if err != nil || runtimeinstall.Hash(leaf) != certificate {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return runtimeinstall.Hash{}, runtimeport.ErrDesktopMutationIntegrity
	}
	after, afterRead, err := digestWindowsDesktopArtifact(ctx, file, resource.Size())
	if err != nil || afterRead != resource.Size() || after != digest || ctx.Err() != nil {
		return runtimeinstall.Hash{}, desktopMutationHelperContextOrIntegrity(ctx)
	}
	return digest, nil
}
