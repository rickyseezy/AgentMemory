//go:build windows

package launcher

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/windowssecurity"
	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"golang.org/x/sys/windows"
)

const windowsDesktopHelperStateRoot = `C:\ProgramData\AgentMemory\runtime-helper`

type windowsDesktopHelperExchange struct {
	ownerSID string
	home     string
}

func nativeDesktopHelperElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func nativeDesktopHelperPlatformBoundaries(_ string) (string, nativeDesktopHelperExchange, error) {
	if !nativeDesktopHelperElevated() {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	_, sid, err := windowssecurity.CurrentUserSID(context.Background())
	if err != nil || sid == "" {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" || !filepath.IsAbs(home) || filepath.Clean(home) != home ||
		windowssecurity.ValidateLocalPath(home) != nil {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return windowsDesktopHelperStateRoot, windowsDesktopHelperExchange{ownerSID: sid, home: home}, nil
}

func (e windowsDesktopHelperExchange) PrincipalID() string { return "sid:" + e.ownerSID }

func nativeDesktopHelperReleaseBundleRoot() (string, error) {
	root := `C:\Program Files\AgentMemory\resources\bundle`
	if filepath.Clean(root) != root || windowssecurity.ValidateLocalPath(root) != nil {
		return "", errNativeInstallerIntegrity
	}
	return root, nil
}

func (e windowsDesktopHelperExchange) ReadDesktopMutationRequest(
	ctx context.Context,
	path string,
) ([]byte, string, error) {
	directory, _, receiptName, err := e.validatePath(path)
	if err != nil || ctx == nil {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	guard, _, err := windowssecurity.OpenVerified(ctx, directory, true, false, true)
	if err != nil {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = guard.Close() }()
	file, _, err := windowssecurity.OpenVerifiedForOwnerSIDLockedRead(ctx, path, e.ownerSID)
	if err != nil {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > 64*1024*1024 {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 64*1024*1024 || ctx.Err() != nil {
		clear(raw)
		return nil, "", desktopHelperCommandContextOrIntegrity(ctx)
	}
	return raw, filepath.Join(directory, receiptName), nil
}

func (e windowsDesktopHelperExchange) WriteDesktopMutationReceipt(
	ctx context.Context,
	path string,
	receipt []byte,
) error {
	directory, _, receiptName, err := e.validatePath(strings.TrimSuffix(path, ".receipt.json") + ".json")
	if err != nil || ctx == nil || !strings.EqualFold(filepath.Join(directory, receiptName), path) ||
		len(receipt) == 0 || len(receipt) > 64*1024 {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	temporary := filepath.Join(directory, "."+receiptName+".partial")
	if err := removeWindowsDesktopHelperTemporary(ctx, temporary); err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	file, err := windowssecurity.CreatePrivateFile(ctx, temporary)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(temporary)
		}
	}()
	written, writeError := file.Write(receipt)
	if writeError != nil || written != len(receipt) || file.Sync() != nil || file.Close() != nil {
		return desktopHelperCommandContextOrIntegrity(ctx)
	}
	published, err := windowssecurity.AtomicPublishNoReplace(ctx, temporary, path)
	if err != nil || !published {
		return desktopHelperCommandContextOrIntegrity(ctx)
	}
	committed = true
	return nil
}

func (e windowsDesktopHelperExchange) validatePath(path string) (string, string, string, error) {
	base := filepath.Join(e.home, "AppData", "Local", "AgentMemory", "bootstrap")
	if e.ownerSID == "" || e.home == "" || path == "" || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") ||
		windowssecurity.ValidateLocalPath(path) != nil {
		return "", "", "", runtimeport.ErrDesktopMutationIntegrity
	}
	relative, err := filepath.Rel(base, path)
	parts := strings.Split(relative, string(filepath.Separator))
	if err != nil || len(parts) != 3 || !strings.EqualFold(parts[1], "native") ||
		!canonicalDesktopHelperDigest(parts[0]) || !strings.HasPrefix(strings.ToLower(parts[2]), "request-") ||
		!strings.HasSuffix(strings.ToLower(parts[2]), ".json") ||
		strings.HasSuffix(strings.ToLower(parts[2]), ".receipt.json") {
		return "", "", "", runtimeport.ErrDesktopMutationIntegrity
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(strings.ToLower(parts[2]), "request-"), ".json")
	if !canonicalDesktopHelperDigest(digest) {
		return "", "", "", runtimeport.ErrDesktopMutationIntegrity
	}
	requestName := "request-" + digest + ".json"
	return filepath.Dir(path), requestName, "request-" + digest + ".receipt.json", nil
}

func removeWindowsDesktopHelperTemporary(ctx context.Context, path string) error {
	file, _, err := windowssecurity.OpenVerified(ctx, path, false, true, true)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	closeError := file.Close()
	if closeError != nil {
		return closeError
	}
	return os.Remove(path)
}

var _ nativeDesktopHelperExchange = windowsDesktopHelperExchange{}
