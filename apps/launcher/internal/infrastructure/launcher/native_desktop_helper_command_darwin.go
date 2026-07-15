//go:build darwin

package launcher

import (
	"context"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	runtimeport "github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/ports/runtimeprovision"
	"golang.org/x/sys/unix"
)

const darwinDesktopHelperStateRoot = "/Library/Application Support/AgentMemory/runtime-helper"

type darwinDesktopHelperExchange struct {
	uid  uint32
	gid  uint32
	home string
}

func (e darwinDesktopHelperExchange) PrincipalID() string {
	return "uid:" + strconv.FormatUint(uint64(e.uid), 10)
}

func nativeDesktopHelperElevated() bool { return os.Geteuid() == 0 }

func nativeDesktopHelperPlatformBoundaries(requestPath string) (string, nativeDesktopHelperExchange, error) {
	if !nativeDesktopHelperElevated() {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	descriptor, err := unix.Open(requestPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	var status unix.Stat_t
	statError := unix.Fstat(descriptor, &status)
	closeError := unix.Close(descriptor)
	if statError != nil || closeError != nil || status.Mode&unix.S_IFMT != unix.S_IFREG || status.Uid == 0 ||
		status.Nlink != 1 || uint32(status.Mode)&0o7777 != 0o600 || status.Size <= 0 || status.Size > 64*1024*1024 {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	uid := int(status.Uid) // #nosec G115 -- Darwin uid_t is uint32 and int is 64 bits on supported hosts.
	current, err := user.LookupId(strconv.Itoa(uid))
	if err != nil || current == nil || current.HomeDir == "" || current.Gid == "" {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	gid, err := strconv.ParseUint(current.Gid, 10, 32)
	if err != nil || gid == 0 {
		return "", nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return darwinDesktopHelperStateRoot, darwinDesktopHelperExchange{
		uid: status.Uid, gid: uint32(gid), home: current.HomeDir, // #nosec G115 -- gid was bounded to uint32.
	}, nil
}

func nativeDesktopHelperReleaseBundleRoot() (string, error) {
	root := "/Library/Application Support/AgentMemory/resources/bundle"
	if filepath.Clean(root) != root {
		return "", errNativeInstallerIntegrity
	}
	return root, nil
}

func (e darwinDesktopHelperExchange) ReadDesktopMutationRequest(
	ctx context.Context,
	path string,
) ([]byte, string, error) {
	directory, requestName, receiptName, err := e.validatePath(path)
	if err != nil || ctx == nil {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	directoryFile, err := e.openDirectory(directory)
	if err != nil {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = directoryFile.Close() }()
	descriptor, err := unix.Openat(
		int(directoryFile.Fd()), requestName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	file := os.NewFile(uintptr(descriptor), requestName)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = file.Close() }()
	var status unix.Stat_t
	if unix.Fstat(descriptor, &status) != nil || status.Mode&unix.S_IFMT != unix.S_IFREG ||
		status.Uid != e.uid || status.Nlink != 1 || uint32(status.Mode)&0o7777 != 0o600 ||
		status.Size <= 0 || status.Size > 64*1024*1024 {
		return nil, "", runtimeport.ErrDesktopMutationIntegrity
	}
	raw, err := io.ReadAll(io.LimitReader(file, 64*1024*1024+1))
	if err != nil || len(raw) == 0 || len(raw) > 64*1024*1024 || ctx.Err() != nil {
		clear(raw)
		return nil, "", desktopHelperCommandContextOrIntegrity(ctx)
	}
	return raw, filepath.Join(directory, receiptName), nil
}

func (e darwinDesktopHelperExchange) WriteDesktopMutationReceipt(
	ctx context.Context,
	path string,
	receipt []byte,
) error {
	if ctx == nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, _, receiptName, err := e.validatePath(strings.TrimSuffix(path, ".receipt.json") + ".json")
	if err != nil || filepath.Join(directory, receiptName) != path || len(receipt) == 0 || len(receipt) > 64*1024 {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	directoryFile, err := e.openDirectory(directory)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	defer func() { _ = directoryFile.Close() }()
	temporaryName := "." + receiptName + ".partial"
	_ = unix.Unlinkat(int(directoryFile.Fd()), temporaryName, 0)
	descriptor, err := unix.Openat(
		int(directoryFile.Fd()), temporaryName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	file := os.NewFile(uintptr(descriptor), temporaryName)
	if file == nil {
		_ = unix.Close(descriptor)
		return runtimeport.ErrDesktopMutationIntegrity
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = unix.Unlinkat(int(directoryFile.Fd()), temporaryName, 0)
		}
	}()
	if unix.Fchown(descriptor, int(e.uid), int(e.gid)) != nil || unix.Fchmod(descriptor, 0o600) != nil {
		return runtimeport.ErrDesktopMutationIntegrity
	}
	written, writeError := file.Write(receipt)
	if writeError != nil || written != len(receipt) || file.Sync() != nil || file.Close() != nil ||
		unix.RenameatxNp(
			int(directoryFile.Fd()), temporaryName, int(directoryFile.Fd()), receiptName, unix.RENAME_EXCL,
		) != nil || unix.Fsync(int(directoryFile.Fd())) != nil {
		return desktopHelperCommandContextOrIntegrity(ctx)
	}
	committed = true
	return nil
}

func (e darwinDesktopHelperExchange) validatePath(path string) (string, string, string, error) {
	base := filepath.Join(e.home, "Library", "Application Support", "AgentMemory", "bootstrap")
	if e.uid == 0 || e.gid == 0 || e.home == "" || path == "" || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
		return "", "", "", runtimeport.ErrDesktopMutationIntegrity
	}
	relative, err := filepath.Rel(base, path)
	parts := strings.Split(relative, string(filepath.Separator))
	if err != nil || len(parts) != 3 || parts[1] != "native" ||
		!canonicalDesktopHelperDigest(parts[0]) || !strings.HasPrefix(parts[2], "request-") ||
		!strings.HasSuffix(parts[2], ".json") || strings.HasSuffix(parts[2], ".receipt.json") {
		return "", "", "", runtimeport.ErrDesktopMutationIntegrity
	}
	digest := strings.TrimSuffix(strings.TrimPrefix(parts[2], "request-"), ".json")
	if !canonicalDesktopHelperDigest(digest) {
		return "", "", "", runtimeport.ErrDesktopMutationIntegrity
	}
	return filepath.Dir(path), parts[2], "request-" + digest + ".receipt.json", nil
}

func (e darwinDesktopHelperExchange) openDirectory(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0o700 || status.Uid != e.uid {
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "desktop-helper-exchange")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, runtimeport.ErrDesktopMutationIntegrity
	}
	return file, nil
}

var _ nativeDesktopHelperExchange = darwinDesktopHelperExchange{}
