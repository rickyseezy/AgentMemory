//go:build darwin || linux

package dockercli

import (
	"os"
	"syscall"
)

func privateComposeFile(info os.FileInfo) bool {
	return privateUnixComposeFile(info, int64(os.Geteuid()))
}

func privateComposePath(path string, wantDirectory bool) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if wantDirectory {
		return privateComposeDirectory(info) && composeACLFree(path)
	}
	return privateComposeFile(info) && composeACLFree(path)
}

func privateUnixComposeFile(info os.FileInfo, expectedUID int64) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(status.Uid) == expectedUID && status.Nlink == 1
}

func privateComposeDirectory(info os.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(status.Uid) == int64(os.Geteuid())
}
