//go:build windows

package dockercli

import (
	"os"
	"strconv"
	"syscall"
)

func composeNativeIdentity(info os.FileInfo) (string, bool) {
	if info == nil {
		return "", false
	}
	status, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return "", false
	}
	return strconv.FormatInt(status.CreationTime.Nanoseconds(), 10) + ":" +
		strconv.FormatInt(status.LastWriteTime.Nanoseconds(), 10) + ":" +
		strconv.FormatUint(uint64(status.FileSizeHigh), 10) + ":" + strconv.FormatUint(uint64(status.FileSizeLow), 10), true
}
