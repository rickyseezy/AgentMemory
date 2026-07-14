//go:build darwin

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
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Dev < 0 {
		return "", false
	}
	return strconv.FormatUint(uint64(status.Dev), 10) + ":" + strconv.FormatUint(status.Ino, 10) + ":" +
		strconv.FormatInt(status.Birthtimespec.Sec, 10) + ":" + strconv.FormatInt(status.Birthtimespec.Nsec, 10), true
}
