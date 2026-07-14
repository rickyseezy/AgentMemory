//go:build linux

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
	if !ok {
		return "", false
	}
	return strconv.FormatUint(status.Dev, 10) + ":" + strconv.FormatUint(status.Ino, 10) + ":" +
		strconv.FormatInt(status.Ctim.Sec, 10) + ":" + strconv.FormatInt(status.Ctim.Nsec, 10), true
}
