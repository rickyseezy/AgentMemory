//go:build darwin || linux

package mcpsessionhost

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func hostDeviceIdentity(_ string, info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", errors.New("workspace stat identity is unavailable")
	}
	return fmt.Sprintf("dev:%d:ino:%d", stat.Dev, stat.Ino), nil
}
