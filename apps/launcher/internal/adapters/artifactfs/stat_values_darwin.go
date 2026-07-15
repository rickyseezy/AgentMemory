//go:build darwin

package artifactfs

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func nativeUnixStatValues(stat *unix.Stat_t) (uint32, uint64) {
	return uint32(stat.Mode), uint64(stat.Nlink)
}

func nativeSystemStatValues(stat *syscall.Stat_t) (uint32, uint64) {
	return uint32(stat.Mode), uint64(stat.Nlink)
}
