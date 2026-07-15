//go:build linux

package artifactfs

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func nativeUnixStatValues(stat *unix.Stat_t) (uint32, uint64) {
	return stat.Mode, nativeLinkCount(stat.Nlink)
}

func nativeSystemStatValues(stat *syscall.Stat_t) (uint32, uint64) {
	return stat.Mode, nativeLinkCount(stat.Nlink)
}

// nativeLinkCount keeps this adapter source-compatible with Go toolchains
// where the Linux Stat_t link field is either uint32 or uint64. The generic
// conversion remains necessary for the complete type set, so unconvert cannot
// incorrectly make the source dependent on the linter's build toolchain.
func nativeLinkCount[T ~uint32 | ~uint64](value T) uint64 { return uint64(value) }
