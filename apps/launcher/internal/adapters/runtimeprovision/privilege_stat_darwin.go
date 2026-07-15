//go:build darwin

package runtimeprovision

import "golang.org/x/sys/unix"

func nativePrivilegeStatMode(stat *unix.Stat_t) uint32 { return uint32(stat.Mode) }
