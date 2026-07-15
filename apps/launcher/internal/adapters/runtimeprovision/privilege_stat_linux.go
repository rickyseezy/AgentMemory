//go:build linux

package runtimeprovision

import "golang.org/x/sys/unix"

func nativePrivilegeStatMode(stat *unix.Stat_t) uint32 { return stat.Mode }
