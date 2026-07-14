//go:build linux

package corehttp

import "golang.org/x/sys/unix"

func credentialDeviceIdentity(status *unix.Stat_t) (uint64, bool) {
	if status == nil {
		return 0, false
	}
	return status.Dev, true
}
