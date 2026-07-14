//go:build darwin

package corehttp

import "golang.org/x/sys/unix"

func credentialDeviceIdentity(status *unix.Stat_t) (uint64, bool) {
	if status == nil || status.Dev < 0 {
		return 0, false
	}
	return uint64(status.Dev), true // #nosec G115 -- the signed native identity is proven nonnegative above.
}
