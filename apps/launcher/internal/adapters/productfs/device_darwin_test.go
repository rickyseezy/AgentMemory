//go:build darwin

package productfs

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestPF001ProductDeviceIdentityRejectsNegativeAndPreservesDarwinDevice(t *testing.T) {
	t.Parallel()
	if device, valid := productDeviceIdentity(&unix.Stat_t{Dev: -1}); valid || device != 0 {
		t.Fatalf("negative device=%d valid=%t", device, valid)
	}
	if device, valid := productDeviceIdentity(&unix.Stat_t{}); !valid || device != 0 {
		t.Fatalf("zero-boundary device=%d valid=%t", device, valid)
	}
	if device, valid := productDeviceIdentity(&unix.Stat_t{Dev: 173}); !valid || device != 173 {
		t.Fatalf("native device=%d valid=%t", device, valid)
	}
}
