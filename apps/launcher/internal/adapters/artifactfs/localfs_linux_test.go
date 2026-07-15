//go:build linux

package artifactfs

import "testing"

func TestPF001LinuxLocalBlockDevicePolicyAllowsNonRemovableVirtioAndRejectsUnsafeBackings(t *testing.T) {
	t.Parallel()
	for _, component := range []string{"loop0", "nbd0", "rbd7", "drbd1", "zram0", "ram0"} {
		if !unsafeLinuxBlockDeviceComponent(component) {
			t.Fatalf("unsafe block device component %q was accepted", component)
		}
	}
	for _, component := range []string{"virtio0", "vda", "nvme0n1", "sda", "block"} {
		if unsafeLinuxBlockDeviceComponent(component) {
			t.Fatalf("ordinary local block device component %q was rejected", component)
		}
	}
}
