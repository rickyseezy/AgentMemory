//go:build windows

package hostverify

import (
	"context"
	"errors"
	"testing"

	"github.com/go-ole/go-ole"
)

func TestPF001WindowsVolumeResolverMapsInstallPathToExactVolumeGUID(t *testing.T) {
	t.Parallel()
	api := &fakeWindowsVolumeAPI{mountPoint: `C:\`, volumeID: testVolumeID}
	resolver := windowsVolumeResolver{api: api}
	path := `C:\Users\person\AppData\Local\AgentMemory`
	volumeID, err := resolver.resolve(context.Background(), path)
	if err != nil || volumeID != testVolumeID {
		t.Fatalf("resolve() = %q, %v", volumeID, err)
	}
	if api.path != path || api.mountRequest != `C:\` {
		t.Fatalf("API requests = %q, %q", api.path, api.mountRequest)
	}

	tests := []struct {
		name string
		api  *fakeWindowsVolumeAPI
		ctx  context.Context
	}{
		{name: "mount lookup failure", api: &fakeWindowsVolumeAPI{pathErr: errors.New("mount")}, ctx: context.Background()},
		{name: "mount missing trailing slash", api: &fakeWindowsVolumeAPI{mountPoint: `C:`, volumeID: testVolumeID}, ctx: context.Background()},
		{name: "volume lookup failure", api: &fakeWindowsVolumeAPI{mountPoint: `C:\`, volumeErr: errors.New("volume")}, ctx: context.Background()},
		{name: "non GUID identity", api: &fakeWindowsVolumeAPI{mountPoint: `C:\`, volumeID: `C:\`}, ctx: context.Background()},
		{name: "cancelled", api: &fakeWindowsVolumeAPI{mountPoint: `C:\`, volumeID: testVolumeID}, ctx: cancelledContext()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := (windowsVolumeResolver{api: test.api}).resolve(test.ctx, path); err == nil {
				t.Fatal("invalid Windows volume evidence was accepted")
			}
		})
	}
}

func TestPF001OLEBitLockerValuesRejectAutomationTypeDrift(t *testing.T) {
	t.Parallel()
	i4 := ole.NewVariant(ole.VT_I4, 100)
	value, err := exactOLEBitLockerValue(&i4, nil)
	if err != nil || value != bitLockerI4(100) {
		t.Fatalf("VT_I4 value = %+v, %v", value, err)
	}
	ui4 := ole.NewVariant(ole.VT_UI4, 100)
	if _, err := exactOLEBitLockerValue(&ui4, nil); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("VT_UI4 drift error = %v", err)
	}
	if _, err := exactOLEBitLockerValue(nil, nil); !errors.Is(err, errBitLockerEvidence) {
		t.Fatalf("nil VARIANT error = %v", err)
	}
}

type fakeWindowsVolumeAPI struct {
	path         string
	mountRequest string
	mountPoint   string
	volumeID     string
	pathErr      error
	volumeErr    error
}

func (a *fakeWindowsVolumeAPI) volumePathName(path string) (string, error) {
	a.path = path
	return a.mountPoint, a.pathErr
}

func (a *fakeWindowsVolumeAPI) volumeNameForMountPoint(mountPoint string) (string, error) {
	a.mountRequest = mountPoint
	return a.volumeID, a.volumeErr
}
