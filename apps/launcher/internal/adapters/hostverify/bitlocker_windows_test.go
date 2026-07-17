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

func TestPF001WindowsBitLockerBackendWiresNativeEvidenceProviders(t *testing.T) {
	t.Parallel()
	backend := newWindowsBitLockerBackend()
	if backend == nil {
		t.Fatal("native Windows BitLocker backend is nil")
	}
	resolver, resolverOK := backend.resolver.(windowsVolumeResolver)
	if !resolverOK || resolver.api == nil {
		t.Fatalf("resolver = %#v, want native Windows volume resolver", backend.resolver)
	}
	if _, factoryOK := backend.factory.(oleBitLockerSessionFactory); !factoryOK {
		t.Fatalf("factory = %#v, want OLE BitLocker session factory", backend.factory)
	}
	if backend.session != nil {
		t.Fatalf("new backend unexpectedly owns session %#v", backend.session)
	}
}

func TestPF001OLEOwnedDispatchRejectsInvalidVariantsAndClearsOwnership(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		variant func() *ole.VARIANT
		err     error
	}{
		{name: "reported automation error", variant: func() *ole.VARIANT {
			value := ole.NewVariant(ole.VT_I4, 7)
			return &value
		}, err: errors.New("automation")},
		{name: "nil variant", variant: func() *ole.VARIANT { return nil }},
		{name: "wrong variant type", variant: func() *ole.VARIANT {
			value := ole.NewVariant(ole.VT_I4, 7)
			return &value
		}},
		{name: "nil dispatch", variant: func() *ole.VARIANT {
			value := ole.NewVariant(ole.VT_DISPATCH, 0)
			return &value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if owned, err := newOLEOwnedDispatch(test.variant(), test.err); owned != nil ||
				!errors.Is(err, errBitLockerEvidence) {
				t.Fatalf("newOLEOwnedDispatch() = %#v, %v", owned, err)
			}
		})
	}

	value := ole.NewVariant(ole.VT_I4, 11)
	owned := &oleOwnedDispatch{variant: &value, dispatch: new(ole.IDispatch)}
	owned.close()
	if owned.variant != nil || owned.dispatch != nil || value.VT != ole.VT_EMPTY {
		t.Fatalf("closed ownership = %#v, variant type=%d", owned, value.VT)
	}
	owned.close()
	(*oleOwnedDispatch)(nil).close()
}

func TestPF001OLEBitLockerQueryServiceCloseClearsNestedOwnership(t *testing.T) {
	t.Parallel()
	value := ole.NewVariant(ole.VT_I4, 19)
	service := &oleBitLockerQueryService{
		service: &oleOwnedDispatch{variant: &value, dispatch: new(ole.IDispatch)},
	}
	service.close()
	if service.service != nil || value.VT != ole.VT_EMPTY {
		t.Fatalf("closed service = %#v, variant type=%d", service.service, value.VT)
	}
	service.close()
	(*oleBitLockerQueryService)(nil).close()
}

func TestPF001ClearOLEVariantIsNilSafeAndReleasesTheVariant(t *testing.T) {
	t.Parallel()
	clearOLEVariant(nil)
	value := ole.NewVariant(ole.VT_I4, 23)
	clearOLEVariant(&value)
	if value.VT != ole.VT_EMPTY {
		t.Fatalf("cleared variant type = %d, want VT_EMPTY", value.VT)
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
