//go:build windows

package hostverify

import (
	"context"
	"math"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

const (
	bitLockerNamespace                  = `ROOT\CIMV2\Security\MicrosoftVolumeEncryption`
	windowsVolumePathBufferCharacters   = uint32(32768)
	windowsVolumeGUIDBufferCharacters   = uint32(50)
	wmiImpersonationLevelImpersonate    = int32(3)
	wmiAuthenticationLevelPacketPrivacy = int32(6)
)

type windowsVolumeAPI interface {
	volumePathName(string) (string, error)
	volumeNameForMountPoint(string) (string, error)
}

type systemWindowsVolumeAPI struct{}

func (systemWindowsVolumeAPI) volumePathName(path string) (string, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", errBitLockerEvidence
	}
	buffer := make([]uint16, windowsVolumePathBufferCharacters)
	if err := windows.GetVolumePathName(pathPointer, &buffer[0], windowsVolumePathBufferCharacters); err != nil {
		return "", errBitLockerEvidence
	}
	return windows.UTF16ToString(buffer), nil
}

func (systemWindowsVolumeAPI) volumeNameForMountPoint(mountPoint string) (string, error) {
	mountPointer, err := windows.UTF16PtrFromString(mountPoint)
	if err != nil {
		return "", errBitLockerEvidence
	}
	buffer := make([]uint16, windowsVolumeGUIDBufferCharacters)
	if err := windows.GetVolumeNameForVolumeMountPoint(
		mountPointer,
		&buffer[0],
		windowsVolumeGUIDBufferCharacters,
	); err != nil {
		return "", errBitLockerEvidence
	}
	return windows.UTF16ToString(buffer), nil
}

type windowsVolumeResolver struct{ api windowsVolumeAPI }

func (r windowsVolumeResolver) resolve(ctx context.Context, path string) (string, error) {
	if ctx == nil {
		return "", context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r.api == nil || path == "" {
		return "", errBitLockerEvidence
	}
	mountPoint, err := r.api.volumePathName(path)
	if err != nil || mountPoint == "" || mountPoint[len(mountPoint)-1] != '\\' {
		return "", errBitLockerEvidence
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	volumeID, err := r.api.volumeNameForMountPoint(mountPoint)
	if err != nil || !validBitLockerVolumeID(volumeID) {
		return "", errBitLockerEvidence
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return volumeID, nil
}

type oleBitLockerSessionFactory struct{}

func (oleBitLockerSessionFactory) open() (bitLockerStatusSession, error) {
	service, err := newOLEBitLockerQueryService()
	if err != nil {
		return nil, errBitLockerEvidence
	}
	return &wmiBitLockerSession{service: service}, nil
}

func newWindowsBitLockerBackend() *bitLockerAttestationBackend {
	return &bitLockerAttestationBackend{
		resolver: windowsVolumeResolver{api: systemWindowsVolumeAPI{}},
		factory:  oleBitLockerSessionFactory{},
	}
}

type oleOwnedDispatch struct {
	variant  *ole.VARIANT
	dispatch *ole.IDispatch
}

func newOLEOwnedDispatch(variant *ole.VARIANT, err error) (*oleOwnedDispatch, error) {
	if err != nil || variant == nil || variant.VT != ole.VT_DISPATCH {
		clearOLEVariant(variant)
		return nil, errBitLockerEvidence
	}
	dispatch := variant.ToIDispatch()
	if dispatch == nil {
		clearOLEVariant(variant)
		return nil, errBitLockerEvidence
	}
	return &oleOwnedDispatch{variant: variant, dispatch: dispatch}, nil
}

func (o *oleOwnedDispatch) close() {
	if o != nil && o.variant != nil {
		clearOLEVariant(o.variant)
		o.variant = nil
		o.dispatch = nil
	}
}

type oleBitLockerQueryService struct {
	locator     *ole.IDispatch
	service     *oleOwnedDispatch
	initialized bool
}

func newOLEBitLockerQueryService() (*oleBitLockerQueryService, error) {
	if err := ole.CoInitializeEx(0, ole.COINIT_APARTMENTTHREADED|ole.COINIT_DISABLE_OLE1DDE); err != nil {
		return nil, errBitLockerEvidence
	}
	initialized := true
	var locator *ole.IDispatch
	var service *oleOwnedDispatch
	cleanup := func() {
		if service != nil {
			service.close()
		}
		if locator != nil {
			locator.Release()
		}
		if initialized {
			ole.CoUninitialize()
		}
	}

	unknown, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil || unknown == nil {
		cleanup()
		return nil, errBitLockerEvidence
	}
	locator, err = unknown.QueryInterface(ole.IID_IDispatch)
	unknown.Release()
	if err != nil || locator == nil {
		cleanup()
		return nil, errBitLockerEvidence
	}
	service, err = newOLEOwnedDispatch(oleutil.CallMethod(locator, "ConnectServer", ".", bitLockerNamespace))
	if err != nil {
		cleanup()
		return nil, errBitLockerEvidence
	}
	if err := configureOLEBitLockerSecurity(service.dispatch); err != nil {
		cleanup()
		return nil, errBitLockerEvidence
	}
	initialized = false
	return &oleBitLockerQueryService{locator: locator, service: service, initialized: true}, nil
}

func configureOLEBitLockerSecurity(service *ole.IDispatch) error {
	security, err := newOLEOwnedDispatch(oleutil.GetProperty(service, "Security_"))
	if err != nil {
		return errBitLockerEvidence
	}
	defer security.close()
	if err := putOLEI4(security.dispatch, "ImpersonationLevel", wmiImpersonationLevelImpersonate); err != nil {
		return errBitLockerEvidence
	}
	if err := putOLEI4(security.dispatch, "AuthenticationLevel", wmiAuthenticationLevelPacketPrivacy); err != nil {
		return errBitLockerEvidence
	}
	return nil
}

func putOLEI4(dispatch *ole.IDispatch, property string, value int32) error {
	result, err := oleutil.PutProperty(dispatch, property, value)
	clearOLEVariant(result)
	if err != nil {
		return errBitLockerEvidence
	}
	return nil
}

func (s *oleBitLockerQueryService) query(query string) (bitLockerAutomationSet, error) {
	if s == nil || s.service == nil || s.service.dispatch == nil {
		return nil, errBitLockerEvidence
	}
	result, err := newOLEOwnedDispatch(oleutil.CallMethod(s.service.dispatch, "ExecQuery", query, "WQL"))
	if err != nil {
		return nil, errBitLockerEvidence
	}
	return &oleBitLockerSet{owned: result}, nil
}

func (s *oleBitLockerQueryService) close() {
	if s == nil {
		return
	}
	if s.service != nil {
		s.service.close()
		s.service = nil
	}
	if s.locator != nil {
		s.locator.Release()
		s.locator = nil
	}
	if s.initialized {
		ole.CoUninitialize()
		s.initialized = false
	}
}

type oleBitLockerSet struct{ owned *oleOwnedDispatch }

func (s *oleBitLockerSet) count() (bitLockerValue, error) {
	if s == nil || s.owned == nil || s.owned.dispatch == nil {
		return bitLockerValue{}, errBitLockerEvidence
	}
	value, err := oleutil.GetProperty(s.owned.dispatch, "Count")
	defer clearOLEVariant(value)
	return exactOLEBitLockerValue(value, err)
}

func (s *oleBitLockerSet) item(index uint32) (bitLockerAutomationObject, error) {
	if s == nil || s.owned == nil || s.owned.dispatch == nil || index != 0 {
		return nil, errBitLockerEvidence
	}
	item, err := newOLEOwnedDispatch(oleutil.CallMethod(s.owned.dispatch, "ItemIndex", int32(0)))
	if err != nil {
		return nil, errBitLockerEvidence
	}
	return &oleBitLockerObject{owned: item}, nil
}

func (s *oleBitLockerSet) close() {
	if s != nil && s.owned != nil {
		s.owned.close()
		s.owned = nil
	}
}

type oleBitLockerObject struct{ owned *oleOwnedDispatch }

func (o *oleBitLockerObject) property(name string) (bitLockerValue, error) {
	if o == nil || o.owned == nil || o.owned.dispatch == nil || name == "" {
		return bitLockerValue{}, errBitLockerEvidence
	}
	value, err := oleutil.GetProperty(o.owned.dispatch, name)
	defer clearOLEVariant(value)
	return exactOLEBitLockerValue(value, err)
}

func (o *oleBitLockerObject) invoke(
	method string,
	inputs []bitLockerInput,
) (bitLockerAutomationObject, error) {
	if o == nil || o.owned == nil || o.owned.dispatch == nil {
		return nil, errBitLockerEvidence
	}
	switch method {
	case bitLockerConversionMethod:
		if len(inputs) != 1 || inputs[0].name != bitLockerPrecisionFactorInput ||
			inputs[0].value.kind != bitLockerValueI4 || inputs[0].value.i4 != 0 {
			return nil, errBitLockerEvidence
		}
		parameters, err := newOLEMethodInputs(o.owned.dispatch, method, inputs)
		if err != nil {
			return nil, errBitLockerEvidence
		}
		defer parameters.close()
		output, err := newOLEOwnedDispatch(oleutil.CallMethod(
			o.owned.dispatch,
			"ExecMethod_",
			method,
			parameters.dispatch,
		))
		if err != nil {
			return nil, errBitLockerEvidence
		}
		return &oleBitLockerObject{owned: output}, nil
	case bitLockerProtectionMethod:
		if len(inputs) != 0 {
			return nil, errBitLockerEvidence
		}
		output, err := newOLEOwnedDispatch(oleutil.CallMethod(o.owned.dispatch, "ExecMethod_", method))
		if err != nil {
			return nil, errBitLockerEvidence
		}
		return &oleBitLockerObject{owned: output}, nil
	default:
		return nil, errBitLockerEvidence
	}
}

func newOLEMethodInputs(
	record *ole.IDispatch,
	method string,
	inputs []bitLockerInput,
) (*oleOwnedDispatch, error) {
	methods, err := newOLEOwnedDispatch(oleutil.GetProperty(record, "Methods_"))
	if err != nil {
		return nil, errBitLockerEvidence
	}
	defer methods.close()
	definition, err := newOLEOwnedDispatch(oleutil.CallMethod(methods.dispatch, "Item", method))
	if err != nil {
		return nil, errBitLockerEvidence
	}
	defer definition.close()
	template, err := newOLEOwnedDispatch(oleutil.GetProperty(definition.dispatch, "InParameters"))
	if err != nil {
		return nil, errBitLockerEvidence
	}
	defer template.close()
	parameters, err := newOLEOwnedDispatch(oleutil.CallMethod(template.dispatch, "SpawnInstance_"))
	if err != nil {
		return nil, errBitLockerEvidence
	}
	for _, input := range inputs {
		if input.name == "" || input.value.kind != bitLockerValueI4 ||
			putOLEI4(parameters.dispatch, input.name, input.value.i4) != nil {
			parameters.close()
			return nil, errBitLockerEvidence
		}
	}
	return parameters, nil
}

func (o *oleBitLockerObject) close() {
	if o != nil && o.owned != nil {
		o.owned.close()
		o.owned = nil
	}
}

func exactOLEBitLockerValue(value *ole.VARIANT, err error) (bitLockerValue, error) {
	if err != nil || value == nil {
		return bitLockerValue{}, errBitLockerEvidence
	}
	if value.VT == ole.VT_I4 {
		if value.Val < math.MinInt32 || value.Val > math.MaxInt32 {
			return bitLockerValue{}, errBitLockerEvidence
		}
		return bitLockerI4(int32(value.Val)), nil // #nosec G115 -- range is proven immediately above.
	}
	if value.VT == ole.VT_BSTR {
		return bitLockerBSTR(value.ToString()), nil
	}
	return bitLockerValue{}, errBitLockerEvidence
}

func clearOLEVariant(value *ole.VARIANT) {
	if value != nil {
		_ = value.Clear()
	}
}
