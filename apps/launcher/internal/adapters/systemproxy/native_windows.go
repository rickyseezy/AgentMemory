//go:build windows

package systemproxy

import (
	"context"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	winHTTPAccessTypeDefaultProxy = uint32(0)
	winHTTPAccessTypeNoProxy      = uint32(1)
	winHTTPAccessTypeNamedProxy   = uint32(3)
	winHTTPAutoProxyAutoDetect    = uint32(1)
	winHTTPAutoProxyConfigURL     = uint32(2)
	winHTTPAutoDetectDHCP         = uint32(1)
	winHTTPAutoDetectDNSA         = uint32(2)
)

var (
	winhttpDLL                       = windows.NewLazySystemDLL("winhttp.dll")
	winHTTPGetCurrentUserProxyConfig = winhttpDLL.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	winHTTPOpen                      = winhttpDLL.NewProc("WinHttpOpen")
	winHTTPGetProxyForURL            = winhttpDLL.NewProc("WinHttpGetProxyForUrl")
	winHTTPCloseHandle               = winhttpDLL.NewProc("WinHttpCloseHandle")
	systemProxyKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	systemProxyGlobalFree            = systemProxyKernel32.NewProc("GlobalFree")
)

type winHTTPCurrentUserProxyConfig struct {
	AutoDetect    int32
	AutoConfigURL *uint16
	Proxy         *uint16
	ProxyBypass   *uint16
}

type winHTTPAutoProxyOptions struct {
	Flags                 uint32
	AutoDetectFlags       uint32
	AutoConfigURL         *uint16
	Reserved              uintptr
	Reserved2             uint32
	AutoLogonIfChallenged int32
}

type winHTTPProxyInfo struct {
	AccessType  uint32
	Proxy       *uint16
	ProxyBypass *uint16
}

func newNativeLookup() (nativeLookup, error) { return windowsSystemProxyLookup, nil }

func windowsSystemProxyLookup(ctx context.Context, target string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	var configuration winHTTPCurrentUserProxyConfig
	//nolint:gosec // G103: WinHTTP writes the reviewed fixed-layout structure above; owner=security expiry=2027-07-15.
	result, _, callError := winHTTPGetCurrentUserProxyConfig.Call(uintptr(unsafe.Pointer(&configuration)))
	if result == 0 {
		if errors.Is(callError, windows.ERROR_FILE_NOT_FOUND) {
			return "direct://", nil
		}
		return "", ErrUnavailable
	}
	defer freeWinHTTPString(configuration.AutoConfigURL)
	defer freeWinHTTPString(configuration.Proxy)
	defer freeWinHTTPString(configuration.ProxyBypass)

	if configuration.AutoDetect != 0 || configuration.AutoConfigURL != nil {
		if route, err := windowsAutoProxyForURL(ctx, target, configuration); err == nil {
			return route, nil
		}
	}
	if configuration.Proxy == nil {
		return "direct://", nil
	}
	if configuration.ProxyBypass != nil {
		bypassed, err := windowsProxyBypasses(target, windows.UTF16PtrToString(configuration.ProxyBypass))
		if err != nil {
			return "", ErrUnavailable
		}
		if bypassed {
			return "direct://", nil
		}
	}
	return parseWindowsProxyList(windows.UTF16PtrToString(configuration.Proxy))
}

func windowsAutoProxyForURL(
	ctx context.Context,
	target string,
	configuration winHTTPCurrentUserProxyConfig,
) (string, error) {
	agent, err := windows.UTF16PtrFromString("AgentMemory-Launcher/1")
	if err != nil {
		return "", ErrUnavailable
	}
	result, _, _ := winHTTPOpen.Call(
		uintptr(unsafe.Pointer(agent)), uintptr(winHTTPAccessTypeNoProxy), 0, 0, 0,
	)
	runtime.KeepAlive(agent)
	if result == 0 {
		return "", ErrUnavailable
	}
	session := windows.Handle(result)
	defer func() { _, _, _ = winHTTPCloseHandle.Call(uintptr(session)) }()

	options := winHTTPAutoProxyOptions{AutoLogonIfChallenged: 1}
	if configuration.AutoConfigURL != nil {
		options.Flags |= winHTTPAutoProxyConfigURL
		options.AutoConfigURL = configuration.AutoConfigURL
	}
	if configuration.AutoDetect != 0 {
		options.Flags |= winHTTPAutoProxyAutoDetect
		options.AutoDetectFlags = winHTTPAutoDetectDHCP | winHTTPAutoDetectDNSA
	}
	targetValue, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return "", ErrUnavailable
	}
	var information winHTTPProxyInfo
	//nolint:gosec // G103: WinHTTP consumes the bounded URL/options and writes the reviewed proxy-info structure; owner=security expiry=2027-07-15.
	callResult, _, _ := winHTTPGetProxyForURL.Call(
		uintptr(session), uintptr(unsafe.Pointer(targetValue)), uintptr(unsafe.Pointer(&options)),
		uintptr(unsafe.Pointer(&information)),
	)
	runtime.KeepAlive(targetValue)
	runtime.KeepAlive(configuration.AutoConfigURL)
	if callResult == 0 {
		return "", ErrUnavailable
	}
	defer freeWinHTTPString(information.Proxy)
	defer freeWinHTTPString(information.ProxyBypass)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	switch information.AccessType {
	case winHTTPAccessTypeNoProxy:
		return "direct://", nil
	case winHTTPAccessTypeNamedProxy:
		if information.Proxy == nil {
			return "", ErrUnavailable
		}
		return parseWindowsProxyList(windows.UTF16PtrToString(information.Proxy))
	case winHTTPAccessTypeDefaultProxy:
		return "", ErrUnavailable
	default:
		return "", ErrUnavailable
	}
}

func freeWinHTTPString(value *uint16) {
	if value == nil {
		return
	}
	//nolint:gosec // G103: GlobalFree receives exactly the buffer allocated by WinHTTP; owner=security expiry=2027-07-15.
	_, _, _ = systemProxyGlobalFree.Call(uintptr(unsafe.Pointer(value)))
}
