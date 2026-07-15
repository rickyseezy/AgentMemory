//go:build windows

package systemproxy

import (
	"bytes"
	"context"
	"errors"
	"net/url"
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
	credUIWinGeneric              = uint32(1)
	maximumWindowsAuthBufferBytes = uint32(64 * 1024)
	maximumWindowsUsernameUTF16   = uint32(514)
	maximumWindowsDomainUTF16     = uint32(338)
	maximumWindowsPasswordUTF16   = uint32(257)
)

var (
	winhttpDLL                       = windows.NewLazySystemDLL("winhttp.dll")
	winHTTPGetCurrentUserProxyConfig = winhttpDLL.NewProc("WinHttpGetIEProxyConfigForCurrentUser")
	winHTTPOpen                      = winhttpDLL.NewProc("WinHttpOpen")
	winHTTPGetProxyForURL            = winhttpDLL.NewProc("WinHttpGetProxyForUrl")
	winHTTPCloseHandle               = winhttpDLL.NewProc("WinHttpCloseHandle")
	systemProxyKernel32              = windows.NewLazySystemDLL("kernel32.dll")
	systemProxyGlobalFree            = systemProxyKernel32.NewProc("GlobalFree")
	systemProxyCredUI                = windows.NewLazySystemDLL("credui.dll")
	credUIPromptWindowsCredentials   = systemProxyCredUI.NewProc("CredUIPromptForWindowsCredentialsW")
	credUIUnpackAuthenticationBuffer = systemProxyCredUI.NewProc("CredUnPackAuthenticationBufferW")
	systemProxyOLE32                 = windows.NewLazySystemDLL("ole32.dll")
	systemProxyCoTaskMemFree         = systemProxyOLE32.NewProc("CoTaskMemFree")
)

type credUIInfo struct {
	Size    uint32
	Parent  uintptr
	Message *uint16
	Caption *uint16
	Banner  uintptr
}

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

func nativeCredentialsForProxy(ctx context.Context, target string, proxy string) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	observed, err := windowsSystemProxyLookup(ctx, target)
	if err != nil || observed != proxy {
		return nil, nil, ErrUnavailable
	}
	parsed, err := url.Parse(proxy)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" ||
		parsed.User != nil {
		return nil, nil, ErrUnavailable
	}
	return promptWindowsProxyCredentials(ctx, parsed.Hostname())
}

func promptWindowsProxyCredentials(ctx context.Context, proxyHostname string) ([]byte, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	message, err := windows.UTF16PtrFromString(
		"Enter credentials for system proxy " + proxyHostname + " for AgentMemory.",
	)
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	caption, err := windows.UTF16PtrFromString("AgentMemory proxy authentication")
	if err != nil {
		return nil, nil, ErrUnavailable
	}
	information := credUIInfo{
		Size: uint32(unsafe.Sizeof(credUIInfo{})), Message: message, Caption: caption,
	}
	var authenticationPackage uint32
	var authenticationBuffer unsafe.Pointer
	var authenticationBufferSize uint32
	result, _, _ := credUIPromptWindowsCredentials.Call(
		uintptr(unsafe.Pointer(&information)), 0, uintptr(unsafe.Pointer(&authenticationPackage)),
		0, 0, uintptr(unsafe.Pointer(&authenticationBuffer)), uintptr(unsafe.Pointer(&authenticationBufferSize)),
		0, uintptr(credUIWinGeneric),
	)
	runtime.KeepAlive(message)
	runtime.KeepAlive(caption)
	if authenticationBuffer != nil {
		defer zeroAndFreeWindowsAuthBuffer(authenticationBuffer, authenticationBufferSize)
	}
	if uint32(result) != uint32(windows.ERROR_SUCCESS) || authenticationBuffer == nil ||
		authenticationBufferSize == 0 || authenticationBufferSize > maximumWindowsAuthBufferBytes {
		return nil, nil, ErrUnavailable
	}
	usernameBuffer := make([]uint16, maximumWindowsUsernameUTF16)
	domainBuffer := make([]uint16, maximumWindowsDomainUTF16)
	passwordBuffer := make([]uint16, maximumWindowsPasswordUTF16)
	defer clear(usernameBuffer)
	defer clear(domainBuffer)
	defer clear(passwordBuffer)
	usernameSize := uint32(len(usernameBuffer))
	domainSize := uint32(len(domainBuffer))
	passwordSize := uint32(len(passwordBuffer))
	unpacked, _, _ := credUIUnpackAuthenticationBuffer.Call(
		0, uintptr(authenticationBuffer), uintptr(authenticationBufferSize),
		uintptr(unsafe.Pointer(&usernameBuffer[0])), uintptr(unsafe.Pointer(&usernameSize)),
		uintptr(unsafe.Pointer(&domainBuffer[0])), uintptr(unsafe.Pointer(&domainSize)),
		uintptr(unsafe.Pointer(&passwordBuffer[0])), uintptr(unsafe.Pointer(&passwordSize)),
	)
	if unpacked == 0 {
		return nil, nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	username, usernameValid := utf16CredentialBytes(usernameBuffer)
	domain, domainValid := utf16CredentialBytes(domainBuffer)
	password, passwordValid := utf16CredentialBytes(passwordBuffer)
	defer clear(domain)
	if !usernameValid || !domainValid || !passwordValid {
		clear(username)
		clear(password)
		return nil, nil, ErrUnavailable
	}
	if len(domain) != 0 && bytes.IndexByte(username, '\\') < 0 && bytes.IndexByte(username, '@') < 0 {
		qualified := make([]byte, 0, len(domain)+1+len(username))
		qualified = append(qualified, domain...)
		qualified = append(qualified, '\\')
		qualified = append(qualified, username...)
		clear(username)
		username = qualified
	}
	if len(username) == 0 {
		clear(username)
		clear(password)
		return nil, nil, ErrUnavailable
	}
	return username, password, nil
}

func zeroAndFreeWindowsAuthBuffer(value unsafe.Pointer, size uint32) {
	if value == nil {
		return
	}
	for offset := uint32(0); offset < size; {
		length := size - offset
		if length > maximumWindowsAuthBufferBytes {
			length = maximumWindowsAuthBufferBytes
		}
		//nolint:gosec // G103: each slice stays inside the exact CredUI-owned buffer returned with this size.
		clear(unsafe.Slice((*byte)(unsafe.Add(value, uintptr(offset))), int(length)))
		offset += length
	}
	runtime.KeepAlive(value)
	_, _, _ = systemProxyCoTaskMemFree.Call(uintptr(value))
}

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
