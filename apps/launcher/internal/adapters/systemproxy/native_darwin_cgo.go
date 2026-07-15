//go:build darwin && cgo

package systemproxy

/*
#cgo LDFLAGS: -framework CoreFoundation -framework CFNetwork -framework SystemConfiguration
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetwork.h>
#include <SystemConfiguration/SystemConfiguration.h>
#include <stdlib.h>
#include <string.h>

enum {
    AM_PROXY_ERROR = -1,
    AM_PROXY_DIRECT = 0,
    AM_PROXY_HTTP = 1,
    AM_PROXY_SOCKS5 = 2
};

typedef struct {
    Boolean done;
    CFArrayRef proxies;
    CFErrorRef error;
} am_pac_state;

static void am_pac_callback(void *client, CFArrayRef proxies, CFErrorRef error) {
    am_pac_state *state = (am_pac_state *)client;
    if (proxies != NULL) state->proxies = (CFArrayRef)CFRetain(proxies);
    if (error != NULL) state->error = (CFErrorRef)CFRetain(error);
    state->done = true;
}

static CFArrayRef am_execute_pac(CFDictionaryRef descriptor, CFURLRef target) {
    CFStringRef type = (CFStringRef)CFDictionaryGetValue(descriptor, kCFProxyTypeKey);
    if (type == NULL) return NULL;
    if (CFEqual(type, kCFProxyTypeAutoConfigurationJavaScript)) {
        CFStringRef script = (CFStringRef)CFDictionaryGetValue(descriptor, kCFProxyAutoConfigurationJavaScriptKey);
        if (script == NULL || CFGetTypeID(script) != CFStringGetTypeID()) return NULL;
        CFErrorRef error = NULL;
        CFArrayRef result = CFNetworkCopyProxiesForAutoConfigurationScript(script, target, &error);
        if (error != NULL) CFRelease(error);
        return result;
    }
    if (!CFEqual(type, kCFProxyTypeAutoConfigurationURL)) return NULL;
    CFURLRef pacURL = (CFURLRef)CFDictionaryGetValue(descriptor, kCFProxyAutoConfigurationURLKey);
    if (pacURL == NULL || CFGetTypeID(pacURL) != CFURLGetTypeID()) return NULL;

    am_pac_state state = {0};
    CFStreamClientContext context = {0, &state, NULL, NULL, NULL};
    CFRunLoopSourceRef source = CFNetworkExecuteProxyAutoConfigurationURL(
        pacURL, target, am_pac_callback, &context);
    if (source == NULL) return NULL;
    CFRunLoopRef loop = CFRunLoopGetCurrent();
    CFRunLoopAddSource(loop, source, kCFRunLoopDefaultMode);
    CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 15.0;
    while (!state.done && CFAbsoluteTimeGetCurrent() < deadline) {
        CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.10, true);
    }
    if (!state.done) CFRunLoopSourceInvalidate(source);
    CFRunLoopRemoveSource(loop, source, kCFRunLoopDefaultMode);
    CFRelease(source);
    if (state.error != NULL) CFRelease(state.error);
    if (!state.done || state.proxies == NULL) {
        if (state.proxies != NULL) CFRelease(state.proxies);
        return NULL;
    }
    return state.proxies;
}

static int am_copy_proxy_host(CFDictionaryRef proxy, char *host, size_t hostSize, int *port) {
    CFStringRef hostname = (CFStringRef)CFDictionaryGetValue(proxy, kCFProxyHostNameKey);
    CFNumberRef portNumber = (CFNumberRef)CFDictionaryGetValue(proxy, kCFProxyPortNumberKey);
    if (hostname == NULL || portNumber == NULL ||
        CFGetTypeID(hostname) != CFStringGetTypeID() ||
        CFGetTypeID(portNumber) != CFNumberGetTypeID() ||
        !CFStringGetCString(hostname, host, hostSize, kCFStringEncodingUTF8) ||
        !CFNumberGetValue(portNumber, kCFNumberIntType, port) || *port <= 0 || *port > 65535) {
        return AM_PROXY_ERROR;
    }
    if (CFDictionaryContainsKey(proxy, kCFProxyUsernameKey) ||
        CFDictionaryContainsKey(proxy, kCFProxyPasswordKey)) {
        memset(host, 0, hostSize);
        return AM_PROXY_ERROR;
    }
    return AM_PROXY_HTTP;
}

static int am_select_proxy(CFArrayRef proxies, char *host, size_t hostSize, int *port) {
    if (proxies == NULL || CFGetTypeID(proxies) != CFArrayGetTypeID()) return AM_PROXY_ERROR;
    CFIndex count = CFArrayGetCount(proxies);
    for (CFIndex index = 0; index < count; index++) {
        CFTypeRef raw = CFArrayGetValueAtIndex(proxies, index);
        if (raw == NULL || CFGetTypeID(raw) != CFDictionaryGetTypeID()) continue;
        CFDictionaryRef proxy = (CFDictionaryRef)raw;
        CFStringRef type = (CFStringRef)CFDictionaryGetValue(proxy, kCFProxyTypeKey);
        if (type == NULL || CFGetTypeID(type) != CFStringGetTypeID()) continue;
        if (CFEqual(type, kCFProxyTypeNone)) return AM_PROXY_DIRECT;
        if (CFEqual(type, kCFProxyTypeHTTP) || CFEqual(type, kCFProxyTypeHTTPS)) {
            return am_copy_proxy_host(proxy, host, hostSize, port);
        }
        if (CFEqual(type, kCFProxyTypeSOCKS)) {
            int result = am_copy_proxy_host(proxy, host, hostSize, port);
            return result == AM_PROXY_HTTP ? AM_PROXY_SOCKS5 : result;
        }
    }
    return AM_PROXY_ERROR;
}

static int am_system_proxy_for_url(const char *targetValue, char *host, size_t hostSize, int *port) {
    if (targetValue == NULL || host == NULL || hostSize < 2 || port == NULL) return AM_PROXY_ERROR;
    memset(host, 0, hostSize);
    *port = 0;
    CFStringRef targetString = CFStringCreateWithCString(NULL, targetValue, kCFStringEncodingUTF8);
    if (targetString == NULL) return AM_PROXY_ERROR;
    CFURLRef target = CFURLCreateWithString(NULL, targetString, NULL);
    CFRelease(targetString);
    if (target == NULL) return AM_PROXY_ERROR;
    CFDictionaryRef settings = SCDynamicStoreCopyProxies(NULL);
    if (settings == NULL) {
        CFRelease(target);
        return AM_PROXY_ERROR;
    }
    CFArrayRef proxies = CFNetworkCopyProxiesForURL(target, settings);
    CFRelease(settings);
    if (proxies == NULL) {
        CFRelease(target);
        return AM_PROXY_ERROR;
    }
    CFArrayRef resolved = proxies;
    if (CFArrayGetCount(proxies) > 0) {
        CFTypeRef first = CFArrayGetValueAtIndex(proxies, 0);
        if (first != NULL && CFGetTypeID(first) == CFDictionaryGetTypeID()) {
            CFStringRef type = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)first, kCFProxyTypeKey);
            if (type != NULL && (CFEqual(type, kCFProxyTypeAutoConfigurationURL) ||
                CFEqual(type, kCFProxyTypeAutoConfigurationJavaScript))) {
                resolved = am_execute_pac((CFDictionaryRef)first, target);
            }
        }
    }
    int result = am_select_proxy(resolved, host, hostSize, port);
    if (resolved != proxies && resolved != NULL) CFRelease(resolved);
    CFRelease(proxies);
    CFRelease(target);
    return result;
}
*/
import "C"

import (
	"context"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unsafe"
)

const maximumNativeProxyHostBytes = 1024

const (
	darwinProxyDirect = int(C.AM_PROXY_DIRECT)
	darwinProxyHTTP   = int(C.AM_PROXY_HTTP)
	darwinProxySOCKS5 = int(C.AM_PROXY_SOCKS5)
)

func newNativeLookup() (nativeLookup, error) {
	return darwinSystemProxyLookup, nil
}

func darwinSystemProxyLookup(ctx context.Context, target string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	targetValue := C.CString(target)
	defer C.free(unsafe.Pointer(targetValue))
	host := make([]byte, maximumNativeProxyHostBytes)
	var port C.int
	kind := C.am_system_proxy_for_url(targetValue, (*C.char)(unsafe.Pointer(&host[0])), C.size_t(len(host)), &port)
	if err := ctx.Err(); err != nil {
		return "", err
	}
	end := 0
	for end < len(host) && host[end] != 0 {
		end++
	}
	hostname := string(host[:end])
	clear(host)
	return darwinProxyRoute(int(kind), hostname, int(port))
}

func darwinProxyRoute(kind int, hostname string, port int) (string, error) {
	if kind == darwinProxyDirect {
		return "direct://", nil
	}
	if kind != darwinProxyHTTP && kind != darwinProxySOCKS5 {
		return "", ErrUnavailable
	}
	hostname = strings.ToLower(hostname)
	if hostname == "" || strings.ContainsAny(hostname, "\x00\r\n\t/@") || port <= 0 || port > 65535 {
		return "", ErrUnavailable
	}
	scheme := "http"
	if kind == darwinProxySOCKS5 {
		scheme = "socks5"
	}
	route := (&url.URL{Scheme: scheme, Host: net.JoinHostPort(hostname, strconv.Itoa(port))}).String()
	return route, nil
}
