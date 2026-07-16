//go:build linux && cgo

package systemproxy

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef void *(*am_g_proxy_resolver_get_default_fn)(void);
typedef char **(*am_g_proxy_resolver_lookup_fn)(void *, const char *, void *, void **);
typedef void (*am_g_strfreev_fn)(char **);
typedef void (*am_g_error_free_fn)(void *);

static void *am_gio_handle = NULL;
static am_g_proxy_resolver_get_default_fn am_get_default = NULL;
static am_g_proxy_resolver_lookup_fn am_lookup = NULL;
static am_g_strfreev_fn am_strfreev = NULL;
static am_g_error_free_fn am_error_free = NULL;

static int am_gio_load(void) {
    if (am_gio_handle != NULL) return 1;
    am_gio_handle = dlopen("libgio-2.0.so.0", RTLD_NOW | RTLD_LOCAL);
    if (am_gio_handle == NULL) return 0;
    am_get_default = (am_g_proxy_resolver_get_default_fn)dlsym(am_gio_handle, "g_proxy_resolver_get_default");
    am_lookup = (am_g_proxy_resolver_lookup_fn)dlsym(am_gio_handle, "g_proxy_resolver_lookup");
    am_strfreev = (am_g_strfreev_fn)dlsym(am_gio_handle, "g_strfreev");
    am_error_free = (am_g_error_free_fn)dlsym(am_gio_handle, "g_error_free");
    if (am_get_default == NULL || am_lookup == NULL || am_strfreev == NULL || am_error_free == NULL) {
        dlclose(am_gio_handle);
        am_gio_handle = NULL;
        am_get_default = NULL;
        am_lookup = NULL;
        am_strfreev = NULL;
        am_error_free = NULL;
        return 0;
    }
    return 1;
}

static int am_gio_proxy_for_url(const char *target, char *route, size_t routeSize) {
    if (target == NULL || route == NULL || routeSize < 2 || !am_gio_load()) return 0;
    memset(route, 0, routeSize);
    void *resolver = am_get_default();
    if (resolver == NULL) return 0;
    void *error = NULL;
    char **routes = am_lookup(resolver, target, NULL, &error);
    if (error != NULL) {
        am_error_free(error);
        if (routes != NULL) am_strfreev(routes);
        return 0;
    }
    if (routes == NULL || routes[0] == NULL) {
        if (routes != NULL) am_strfreev(routes);
        return 0;
    }
    size_t length = strlen(routes[0]);
    if (length == 0 || length >= routeSize) {
        am_strfreev(routes);
        return 0;
    }
    memcpy(route, routes[0], length);
    route[length] = '\0';
    am_strfreev(routes);
    return 1;
}
*/
import "C"

import (
	"context"
	"sync"
	"unsafe"
)

const maximumNativeProxyRouteBytes = 2048

type linuxGIOProxyRawLookup func(context.Context, string) ([]byte, error)

var (
	linuxGIOLoadOnce sync.Once
	linuxGIOReady    bool
)

func newNativeLookup() (nativeLookup, error) {
	linuxGIOLoadOnce.Do(func() { linuxGIOReady = C.am_gio_load() != 0 })
	if !linuxGIOReady {
		return nil, ErrUnavailable
	}
	return linuxGIOProxyLookup, nil
}

func linuxGIOProxyLookup(ctx context.Context, target string) (string, error) {
	value, err := linuxGIOProxyRaw(ctx, target)
	if err != nil {
		return "", err
	}
	defer clear(value)
	route, username, password, err := splitNativeProxyRouteBytes(value)
	clear(username)
	clear(password)
	if err != nil {
		return "", ErrUnavailable
	}
	return route, nil
}

func nativeCredentialsForProxy(
	ctx context.Context,
	target string,
	proxy string,
) ([]byte, []byte, error) {
	return nativeCredentialsForProxyUsing(ctx, target, proxy, linuxGIOProxyRaw)
}

func nativeCredentialsForProxyUsing(
	ctx context.Context,
	target string,
	proxy string,
	lookup linuxGIOProxyRawLookup,
) ([]byte, []byte, error) {
	if lookup == nil {
		return nil, nil, ErrUnavailable
	}
	value, err := lookup(ctx, target)
	if err != nil {
		return nil, nil, err
	}
	defer clear(value)
	route, username, password, err := splitNativeProxyRouteBytes(value)
	if err != nil || route != proxy || len(username) == 0 {
		clear(username)
		clear(password)
		return nil, nil, ErrUnavailable
	}
	return username, password, nil
}

func linuxGIOProxyRaw(ctx context.Context, target string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	targetValue := C.CString(target)
	defer C.free(unsafe.Pointer(targetValue))
	route := make([]byte, maximumNativeProxyRouteBytes)
	result := C.am_gio_proxy_for_url(targetValue, (*C.char)(unsafe.Pointer(&route[0])), C.size_t(len(route)))
	if err := ctx.Err(); err != nil {
		clear(route)
		return nil, err
	}
	if result == 0 {
		clear(route)
		return nil, ErrUnavailable
	}
	end := 0
	for end < len(route) && route[end] != 0 {
		end++
	}
	if end == 0 || end == len(route) {
		clear(route)
		return nil, ErrUnavailable
	}
	return route[:end], nil
}
