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
	if err := ctx.Err(); err != nil {
		return "", err
	}
	targetValue := C.CString(target)
	defer C.free(unsafe.Pointer(targetValue))
	route := make([]byte, maximumNativeProxyRouteBytes)
	//nolint:gosec // G103: GIO copies one bounded proxy URI into the supplied buffer; owner=security expiry=2027-07-15.
	result := C.am_gio_proxy_for_url(targetValue, (*C.char)(unsafe.Pointer(&route[0])), C.size_t(len(route)))
	if err := ctx.Err(); err != nil {
		clear(route)
		return "", err
	}
	if result == 0 {
		clear(route)
		return "", ErrUnavailable
	}
	end := 0
	for end < len(route) && route[end] != 0 {
		end++
	}
	value := string(route[:end])
	clear(route)
	if value == "" {
		return "", ErrUnavailable
	}
	return value, nil
}
