//go:build linux && cgo

package systemproxy

import (
	"errors"
	"net/url"
	"testing"
)

func TestPF001LinuxNativeGIOSystemProxyIntegration(t *testing.T) {
	resolver, err := New()
	if errors.Is(err, ErrUnavailable) {
		t.Skip("native GIO proxy resolver is not installed on this host")
	}
	if err != nil {
		t.Fatal(err)
	}
	route, err := resolver.ProxyForURL(t.Context(), "https://example.com/agentmemory-proxy-probe")
	if err != nil {
		t.Fatal(err)
	}
	if route == "direct://" {
		return
	}
	parsed, err := url.Parse(route)
	if err != nil || parsed.Host == "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5") {
		t.Fatalf("native GIO proxy route=%q error=%v", route, err)
	}
}
