//go:build linux && cgo

package systemproxy

import (
	"context"
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

func TestPF001LinuxNativeGIOCredentialsRequireExactChallengedRoute(t *testing.T) {
	t.Parallel()
	const target = "https://downloads.example/artifact.bin"
	const proxy = "http://proxy.example:8080"
	lookup := func(_ context.Context, observed string) ([]byte, error) {
		if observed != target {
			t.Fatalf("native target=%q", observed)
		}
		return []byte("http://owner:sec%72et@proxy.example:8080"), nil
	}
	username, password, err := nativeCredentialsForProxyUsing(t.Context(), target, proxy, lookup)
	if err != nil || string(username) != "owner" || string(password) != "secret" {
		t.Fatalf("native credentials=(%q,%q,%v)", username, password, err)
	}
	clear(username)
	clear(password)

	for name, test := range map[string]struct {
		proxy  string
		lookup linuxGIOProxyRawLookup
	}{
		"nil lookup": {proxy: proxy},
		"native error": {proxy: proxy, lookup: func(context.Context, string) ([]byte, error) {
			return nil, context.DeadlineExceeded
		}},
		"malformed route": {proxy: proxy, lookup: func(context.Context, string) ([]byte, error) {
			return []byte("malformed"), nil
		}},
		"route substitution": {proxy: "http://other.example:8080", lookup: lookup},
		"missing username": {proxy: proxy, lookup: func(context.Context, string) ([]byte, error) {
			return []byte(proxy), nil
		}},
	} {
		username, password, err := nativeCredentialsForProxyUsing(t.Context(), target, test.proxy, test.lookup)
		clear(username)
		clear(password)
		if err == nil || username != nil || password != nil {
			t.Fatalf("%s credentials=(%q,%q,%v)", name, username, password, err)
		}
	}
}
