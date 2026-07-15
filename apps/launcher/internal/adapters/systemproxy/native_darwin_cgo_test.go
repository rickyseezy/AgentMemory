//go:build darwin && cgo

package systemproxy

import (
	"errors"
	"net/url"
	"testing"
	"time"
)

func TestPF001DarwinNativeSystemProxyIntegration(t *testing.T) {
	resolver, err := New()
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	started := time.Now()
	route, err := resolver.ProxyForURL(ctx, "https://example.com/agentmemory-proxy-probe")
	if err != nil {
		t.Fatalf("native proxy lookup after %s: %v", time.Since(started), err)
	}
	username, password, credentialError := nativeCredentialsForProxy(
		ctx, "https://example.com/agentmemory-proxy-probe", route,
	)
	if credentialError == nil {
		if route == "direct://" || len(username) == 0 {
			t.Fatalf("native credential accepted for route %q", route)
		}
		clear(username)
		clear(password)
	} else if !errors.Is(credentialError, ErrUnavailable) {
		t.Fatalf("native credential lookup error=%v", credentialError)
	}
	if route == "direct://" {
		return
	}
	parsed, err := url.Parse(route)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "socks5") || parsed.User != nil {
		t.Fatalf("native proxy route=%q error=%v", route, err)
	}
}

func TestPF001DarwinNativeProxyResultProjectionIsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		kind int
		host string
		port int
		want string
	}{
		{kind: darwinProxyDirect, want: "direct://"},
		{kind: darwinProxyHTTP, host: "PROXY.EXAMPLE", port: 8080, want: "http://proxy.example:8080"},
		{kind: darwinProxySOCKS5, host: "2001:db8::1", port: 1080, want: "socks5://[2001:db8::1]:1080"},
	} {
		got, err := darwinProxyRoute(test.kind, test.host, test.port)
		if err != nil || got != test.want {
			t.Fatalf("darwinProxyRoute(%d,%q,%d)=(%q,%v)", test.kind, test.host, test.port, got, err)
		}
	}
	for _, test := range []struct {
		kind int
		host string
		port int
	}{
		{kind: 99, host: "proxy.example", port: 80},
		{kind: darwinProxyHTTP, port: 80},
		{kind: darwinProxyHTTP, host: "user@proxy.example", port: 80},
		{kind: darwinProxyHTTP, host: "proxy.example", port: 0},
		{kind: darwinProxyHTTP, host: "proxy.example", port: 65536},
	} {
		if _, err := darwinProxyRoute(test.kind, test.host, test.port); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("darwinProxyRoute(%+v) error=%v", test, err)
		}
	}
}

func TestPF001DarwinNativeCredentialBuffersCopyOnlyBoundedCString(t *testing.T) {
	t.Parallel()
	buffer := []byte{'o', 'w', 'n', 'e', 'r', 0, 's', 'e', 'c', 'r', 'e', 't'}
	if got := nativeCString(buffer); got != "owner" {
		t.Fatalf("nativeCString()=%q", got)
	}
	credential := nativeCStringBytes(buffer)
	if string(credential) != "owner" {
		t.Fatalf("nativeCStringBytes()=%q", credential)
	}
	buffer[0] = 'x'
	if string(credential) != "owner" {
		t.Fatal("credential bytes alias the native buffer")
	}
	clear(credential)
}
