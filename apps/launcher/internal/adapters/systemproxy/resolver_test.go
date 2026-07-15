package systemproxy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPF001SystemProxyResolverDelegatesOnlyExactHTTPSDestinations(t *testing.T) {
	t.Parallel()
	lookup := &nativeLookupStub{route: "direct://"}
	resolver, err := newResolver(lookup.lookup)
	if err != nil {
		t.Fatal(err)
	}
	route, err := resolver.ProxyForURL(t.Context(), "https://downloads.example/artifact.bin")
	if err != nil || route != "direct://" || lookup.target != "https://downloads.example/artifact.bin" {
		t.Fatalf("ProxyForURL()=(%q,%v) target=%q", route, err, lookup.target)
	}

	for _, target := range []string{
		"", "http://downloads.example/artifact.bin", "https://user@downloads.example/artifact.bin",
		"https://downloads.example/artifact.bin?query", "https://downloads.example/artifact.bin#fragment",
		"https://downloads.example/artifact.bin\n",
	} {
		if _, err := resolver.ProxyForURL(t.Context(), target); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("target %q error=%v", target, err)
		}
	}
}

func TestPF001SystemProxyResolverFailsClosedAndDoesNotLeakNativeDiagnostics(t *testing.T) {
	t.Parallel()
	if _, err := newResolver(nil); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil lookup error=%v", err)
	}
	lookup := &nativeLookupStub{err: errors.New("secret PAC URL and credentials")}
	resolver, err := newResolver(lookup.lookup)
	if err != nil {
		t.Fatal(err)
	}
	_, err = resolver.ProxyForURL(t.Context(), "https://downloads.example/artifact.bin")
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("native error=%v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	lookup.err = nil
	_, err = resolver.ProxyForURL(cancelled, "https://downloads.example/artifact.bin")
	if !errors.Is(err, context.Canceled) || lookup.calls != 1 {
		t.Fatalf("cancelled error=%v calls=%d", err, lookup.calls)
	}
}

func TestPF001SystemProxyStripsNativeCredentialsUntilExactChallenge(t *testing.T) {
	t.Parallel()
	raw := []byte("http://owner:sec%72et@proxy.example:8080")
	route, username, password, err := splitNativeProxyRouteBytes(raw)
	if err != nil || route != "http://proxy.example:8080" || string(username) != "owner" || string(password) != "secret" {
		t.Fatalf("splitNativeProxyRouteBytes()=(%q,%q,%q,%v)", route, username, password, err)
	}
	clear(raw)
	if string(username) != "owner" || string(password) != "secret" {
		t.Fatal("credential bytes alias the native proxy URI buffer")
	}
	clear(username)
	clear(password)

	credentialCalls := 0
	resolver, err := newResolverWithCredentials(
		func(context.Context, string) (string, error) { return route, nil },
		func(_ context.Context, target string, proxy string) ([]byte, []byte, error) {
			credentialCalls++
			if target != "https://downloads.example/artifact.bin" || proxy != route {
				return nil, nil, ErrUnavailable
			}
			return []byte("owner"), []byte("secret"), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := resolver.credentialsForProxy(
		t.Context(), "https://downloads.example/artifact.bin", route, true,
	)
	if err != nil || credential == nil || credentialCalls != 1 {
		t.Fatalf("credentialsForProxy()=(%T,%v) calls=%d", credential, err, credentialCalls)
	}
	credential.Destroy()
	if credential, err := resolver.credentialsForProxy(
		t.Context(), "https://downloads.example/artifact.bin", route, false,
	); credential != nil || !errors.Is(err, ErrUnavailable) || credentialCalls != 1 {
		t.Fatalf("unchallenged credential=(%T,%v) calls=%d", credential, err, credentialCalls)
	}

	for _, value := range []string{
		"http://owner:secret@proxy.example/path", "ftp://owner:secret@proxy.example",
		"http://owner%0a:secret@proxy.example", "http://owner%zz:secret@proxy.example",
		"http://owner:secret@other@proxy.example", "direct://owner:secret@",
	} {
		if route, username, password, err := splitNativeProxyRoute(value); err == nil || route != "" ||
			username != nil || password != nil {
			t.Fatalf("unsafe native route %q accepted as %q/%q/%q", value, route, username, password)
		}
	}
}

func TestPF001WindowsCredentialUTF16ConversionIsMutableAndFailsClosed(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		value []uint16
		want  string
	}{
		{name: "ascii", value: []uint16{'o', 'w', 'n', 'e', 'r', 0}, want: "owner"},
		{name: "empty", value: []uint16{0}, want: ""},
		{name: "surrogate pair", value: []uint16{0xD83D, 0xDD10, 0}, want: "🔐"},
		{name: "bounded at null", value: []uint16{'a', 0, 'b'}, want: "a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := utf16CredentialBytes(test.value)
			if !ok || string(got) != test.want {
				t.Fatalf("utf16CredentialBytes()=(%q,%t), want %q", got, ok, test.want)
			}
			clear(got)
		})
	}
	for _, value := range [][]uint16{
		nil,
		{'n', 'o', '-', 'n', 'u', 'l', 'l'},
		{0xD83D, 0},
		{0xDD10, 0},
	} {
		if got, ok := utf16CredentialBytes(value); ok || got != nil {
			clear(got)
			t.Fatalf("invalid UTF-16 accepted: %#v", value)
		}
	}
}

func TestPF001WindowsProxyListSelectsHTTPSWithoutAcceptingAmbiguity(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		value string
		want  string
	}{
		{value: "proxy.example:8080", want: "http://proxy.example:8080"},
		{value: "http=plain.example:8080;https=secure.example:8443", want: "http://secure.example:8443"},
		{value: "https=secure.example:8443;http=plain.example:8080", want: "http://secure.example:8443"},
		{value: "PROXY proxy.example:8080; DIRECT", want: "http://proxy.example:8080"},
		{value: "DIRECT", want: "direct://"},
	} {
		got, err := parseWindowsProxyList(test.value)
		if err != nil || got != test.want {
			t.Fatalf("parseWindowsProxyList(%q)=(%q,%v), want %q", test.value, got, err, test.want)
		}
	}
	for _, value := range []string{"", "http=one:80;https=two:443;https=three:443", "https=user@proxy:443", "https=proxy/path"} {
		if _, err := parseWindowsProxyList(value); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("parseWindowsProxyList(%q) error=%v", value, err)
		}
	}
}

func TestPF001WindowsManualBypassUsesOnlyDocumentedHostPatterns(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		target string
		list   string
		want   bool
	}{
		{target: "https://localhost/artifact", list: "<local>", want: true},
		{target: "https://repo.corp.example/artifact", list: "*.corp.example;localhost", want: true},
		{target: "https://repo.example/artifact", list: "*.corp.example;localhost", want: false},
		{target: "https://127.0.0.1/artifact", list: "<local>", want: false},
		{target: "https://repo.example/artifact", list: "*", want: true},
	} {
		got, err := windowsProxyBypasses(test.target, test.list)
		if err != nil || got != test.want {
			t.Fatalf("windowsProxyBypasses(%q,%q)=(%t,%v), want %t", test.target, test.list, got, err, test.want)
		}
	}
	for _, list := range []string{"bad[", "pattern/path", "user@host"} {
		if _, err := windowsProxyBypasses("https://repo.example/artifact", list); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("bypass %q error=%v", list, err)
		}
	}
}

type nativeLookupStub struct {
	route  string
	err    error
	target string
	calls  int
}

func (s *nativeLookupStub) lookup(_ context.Context, target string) (string, error) {
	s.calls++
	s.target = target
	return s.route, s.err
}
