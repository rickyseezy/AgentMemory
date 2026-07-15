// Package systemproxy resolves acquisition routes exclusively through the
// invoking user's native operating-system proxy/PAC authority.
package systemproxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/adapters/artifacthttp"
)

// ErrUnavailable is deliberately diagnostic-free: native PAC URLs, proxy
// hosts, realms, and credentials must not escape into journals or logs.
var ErrUnavailable = errors.New("native system proxy resolution unavailable")

type nativeLookup func(context.Context, string) (string, error)
type nativeCredentialLookup func(context.Context, string, string) ([]byte, []byte, error)

// Resolver owns one native per-URL lookup capability.
type Resolver struct {
	lookup      nativeLookup
	credentials nativeCredentialLookup
}

// New constructs the platform-native resolver. Unsupported native facilities
// fail closed instead of consulting HTTP_PROXY, HTTPS_PROXY, or NO_PROXY.
func New() (*Resolver, error) {
	lookup, err := newNativeLookup()
	if err != nil {
		return nil, ErrUnavailable
	}
	return newResolverWithCredentials(lookup, nativeCredentialsForProxy)
}

func newResolver(lookup nativeLookup) (*Resolver, error) {
	return newResolverWithCredentials(
		lookup,
		func(context.Context, string, string) ([]byte, []byte, error) {
			return nil, nil, ErrUnavailable
		},
	)
}

func newResolverWithCredentials(
	lookup nativeLookup,
	credentials nativeCredentialLookup,
) (*Resolver, error) {
	if lookup == nil || credentials == nil {
		return nil, ErrUnavailable
	}
	return &Resolver{lookup: lookup, credentials: credentials}, nil
}

// ProxyForURL returns direct:// or one exact native proxy URI. It accepts only
// the same strict HTTPS destination shape admitted by signed acquisition.
func (r *Resolver) ProxyForURL(ctx context.Context, target string) (string, error) {
	if r == nil || r.lookup == nil || ctx == nil || !strictTarget(target) {
		return "", ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	route, err := r.lookup(ctx, target)
	if err != nil || route == "" {
		if contextError := ctx.Err(); contextError != nil {
			return "", contextError
		}
		return "", ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return route, nil
}

// CredentialsForProxy implements the artifact transport's challenge-only
// credential port. It never returns raw native diagnostics.
func (r *Resolver) CredentialsForProxy(
	ctx context.Context,
	challenge artifacthttp.ProxyCredentialChallenge,
) (*artifacthttp.ProxyCredential, error) {
	return r.credentialsForProxy(
		ctx, challenge.TargetURL(), challenge.ProxyURL(), challenge.BasicAvailable(),
	)
}

func (r *Resolver) credentialsForProxy(
	ctx context.Context,
	target string,
	proxy string,
	basic bool,
) (*artifacthttp.ProxyCredential, error) {
	if r == nil || r.credentials == nil || ctx == nil || !basic || !strictTarget(target) {
		return nil, ErrUnavailable
	}
	credentialFree, username, password, err := splitNativeProxyRoute(proxy)
	if err != nil || credentialFree != proxy || len(username) != 0 || len(password) != 0 || proxy == "direct://" {
		clear(username)
		clear(password)
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	username, password, err = r.credentials(ctx, target, proxy)
	if err != nil {
		clear(username)
		clear(password)
		if contextError := ctx.Err(); contextError != nil {
			return nil, contextError
		}
		return nil, ErrUnavailable
	}
	defer clear(username)
	defer clear(password)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	credential, err := artifacthttp.NewProxyCredential(username, password)
	if err != nil {
		return nil, ErrUnavailable
	}
	return credential, nil
}

func splitNativeProxyRoute(value string) (string, []byte, []byte, error) {
	mutable := []byte(value)
	defer clear(mutable)
	return splitNativeProxyRouteBytes(mutable)
}

func splitNativeProxyRouteBytes(value []byte) (string, []byte, []byte, error) {
	if bytes.Equal(value, []byte("direct://")) {
		return "direct://", nil, nil, nil
	}
	if len(value) == 0 || len(value) > 2048 || bytes.ContainsAny(value, "\x00\r\n\t") {
		return "", nil, nil, ErrUnavailable
	}
	delimiter := bytes.Index(value, []byte("://"))
	if delimiter <= 0 {
		return "", nil, nil, ErrUnavailable
	}
	scheme := value[:delimiter]
	if !bytes.Equal(scheme, []byte("http")) && !bytes.Equal(scheme, []byte("https")) &&
		!bytes.Equal(scheme, []byte("socks5")) {
		return "", nil, nil, ErrUnavailable
	}
	authority := value[delimiter+3:]
	if len(authority) == 0 {
		return "", nil, nil, ErrUnavailable
	}
	var username, password []byte
	if at := bytes.IndexByte(authority, '@'); at >= 0 {
		if at == 0 || at != bytes.LastIndexByte(authority, '@') {
			return "", nil, nil, ErrUnavailable
		}
		userinfo := authority[:at]
		authority = authority[at+1:]
		usernameValue, passwordValue, hasPassword := bytes.Cut(userinfo, []byte{':'})
		var usernameValid, passwordValid bool
		username, usernameValid = decodeNativeProxyCredential(usernameValue)
		if hasPassword {
			password, passwordValid = decodeNativeProxyCredential(passwordValue)
		} else {
			password = []byte{}
			passwordValid = true
		}
		if !usernameValid || !passwordValid || len(username) == 0 || len(username) > 1024 || len(password) > 1024 ||
			!utf8.Valid(username) || !utf8.Valid(password) || bytes.ContainsAny(username, ":\x00\r\n") ||
			bytes.ContainsAny(password, "\x00\r\n") {
			clear(username)
			clear(password)
			return "", nil, nil, ErrUnavailable
		}
	}
	sanitized := make([]byte, 0, len(scheme)+3+len(authority))
	sanitized = append(sanitized, scheme...)
	sanitized = append(sanitized, ':', '/', '/')
	sanitized = append(sanitized, authority...)
	parsed, err := url.Parse(string(sanitized))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5") ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		clear(username)
		clear(password)
		return "", nil, nil, ErrUnavailable
	}
	hostname := strings.ToLower(parsed.Hostname())
	if port := parsed.Port(); port != "" {
		portNumber, parseError := strconv.ParseUint(port, 10, 16)
		if parseError != nil || portNumber == 0 {
			clear(username)
			clear(password)
			return "", nil, nil, ErrUnavailable
		}
		parsed.Host = net.JoinHostPort(hostname, port)
	} else {
		parsed.Host = hostname
		if strings.Contains(hostname, ":") {
			parsed.Host = "[" + hostname + "]"
		}
	}
	route := parsed.String()
	if route == "" || strings.ContainsAny(route, "\x00\r\n\t@") {
		clear(username)
		clear(password)
		return "", nil, nil, ErrUnavailable
	}
	return route, username, password, nil
}

func decodeNativeProxyCredential(value []byte) ([]byte, bool) {
	result := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '%' {
			result = append(result, value[index])
			continue
		}
		if index+2 >= len(value) {
			clear(result)
			return nil, false
		}
		high, highValid := hexadecimalNibble(value[index+1])
		low, lowValid := hexadecimalNibble(value[index+2])
		if !highValid || !lowValid {
			clear(result)
			return nil, false
		}
		result = append(result, high<<4|low)
		index += 2
	}
	return result, true
}

func hexadecimalNibble(value byte) (byte, bool) {
	switch {
	case value >= '0' && value <= '9':
		return value - '0', true
	case value >= 'a' && value <= 'f':
		return value - 'a' + 10, true
	case value >= 'A' && value <= 'F':
		return value - 'A' + 10, true
	default:
		return 0, false
	}
}

func strictTarget(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.Hostname() != "" &&
		parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value &&
		!strings.ContainsAny(value, "\x00\r\n\t")
}

// parseWindowsProxyList reduces the documented WinHTTP/WinINet proxy-list
// syntax to the route for an HTTPS destination. WinHTTP proxy endpoints are
// HTTP CONNECT proxies even when selected by the `https=` mapping.
func parseWindowsProxyList(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || strings.ContainsAny(value, "\x00\r\n\t") {
		return "", ErrUnavailable
	}
	var httpsRoute, httpRoute, firstRoute string
	seenHTTPS := false
	for _, raw := range strings.Split(value, ";") {
		token := strings.TrimSpace(raw)
		if token == "" {
			return "", ErrUnavailable
		}
		if strings.EqualFold(token, "DIRECT") {
			if firstRoute == "" {
				firstRoute = "direct://"
			}
			continue
		}
		if len(token) > len("PROXY ") && strings.EqualFold(token[:len("PROXY ")], "PROXY ") {
			token = strings.TrimSpace(token[len("PROXY "):])
		}
		kind, address, mapped := strings.Cut(token, "=")
		if mapped {
			kind = strings.ToLower(strings.TrimSpace(kind))
			address = strings.TrimSpace(address)
			if kind != "http" && kind != "https" {
				return "", ErrUnavailable
			}
		} else {
			address = token
		}
		route, err := windowsHTTPProxyRoute(address)
		if err != nil {
			return "", err
		}
		if firstRoute == "" {
			firstRoute = route
		}
		switch kind {
		case "https":
			if seenHTTPS {
				return "", ErrUnavailable
			}
			seenHTTPS, httpsRoute = true, route
		case "http":
			if httpRoute != "" {
				return "", ErrUnavailable
			}
			httpRoute = route
		}
	}
	if httpsRoute != "" {
		return httpsRoute, nil
	}
	if httpRoute != "" {
		return httpRoute, nil
	}
	if firstRoute != "" {
		return firstRoute, nil
	}
	return "", ErrUnavailable
}

func windowsHTTPProxyRoute(address string) (string, error) {
	if address == "" || strings.Contains(address, "://") {
		return "", ErrUnavailable
	}
	parsed, err := url.Parse("http://" + strings.ToLower(address))
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.Path != "" ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", ErrUnavailable
	}
	if port := parsed.Port(); port != "" {
		portNumber, parseError := strconv.ParseUint(port, 10, 16)
		if parseError != nil || portNumber == 0 {
			return "", ErrUnavailable
		}
	}
	return parsed.String(), nil
}

func windowsProxyBypasses(target, value string) (bool, error) {
	if value == "" {
		return false, nil
	}
	parsed, err := url.Parse(target)
	if err != nil || parsed.Hostname() == "" {
		return false, ErrUnavailable
	}
	hostname := strings.ToLower(parsed.Hostname())
	for _, raw := range strings.FieldsFunc(value, func(character rune) bool {
		return character == ';' || character == ','
	}) {
		pattern := strings.ToLower(strings.TrimSpace(raw))
		if pattern == "" {
			continue
		}
		if strings.ContainsAny(pattern, "/@\x00\r\n\t") {
			return false, ErrUnavailable
		}
		if pattern == "<local>" {
			if !strings.Contains(hostname, ".") && net.ParseIP(hostname) == nil {
				return true, nil
			}
			continue
		}
		matched, matchError := path.Match(pattern, hostname)
		if matchError != nil {
			return false, ErrUnavailable
		}
		if matched {
			return true, nil
		}
	}
	return false, nil
}
