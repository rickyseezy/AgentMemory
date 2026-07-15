// Package systemproxy resolves acquisition routes exclusively through the
// invoking user's native operating-system proxy/PAC authority.
package systemproxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// ErrUnavailable is deliberately diagnostic-free: native PAC URLs, proxy
// hosts, realms, and credentials must not escape into journals or logs.
var ErrUnavailable = errors.New("native system proxy resolution unavailable")

type nativeLookup func(context.Context, string) (string, error)

// Resolver owns one native per-URL lookup capability.
type Resolver struct{ lookup nativeLookup }

// New constructs the platform-native resolver. Unsupported native facilities
// fail closed instead of consulting HTTP_PROXY, HTTPS_PROXY, or NO_PROXY.
func New() (*Resolver, error) {
	lookup, err := newNativeLookup()
	if err != nil {
		return nil, ErrUnavailable
	}
	return newResolver(lookup)
}

func newResolver(lookup nativeLookup) (*Resolver, error) {
	if lookup == nil {
		return nil, ErrUnavailable
	}
	return &Resolver{lookup: lookup}, nil
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
		return "", ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return route, nil
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
