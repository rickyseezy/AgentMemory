// Package artifacthttp implements strict HTTPS signed-range acquisition without
// ambient proxy or redirect authority.
package artifacthttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

const maximumRedirects = 3

var (
	errRedirectUnauthorized = errors.New("redirect target is not authorized")
	errProxyResolution      = errors.New("system proxy resolution failed")
	errProxyAuthentication  = errors.New("system proxy authentication required")
)

// ProxyMode is an explicit acquisition proxy policy.
type ProxyMode uint8

const (
	// ProxyDisabled ignores HTTP_PROXY, HTTPS_PROXY, and NO_PROXY.
	ProxyDisabled ProxyMode = iota
	// ProxyExplicit uses one exact policy-provided HTTPS proxy URL.
	ProxyExplicit
	// ProxySystem resolves each exact request URL through the invoking user's
	// native OS proxy/PAC authority. Process environment is still ignored.
	ProxySystem
)

// ProxyResolver is the narrow OS authority used for per-destination proxy and
// PAC decisions. It returns direct:// or one exact proxy URI. Implementations
// must not consult process environment or persist credentials.
type ProxyResolver interface {
	ProxyForURL(context.Context, string) (string, error)
}

// ProxyPolicy never reads process environment.
type ProxyPolicy struct {
	Mode     ProxyMode
	URL      string
	Resolver ProxyResolver
}

// Fetcher performs bounded strict HTTP range requests.
type Fetcher struct {
	transport http.RoundTripper
	timeout   time.Duration
	proxyMode ProxyMode
}

// New creates a TLS-1.3 HTTPS fetcher with bounded dialing, headers, and total
// request time. Ambient proxy discovery is deliberately absent.
func New(policy ProxyPolicy, timeout time.Duration) (*Fetcher, error) {
	if timeout < time.Second || timeout > 10*time.Minute {
		return nil, artifactapp.ErrFetchIntegrity
	}
	var proxy func(*http.Request) (*url.URL, error)
	switch policy.Mode {
	case ProxyDisabled:
		if policy.URL != "" || !nilProxyResolver(policy.Resolver) {
			return nil, artifactapp.ErrFetchIntegrity
		}
		proxy = nil
	case ProxyExplicit:
		if !nilProxyResolver(policy.Resolver) {
			return nil, artifactapp.ErrFetchIntegrity
		}
		proxyURL, err := parseExplicitProxy(policy.URL)
		if err != nil {
			return nil, artifactapp.ErrFetchIntegrity
		}
		proxy = http.ProxyURL(proxyURL)
	case ProxySystem:
		if policy.URL != "" || nilProxyResolver(policy.Resolver) {
			return nil, artifactapp.ErrFetchIntegrity
		}
		proxy = func(request *http.Request) (*url.URL, error) {
			if request == nil || request.Context() == nil || !strictHTTPS(request.URL.String()) {
				return nil, errProxyResolution
			}
			route, err := policy.Resolver.ProxyForURL(request.Context(), request.URL.String())
			if err != nil {
				return nil, errProxyResolution
			}
			return parseSystemProxy(route)
		}
	default:
		return nil, artifactapp.ErrFetchIntegrity
	}
	dialer := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  proxy,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 64 * 1024,
		DisableCompression:     true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13},
		OnProxyConnectResponse: func(_ context.Context, _ *url.URL, _ *http.Request, response *http.Response) error {
			if response != nil && response.StatusCode == http.StatusProxyAuthRequired {
				return errProxyAuthentication
			}
			return nil
		},
	}
	return &Fetcher{transport: transport, timeout: timeout, proxyMode: policy.Mode}, nil
}

// Fetch obtains and verifies one exact range. Redirects are accepted only when
// their complete target string is another signed source for the same artifact.
func (f *Fetcher) Fetch(
	ctx context.Context,
	artifact artifactacquisition.Artifact,
	source string,
	chunk artifactacquisition.Chunk,
) ([]byte, error) {
	if ctx == nil || !artifact.SourceAuthorized(source) || !strictHTTPS(source) || chunk.Size() == 0 ||
		!proxyModeAuthorizes(f.proxyMode, artifact.ProxyMode()) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, artifactapp.ErrFetchIntegrity
	}
	rangeValue := fmt.Sprintf("bytes=%d-%d", chunk.Offset(), chunk.End())
	request.Header.Set("Range", rangeValue)
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "AgentMemory-Launcher/1")

	client := &http.Client{
		Transport: f.transport,
		Timeout:   f.timeout,
		CheckRedirect: func(next *http.Request, via []*http.Request) error {
			if len(via) >= maximumRedirects || !artifact.SourceAuthorized(next.URL.String()) ||
				!strictHTTPS(next.URL.String()) || next.Method != http.MethodGet ||
				next.Header.Get("Range") != rangeValue || next.Header.Get("Accept-Encoding") != "identity" {
				return errRedirectUnauthorized
			}
			return nil
		},
	}
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, errors.Join(artifactapp.ErrFetchUnavailable, err)
		}
		if errors.Is(err, errRedirectUnauthorized) {
			return nil, errors.Join(artifactapp.ErrFetchIntegrity, artifactapp.ErrFetchNetworkInterception)
		}
		if errors.Is(err, errProxyResolution) {
			return nil, errors.Join(artifactapp.ErrFetchUnavailable, artifactapp.ErrFetchProxyConfiguration)
		}
		if errors.Is(err, errProxyAuthentication) {
			return nil, errors.Join(artifactapp.ErrFetchUnavailable, artifactapp.ErrFetchProxyAuthentication)
		}
		if certificateFailure(err) {
			return nil, errors.Join(artifactapp.ErrFetchUnavailable, artifactapp.ErrFetchTLSInterception)
		}
		return nil, artifactapp.ErrFetchUnavailable
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusPartialContent {
		if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusRequestTimeout ||
			response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			return nil, artifactapp.ErrFetchUnavailable
		}
		return nil, artifactapp.ErrFetchIntegrity
	}
	chunkSize, validSize := boundedHTTPSize(chunk.Size())
	if !validSize {
		return nil, artifactapp.ErrFetchIntegrity
	}
	expectedLength := strconv.FormatUint(chunk.Size(), 10)
	expectedRange := fmt.Sprintf("bytes %d-%d/%d", chunk.Offset(), chunk.End(), artifact.Size())
	encoding := response.Header.Get("Content-Encoding")
	if response.Header.Get("Content-Range") != expectedRange || response.Header.Get("Content-Length") != expectedLength ||
		response.ContentLength != chunkSize || (encoding != "" && encoding != "identity") ||
		len(response.TransferEncoding) != 0 {
		return nil, artifactapp.ErrFetchIntegrity
	}
	value, err := io.ReadAll(io.LimitReader(response.Body, chunkSize+1))
	if err != nil || !chunk.VerifyBytes(value) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	return value, nil
}

func proxyModeAuthorizes(configured ProxyMode, signed artifactacquisition.ProxyMode) bool {
	switch configured {
	case ProxySystem, ProxyExplicit:
		return signed == artifactacquisition.ProxyModeSystem || signed == artifactacquisition.ProxyModeDirectAndSystem
	case ProxyDisabled:
		return signed == artifactacquisition.ProxyModeDirectAndSystem
	default:
		// Test-only injected transports created before proxy composition do not
		// gain production authority; their artifacts still require a valid mode.
		return signed.Valid()
	}
}

func boundedHTTPSize(value uint64) (int64, bool) {
	if value == 0 || value >= math.MaxInt64 {
		return 0, false
	}
	return int64(value), true // #nosec G115 -- the signed range is proven above.
}

func parseExplicitProxy(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.Hostname() == "" || parsed.Hostname() != strings.ToLower(parsed.Hostname()) {
		return nil, artifactapp.ErrFetchIntegrity
	}
	if port := parsed.Port(); port != "" {
		portNumber, parseError := strconv.ParseUint(port, 10, 16)
		if parseError != nil || portNumber == 0 {
			return nil, artifactapp.ErrFetchIntegrity
		}
	}
	return parsed, nil
}

func parseSystemProxy(value string) (*url.URL, error) {
	if value == "direct://" {
		return nil, nil
	}
	if value == "" || len(value) > 2048 || strings.ContainsAny(value, "\x00\r\n\t") {
		return nil, errProxyResolution
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5") ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") || parsed.Hostname() != strings.ToLower(parsed.Hostname()) ||
		parsed.String() != value {
		return nil, errProxyResolution
	}
	if port := parsed.Port(); port != "" {
		portNumber, parseError := strconv.ParseUint(port, 10, 16)
		if parseError != nil || portNumber == 0 {
			return nil, errProxyResolution
		}
	}
	return parsed, nil
}

func certificateFailure(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &unknownAuthority) || errors.As(err, &hostname) || errors.As(err, &invalid)
}

func nilProxyResolver(value ProxyResolver) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

func strictHTTPS(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

var _ artifactapp.Fetcher = (*Fetcher)(nil)
