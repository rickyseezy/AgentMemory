// Package artifacthttp implements strict HTTPS signed-range acquisition without
// ambient proxy or redirect authority.
package artifacthttp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
)

const maximumRedirects = 3

var errRedirectUnauthorized = errors.New("redirect target is not authorized")

// ProxyMode is an explicit acquisition proxy policy.
type ProxyMode uint8

const (
	// ProxyDisabled ignores HTTP_PROXY, HTTPS_PROXY, and NO_PROXY.
	ProxyDisabled ProxyMode = iota
	// ProxyExplicit uses one exact policy-provided HTTPS proxy URL.
	ProxyExplicit
)

// ProxyPolicy never reads process environment.
type ProxyPolicy struct {
	Mode ProxyMode
	URL  string
}

// Fetcher performs bounded strict HTTP range requests.
type Fetcher struct {
	transport http.RoundTripper
	timeout   time.Duration
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
		if policy.URL != "" {
			return nil, artifactapp.ErrFetchIntegrity
		}
		proxy = nil
	case ProxyExplicit:
		proxyURL, err := parseExplicitProxy(policy.URL)
		if err != nil {
			return nil, artifactapp.ErrFetchIntegrity
		}
		proxy = http.ProxyURL(proxyURL)
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
	}
	return &Fetcher{transport: transport, timeout: timeout}, nil
}

// Fetch obtains and verifies one exact range. Redirects are accepted only when
// their complete target string is another signed source for the same artifact.
func (f *Fetcher) Fetch(
	ctx context.Context,
	artifact artifactacquisition.Artifact,
	source string,
	chunk artifactacquisition.Chunk,
) ([]byte, error) {
	if ctx == nil || !artifact.SourceAuthorized(source) || !strictHTTPS(source) || chunk.Size() == 0 {
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
			return nil, artifactapp.ErrFetchIntegrity
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

func strictHTTPS(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil &&
		parsed.RawQuery == "" && parsed.Fragment == "" && parsed.String() == value
}

var _ artifactapp.Fetcher = (*Fetcher)(nil)
