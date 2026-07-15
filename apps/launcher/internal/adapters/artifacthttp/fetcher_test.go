package artifacthttp

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/artifactapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001HTTPFetcherUsesExactRangeAndIgnoresAmbientProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://ambient.invalid:9443")
	fetcher, err := New(ProxyPolicy{Mode: ProxyDisabled}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transport := fetcher.transport.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableCompression || transport.TLSClientConfig.MinVersion != 0x0304 {
		t.Fatalf("transport has_proxy=%v compression_disabled=%v TLS=%x", transport.Proxy != nil, transport.DisableCompression, transport.TLSClientConfig.MinVersion)
	}
	artifact, chunk := httpFixture(t)
	roundTripper := &scriptedRoundTripper{responses: []*http.Response{partialResponse(chunk, artifact.Size(), "abc")}}
	fetcher.transport = roundTripper
	value, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], chunk)
	if err != nil || string(value) != "abc" {
		t.Fatalf("Fetch()=(%q,%v)", value, err)
	}
	request := roundTripper.requests[0]
	if request.Method != http.MethodGet || request.URL.String() != artifact.Sources()[0] ||
		request.Header.Get("Range") != "bytes=0-2" || request.Header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("request=%s %s headers=%v", request.Method, request.URL, request.Header)
	}
	if os.Getenv("HTTPS_PROXY") != "https://ambient.invalid:9443" {
		t.Fatal("test environment unexpectedly changed")
	}
}

func TestPF001HTTPFetcherReauthorizesEveryRedirectTarget(t *testing.T) {
	t.Parallel()
	artifact, chunk := httpFixture(t)
	redirect := artifact.Sources()[1]
	roundTripper := &scriptedRoundTripper{responses: []*http.Response{
		redirectResponse(redirect), partialResponse(chunk, artifact.Size(), "abc"),
	}}
	fetcher := &Fetcher{transport: roundTripper, timeout: time.Minute}
	value, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], chunk)
	if err != nil || string(value) != "abc" || len(roundTripper.requests) != 2 {
		t.Fatalf("authorized redirect=(%q,%v) calls=%d", value, err, len(roundTripper.requests))
	}

	roundTripper = &scriptedRoundTripper{responses: []*http.Response{redirectResponse("https://evil.example/artifact")}}
	fetcher = &Fetcher{transport: roundTripper, timeout: time.Minute}
	if _, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], chunk); !errors.Is(err, artifactapp.ErrFetchIntegrity) || len(roundTripper.requests) != 1 {
		t.Fatalf("unauthorized redirect error=%v calls=%d", err, len(roundTripper.requests))
	}
}

func TestPF001HTTPFetcherRejectsStatusRangeEncodingSizeAndDigestContradictions(t *testing.T) {
	t.Parallel()
	artifact, chunk := httpFixture(t)
	tests := []struct {
		name     string
		response *http.Response
		want     error
	}{
		{name: "full status", response: response(http.StatusOK, chunk, artifact.Size(), "abc"), want: artifactapp.ErrFetchIntegrity},
		{name: "missing", response: response(http.StatusNotFound, chunk, artifact.Size(), "abc"), want: artifactapp.ErrFetchUnavailable},
		{name: "server", response: response(http.StatusBadGateway, chunk, artifact.Size(), "abc"), want: artifactapp.ErrFetchUnavailable},
		{name: "wrong range", response: mutateResponse(partialResponse(chunk, artifact.Size(), "abc"), func(r *http.Response) { r.Header.Set("Content-Range", "bytes 1-3/6") }), want: artifactapp.ErrFetchIntegrity},
		{name: "wrong length header", response: mutateResponse(partialResponse(chunk, artifact.Size(), "abc"), func(r *http.Response) { r.Header.Set("Content-Length", "4") }), want: artifactapp.ErrFetchIntegrity},
		{name: "compressed", response: mutateResponse(partialResponse(chunk, artifact.Size(), "abc"), func(r *http.Response) { r.Header.Set("Content-Encoding", "gzip") }), want: artifactapp.ErrFetchIntegrity},
		{name: "chunked", response: mutateResponse(partialResponse(chunk, artifact.Size(), "abc"), func(r *http.Response) { r.TransferEncoding = []string{"chunked"} }), want: artifactapp.ErrFetchIntegrity},
		{name: "wrong digest", response: partialResponse(chunk, artifact.Size(), "abd"), want: artifactapp.ErrFetchIntegrity},
		{name: "oversize", response: partialResponse(chunk, artifact.Size(), "abcd"), want: artifactapp.ErrFetchIntegrity},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fetcher := &Fetcher{transport: &scriptedRoundTripper{responses: []*http.Response{test.response}}, timeout: time.Minute}
			_, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], chunk)
			if !errors.Is(err, test.want) {
				t.Fatalf("Fetch() error=%v want=%v", err, test.want)
			}
		})
	}
}

func TestPF001HTTPFetcherRejectsUnauthorizedSourceCancellationAndRawErrors(t *testing.T) {
	t.Parallel()
	artifact, chunk := httpFixture(t)
	fetcher := &Fetcher{transport: &scriptedRoundTripper{err: errors.New("secret URL diagnostic")}, timeout: time.Minute}
	if _, err := fetcher.Fetch(context.Background(), artifact, "https://evil.example/artifact", chunk); !errors.Is(err, artifactapp.ErrFetchIntegrity) {
		t.Fatalf("unauthorized source error=%v", err)
	}
	_, err := fetcher.Fetch(context.Background(), artifact, artifact.Sources()[0], chunk)
	if !errors.Is(err, artifactapp.ErrFetchUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("raw error=%v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	fetcher = &Fetcher{transport: &scriptedRoundTripper{err: context.Canceled}, timeout: time.Minute}
	_, err = fetcher.Fetch(cancelled, artifact, artifact.Sources()[0], chunk)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, artifactapp.ErrFetchUnavailable) {
		t.Fatalf("cancellation error=%v", err)
	}
}

func TestPF001HTTPFetcherExplicitProxyPolicyIsClosed(t *testing.T) {
	t.Parallel()
	valid, err := New(ProxyPolicy{Mode: ProxyExplicit, URL: "https://proxy.example:8443"}, time.Minute)
	if err != nil || valid.transport.(*http.Transport).Proxy == nil {
		t.Fatalf("valid proxy=(%+v,%v)", valid, err)
	}
	for _, policy := range []ProxyPolicy{
		{Mode: ProxyDisabled, URL: "https://proxy.example"},
		{Mode: ProxyExplicit},
		{Mode: ProxyExplicit, URL: "http://proxy.example"},
		{Mode: ProxyExplicit, URL: "https://user@proxy.example"},
		{Mode: ProxyExplicit, URL: "https://proxy.example/path"},
		{Mode: 99},
	} {
		if _, err := New(policy, time.Minute); err == nil {
			t.Fatalf("New(%+v) succeeded", policy)
		}
	}
	if _, err := New(ProxyPolicy{}, 0); err == nil {
		t.Fatal("zero timeout succeeded")
	}
}

func TestPF001HTTPFetcherUsesSystemResolverPerExactRequestWithoutAmbientAuthority(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "https://ambient.invalid:9443")
	resolver := &proxyResolverStub{routes: map[string]string{
		"https://a.example/artifact.bin": "http://proxy.example:8080",
		"https://b.example/artifact.bin": "direct://",
	}}
	fetcher, err := New(ProxyPolicy{Mode: ProxySystem, Resolver: resolver}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	transport := fetcher.transport.(*http.Transport)
	for target, expected := range resolver.routes {
		request, requestError := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if requestError != nil {
			t.Fatal(requestError)
		}
		proxy, proxyError := transport.Proxy(request)
		if proxyError != nil {
			t.Fatalf("Proxy(%q): %v", target, proxyError)
		}
		if expected == "direct://" {
			if proxy != nil {
				t.Fatalf("Proxy(%q)=%v, want direct", target, proxy)
			}
		} else if proxy == nil || proxy.String() != expected {
			t.Fatalf("Proxy(%q)=%v, want %q", target, proxy, expected)
		}
	}
	if len(resolver.targets) != 2 || os.Getenv("HTTPS_PROXY") != "https://ambient.invalid:9443" {
		t.Fatalf("targets=%v ambient=%q", resolver.targets, os.Getenv("HTTPS_PROXY"))
	}
}

func TestPF001HTTPFetcherRejectsUnsafeSystemRoutesAndClosedPolicyShapes(t *testing.T) {
	t.Parallel()
	valid := &proxyResolverStub{routes: map[string]string{}}
	for _, policy := range []ProxyPolicy{
		{Mode: ProxySystem},
		{Mode: ProxySystem, URL: "https://proxy.example", Resolver: valid},
		{Mode: ProxyDisabled, Resolver: valid},
		{Mode: ProxyExplicit, URL: "https://proxy.example", Resolver: valid},
	} {
		if _, err := New(policy, time.Minute); err == nil {
			t.Fatalf("New(%+v) succeeded", policy)
		}
	}
	for _, route := range []string{
		"", "ftp://proxy.example", "http://proxy.example/path", "http://proxy.example?query",
		"http://proxy.example#fragment", "http://proxy.example:0", "http://proxy.example:\n80",
		"http://owner:secret@proxy.example:8080",
	} {
		resolver := &proxyResolverStub{routes: map[string]string{"https://a.example/artifact.bin": route}}
		fetcher, err := New(ProxyPolicy{Mode: ProxySystem, Resolver: resolver}, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://a.example/artifact.bin", nil)
		if _, err := fetcher.transport.(*http.Transport).Proxy(request); !errors.Is(err, errProxyResolution) {
			t.Fatalf("route %q error=%v", route, err)
		}
	}
}

func TestPF001HTTPFetcherBindsTransportChoiceToSignedProxyMode(t *testing.T) {
	t.Parallel()
	artifact, chunk := httpFixtureForMode(t, artifactacquisition.ProxyModeSystem)
	direct, err := New(ProxyPolicy{Mode: ProxyDisabled}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	roundTripper := &scriptedRoundTripper{responses: []*http.Response{partialResponse(chunk, artifact.Size(), "abc")}}
	direct.transport = roundTripper
	if _, err := direct.Fetch(t.Context(), artifact, artifact.Sources()[0], chunk); !errors.Is(err, artifactapp.ErrFetchIntegrity) || len(roundTripper.requests) != 0 {
		t.Fatalf("direct fetch error=%v calls=%d", err, len(roundTripper.requests))
	}

	system, err := New(ProxyPolicy{Mode: ProxySystem, Resolver: &proxyResolverStub{
		routes: map[string]string{artifact.Sources()[0]: "direct://"},
	}}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	roundTripper = &scriptedRoundTripper{responses: []*http.Response{partialResponse(chunk, artifact.Size(), "abc")}}
	system.transport = roundTripper
	if value, err := system.Fetch(t.Context(), artifact, artifact.Sources()[0], chunk); err != nil || string(value) != "abc" {
		t.Fatalf("system fetch=(%q,%v)", value, err)
	}
}

func TestPF001HTTPFetcherClassifiesProxyTLSAndCaptivePortalWithoutRawDiagnostics(t *testing.T) {
	t.Parallel()
	artifact, chunk := httpFixture(t)
	tests := []struct {
		name string
		err  error
		want error
	}{
		{name: "proxy resolution", err: errors.Join(errProxyResolution, errors.New("secret PAC URL")), want: artifactapp.ErrFetchProxyConfiguration},
		{name: "proxy authentication", err: errProxyAuthentication, want: artifactapp.ErrFetchProxyAuthentication},
		{name: "TLS interception", err: x509.UnknownAuthorityError{}, want: artifactapp.ErrFetchTLSInterception},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			fetcher := &Fetcher{transport: &scriptedRoundTripper{err: test.err}, timeout: time.Minute}
			_, err := fetcher.Fetch(t.Context(), artifact, artifact.Sources()[0], chunk)
			if !errors.Is(err, artifactapp.ErrFetchUnavailable) || !errors.Is(err, test.want) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("Fetch() error=%v want unavailable+%v", err, test.want)
			}
		})
	}

	fetcher := &Fetcher{transport: &scriptedRoundTripper{responses: []*http.Response{
		redirectResponse("https://login.captive.example/portal"),
	}}, timeout: time.Minute}
	_, err := fetcher.Fetch(t.Context(), artifact, artifact.Sources()[0], chunk)
	if !errors.Is(err, artifactapp.ErrFetchIntegrity) || !errors.Is(err, artifactapp.ErrFetchNetworkInterception) {
		t.Fatalf("captive portal error=%v", err)
	}
}

func httpFixture(t *testing.T) (artifactacquisition.Artifact, artifactacquisition.Chunk) {
	t.Helper()
	return httpFixtureForMode(t, artifactacquisition.ProxyModeDirectAndSystem)
}

func httpFixtureForMode(
	t *testing.T,
	proxyMode artifactacquisition.ProxyMode,
) (artifactacquisition.Artifact, artifactacquisition.Chunk) {
	t.Helper()
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("plan")),
		ProxyMode:  proxyMode,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "artifact", Digest: releaseinventory.DigestBytes([]byte("abcdef")), Size: 6,
			Sources: []string{"https://a.example/artifact.bin", "https://b.example/artifact.bin"},
			Chunks: []artifactacquisition.ChunkInput{
				{Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc"))},
				{Offset: 3, Size: 3, Digest: releaseinventory.DigestBytes([]byte("def"))},
			},
		}},
		Totals: artifactacquisition.TotalsInput{DownloadBytes: 6, RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1, RequiredBytes: 8},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := plan.Artifacts()[0]
	return artifact, artifact.Chunks()[0]
}

func partialResponse(chunk artifactacquisition.Chunk, total uint64, value string) *http.Response {
	return response(http.StatusPartialContent, chunk, total, value)
}

func response(status int, _ artifactacquisition.Chunk, total uint64, value string) *http.Response {
	header := make(http.Header)
	header.Set("Content-Range", "bytes 0-2/"+strconvUint(total))
	header.Set("Content-Length", strconvUint(uint64(len(value))))
	return &http.Response{
		StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(value)), ContentLength: int64(len(value)),
	}
}

func redirectResponse(location string) *http.Response {
	header := make(http.Header)
	header.Set("Location", location)
	return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: header, Body: io.NopCloser(strings.NewReader("")), ContentLength: 0}
}

func mutateResponse(response *http.Response, mutate func(*http.Response)) *http.Response {
	mutate(response)
	return response
}

func strconvUint(value uint64) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	buffer := make([]byte, 0, 20)
	for value > 0 {
		buffer = append(buffer, digits[value%10])
		value /= 10
	}
	for left, right := 0, len(buffer)-1; left < right; left, right = left+1, right-1 {
		buffer[left], buffer[right] = buffer[right], buffer[left]
	}
	return string(buffer)
}

type scriptedRoundTripper struct {
	responses []*http.Response
	requests  []*http.Request
	err       error
}

type proxyResolverStub struct {
	routes  map[string]string
	targets []string
	err     error
}

func (r *proxyResolverStub) ProxyForURL(_ context.Context, target string) (string, error) {
	r.targets = append(r.targets, target)
	if r.err != nil {
		return "", r.err
	}
	return r.routes[target], nil
}

func (r *scriptedRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	r.requests = append(r.requests, request.Clone(request.Context()))
	if r.err != nil {
		return nil, r.err
	}
	if len(r.responses) == 0 {
		return nil, errors.New("unexpected request")
	}
	response := r.responses[0]
	r.responses = r.responses[1:]
	response.Request = request
	return response, nil
}
