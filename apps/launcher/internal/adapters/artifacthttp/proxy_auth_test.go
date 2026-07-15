package artifacthttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/artifactacquisition"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/releaseinventory"
)

func TestPF001HTTPFetcherCompletesOneChallengeScopedAuthenticatedCONNECT(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://ambient-owner:ambient-secret@ambient.invalid:8080")

	target := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("Range") != "bytes=0-2" {
			t.Errorf("target request=%s range=%q", request.Method, request.Header.Get("Range"))
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Range", "bytes 0-2/3")
		writer.Header().Set("Content-Length", "3")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("abc"))
	}))
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	target.StartTLS()
	t.Cleanup(target.Close)

	const source = "https://example.com/artifact.bin"
	proxy := newAuthenticatedCONNECTProxy(t, target.Listener.Addr().String(), "owner", "proxy-secret")
	provider := &proxyCredentialProviderStub{username: []byte("owner"), password: []byte("proxy-secret")}
	resolver := &proxyResolverStub{routes: map[string]string{source: proxy.URL}}
	fetcher, err := New(ProxyPolicy{
		Mode: ProxySystem, Resolver: resolver, CredentialProvider: provider,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	fetcher.transport.(*http.Transport).TLSClientConfig.RootCAs = roots

	artifact, chunk := authenticatedProxyArtifact(t, source)
	value, err := fetcher.Fetch(t.Context(), artifact, artifact.Sources()[0], chunk)
	if err != nil || string(value) != "abc" {
		first, second, attempts := proxy.observed()
		t.Fatalf("Fetch()=(%q,%v) proxy=%d/%q/%q provider_calls=%d", value, err, attempts, first, second, provider.calls)
	}
	first, second, attempts := proxy.observed()
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("owner:proxy-secret"))
	if attempts != 2 || first != "" || second != expected || provider.calls != 1 {
		t.Fatalf("proxy attempts=%d first=%q second=%q provider_calls=%d", attempts, first, second, provider.calls)
	}
	if provider.challenge.TargetURL() != artifact.Sources()[0] ||
		provider.challenge.ProxyURL() != proxy.URL || !provider.challenge.BasicAvailable() {
		t.Fatalf("challenge target=%q proxy=%q basic=%t", provider.challenge.TargetURL(), provider.challenge.ProxyURL(), provider.challenge.BasicAvailable())
	}
	if provider.credential == nil || !provider.credential.destroyed() {
		t.Fatal("challenge-scoped credential was not destroyed after the retry")
	}
}

func TestPF001HTTPFetcherRechallengesCredentialsForSignedRedirectTarget(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://ambient-owner:ambient-secret@ambient.invalid:8080")
	const redirectSource = "https://redirect.example.com/start"
	const finalSource = "https://final.example.com/artifact.bin"
	const redirectHost = "redirect.example.com:443"
	const finalHost = "final.example.com:443"

	final := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Range", "bytes 0-2/3")
		writer.Header().Set("Content-Length", "3")
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write([]byte("abc"))
	}))
	final.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	final.StartTLS()
	t.Cleanup(final.Close)

	redirect := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", finalSource)
		writer.WriteHeader(http.StatusFound)
	}))
	redirect.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	redirect.StartTLS()
	t.Cleanup(redirect.Close)

	const username = "owner"
	const password = "redirect-secret"
	expected := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
	proxy, observed := newRedirectChallengeProxy(t, map[string]string{
		redirectHost: redirect.Listener.Addr().String(),
		finalHost:    final.Listener.Addr().String(),
	}, finalHost, expected)

	provider := &proxyCredentialProviderStub{username: []byte(username), password: []byte(password)}
	resolver := &proxyResolverStub{routes: map[string]string{
		redirectSource: proxy,
		finalSource:    proxy,
	}}
	fetcher, err := New(ProxyPolicy{
		Mode: ProxySystem, Resolver: resolver, CredentialProvider: provider,
	}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(redirect.Certificate())
	roots.AddCert(final.Certificate())
	fetcher.transport.(*http.Transport).TLSClientConfig.RootCAs = roots

	artifact, chunk := authenticatedProxyArtifactSources(t, []string{redirectSource, finalSource})
	value, err := fetcher.Fetch(t.Context(), artifact, redirectSource, chunk)
	if err != nil || string(value) != "abc" {
		t.Fatalf("Fetch()=(%q,%v) observed=%v provider_calls=%d", value, err, observed(), provider.calls)
	}
	requests := observed()
	if len(requests) != 3 || requests[0] != redirectHost+"|" ||
		requests[1] != finalHost+"|" || requests[2] != finalHost+"|"+expected ||
		provider.calls != 1 || provider.challenge.TargetURL() != finalSource {
		t.Fatalf("observed=%v provider_calls=%d target=%q", requests, provider.calls, provider.challenge.TargetURL())
	}
	if provider.credential == nil || !provider.credential.destroyed() {
		t.Fatal("redirect challenge credential was not destroyed")
	}
}

func TestPF001ProxyCredentialIsBoundedAndDestroyable(t *testing.T) {
	t.Parallel()
	credential, err := NewProxyCredential([]byte("owner"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	header, err := credential.basicAuthorization()
	if err != nil || header != "Basic b3duZXI6c2VjcmV0" {
		t.Fatalf("basicAuthorization()=(%q,%v)", header, err)
	}
	credential.Destroy()
	credential.Destroy()
	if !credential.destroyed() {
		t.Fatal("credential is not destroyed")
	}
	if header, err := credential.basicAuthorization(); err == nil || header != "" {
		t.Fatalf("destroyed basicAuthorization()=(%q,%v)", header, err)
	}
	for _, input := range []struct {
		username []byte
		password []byte
	}{
		{},
		{username: []byte("owner:name"), password: []byte("secret")},
		{username: []byte("owner\n"), password: []byte("secret")},
		{username: []byte("owner"), password: []byte("secret\x00")},
		{username: make([]byte, maximumProxyCredentialBytes+1), password: []byte("secret")},
	} {
		if credential, err := NewProxyCredential(input.username, input.password); err == nil || credential != nil {
			t.Fatalf("invalid credential accepted: username_bytes=%d password_bytes=%d", len(input.username), len(input.password))
		}
	}
}

type proxyCredentialProviderStub struct {
	username   []byte
	password   []byte
	calls      int
	challenge  ProxyCredentialChallenge
	credential *ProxyCredential
}

func (p *proxyCredentialProviderStub) CredentialsForProxy(
	_ context.Context,
	challenge ProxyCredentialChallenge,
) (*ProxyCredential, error) {
	p.calls++
	p.challenge = challenge
	credential, err := NewProxyCredential(p.username, p.password)
	p.credential = credential
	return credential, err
}

type authenticatedCONNECTProxy struct {
	URL      string
	server   *httptest.Server
	mu       sync.Mutex
	headers  []string
	expected string
	upstream string
}

func newAuthenticatedCONNECTProxy(
	t testing.TB,
	upstream string,
	username string,
	password string,
) *authenticatedCONNECTProxy {
	t.Helper()
	proxy := &authenticatedCONNECTProxy{
		expected: "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)),
		upstream: upstream,
	}
	proxy.server = httptest.NewServer(http.HandlerFunc(proxy.serveHTTP))
	proxy.URL = proxy.server.URL
	t.Cleanup(proxy.server.Close)
	return proxy
}

func (p *authenticatedCONNECTProxy) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	authorization := request.Header.Get("Proxy-Authorization")
	p.mu.Lock()
	p.headers = append(p.headers, authorization)
	p.mu.Unlock()
	if request.Method != http.MethodConnect {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if authorization != p.expected {
		writer.Header().Set("Proxy-Authenticate", `Basic realm="AgentMemory test proxy"`)
		writer.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(request.Context(), "tcp", p.upstream)
	if err != nil {
		writer.WriteHeader(http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	client, buffer, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err = fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffer.Flush() != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	go proxyTunnel(client, upstream)
	go proxyTunnel(upstream, client)
}

func (p *authenticatedCONNECTProxy) observed() (string, string, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	first, second := "", ""
	if len(p.headers) > 0 {
		first = p.headers[0]
	}
	if len(p.headers) > 1 {
		second = p.headers[1]
	}
	return first, second, len(p.headers)
}

func proxyTunnel(destination net.Conn, source net.Conn) {
	defer func() { _ = destination.Close() }()
	defer func() { _ = source.Close() }()
	_, _ = io.Copy(destination, source)
}

func newRedirectChallengeProxy(
	t testing.TB,
	upstreams map[string]string,
	authenticatedHost string,
	expectedAuthorization string,
) (string, func() []string) {
	t.Helper()
	var mu sync.Mutex
	requests := make([]string, 0, 3)
	proxy := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Proxy-Authorization")
		mu.Lock()
		requests = append(requests, request.Host+"|"+authorization)
		mu.Unlock()
		if request.Method != http.MethodConnect {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if request.Host == authenticatedHost && authorization != expectedAuthorization {
			writer.Header().Set("Proxy-Authenticate", `Basic realm="redirect target"`)
			writer.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		upstreamAddress, ok := upstreams[request.Host]
		if !ok {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(
			request.Context(), "tcp", upstreamAddress,
		)
		if err != nil {
			writer.WriteHeader(http.StatusBadGateway)
			return
		}
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			_ = upstream.Close()
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		client, buffer, err := hijacker.Hijack()
		if err != nil {
			_ = upstream.Close()
			return
		}
		if _, err = fmt.Fprint(buffer, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffer.Flush() != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
		go proxyTunnel(client, upstream)
		go proxyTunnel(upstream, client)
	}))
	t.Cleanup(proxy.Close)
	return proxy.URL, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), requests...)
	}
}

func authenticatedProxyArtifact(t testing.TB, source string) (artifactacquisition.Artifact, artifactacquisition.Chunk) {
	return authenticatedProxyArtifactSources(t, []string{source})
}

func authenticatedProxyArtifactSources(
	t testing.TB,
	sources []string,
) (artifactacquisition.Artifact, artifactacquisition.Chunk) {
	t.Helper()
	plan, err := artifactacquisition.NewPlan(artifactacquisition.PlanInput{
		PlanDigest: releaseinventory.DigestBytes([]byte("authenticated proxy plan")),
		ProxyMode:  artifactacquisition.ProxyModeSystem,
		Artifacts: []artifactacquisition.ArtifactInput{{
			ID: "authenticated-proxy-artifact", Digest: releaseinventory.DigestBytes([]byte("abc")), Size: 3,
			Sources: sources, Chunks: []artifactacquisition.ChunkInput{{
				Offset: 0, Size: 3, Digest: releaseinventory.DigestBytes([]byte("abc")),
			}},
		}},
		Totals: artifactacquisition.TotalsInput{
			DownloadBytes: 3, RollbackHeadroomBytes: 1, SafetyHeadroomBytes: 1, RequiredBytes: 5,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact := plan.Artifacts()[0]
	return artifact, artifact.Chunks()[0]
}
