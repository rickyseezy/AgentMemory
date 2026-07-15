package artifacthttp

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"unicode/utf8"
)

const (
	maximumProxyCredentialBytes = 1024
	maximumProxyChallenges      = 8
	maximumProxyChallengeBytes  = 4096
)

var errProxyCredential = errors.New("proxy credential is unavailable")

// ProxyCredentialChallenge is privacy-bounded evidence from one HTTP 407
// response. Realm and raw response headers are deliberately not exposed.
type ProxyCredentialChallenge struct {
	targetURL     string
	proxyURL      string
	connectTarget string
	basic         bool
}

// TargetURL returns the exact signed HTTPS destination that caused the
// challenge.
func (c ProxyCredentialChallenge) TargetURL() string { return c.targetURL }

// ProxyURL returns the exact credential-free proxy endpoint selected by the
// native resolver.
func (c ProxyCredentialChallenge) ProxyURL() string { return c.proxyURL }

// BasicAvailable reports whether the proxy offered one bounded Basic
// challenge. Other schemes remain available to future native transports but
// are never guessed by this portable transport.
func (c ProxyCredentialChallenge) BasicAvailable() bool { return c.basic }

// ProxyCredentialProvider obtains one ephemeral credential only after an
// observed proxy challenge. Implementations must use the invoking user's
// native credential flow and must not persist the result.
type ProxyCredentialProvider interface {
	CredentialsForProxy(context.Context, ProxyCredentialChallenge) (*ProxyCredential, error)
}

// ProxyCredential owns mutable credential bytes so the caller can destroy
// them immediately after the CONNECT attempt.
type ProxyCredential struct {
	mu             sync.Mutex
	username       []byte
	password       []byte
	destroyedValue bool
}

// NewProxyCredential copies one bounded username/password pair returned by a
// native credential flow. The username may not contain Basic's colon
// delimiter; neither field may contain transport controls.
func NewProxyCredential(username []byte, password []byte) (*ProxyCredential, error) {
	if len(username) == 0 || len(username) > maximumProxyCredentialBytes ||
		len(password) > maximumProxyCredentialBytes || !utf8.Valid(username) || !utf8.Valid(password) ||
		strings.ContainsAny(string(username), ":\x00\r\n") || strings.ContainsAny(string(password), "\x00\r\n") {
		return nil, errProxyCredential
	}
	return &ProxyCredential{
		username: append([]byte(nil), username...),
		password: append([]byte(nil), password...),
	}, nil
}

func (c *ProxyCredential) basicAuthorization() (string, error) {
	if c == nil {
		return "", errProxyCredential
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.destroyedValue || len(c.username) == 0 {
		return "", errProxyCredential
	}
	plain := make([]byte, 0, len(c.username)+1+len(c.password))
	plain = append(plain, c.username...)
	plain = append(plain, ':')
	plain = append(plain, c.password...)
	encoded := base64.StdEncoding.EncodeToString(plain)
	clear(plain)
	return "Basic " + encoded, nil
}

// Destroy clears both owned byte slices. It is idempotent and race-safe.
func (c *ProxyCredential) Destroy() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.username)
	clear(c.password)
	c.username = nil
	c.password = nil
	c.destroyedValue = true
}

func (c *ProxyCredential) destroyed() bool {
	if c == nil {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.destroyedValue
}

type proxyRequestContextKey struct{}

type proxyRequestAuthority struct {
	targetURL     string
	proxyURL      string
	connectTarget string
	authorization string
}

type proxyChallengeError struct{ challenge ProxyCredentialChallenge }

func (*proxyChallengeError) Error() string { return errProxyAuthentication.Error() }
func (*proxyChallengeError) Unwrap() error { return errProxyAuthentication }

func bindProxyRequest(
	request *http.Request,
	targetURL string,
	proxyURL string,
	connectTarget string,
	authorization string,
) *http.Request {
	authority := &proxyRequestAuthority{
		targetURL: targetURL, proxyURL: proxyURL, connectTarget: connectTarget, authorization: authorization,
	}
	return request.Clone(context.WithValue(request.Context(), proxyRequestContextKey{}, authority))
}

func proxyConnectHeader(ctx context.Context, proxyURL *url.URL, target string) (http.Header, error) {
	authority, ok := ctx.Value(proxyRequestContextKey{}).(*proxyRequestAuthority)
	if !ok || authority == nil || authority.authorization == "" {
		return nil, nil
	}
	if proxyURL == nil || authority.proxyURL != proxyURL.String() || authority.connectTarget != target {
		return nil, errProxyAuthentication
	}
	return http.Header{"Proxy-Authorization": []string{authority.authorization}}, nil
}

func proxyChallenge(
	ctx context.Context,
	proxyURL *url.URL,
	connectRequest *http.Request,
	response *http.Response,
) (ProxyCredentialChallenge, error) {
	authority, ok := ctx.Value(proxyRequestContextKey{}).(*proxyRequestAuthority)
	if !ok || authority == nil || !strictHTTPS(authority.targetURL) || proxyURL == nil || proxyURL.User != nil ||
		connectRequest == nil || response == nil || response.StatusCode != http.StatusProxyAuthRequired {
		return ProxyCredentialChallenge{}, errProxyAuthentication
	}
	parsedTarget, err := url.Parse(authority.targetURL)
	if err != nil || parsedTarget.Host == "" {
		return ProxyCredentialChallenge{}, errProxyAuthentication
	}
	targetPort := parsedTarget.Port()
	if targetPort == "" {
		targetPort = "443"
	}
	expectedConnectTarget := net.JoinHostPort(parsedTarget.Hostname(), targetPort)
	if connectRequest.Host != expectedConnectTarget {
		return ProxyCredentialChallenge{}, errProxyAuthentication
	}
	proxy := proxyURL.String()
	if parsed, parseError := parseSystemProxy(proxy); parseError != nil || parsed == nil || parsed.String() != proxy {
		return ProxyCredentialChallenge{}, errProxyAuthentication
	}
	values := response.Header.Values("Proxy-Authenticate")
	if len(values) == 0 || len(values) > maximumProxyChallenges {
		return ProxyCredentialChallenge{}, errProxyAuthentication
	}
	basic := false
	for _, value := range values {
		if len(value) == 0 || len(value) > maximumProxyChallengeBytes || strings.ContainsAny(value, "\x00\r\n") {
			return ProxyCredentialChallenge{}, errProxyAuthentication
		}
		trimmed := strings.TrimSpace(value)
		if strings.EqualFold(trimmed, "Basic") ||
			(len(trimmed) > len("Basic") && strings.EqualFold(trimmed[:len("Basic")], "Basic") &&
				(trimmed[len("Basic")] == ' ' || trimmed[len("Basic")] == '\t')) {
			basic = true
		}
	}
	return ProxyCredentialChallenge{
		targetURL: authority.targetURL, proxyURL: proxy, connectTarget: connectRequest.Host, basic: basic,
	}, nil
}
