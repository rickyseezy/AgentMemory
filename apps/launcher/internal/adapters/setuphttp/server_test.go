package setuphttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001SetupHTTPStartsDualLoopbackAndOpensFragmentCapability(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{})
	defer harness.close()
	if !strings.HasPrefix(harness.launch.IPv4Origin(), "http://127.0.0.1:") ||
		!strings.HasPrefix(harness.launch.IPv6Origin(), "http://[::1]:") ||
		harness.launch.IPv4Origin() == harness.launch.IPv6Origin() {
		t.Fatalf("launch=%+v", harness.launch)
	}
	opened, err := url.Parse(harness.opener.url)
	if err != nil {
		t.Fatal(err)
	}
	if opened.RawQuery != "" || opened.User != nil || opened.Path != "/" ||
		!strings.HasPrefix(opened.Fragment, "capability=") || strings.Contains(opened.String(), "?capability=") {
		t.Fatalf("unsafe browser URL=%q", opened)
	}
	fragment, err := url.ParseQuery(opened.Fragment)
	if err != nil || len(fragment) != 1 || !validToken(fragment.Get("capability")) {
		t.Fatalf("fragment=%v error=%v", fragment, err)
	}
	if harness.server.capabilityHash == ([32]byte{}) || harness.server.session != nil {
		t.Fatal("server did not retain only an unexchanged capability hash")
	}
}

func TestPF001SetupHTTPCapabilityIsOneUseUnderConcurrentExchange(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{})
	defer harness.close()
	capability := harness.capability(t)
	type result struct {
		status int
		body   []byte
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			response, body := harness.exchange(capability)
			results <- result{status: response.StatusCode, body: body}
		}()
	}
	successes, failures := 0, 0
	var session sessionDocument
	for range 2 {
		got := <-results
		switch got.status {
		case http.StatusOK:
			successes++
			if err := json.Unmarshal(got.body, &session); err != nil {
				t.Fatal(err)
			}
		case http.StatusUnauthorized, http.StatusGone:
			failures++
		default:
			t.Fatalf("status=%d body=%q", got.status, got.body)
		}
	}
	if successes != 1 || failures != 1 || !validToken(session.SessionToken) || !validToken(session.CSRFToken) {
		t.Fatalf("successes=%d failures=%d session=%+v", successes, failures, session)
	}
	if harness.server.session == nil || harness.server.session.tokenHash != tokenHash(session.SessionToken) ||
		harness.server.session.csrfHash != tokenHash(session.CSRFToken) {
		t.Fatal("server did not retain exact one-way session hashes")
	}
	response, _ := harness.exchange(capability)
	if response.StatusCode != http.StatusGone && response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status=%d", response.StatusCode)
	}
}

func TestPF001SetupHTTPRejectsHostOriginSessionCSRFFetchAndPrincipalDrift(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*setupHarness, *http.Request)
	}{
		{name: "host", mutate: func(_ *setupHarness, request *http.Request) { request.Host = "evil.example" }},
		{name: "origin", mutate: func(_ *setupHarness, request *http.Request) { request.Header.Set("Origin", "http://evil.example") }},
		{name: "fetch site", mutate: func(_ *setupHarness, request *http.Request) { request.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{name: "fetch mode", mutate: func(_ *setupHarness, request *http.Request) { request.Header.Set("Sec-Fetch-Mode", "navigate") }},
		{name: "fetch destination", mutate: func(_ *setupHarness, request *http.Request) { request.Header.Set("Sec-Fetch-Dest", "document") }},
		{name: "session", mutate: func(_ *setupHarness, request *http.Request) {
			request.Header.Set("Authorization", "AgentMemorySession "+strings.Repeat("z", 43))
		}},
		{name: "csrf", mutate: func(_ *setupHarness, request *http.Request) {
			request.Header.Set("X-AgentMemory-CSRF", strings.Repeat("z", 43))
		}},
		{name: "session binding", mutate: func(harness *setupHarness, _ *http.Request) {
			harness.server.stateMu.Lock()
			harness.server.session.binding = setupprogressapp.Binding{}
			harness.server.stateMu.Unlock()
		}},
		{name: "principal", mutate: func(harness *setupHarness, _ *http.Request) {
			harness.principal.current = install.DigestBytes([]byte("changed-principal"))
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newSetupHarness(t, Config{})
			defer harness.close()
			session := harness.mustExchange(t)
			request := harness.commandRequest(session, validCommandJSON())
			test.mutate(harness, request)
			response, _ := harness.do(request)
			if response.StatusCode == http.StatusOK {
				t.Fatal("authority drift accepted")
			}
		})
	}
}

func TestPF001SetupHTTPSessionExpiryFailsClosed(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{SessionLifetime: time.Second})
	defer harness.close()
	session := harness.mustExchange(t)
	harness.clock.advance(2 * time.Second)
	response, _ := harness.do(harness.commandRequest(session, validCommandJSON()))
	if response.StatusCode != http.StatusGone {
		t.Fatalf("expired status=%d", response.StatusCode)
	}
}

func TestPF001SetupHTTPRejectsUnknownMethodMediaFramingBodyAndRate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{name: "method", mutate: func(request *http.Request) { request.Method = http.MethodPut }},
		{name: "content type", mutate: func(request *http.Request) { request.Header.Set("Content-Type", "application/json; charset=utf-8") }},
		{name: "accept", mutate: func(request *http.Request) { request.Header.Set("Accept", "*/*") }},
		{name: "transfer encoding", mutate: func(request *http.Request) {
			request.TransferEncoding = []string{"chunked"}
			request.ContentLength = -1
		}},
		{name: "duplicate length", mutate: func(request *http.Request) { request.Header["Content-Length"] = []string{"181", "181"} }},
		{name: "nonnumeric length", mutate: func(request *http.Request) { request.Header["Content-Length"] = []string{"x"} }},
		{name: "unknown field", mutate: func(request *http.Request) {
			replaceRequestBody(request, `{"contractVersion":1,"decision":"accept","idempotencyKey":"018f47ab-9a77-7df0-8f4c-3e934c0a7d41","planDigest":"`+strings.Repeat("a", 64)+`","secret":"x"}`)
		}},
		{name: "duplicate field", mutate: func(request *http.Request) {
			replaceRequestBody(request, strings.Replace(validCommandJSON(), `"decision":"accept"`, `"decision":"accept","decision":"accept"`, 1))
		}},
		{name: "noncanonical order", mutate: func(request *http.Request) {
			replaceRequestBody(request, `{"decision":"accept","contractVersion":1,"idempotencyKey":"018f47ab-9a77-7df0-8f4c-3e934c0a7d41","planDigest":"`+strings.Repeat("a", 64)+`"}`)
		}},
		{name: "oversized", mutate: func(request *http.Request) { replaceRequestBody(request, strings.Repeat("x", maximumDynamicBytes+1)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newSetupHarness(t, Config{})
			defer harness.close()
			session := harness.mustExchange(t)
			request := harness.commandRequest(session, validCommandJSON())
			test.mutate(request)
			recorder := httptest.NewRecorder()
			harness.server.ServeHTTP(recorder, request)
			if recorder.Code == http.StatusOK {
				t.Fatalf("invalid request accepted body=%q", recorder.Body.Bytes())
			}
		})
	}

	harness := newSetupHarness(t, Config{RequestsPerSecond: 1})
	defer harness.close()
	first, _ := harness.exchange(harness.capability(t))
	second, _ := harness.exchange(strings.Repeat("z", 43))
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("rate statuses=%d,%d", first.StatusCode, second.StatusCode)
	}
}

func TestPF001SetupHTTPCommandsArePlanBoundCanonicalAndDurablyIdempotent(t *testing.T) {
	t.Parallel()
	for _, decision := range []string{"accept", "decline", "retry", "cancel"} {
		t.Run(decision, func(t *testing.T) {
			harness := newSetupHarness(t, Config{})
			defer harness.close()
			session := harness.mustExchange(t)
			body := strings.Replace(validCommandJSON(), `"decision":"accept"`, `"decision":"`+decision+`"`, 1)
			body = strings.Replace(body, "018f47ab-9a77-7df0-8f4c-3e934c0a7d41", commandUUID(decision), 1)
			response, responseBody := harness.do(harness.commandRequest(session, body))
			if response.StatusCode != http.StatusOK || !bytes.Contains(responseBody, []byte(`"contractVersion":1`)) {
				t.Fatalf("decision=%s status=%d body=%s", decision, response.StatusCode, responseBody)
			}
		})
	}

	harness := newSetupHarness(t, Config{})
	defer harness.close()
	session := harness.mustExchange(t)
	body := strings.Replace(validCommandJSON(), strings.Repeat("a", 64), strings.Repeat("b", 64), 1)
	response, _ := harness.do(harness.commandRequest(session, body))
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("foreign plan status=%d", response.StatusCode)
	}

	idempotent := validCommandJSON()
	first, firstBody := harness.do(harness.commandRequest(session, idempotent))
	second, secondBody := harness.do(harness.commandRequest(session, idempotent))
	if first.StatusCode != http.StatusOK || second.StatusCode != http.StatusOK || !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("idempotent statuses=%d,%d equal=%t", first.StatusCode, second.StatusCode, bytes.Equal(firstBody, secondBody))
	}
}

func TestPF001SetupHTTPConcurrentCompetingDecisionsReturnOneConflict(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{})
	defer harness.close()
	session := harness.mustExchange(t)
	results := make(chan int, 2)
	for index, decision := range []string{"accept", "retry"} {
		body := strings.Replace(validCommandJSON(), `"decision":"accept"`, `"decision":"`+decision+`"`, 1)
		body = strings.Replace(body, "018f47ab-9a77-7df0-8f4c-3e934c0a7d41", commandUUID(string(rune('a'+index))), 1)
		go func(commandBody string) {
			response, _ := harness.do(harness.commandRequest(session, commandBody))
			results <- response.StatusCode
		}(body)
	}
	statuses := []int{<-results, <-results}
	if !containsStatus(statuses, http.StatusOK) || !containsStatus(statuses, http.StatusConflict) {
		t.Fatalf("statuses=%v", statuses)
	}
}

func TestPF001SetupHTTPAssetsAreExactEmbeddedBytesWithSecurityHeaders(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{})
	defer harness.close()
	assets := []struct {
		path     string
		diskPath string
		accept   string
		mode     string
		dest     string
	}{
		{path: "/", diskPath: "assets/index.html", accept: "text/html", mode: "navigate", dest: "document"},
		{path: "/assets/index-qF1Dmln1.js", diskPath: "assets/assets/index-qF1Dmln1.js", accept: "*/*", mode: "cors", dest: "script"},
		{path: "/assets/style-CamGnmCt.css", diskPath: "assets/assets/style-CamGnmCt.css", accept: "text/css", mode: "no-cors", dest: "style"},
	}
	for _, asset := range assets {
		request, err := http.NewRequestWithContext(
			context.Background(), http.MethodGet, harness.launch.IPv4Origin()+asset.path, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Accept", asset.accept)
		request.Header.Set("Sec-Fetch-Site", map[bool]string{true: "none", false: "same-origin"}[asset.path == "/"])
		request.Header.Set("Sec-Fetch-Mode", asset.mode)
		request.Header.Set("Sec-Fetch-Dest", asset.dest)
		if asset.path == "/" {
			request.Header.Set("Sec-Fetch-User", "?1")
		}
		response, body := harness.do(request)
		expected, err := os.ReadFile(filepath.Join(".", asset.diskPath))
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || !bytes.Equal(body, expected) ||
			response.Header.Get("Content-Security-Policy") != contentSecurityPolicy ||
			response.Header.Get("Cross-Origin-Embedder-Policy") != "require-corp" ||
			response.Header.Get("Cross-Origin-Opener-Policy") != "same-origin" ||
			response.Header.Get("X-Content-Type-Options") != "nosniff" ||
			response.Header.Get("Referrer-Policy") != "no-referrer" ||
			response.Header.Get("Cache-Control") != "no-store" ||
			response.Header.Get("Permissions-Policy") != permissionsPolicy {
			t.Fatalf("asset=%s status=%d headers=%v exact=%t", asset.path, response.StatusCode, response.Header, bytes.Equal(body, expected))
		}
	}
	request, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet, harness.launch.IPv4Origin()+"/", nil,
	)
	request.Header.Set("Accept", "text/html")
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	response, _ := harness.do(request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("OS-opened navigation without Sec-Fetch-User status=%d", response.StatusCode)
	}
	request, _ = http.NewRequestWithContext(
		context.Background(), http.MethodGet, harness.launch.IPv4Origin()+"/", nil,
	)
	request.Header.Set("Accept", "application/x-text/html-invalid")
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	response, _ = harness.do(request)
	if response.StatusCode == http.StatusOK {
		t.Fatal("substring-only HTML Accept value was accepted")
	}
	request, _ = http.NewRequestWithContext(
		context.Background(), http.MethodGet, harness.launch.IPv4Origin()+"/assets/../index.html", nil,
	)
	response, _ = harness.do(request)
	if response.StatusCode == http.StatusOK || response.StatusCode/100 == 3 {
		t.Fatalf("traversal status=%d", response.StatusCode)
	}
}

func FuzzPF001SetupHTTPStrictRequestParsers(f *testing.F) {
	f.Add([]byte(validCommandJSON()), "12", "0")
	f.Add([]byte(`{"decision":"accept","decision":"decline"}`), "x", "-1")
	f.Fuzz(func(_ *testing.T, body []byte, contentLength string, after string) {
		if len(body) > maximumDynamicBytes+1 {
			body = body[:maximumDynamicBytes+1]
		}
		var command commandDocument
		_ = decodeCanonicalJSON(body, &command)
		_ = parseContentLengthValues([]string{contentLength}, int64(len(body)))
		_, _ = parseAfter(after)
	})
}

type setupHarness struct {
	t           *testing.T
	server      *Server
	launch      Launch
	application *setupprogressapp.Application
	authority   *setupAuthority
	principal   *principalStub
	opener      *openerStub
	clock       *clockStub
	client      *http.Client
}

func newSetupHarness(t *testing.T, config Config) *setupHarness {
	t.Helper()
	now := time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)
	clock := &clockStub{now: now}
	if config.ExpiresAt.IsZero() {
		config.ExpiresAt = now.Add(time.Hour)
	}
	binding := setupBinding(t)
	authority := newSetupAuthority(t, binding)
	application, err := setupprogressapp.NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	principal := &principalStub{current: install.DigestBytes([]byte("principal-1"))}
	opener := &openerStub{}
	server, err := NewServer(config, Dependencies{
		Application: application, PrincipalVerifier: principal, BrowserOpener: opener, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	launch, err := server.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return &setupHarness{
		t: t, server: server, launch: launch, application: application, authority: authority,
		principal: principal, opener: opener, clock: clock, client: &http.Client{Timeout: 3 * time.Second},
	}
}

func (h *setupHarness) close() {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = h.server.Close(ctx)
}

func (h *setupHarness) capability(t testing.TB) string {
	t.Helper()
	parsed, err := url.Parse(h.opener.url)
	if err != nil {
		t.Fatal(err)
	}
	values, err := url.ParseQuery(parsed.Fragment)
	if err != nil {
		t.Fatal(err)
	}
	return values.Get("capability")
}

func (h *setupHarness) exchange(capability string) (*http.Response, []byte) {
	h.t.Helper()
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, h.launch.IPv4Origin()+sessionPath,
		strings.NewReader(`{"contractVersion":1}`),
	)
	if err != nil {
		h.t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "AgentMemorySetup "+capability)
	request.Header.Set("Content-Type", "application/json")
	h.apiHeaders(request)
	return h.do(request)
}

func (h *setupHarness) mustExchange(t testing.TB) sessionDocument {
	t.Helper()
	response, body := h.exchange(h.capability(t))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", response.StatusCode, body)
	}
	var session sessionDocument
	if err := json.Unmarshal(body, &session); err != nil {
		t.Fatal(err)
	}
	return session
}

func (h *setupHarness) commandRequest(session sessionDocument, body string) *http.Request {
	h.t.Helper()
	request, err := http.NewRequestWithContext(
		context.Background(), http.MethodPost, h.launch.IPv4Origin()+commandsPath, strings.NewReader(body),
	)
	if err != nil {
		h.t.Fatal(err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "AgentMemorySession "+session.SessionToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AgentMemory-CSRF", session.CSRFToken)
	h.apiHeaders(request)
	return request
}

func (h *setupHarness) apiHeaders(request *http.Request) {
	request.Header.Set("Origin", h.launch.IPv4Origin())
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Sec-Fetch-Mode", "cors")
	request.Header.Set("Sec-Fetch-Dest", "empty")
}

func (h *setupHarness) do(request *http.Request) (*http.Response, []byte) {
	h.t.Helper()
	response, err := h.client.Do(request)
	if err != nil {
		h.t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	return response, body
}

type setupAuthority struct {
	t             testing.TB
	binding       setupprogressapp.Binding
	mu            sync.Mutex
	current       setupprogressapp.Snapshot
	currentError  error
	waitError     error
	decisionError error
	receipts      map[string]setupprogressapp.DecisionReceipt
	decision      setupprogressapp.Decision
	next          chan setupprogressapp.Snapshot
	waiting       atomic.Int64
	cancelled     chan struct{}
}

func newSetupAuthority(t testing.TB, binding setupprogressapp.Binding) *setupAuthority {
	t.Helper()
	return &setupAuthority{
		t: t, binding: binding, current: setupSnapshot(t, binding, 1, setupprogressapp.StateAwaitingConsent),
		receipts: make(map[string]setupprogressapp.DecisionReceipt), next: make(chan setupprogressapp.Snapshot, 8),
		cancelled: make(chan struct{}, 8),
	}
}

func (a *setupAuthority) CurrentSnapshot(context.Context, setupprogressapp.Binding) (setupprogressapp.Snapshot, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current, a.currentError
}

func (a *setupAuthority) WaitSnapshotAfter(ctx context.Context, _ setupprogressapp.Binding, after uint64) (setupprogressapp.Snapshot, error) {
	a.waiting.Add(1)
	defer a.waiting.Add(-1)
	a.mu.Lock()
	current := a.current
	waitError := a.waitError
	a.mu.Unlock()
	if waitError != nil {
		return setupprogressapp.Snapshot{}, waitError
	}
	if current.Sequence() > after {
		return current, nil
	}
	select {
	case snapshot := <-a.next:
		a.mu.Lock()
		a.current = snapshot
		a.mu.Unlock()
		return snapshot, nil
	case <-ctx.Done():
		select {
		case a.cancelled <- struct{}{}:
		default:
		}
		return setupprogressapp.Snapshot{}, ctx.Err()
	}
}

func (a *setupAuthority) ApplyDecision(_ context.Context, command setupprogressapp.DecisionCommand) (setupprogressapp.DecisionReceipt, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.decisionError != nil {
		return setupprogressapp.DecisionReceipt{}, a.decisionError
	}
	if receipt, present := a.receipts[command.IdempotencyKey()]; present {
		return receipt, nil
	}
	if a.decision != "" && a.decision != command.Decision() {
		return setupprogressapp.DecisionReceipt{}, setupprogressapp.ErrAuthorityConflict
	}
	a.decision = command.Decision()
	state := setupprogressapp.StateRunning
	if command.Decision() == setupprogressapp.DecisionDecline || command.Decision() == setupprogressapp.DecisionCancel {
		state = setupprogressapp.StateCancelled
	}
	a.current = setupSnapshot(a.t, a.binding, a.current.Sequence()+1, state)
	receipt, err := setupprogressapp.NewDecisionReceipt(command.IdempotencyKey(), command.Decision(), a.current)
	if err != nil {
		return setupprogressapp.DecisionReceipt{}, err
	}
	a.receipts[command.IdempotencyKey()] = receipt
	return receipt, nil
}

type principalStub struct {
	mu      sync.Mutex
	current install.Digest
	err     error
}

func (p *principalStub) CurrentPrincipal(context.Context) (install.Digest, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current, p.err
}

type openerStub struct {
	mu  sync.Mutex
	url string
	err error
}

func (o *openerStub) Open(_ context.Context, target string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.url = target
	return o.err
}

type clockStub struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clockStub) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clockStub) advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func setupBinding(t testing.TB) setupprogressapp.Binding {
	t.Helper()
	operation, _ := install.NewOperationID("operation-1")
	plan, _ := install.ParsePlanDigest(strings.Repeat("a", 64))
	binding, err := setupprogressapp.NewBinding(operation, plan)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}

func setupSnapshot(
	t testing.TB,
	binding setupprogressapp.Binding,
	sequence uint64,
	state setupprogressapp.State,
) setupprogressapp.Snapshot {
	t.Helper()
	message, action := setupprogressapp.MessagePreparingRuntime, setupprogressapp.ActionCancel
	var consent *setupprogressapp.ConsentInput
	if state == setupprogressapp.StateAwaitingConsent {
		message = setupprogressapp.MessageAwaitingConsent
		consent = &setupprogressapp.ConsentInput{
			TermsTitle:  "Docker Subscription Service Agreement",
			TermsURL:    "https://www.docker.com/legal/docker-subscription-service-agreement/",
			TermsDigest: strings.Repeat("b", 64), DownloadBytes: 1024, ExpandedBytes: 4096,
			Changes: []string{"Install the verified local runtime"},
		}
	}
	if state == setupprogressapp.StateReady {
		message, action = setupprogressapp.MessageReady, setupprogressapp.ActionNone
	}
	if state == setupprogressapp.StateCancelled {
		message, action = setupprogressapp.MessageCancelled, setupprogressapp.ActionNone
	}
	snapshot, err := setupprogressapp.NewSnapshot(setupprogressapp.SnapshotInput{
		Sequence: sequence, OperationID: binding.OperationID(), PlanDigest: binding.PlanDigest(),
		State: state, Phase: setupprogressapp.PhaseEnsureContainerRuntime, MessageKey: message,
		Progress:   setupprogressapp.Progress{CompletedStages: 1, TotalStages: 14, TotalBytes: 1024},
		SafeAction: action, Consent: consent,
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func validCommandJSON() string {
	return `{"contractVersion":1,"decision":"accept","idempotencyKey":"018f47ab-9a77-7df0-8f4c-3e934c0a7d41","planDigest":"` + strings.Repeat("a", 64) + `"}`
}

func commandUUID(seed string) string {
	hex := "a"
	if seed != "" {
		candidate := seed[0]
		if candidate >= '0' && candidate <= '9' || candidate >= 'a' && candidate <= 'f' {
			hex = string(candidate)
		}
	}
	return "018f47ab-9a77-7df0-8f4c-3e934c0a7d4" + hex
}

func replaceRequestBody(request *http.Request, body string) {
	request.Body = io.NopCloser(strings.NewReader(body))
	request.ContentLength = int64(len(body))
}

func containsStatus(values []int, expected int) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

var _ = bufio.ErrInvalidUnreadByte
var _ = errors.New
