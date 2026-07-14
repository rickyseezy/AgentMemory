package setuphttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/domain/install"
)

func TestPF001SetupHTTPConstructorRejectsEveryInvalidDependencyAndPolicy(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)
	validConfig := Config{ExpiresAt: now.Add(time.Hour)}
	validDependencies := setupDependencies(t, now)
	tests := []struct {
		name   string
		config Config
		deps   Dependencies
	}{
		{name: "expiry", config: Config{}, deps: validDependencies},
		{name: "request timeout", config: Config{ExpiresAt: validConfig.ExpiresAt, RequestTimeout: 2 * time.Minute}, deps: validDependencies},
		{name: "session lifetime", config: Config{ExpiresAt: validConfig.ExpiresAt, SessionLifetime: 2 * time.Hour}, deps: validDependencies},
		{name: "heartbeat", config: Config{ExpiresAt: validConfig.ExpiresAt, HeartbeatInterval: 2 * time.Second}, deps: validDependencies},
		{name: "concurrency", config: Config{ExpiresAt: validConfig.ExpiresAt, MaximumConcurrentRequests: 257}, deps: validDependencies},
		{name: "rate", config: Config{ExpiresAt: validConfig.ExpiresAt, RequestsPerSecond: 4097}, deps: validDependencies},
		{name: "application", config: validConfig, deps: editDependencies(validDependencies, func(value *Dependencies) { value.Application = nil })},
		{name: "principal", config: validConfig, deps: editDependencies(validDependencies, func(value *Dependencies) { value.PrincipalVerifier = nil })},
		{name: "opener", config: validConfig, deps: editDependencies(validDependencies, func(value *Dependencies) { value.BrowserOpener = nil })},
		{name: "clock", config: validConfig, deps: editDependencies(validDependencies, func(value *Dependencies) { value.Clock = nil })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewServer(test.config, test.deps); err == nil {
				t.Fatal("invalid server accepted")
			}
		})
	}
	var typedNilPrincipal *principalStub
	dependencies := validDependencies
	dependencies.PrincipalVerifier = typedNilPrincipal
	if _, err := NewServer(validConfig, dependencies); err == nil {
		t.Fatal("typed-nil principal accepted")
	}
	for _, value := range []any{nil, (chan int)(nil), (func())(nil), (map[string]string)(nil), ([]byte)(nil), struct{}{}} {
		want := value == nil
		switch value.(type) {
		case chan int, func(), map[string]string, []byte:
			want = true
		}
		if got := nilDependency(value); got != want {
			t.Fatalf("nilDependency(%T)=%t", value, got)
		}
	}
}

func TestPF001SetupHTTPStartAndCloseFailureEdges(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)
	dependencies := setupDependencies(t, now)
	server, err := NewServer(Config{ExpiresAt: now.Add(time.Hour)}, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, err := server.Start(nil); err == nil {
		t.Fatal("nil start context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.Start(ctx); err == nil {
		t.Fatal("cancelled start accepted")
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-server.Done():
	default:
		t.Fatal("unstarted close did not close Done")
	}
	if _, err := server.Start(context.Background()); err == nil {
		t.Fatal("closed server restarted")
	}
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if err := server.Close(nil); err == nil {
		t.Fatal("nil close context accepted")
	}
	var absent *Server
	if _, err := absent.Start(context.Background()); err == nil {
		t.Fatal("nil server start accepted")
	}
	if err := absent.Close(context.Background()); err == nil {
		t.Fatal("nil server close accepted")
	}
	select {
	case <-absent.Done():
	default:
		t.Fatal("nil server Done was not closed")
	}

	expiredDependencies := setupDependencies(t, now)
	expiredDependencies.Clock.(*clockStub).advance(2 * time.Hour)
	expired, _ := NewServer(Config{ExpiresAt: now.Add(time.Hour)}, expiredDependencies)
	if _, err := expired.Start(context.Background()); err == nil {
		t.Fatal("expired server started")
	}

	principalDependencies := setupDependencies(t, now)
	principalDependencies.PrincipalVerifier.(*principalStub).err = errors.New("raw principal failure")
	principalFailure, _ := NewServer(Config{ExpiresAt: now.Add(time.Hour)}, principalDependencies)
	if _, err := principalFailure.Start(context.Background()); err == nil || strings.Contains(err.Error(), "raw") {
		t.Fatalf("principal error=%v", err)
	}

	openerDependencies := setupDependencies(t, now)
	openerDependencies.BrowserOpener.(*openerStub).err = errors.New("raw browser failure")
	openerFailure, _ := NewServer(Config{ExpiresAt: now.Add(time.Hour)}, openerDependencies)
	if _, err := openerFailure.Start(context.Background()); err == nil || strings.Contains(err.Error(), "raw") {
		t.Fatalf("opener error=%v", err)
	}
}

func TestPF001SetupHTTPOwnerCancellationClosesBothListeners(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)
	server, err := NewServer(Config{ExpiresAt: now.Add(time.Hour)}, setupDependencies(t, now))
	if err != nil {
		t.Fatal(err)
	}
	owner, cancelOwner := context.WithCancel(context.Background())
	launch, err := server.Start(owner)
	if err != nil {
		cancelOwner()
		t.Fatal(err)
	}
	cancelOwner()
	select {
	case <-server.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("owner cancellation did not stop setup listeners")
	}
	for _, origin := range []string{launch.IPv4Origin(), launch.IPv6Origin()} {
		request, requestError := http.NewRequestWithContext(context.Background(), http.MethodGet, origin+"/", nil)
		if requestError != nil {
			t.Fatal(requestError)
		}
		client := &http.Client{Timeout: 200 * time.Millisecond}
		if response, requestError := client.Do(request); requestError == nil {
			_ = response.Body.Close()
			t.Fatalf("cancelled owner listener still accepts %s", origin)
		}
	}
}

func TestPF001SetupHTTPParserAndFramingEdgeCoverage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		data []byte
	}{
		{name: "empty"},
		{name: "scalar", data: []byte(`1`)},
		{name: "array", data: []byte(`[]`)},
		{name: "trailing", data: []byte(`{"contractVersion":1}{}`)},
		{name: "unknown", data: []byte(`{"contractVersion":1,"unknown":true}`)},
		{name: "duplicate", data: []byte(`{"contractVersion":1,"contractVersion":1}`)},
		{name: "incomplete", data: []byte(`{"contractVersion":`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			var target sessionRequestDocument
			if err := decodeCanonicalJSON(test.data, &target); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
	if err := decodeCanonicalJSON([]byte(`{"contractVersion":1}`), nil); err == nil {
		t.Fatal("nil JSON target accepted")
	}
	for _, data := range [][]byte{
		[]byte(`{"a":[1,2,{"b":true}]}`),
		[]byte(`{"a":{"b":1,"b":2}}`),
		[]byte(`[1,2,3] trailing`),
	} {
		_ = rejectDuplicateJSONKeys(data)
	}
	for _, values := range []struct {
		headers []string
		length  int64
	}{
		{length: -1}, {headers: []string{"1", "1"}, length: 1},
		{headers: []string{"01"}, length: 1}, {headers: []string{"2"}, length: 1},
		{headers: []string{"65537"}, length: 65537},
	} {
		if err := parseContentLengthValues(values.headers, values.length); err == nil {
			t.Fatal("invalid Content-Length accepted")
		}
	}
	for _, value := range []string{"", "00", "+1", "-1", "9007199254740992", strings.Repeat("1", 17)} {
		if _, err := parseAfter(value); err == nil {
			t.Fatalf("invalid cursor accepted %q", value)
		}
	}

	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, commandsPath, &failingReader{})
	request.ContentLength = 1
	if err := readCanonicalBody(request, &commandDocument{}); err == nil {
		t.Fatal("body read failure accepted")
	}
	request = httptest.NewRequestWithContext(context.Background(), http.MethodPost, commandsPath, strings.NewReader(`{}`))
	request.ContentLength = 3
	if err := readCanonicalBody(request, &commandDocument{}); err == nil {
		t.Fatal("body length mismatch accepted")
	}
}

func TestPF001SetupHTTPHandlerClosedSurfaceAndConcurrencyCoverage(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{MaximumConcurrentRequests: 1})
	defer harness.close()
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/unknown", nil)
	request.Host = strings.TrimPrefix(harness.launch.IPv4Origin(), "http://")
	recorder := httptest.NewRecorder()
	harness.server.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown status=%d", recorder.Code)
	}

	harness.server.slots <- struct{}{}
	recorder = httptest.NewRecorder()
	harness.server.ServeHTTP(recorder, request)
	<-harness.server.slots
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("concurrency status=%d", recorder.Code)
	}

	var absent *Server
	recorder = httptest.NewRecorder()
	absent.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("nil server status=%d", recorder.Code)
	}

	for _, test := range []struct {
		code setupprogressapp.ErrorCode
		want int
	}{
		{code: setupprogressapp.ErrorInvalidArgument, want: http.StatusBadRequest},
		{code: setupprogressapp.ErrorConflict, want: http.StatusConflict},
		{code: setupprogressapp.ErrorDeadline, want: http.StatusGatewayTimeout},
		{code: setupprogressapp.ErrorIntegrity, want: http.StatusServiceUnavailable},
		{code: setupprogressapp.ErrorUnavailable, want: http.StatusServiceUnavailable},
	} {
		applicationError := setupApplicationErrorForCode(t, test.code)
		recorder = httptest.NewRecorder()
		rejectApplicationError(recorder, applicationError)
		if recorder.Code != test.want || strings.Contains(recorder.Body.String(), "secret") {
			t.Fatalf("error=%v status=%d body=%q", applicationError, recorder.Code, recorder.Body.String())
		}
	}
}

func TestPF001SetupHTTPTokenAndHeaderEdgeCoverage(t *testing.T) {
	t.Parallel()
	var absent *Server
	//lint:ignore SA1012 Deliberate nil-context boundary test.
	//nolint:staticcheck // SA1012: security regression fixture; owner=security expiry=2027-07-14.
	if _, ok := absent.verifyCurrentPrincipal(nil); ok {
		t.Fatal("nil principal boundary accepted")
	}
	token, err := randomToken()
	if err != nil || !validToken(token) {
		t.Fatalf("token=%q error=%v", token, err)
	}
	for _, value := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 43), strings.Repeat("!", 43)} {
		if validToken(value) {
			t.Fatalf("invalid token accepted %q", value)
		}
	}
	header := make(http.Header)
	header["X-Test"] = []string{"a", "b"}
	if _, ok := exactSingleHeader(header, "X-Test"); ok {
		t.Fatal("duplicate header accepted")
	}
	header["X-Test"] = []string{"bad\nvalue"}
	if _, ok := exactSingleHeader(header, "X-Test"); ok {
		t.Fatal("newline header accepted")
	}
	if err := readCanonicalBody(nil, &commandDocument{}); err == nil {
		t.Fatal("nil request body accepted")
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodPost, commandsPath, nil)
	if err := readCanonicalBody(request, &commandDocument{}); err == nil {
		t.Fatal("absent request body accepted")
	}
}

func TestPF001SetupHTTPExchangeFailureAndTerminalCoverage(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name       string
		mutate     func(*setupHarness)
		capability func(*setupHarness, testing.TB) string
		body       string
		want       int
	}{
		{name: "invalid contract", body: `{"contractVersion":2}`, want: http.StatusBadRequest},
		{name: "missing authorization", capability: func(*setupHarness, testing.TB) string { return "" }, want: http.StatusUnauthorized},
		{name: "foreign capability", capability: func(*setupHarness, testing.TB) string { return strings.Repeat("z", 43) }, want: http.StatusUnauthorized},
		{name: "principal unavailable", mutate: func(harness *setupHarness) { harness.principal.err = errors.New("raw") }, want: http.StatusForbidden},
		{name: "backend unavailable", mutate: func(harness *setupHarness) { harness.authority.currentError = errors.New("raw") }, want: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newSetupHarness(t, Config{})
			defer harness.close()
			if test.mutate != nil {
				test.mutate(harness)
			}
			capability := harness.capability(t)
			if test.capability != nil {
				capability = test.capability(harness, t)
			}
			request, err := http.NewRequestWithContext(
				context.Background(), http.MethodPost, harness.launch.IPv4Origin()+sessionPath,
				strings.NewReader(map[bool]string{true: test.body, false: `{"contractVersion":1}`}[test.body != ""]),
			)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Accept", "application/json")
			if capability != "" {
				request.Header.Set("Authorization", "AgentMemorySetup "+capability)
			}
			request.Header.Set("Content-Type", "application/json")
			harness.apiHeaders(request)
			response, _ := harness.do(request)
			if response.StatusCode != test.want {
				t.Fatalf("status=%d want=%d", response.StatusCode, test.want)
			}
		})
	}

	harness := newSetupHarness(t, Config{})
	harness.authority.mu.Lock()
	harness.authority.current = setupSnapshot(t, harness.authority.binding, 2, setupprogressapp.StateReady)
	harness.authority.mu.Unlock()
	response, _ := harness.exchange(harness.capability(t))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("terminal exchange status=%d", response.StatusCode)
	}
	select {
	case <-harness.server.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("terminal exchange did not stop listeners")
	}
}

func TestPF001SetupHTTPCommandAndEventFailureCoverage(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{HeartbeatInterval: 50 * time.Millisecond})
	defer harness.close()
	session := harness.mustExchange(t)

	request := harness.commandRequest(session, `{"contractVersion":2,"decision":"accept","idempotencyKey":"018f47ab-9a77-7df0-8f4c-3e934c0a7d41","planDigest":"`+strings.Repeat("a", 64)+`"}`)
	response, _ := harness.do(request)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("contract status=%d", response.StatusCode)
	}
	harness.authority.mu.Lock()
	harness.authority.decisionError = setupprogressapp.ErrAuthorityConflict
	harness.authority.mu.Unlock()
	response, _ = harness.do(harness.commandRequest(session, validCommandJSON()))
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("decision conflict status=%d", response.StatusCode)
	}

	for _, target := range []string{
		harness.launch.IPv4Origin() + eventsPath,
		harness.launch.IPv4Origin() + eventsPath + "?after=1&after=2",
		harness.launch.IPv4Origin() + eventsPath + "?after=bad",
	} {
		request, _ = http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		request.Header.Set("Accept", "text/event-stream")
		request.Header.Set("Authorization", "AgentMemorySession "+session.SessionToken)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-AgentMemory-CSRF", session.CSRFToken)
		harness.apiHeaders(request)
		response, _ = harness.do(request)
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("target=%s status=%d", target, response.StatusCode)
		}
	}

	response, reader, cancel := harness.openEvents(t, session, 1)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("events status=%d", response.StatusCode)
	}
	harness.principal.mu.Lock()
	harness.principal.current = install.DigestBytes([]byte("changed"))
	harness.principal.mu.Unlock()
	block := readSSEBlock(t, reader)
	if block == ": heartbeat\n\n" {
		block = readSSEBlock(t, reader)
	}
	cancel()
	if block != ": closed\n\n" {
		t.Fatalf("principal-drift event=%q", block)
	}
}

func TestPF001SetupHTTPAssetMethodAndOriginFailures(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{})
	defer harness.close()
	for _, method := range []string{http.MethodPost, http.MethodHead} {
		request, _ := http.NewRequestWithContext(
			context.Background(), method, harness.launch.IPv4Origin()+"/", nil,
		)
		request.Header.Set("Accept", "text/html")
		request.Header.Set("Sec-Fetch-Site", "none")
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Sec-Fetch-Dest", "document")
		request.Header.Set("Sec-Fetch-User", "?1")
		response, _ := harness.do(request)
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("method=%s status=%d", method, response.StatusCode)
		}
	}
	request, _ := http.NewRequestWithContext(
		context.Background(), http.MethodGet, harness.launch.IPv4Origin()+"/assets/index-qF1Dmln1.js", nil,
	)
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Origin", "http://evil.example")
	request.Header.Set("Sec-Fetch-Site", "same-origin")
	request.Header.Set("Sec-Fetch-Mode", "cors")
	request.Header.Set("Sec-Fetch-Dest", "script")
	response, _ := harness.do(request)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("asset origin status=%d", response.StatusCode)
	}
	request, _ = http.NewRequestWithContext(
		context.Background(), http.MethodGet, harness.launch.IPv4Origin()+"/", nil,
	)
	request.Header.Set("Accept", "text/html")
	request.Header.Set("Sec-Fetch-Site", "none")
	request.Header.Set("Sec-Fetch-Mode", "navigate")
	request.Header.Set("Sec-Fetch-Dest", "document")
	request.Header.Set("Sec-Fetch-User", "?0")
	response, _ = harness.do(request)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("invalid Sec-Fetch-User status=%d", response.StatusCode)
	}
}

func setupDependencies(t testing.TB, now time.Time) Dependencies {
	t.Helper()
	binding := setupBinding(t)
	authority := newSetupAuthority(t, binding)
	application, err := setupprogressapp.NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	return Dependencies{
		Application:       application,
		PrincipalVerifier: &principalStub{current: install.DigestBytes([]byte("principal"))},
		BrowserOpener:     &openerStub{}, Clock: &clockStub{now: now},
	}
}

func editDependencies(value Dependencies, edit func(*Dependencies)) Dependencies {
	edit(&value)
	return value
}

func setupApplicationErrorForCode(t testing.TB, code setupprogressapp.ErrorCode) error {
	t.Helper()
	binding := setupBinding(t)
	authority := newSetupAuthority(t, binding)
	application, err := setupprogressapp.NewApplication(binding, authority, authority)
	if err != nil {
		t.Fatal(err)
	}
	switch code {
	case setupprogressapp.ErrorInvalidArgument:
		_, err = application.Decide(context.Background(), setupprogressapp.DecisionInput{})
	case setupprogressapp.ErrorDeadline:
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err = application.Current(ctx)
	case setupprogressapp.ErrorConflict:
		authority.decision = setupprogressapp.DecisionAccept
		_, err = application.Decide(context.Background(), setupprogressapp.DecisionInput{
			PlanDigest: binding.PlanDigest().String(), Decision: setupprogressapp.DecisionRetry,
			IdempotencyKey: "018f47ab-9a77-7df0-8f4c-3e934c0a7d41",
		})
	case setupprogressapp.ErrorIntegrity:
		foreignOperation, _ := install.NewOperationID("foreign")
		foreignBinding, _ := setupprogressapp.NewBinding(foreignOperation, binding.PlanDigest())
		authority.current = setupSnapshot(t, foreignBinding, 1, setupprogressapp.StateRunning)
		_, err = application.Current(context.Background())
	case setupprogressapp.ErrorUnavailable:
		failing := &failingSetupAuthority{err: errors.New("raw secret")}
		application, _ = setupprogressapp.NewApplication(binding, failing, failing)
		_, err = application.Current(context.Background())
	}
	return err
}

type failingSetupAuthority struct{ err error }

func (a *failingSetupAuthority) CurrentSnapshot(context.Context, setupprogressapp.Binding) (setupprogressapp.Snapshot, error) {
	return setupprogressapp.Snapshot{}, a.err
}

func (a *failingSetupAuthority) WaitSnapshotAfter(context.Context, setupprogressapp.Binding, uint64) (setupprogressapp.Snapshot, error) {
	return setupprogressapp.Snapshot{}, a.err
}

func (a *failingSetupAuthority) ApplyDecision(context.Context, setupprogressapp.DecisionCommand) (setupprogressapp.DecisionReceipt, error) {
	return setupprogressapp.DecisionReceipt{}, a.err
}

type failingReader struct{}

func (*failingReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

var _ io.Reader = (*failingReader)(nil)
