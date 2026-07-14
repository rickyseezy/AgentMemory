package setuphttp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/rickyseezy/AgentMemory/apps/launcher/internal/application/setupprogressapp"
)

func TestPF001SetupHTTPSSEReconnectEmitsStrictlyIncreasingBoundSnapshot(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{HeartbeatInterval: 100 * time.Millisecond})
	defer harness.close()
	session := harness.mustExchange(t)
	harness.authority.mu.Lock()
	harness.authority.current = setupSnapshot(t, harness.authority.binding, 3, setupprogressapp.StateRunning)
	harness.authority.mu.Unlock()
	response, reader, cancel := harness.openEvents(t, session, 2)
	defer cancel()
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status=%d headers=%v", response.StatusCode, response.Header)
	}
	block := readSSEBlock(t, reader)
	wantPrefix := "id: 3\nevent: snapshot\nretry: 1000\ndata: "
	if !strings.HasPrefix(block, wantPrefix) || !strings.Contains(block, `"sequence":3`) ||
		!strings.Contains(block, `"operationId":"operation-1"`) {
		t.Fatalf("event=%q", block)
	}
}

func TestPF001SetupHTTPSSEHeartbeatsWithinOneSecondAndHonorsCancellation(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{HeartbeatInterval: 100 * time.Millisecond})
	defer harness.close()
	session := harness.mustExchange(t)
	response, reader, cancel := harness.openEvents(t, session, 1)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	started := time.Now()
	block := readSSEBlock(t, reader)
	if block != ": heartbeat\n\n" || time.Since(started) > time.Second {
		t.Fatalf("heartbeat=%q elapsed=%s", block, time.Since(started))
	}
	cancel()
	select {
	case <-harness.authority.cancelled:
	case <-time.After(time.Second):
		t.Fatal("backend wait context was not cancelled")
	}
	deadline := time.Now().Add(time.Second)
	for harness.authority.waiting.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if harness.authority.waiting.Load() != 0 {
		t.Fatal("SSE backend wait leaked")
	}
}

func TestPF001SetupHTTPSSETerminalEventClosesBothListeners(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{HeartbeatInterval: 50 * time.Millisecond})
	session := harness.mustExchange(t)
	harness.authority.mu.Lock()
	harness.authority.current = setupSnapshot(t, harness.authority.binding, 2, setupprogressapp.StateReady)
	harness.authority.mu.Unlock()
	response, reader, cancel := harness.openEvents(t, session, 1)
	defer cancel()
	block := readSSEBlock(t, reader)
	if response.StatusCode != http.StatusOK || !strings.Contains(block, `"state":"ready"`) {
		t.Fatalf("status=%d event=%q", response.StatusCode, block)
	}
	select {
	case <-harness.server.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("terminal setup did not close server")
	}
	for _, origin := range []string{harness.launch.IPv4Origin(), harness.launch.IPv6Origin()} {
		request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, origin+"/", nil)
		client := &http.Client{Timeout: 200 * time.Millisecond}
		if response, err := client.Do(request); err == nil {
			_ = response.Body.Close()
			t.Fatalf("terminal listener still accepts %s", origin)
		}
	}
}

func TestPF001SetupHTTPSSERejectsBackendSequenceContradictionWithoutEvent(t *testing.T) {
	t.Parallel()
	harness := newSetupHarness(t, Config{HeartbeatInterval: 50 * time.Millisecond})
	defer harness.close()
	session := harness.mustExchange(t)
	// Sequence 1 is not after the authenticated reconnect cursor 2.
	harness.authority.next <- setupSnapshot(t, harness.authority.binding, 1, setupprogressapp.StateAwaitingConsent)
	response, reader, cancel := harness.openEvents(t, session, 2)
	defer cancel()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	block := readSSEBlock(t, reader)
	if strings.HasPrefix(block, "id:") || strings.Contains(block, "data:") {
		t.Fatalf("contradictory backend event emitted=%q", block)
	}
}

func (h *setupHarness) openEvents(
	t testing.TB,
	session sessionDocument,
	after uint64,
) (*http.Response, *bufio.Reader, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s%s?after=%d", h.launch.IPv4Origin(), eventsPath, after),
		nil,
	)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	request.Header.Set("Accept", "text/event-stream")
	request.Header.Set("Authorization", "AgentMemorySession "+session.SessionToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AgentMemory-CSRF", session.CSRFToken)
	h.apiHeaders(request)
	response, err := h.client.Do(request)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return response, bufio.NewReader(response.Body), func() {
		cancel()
		_ = response.Body.Close()
	}
}

func readSSEBlock(t testing.TB, reader *bufio.Reader) string {
	t.Helper()
	type result struct {
		value string
		err   error
	}
	resultChannel := make(chan result, 1)
	go func() {
		var builder strings.Builder
		for {
			line, err := reader.ReadString('\n')
			builder.WriteString(line)
			if err != nil || strings.HasSuffix(builder.String(), "\n\n") {
				resultChannel <- result{value: builder.String(), err: err}
				return
			}
		}
	}()
	select {
	case got := <-resultChannel:
		if got.err != nil && !errors.Is(got.err, io.EOF) {
			t.Fatalf("read SSE: %v", got.err)
		}
		return got.value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE block")
		return ""
	}
}
