package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// fakeServer is a minimal Streamable HTTP MCP server: initialize issues a new
// Mcp-Session-Id, requests with an unknown session get 404 (per the MCP spec),
// requests that don't accept both JSON and SSE get 406, and DELETE ends a session.
type fakeServer struct {
	mu       sync.Mutex
	next     int
	live     map[string]bool
	notified map[string]bool
	deleted  []string
	// sessionless makes initialize succeed without issuing a session id.
	sessionless bool
	inits       int
}

func (f *fakeServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	sid := r.Header.Get("Mcp-Session-Id")
	if r.Method == http.MethodDelete {
		f.deleted = append(f.deleted, sid)
		delete(f.live, sid)
		return
	}
	if r.Header.Get("Accept") != "application/json, text/event-stream" {
		w.WriteHeader(http.StatusNotAcceptable)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var rpc struct {
		Method string `json:"method"`
	}
	_ = json.Unmarshal(body, &rpc)
	switch {
	case rpc.Method == "initialize" && f.sessionless:
		f.inits++
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":0,"result":{}}`))
	case f.sessionless:
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	case rpc.Method == "initialize":
		f.inits++
		f.next++
		sid = fmt.Sprintf("s%d", f.next)
		f.live[sid] = true
		w.Header().Set("Mcp-Session-Id", sid)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":0,"result":{}}`))
	case !f.live[sid]:
		w.WriteHeader(http.StatusNotFound)
	case rpc.Method == "notifications/initialized":
		f.notified[sid] = true
		w.WriteHeader(http.StatusAccepted)
	default:
		// Reply SSE-framed, as Streamable HTTP servers may.
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"session\":%q}}\n\n", sid)
	}
}

func (f *fakeServer) deletedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deleted...)
}

func newTestProxy(t *testing.T) (*Proxy, *fakeServer) {
	t.Helper()
	fake := &fakeServer{live: map[string]bool{}, notified: map[string]bool{}}
	srv := httptest.NewServer(fake)
	p := New(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err := p.Configure(map[string]any{"transport": "http", "url": srv.URL}, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	t.Cleanup(func() {
		_ = p.Close()
		srv.Close()
	})
	return p, fake
}

func toolCall(t *testing.T, p *Proxy, sessionID string) string {
	t.Helper()
	params := map[string]any{"method": "tools/call", "params": map[string]any{"name": "x"}}
	if sessionID != "" {
		params["session_id"] = sessionID
	}
	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "mcp_request", Params: params})
	if err != nil {
		t.Fatalf("HandleRequest: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, resp.Data)
	}
	return resp.Data
}

func result(sid string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":{"session":%q}}`, sid)
}

func TestSession_EachCallerSessionGetsItsOwnUpstreamSession(t *testing.T) {
	p, fake := newTestProxy(t)

	a1 := toolCall(t, p, "conv-a")
	b := toolCall(t, p, "conv-b")
	a2 := toolCall(t, p, "conv-a")

	if a1 != result("s1") || a2 != result("s1") {
		t.Fatalf("conv-a should keep session s1, got %s then %s", a1, a2)
	}
	if b != result("s2") {
		t.Fatalf("conv-b should get its own session s2, got %s", b)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !fake.notified["s1"] || !fake.notified["s2"] {
		t.Fatalf("initialized notification not sent: %v", fake.notified)
	}
}

func TestSession_NoSessionIDSharesOneSession(t *testing.T) {
	p, _ := newTestProxy(t)
	if first, second := toolCall(t, p, ""), toolCall(t, p, ""); first != second {
		t.Fatalf("calls without session_id should share a session: %s vs %s", first, second)
	}
}

func TestSession_Upstream404ReinitializesAndRetries(t *testing.T) {
	p, fake := newTestProxy(t)
	toolCall(t, p, "conv")

	fake.mu.Lock()
	fake.live = map[string]bool{} // server restarted, forgot every session
	fake.mu.Unlock()

	if got := toolCall(t, p, "conv"); got != result("s2") {
		t.Fatalf("expected retry on fresh session s2, got %s", got)
	}
}

func TestSession_IdleSessionIsTerminatedAndReplaced(t *testing.T) {
	p, fake := newTestProxy(t)
	toolCall(t, p, "conv")

	p.sessionMu.Lock()
	p.sessions["conv"].lastUsed = time.Now().Add(-sessionIdleTTL - time.Second)
	p.sessionMu.Unlock()

	if got := toolCall(t, p, "conv"); got != result("s2") {
		t.Fatalf("idle session should be replaced, got %s", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for len(fake.deletedIDs()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if d := fake.deletedIDs(); len(d) != 1 || d[0] != "s1" {
		t.Fatalf("expected DELETE of s1, got %v", d)
	}
}

func TestSession_CloseTerminatesLiveSessions(t *testing.T) {
	p, fake := newTestProxy(t)
	toolCall(t, p, "conv-a")
	toolCall(t, p, "conv-b")

	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := fake.deletedIDs(); len(d) != 2 {
		t.Fatalf("Close should DELETE both sessions, got %v", d)
	}
}

func TestSessionGone(t *testing.T) {
	cases := []struct {
		name   string
		status int
		data   string
		sid    string
		want   bool
	}{
		{"404 with session", 404, "", "s1", true},
		{"400 mentioning session is not treated as gone", 400, "browser session not found", "s1", false},
		{"404 without session", 404, "", "", false},
		{"200", 200, "session", "s1", false},
	}
	for _, c := range cases {
		got := sessionGone(&proxy.ActionResponse{StatusCode: c.status, Data: c.data}, c.sid)
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSession_SessionlessServerIsInitializedOnce(t *testing.T) {
	p, fake := newTestProxy(t)
	fake.mu.Lock()
	fake.sessionless = true
	fake.mu.Unlock()

	for range 3 {
		toolCall(t, p, "conv")
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.inits != 1 {
		t.Fatalf("sessionless server should be initialized once, got %d", fake.inits)
	}
}

func TestSession_ClosedProxyOpensNoSession(t *testing.T) {
	p, fake := newTestProxy(t)
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := p.ensureSession(context.Background(), "conv"); err != errProxyClosed {
		t.Fatalf("expected errProxyClosed, got %v", err)
	}
	req := &proxy.ActionRequest{Params: map[string]any{"method": "tools/call", "session_id": "conv"}}
	if _, err := p.HandleRequest(context.Background(), req); !errors.Is(err, errProxyClosed) {
		t.Fatalf("request on a closed proxy should fail with errProxyClosed, got %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.inits != 0 {
		t.Fatalf("closed proxy should not initialize, got %d", fake.inits)
	}
}
