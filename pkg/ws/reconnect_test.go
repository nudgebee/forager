package ws

import (
	"context"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestReconnectWaitBounds(t *testing.T) {
	const base, limit = 3 * time.Second, 30 * time.Second
	highest := func(n int64) int64 { return n - 1 }
	for attempt, want := range []time.Duration{3 * time.Second, 6 * time.Second, 12 * time.Second, 24 * time.Second, 30 * time.Second, 30 * time.Second} {
		if got := reconnectWait(base, limit, attempt, highest); got != want {
			t.Errorf("attempt %d: longest wait = %v, want %v", attempt, got, want)
		}
		if got := reconnectWait(base, limit, attempt, func(int64) int64 { return 0 }); got != 0 {
			t.Errorf("attempt %d: shortest wait = %v, want 0", attempt, got)
		}
	}
	// Doubling must not overflow however many attempts have failed.
	if got := reconnectWait(base, limit, 1000, highest); got != limit {
		t.Errorf("attempt 1000: longest wait = %v, want %v", got, limit)
	}
	// A huge limit must not overflow the doubling or randN's bound.
	if got := reconnectWait(time.Hour, math.MaxInt64, 1000, highest); got != math.MaxInt64-1 {
		t.Errorf("max limit: longest wait = %v, want %v", got, time.Duration(math.MaxInt64-1))
	}
	if got := reconnectWait(0, limit, 0, highest); got != 0 {
		t.Errorf("zero base: wait = %v, want 0", got)
	}
}

// TestReconnectWaitSpreadsAgents pins the point of the jitter: agents that
// lose the relay at the same moment do not all redial it at the same moment.
func TestReconnectWaitSpreadsAgents(t *testing.T) {
	const agents = 200
	buckets := map[time.Duration]int{}
	for range agents {
		buckets[reconnectWait(3*time.Second, 30*time.Second, 0, rand.Int64N).Truncate(500*time.Millisecond)]++
	}
	for b, n := range buckets {
		if n > agents/2 {
			t.Fatalf("%d of %d agents redial within the same 500ms (%v); want them spread over the first 3s", n, agents, b)
		}
	}
	if len(buckets) < 5 {
		t.Fatalf("redials fell in %d half-second buckets, want spread over ~6", len(buckets))
	}
}

type fakeHandler struct{}

func (f *fakeHandler) HandleMessage(ctx context.Context, msg []byte) ([]byte, error) {
	return nil, nil
}

type errorCounterHandler struct {
	errors atomic.Int32
}

func (h *errorCounterHandler) Enabled(_ context.Context, level slog.Level) bool {
	return true
}

func (h *errorCounterHandler) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= slog.LevelError {
		h.errors.Add(1)
	}
	return nil
}

func (h *errorCounterHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *errorCounterHandler) WithGroup(name string) slog.Handler {
	return h
}

func TestSimulatedDisconnectLogsNoErrors(t *testing.T) {
	upgrader := websocket.Upgrader{}
	var connCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		num := connCount.Add(1)
		if num == 1 {
			// Read the greeting message, then immediately close connection abnormally to simulate drop
			_, _, _ = conn.ReadMessage()
			_ = conn.Close()
		} else {
			// Hold the connection open until test finishes
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}
	}))
	defer srv.Close()

	errCounter := &errorCounterHandler{}
	logger := slog.New(errCounter)

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	client := NewClient(wsURL, "key", "secret", &fakeHandler{}, logger, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = client.Run(ctx)
	}()

	// Wait until client reconnects (reaches connection 2)
	deadline := time.Now().Add(2 * time.Second)
	for connCount.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if connCount.Load() < 2 {
		t.Fatalf("client did not reconnect, connections = %d", connCount.Load())
	}

	if errs := errCounter.errors.Load(); errs > 0 {
		t.Fatalf("expected 0 error-level logs during routine reconnect, got %d", errs)
	}
}
