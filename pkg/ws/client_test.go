package ws

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type logCaptureHandler struct {
	mu     sync.Mutex
	warns  []string
	errors []string
}

func (h *logCaptureHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return true
}

func (h *logCaptureHandler) Handle(ctx context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch r.Level {
	case slog.LevelWarn:
		h.warns = append(h.warns, r.Message)
	case slog.LevelError:
		h.errors = append(h.errors, r.Message)
	}
	return nil
}

func (h *logCaptureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return h
}

func (h *logCaptureHandler) WithGroup(name string) slog.Handler {
	return h
}

func (h *logCaptureHandler) WarnCount(msg string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	count := 0
	for _, w := range h.warns {
		if strings.Contains(w, msg) {
			count++
		}
	}
	return count
}

func (h *logCaptureHandler) ErrorCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.errors)
}

type testMsgHandler struct{}

func (t *testMsgHandler) HandleMessage(ctx context.Context, msg []byte) ([]byte, error) {
	return nil, nil
}

func TestClient_Run_ReconnectionLogsWarnNotError(t *testing.T) {
	// Configure short initial reconnect delay for test
	origDelay := initialDelay
	initialDelay = 10 * time.Millisecond
	defer func() { initialDelay = origDelay }()

	var connAttempts atomic.Int32
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := connAttempts.Add(1)
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()

		// Read the greeting message
		_, _, err = conn.ReadMessage()
		if err != nil {
			return
		}

		if attempt == 1 {
			// Abruptly close first connection to simulate unexpected disconnect
			return
		}

		// Keep subsequent connections alive until client disconnects
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")

	capture := &logCaptureHandler{}
	logger := slog.New(capture)

	client := NewClient(wsURL, "test-key", "test-secret", &testMsgHandler{}, logger, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	runErrCh := make(chan error, 1)
	go func() {
		runErrCh <- client.Run(ctx)
	}()

	// Wait for reconnection to occur
	deadline := time.Now().Add(2 * time.Second)
	for connAttempts.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if attempts := connAttempts.Load(); attempts < 2 {
		t.Fatalf("expected at least 2 connection attempts (initial + reconnect), got %d", attempts)
	}

	// Cancel context to shut down client
	cancel()
	if err := <-runErrCh; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error from client.Run: %v", err)
	}

	// Verify that disconnection was logged as Warn and NOT as Error
	warnCount := capture.WarnCount("websocket session ended")
	if warnCount == 0 {
		t.Errorf("expected at least one 'websocket session ended' log at Warn level, got %d", warnCount)
	}

	errorCount := capture.ErrorCount()
	if errorCount != 0 {
		capture.mu.Lock()
		t.Errorf("expected 0 error logs during transient reconnection, got %d: %v", errorCount, capture.errors)
		capture.mu.Unlock()
	}
}
