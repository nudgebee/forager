package ws

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestPingAndWriteLoopsDoNotWriteConcurrently runs pingLoop and writeLoop on
// one connection at high rates. gorilla/websocket allows one concurrent
// writer; a second WriteMessage caller panics with "concurrent write to
// websocket connection" (and trips -race).
func TestPingAndWriteLoopsDoNotWriteConcurrently(t *testing.T) {
	old := pingPeriod
	pingPeriod = 50 * time.Microsecond
	defer func() { pingPeriod = old }()

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	c := NewClient(srv.URL, "", "", nil, slog.New(slog.NewTextHandler(io.Discard, nil)), 0)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); c.writeLoop(ctx, conn) }()
	go func() { defer wg.Done(); c.pingLoop(ctx, conn) }()
	go func() {
		defer wg.Done()
		payload := []byte(strings.Repeat("x", 4096))
		for ctx.Err() == nil {
			select {
			case c.sendCh <- payload:
			case <-ctx.Done():
			}
		}
	}()
	wg.Wait()
}
