package ws

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"nudgebee/forager/pkg/proxy"
)

// fakeRedis answers just enough RESP for the redis proxy: HELLO is refused
// (the client falls back to RESP2), PING gets PONG, DBSIZE gets 0, anything
// else OK. While down, it drops every connection, as an unreachable server.
type fakeRedis struct {
	ln   net.Listener
	down atomic.Bool
}

func startFakeRedis(t *testing.T) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRedis{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if f.down.Load() {
				_ = c.Close()
				continue
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeRedis) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	for {
		if f.down.Load() {
			return
		}
		args, err := readRESPArray(r)
		if err != nil {
			return
		}
		var reply string
		switch strings.ToUpper(args[0]) {
		case "HELLO":
			reply = "-ERR unknown command 'HELLO'\r\n"
		case "PING":
			reply = "+PONG\r\n"
		case "DBSIZE":
			reply = ":0\r\n"
		default:
			reply = "+OK\r\n"
		}
		if _, err := c.Write([]byte(reply)); err != nil {
			return
		}
	}
}

func readRESPArray(r *bufio.Reader) ([]string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	var n int
	if _, err := fmt.Sscanf(line, "*%d", &n); err != nil || n < 1 {
		return nil, fmt.Errorf("bad frame %q", line)
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := r.ReadString('\n'); err != nil { // $len
			return nil, err
		}
		v, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		args = append(args, strings.TrimRight(v, "\r\n"))
	}
	return args, nil
}

// A reconnect sync that changes nothing but fails because the target is
// briefly unreachable keeps the working proxy and its stored credentials, as
// before this PR; the datasource serves again when the target is back.
func TestHandler_ConfigSync_TransientFailureKeepsWorkingProxy(t *testing.T) {
	f := startFakeRedis(t)
	_, port, _ := net.SplitHostPort(f.ln.Addr().String())
	h := newTestHandler(t)
	sync := `{"action":"datasource_config_sync","account_id":"acc","datasources":[
		{"id":"ds-redis","type":"redis","proxy_type":"redis-proxy","config":{"host":"127.0.0.1","port":` + port + `},
		 "credentials":{"password":"p"},"credential_source":"cloud_push"}]}`
	if ack := syncAndParse(t, h, sync); ack.Status != "ok" {
		t.Fatalf("first sync %+v", ack)
	}

	f.down.Store(true)
	ack := syncAndParse(t, h, sync)
	if ack.Status != "partial" || ack.Datasources[0].ErrorCode != errCodeConfigureFailed {
		t.Fatalf("reconnect sync while down: %+v", ack)
	}
	p, ok := h.registry.Get("ds-redis")
	if !ok {
		t.Fatal("a transient failure with nothing changed must keep the working proxy")
	}
	if _, ok := h.credStore.Get("ds-redis"); !ok {
		t.Fatal("a transient failure must keep the stored credentials")
	}

	f.down.Store(false)
	if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "redis_command",
		Params: map[string]any{"command": "dbsize"}}); err != nil {
		t.Fatalf("the kept proxy should serve once the target is back: %v", err)
	}

	// A rotation (new credentials) that fails the same way does tear down.
	f.down.Store(true)
	rotated := strings.Replace(sync, `"password":"p"`, `"password":"rotated"`, 1)
	syncAndParse(t, h, rotated)
	if _, ok := h.registry.Get("ds-redis"); ok {
		t.Fatal("a failed rotation must not keep serving the old credentials")
	}
	if _, ok := h.credStore.Get("ds-redis"); ok {
		t.Fatal("a failed rotation must drop the rotated-out credentials")
	}
}
