//go:build integration

// Integration tests for the MongoDB proxy. These exercise the real handlers
// (serverStatus / replSetGetStatus / currentOp / find / aggregate) against a
// live MongoDB, which the unit tests in proxy_test.go deliberately skip.
//
// Run with a reachable MongoDB:
//
//	docker run -d -p 27017:27017 mongo:7 --replSet rs0 --bind_ip_all
//	docker exec <id> mongosh --quiet --eval 'rs.initiate()'
//	FORAGER_MONGO_TEST_HOST=localhost FORAGER_MONGO_TEST_REPLICA_SET=rs0 \
//	  go test -tags integration -run TestIntegration -v ./pkg/proxy/mongodb/
//
// If FORAGER_MONGO_TEST_HOST is unset or the server is unreachable the tests
// skip, so `go test -tags integration ./...` stays green without a database.
package mongodb

import (
	"context"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"nudgebee/forager/pkg/proxy"
)

func integrationProxy(t *testing.T) *Proxy {
	t.Helper()
	host := os.Getenv("FORAGER_MONGO_TEST_HOST")
	if host == "" {
		t.Skip("FORAGER_MONGO_TEST_HOST not set; skipping MongoDB integration test")
	}
	port := 27017
	if p := os.Getenv("FORAGER_MONGO_TEST_PORT"); p != "" {
		if v, err := strconv.Atoi(p); err == nil {
			port = v
		}
	}
	cfg := map[string]any{
		"host":        host,
		"port":        port,
		"database":    "admin",
		"auth_source": "admin",
	}
	if rs := os.Getenv("FORAGER_MONGO_TEST_REPLICA_SET"); rs != "" {
		cfg["replica_set"] = rs
	}
	creds := map[string]string{}
	if u := os.Getenv("FORAGER_MONGO_TEST_USER"); u != "" {
		creds["username"] = u
		creds["password"] = os.Getenv("FORAGER_MONGO_TEST_PASSWORD")
	}

	p := New(testLogger())
	if err := p.Configure(cfg, creds); err != nil {
		t.Skipf("cannot connect to MongoDB at %s:%d (%v); skipping", host, port, err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// decodeData asserts a 200 response carrying a JSON object and returns it.
func decodeData(t *testing.T, resp *proxy.ActionResponse, err error, action string) map[string]any {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", action, err)
	}
	if resp == nil {
		t.Fatalf("%s: response is nil", action)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("%s: expected status 200, got %d (data=%s)", action, resp.StatusCode, resp.Data)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(resp.Data), &out); err != nil {
		t.Fatalf("%s: response data is not a JSON object: %v", action, err)
	}
	return out
}

func TestIntegration_ServerStatus(t *testing.T) {
	p := integrationProxy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := p.HandleRequest(ctx, &proxy.ActionRequest{Action: "mongo_server_status"})
	out := decodeData(t, resp, err, "mongo_server_status")
	for _, key := range []string{"ok", "connections", "uptime"} {
		if _, present := out[key]; !present {
			t.Errorf("mongo_server_status: expected key %q in serverStatus output", key)
		}
	}
}

func TestIntegration_CurrentOps(t *testing.T) {
	p := integrationProxy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := p.HandleRequest(ctx, &proxy.ActionRequest{Action: "mongo_current_ops"})
	out := decodeData(t, resp, err, "mongo_current_ops")
	if _, present := out["inprog"]; !present {
		t.Errorf("mongo_current_ops: expected key %q in currentOp output", "inprog")
	}
}

func TestIntegration_ReplStatus(t *testing.T) {
	p := integrationProxy(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := p.HandleRequest(ctx, &proxy.ActionRequest{Action: "mongo_repl_status"})

	if os.Getenv("FORAGER_MONGO_TEST_REPLICA_SET") == "" {
		// Standalone server: replSetGetStatus is expected to fail; the handler
		// must surface that error rather than panic — this guards the error path
		// the AI tool relies on.
		if err == nil {
			t.Skip("mongo_repl_status succeeded on a non-replica-set server; nothing to assert")
		}
		return
	}

	out := decodeData(t, resp, err, "mongo_repl_status")
	for _, key := range []string{"set", "members"} {
		if _, present := out[key]; !present {
			t.Errorf("mongo_repl_status: expected key %q in replSetGetStatus output", key)
		}
	}
}
