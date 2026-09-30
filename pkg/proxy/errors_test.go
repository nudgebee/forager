package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

func TestRedactError(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"ipv4", "dial tcp 10.1.2.3:5432: connection refused", "dial tcp [redacted-host]:5432: connection refused"},
		{"dotted host", "connect to db.internal.example.com:5432 failed", "connect to [redacted-host] failed"},
		{"url userinfo", "postgres://admin:hunter2@db/x failed", "postgres://[redacted]@db/x failed"},
		{"kv", "auth failed password=hunter2 for user", "auth failed password=[redacted] for user"},
		{"json", `body {"password":"hunter2","db":"x"}`, `body {"password":[redacted],"db":"x"}`},
		{"bearer", "401 Authorization: Bearer abc123def456", "401 Authorization: [redacted] [redacted]"},
		{"basic", "sent Basic dXNlcjpwYXNz rejected", "sent Basic [redacted] rejected"},
		{"ipv6 bracket", "dial tcp [fd00::5]:5432: refused", "dial tcp [redacted-host]:5432: refused"},
		{"lookup", "dial tcp: lookup db.internal.example.com: no such host", "dial tcp: lookup [redacted-host]: no such host"},
		{"dial single label", "dial tcp postgres:5432: connect: refused", "dial tcp [redacted-host]:5432: connect: refused"},
		{"pem", "key -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----", "key [redacted-key]"},
		{"plain", "connection refused", "connection refused"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := RedactError(tc.in); got != tc.want {
				t.Errorf("RedactError(%q)\n got %q\nwant %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestRedactErrorTruncatesOnRuneBoundary(t *testing.T) {
	// 3-byte runes so byte 512 lands mid-rune.
	got := RedactError(strings.Repeat("€", 400))
	if !utf8.ValidString(got) {
		t.Fatalf("invalid UTF-8 after truncation: %q", got)
	}
	if !strings.HasSuffix(got, "…") || len(got) > maxReportedErrorLen+len("…") {
		t.Fatalf("not truncated properly: len=%d", len(got))
	}
	if !utf8.ValidString(RedactError("bad \xff byte")) {
		t.Fatal("invalid input bytes not scrubbed")
	}
}

func TestErrorClass(t *testing.T) {
	if ErrorClass("ssh-proxy") != ErrorClassSSH || ErrorClass("db-proxy") != ErrorClassDatasource {
		t.Fatal("wrong class")
	}
}

func TestIsIntegrationError(t *testing.T) {
	yes := []error{
		&net.OpError{Op: "dial", Err: errors.New("boom")},
		errors.New("dial tcp 1.2.3.4:22: connect: connection refused"),
		errors.New("ssh: handshake failed: ssh: unable to authenticate"),
		errors.New(`pq: password authentication failed for user "x"`),
	}
	no := []error{
		nil,
		errors.New("command \"FLUSHALL\" not allowed"),
		errors.New("datasource is read-only, execute not allowed"),
		errors.New("invalid base64 content"),
		errors.New(`ERROR: relation "typo_table" does not exist`),
	}
	for _, e := range yes {
		if !IsIntegrationError(e) {
			t.Errorf("want integration error: %v", e)
		}
	}
	for _, e := range no {
		if IsIntegrationError(e) {
			t.Errorf("want caller error: %v", e)
		}
	}
}

type stubProxy struct{ Proxy }

func (stubProxy) HealthCheck(context.Context) error { return nil }
func (stubProxy) Close() error                      { return nil }

var errRefused = errors.New("dial tcp 10.0.0.5:22: connect: connection refused")

func TestRequestErrorReportedThenCleared(t *testing.T) {
	r := NewRegistry()
	r.Register("ssh1", DatasourceEntry{ID: "ssh1", ProxyType: "ssh-proxy"}, stubProxy{})

	r.RecordRequestResult(context.Background(), "ssh1", errRefused)
	h := r.HealthReport(context.Background())["ssh1"]
	if h.Status != "error" || h.ErrorClass != ErrorClassSSH || strings.Contains(h.Error, "10.0.0.5") || h.Error == "" {
		t.Fatalf("unexpected: %+v", h)
	}

	r.RecordRequestResult(context.Background(), "ssh1", nil)
	if h := r.HealthReport(context.Background())["ssh1"]; h.Status != "healthy" || h.ErrorClass != "" {
		t.Fatalf("not cleared: %+v", h)
	}
}

func TestCallerErrorsAndCancelledRequestsIgnored(t *testing.T) {
	r := NewRegistry()
	r.Register("db1", DatasourceEntry{ID: "db1", ProxyType: "db-proxy"}, stubProxy{})

	r.RecordRequestResult(context.Background(), "db1", errors.New(`relation "typo" does not exist`))
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	r.RecordRequestResult(cancelled, "db1", errRefused)

	if h := r.HealthReport(context.Background())["db1"]; h.Status != "healthy" {
		t.Fatalf("caller error flagged datasource: %+v", h)
	}
}

func TestRequestErrorClearedOnRegisterAndRemove(t *testing.T) {
	r := NewRegistry()
	r.Register("ssh1", DatasourceEntry{ID: "ssh1", ProxyType: "ssh-proxy"}, stubProxy{})
	r.RecordRequestResult(context.Background(), "ssh1", errRefused)

	// Re-registering (e.g. after a corrected password) discards the old failure.
	r.Register("ssh1", DatasourceEntry{ID: "ssh1", ProxyType: "ssh-proxy"}, stubProxy{})
	if h := r.HealthReport(context.Background())["ssh1"]; h.Status != "healthy" {
		t.Fatalf("stale error after Register: %+v", h)
	}

	r.RecordRequestResult(context.Background(), "ssh1", errRefused)
	if err := r.Remove("ssh1"); err != nil {
		t.Fatal(err)
	}
	// A late result for a removed datasource must not recreate an entry.
	r.RecordRequestResult(context.Background(), "ssh1", errRefused)
	r.reqErrMu.Lock()
	n := len(r.reqErrors)
	r.reqErrMu.Unlock()
	if n != 0 {
		t.Fatalf("reqErrors leaked %d entries", n)
	}

	r.Register("a", DatasourceEntry{ID: "a"}, stubProxy{})
	r.RecordRequestResult(context.Background(), "a", errRefused)
	r.CloseAll()
	r.reqErrMu.Lock()
	n = len(r.reqErrors)
	r.reqErrMu.Unlock()
	if n != 0 {
		t.Fatalf("CloseAll leaked %d entries", n)
	}
}

func TestRecordRequestResultConcurrent(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 4; i++ {
		r.Register(fmt.Sprint("d", i), DatasourceEntry{ID: fmt.Sprint("d", i)}, stubProxy{})
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprint("d", i%4)
			for j := 0; j < 50; j++ {
				switch j % 4 {
				case 0:
					r.RecordRequestResult(context.Background(), id, errRefused)
				case 1:
					r.RecordRequestResult(context.Background(), id, nil)
				case 2:
					r.HealthReport(context.Background())
				default:
					r.Register(id, DatasourceEntry{ID: id}, stubProxy{})
				}
			}
		}(i)
	}
	wg.Wait()
}
