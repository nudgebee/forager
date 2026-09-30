package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRedactError(t *testing.T) {
	cases := map[string]string{
		"dial tcp 10.1.2.3:5432: connection refused":                              "10.1.2.3",
		"connect to db.internal.example.com:5432 failed":                          "db.internal.example.com",
		"postgres://admin:hunter2@db/x failed":                                    "hunter2",
		"auth failed password=hunter2 for user":                                   "hunter2",
		"key -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----": "abc",
	}
	for in, leak := range cases {
		if out := RedactError(in); strings.Contains(out, leak) {
			t.Errorf("RedactError(%q) = %q leaks %q", in, out, leak)
		}
	}
	if got := RedactError(strings.Repeat("x", 2000)); len(got) > maxReportedErrorLen+4 {
		t.Errorf("not truncated: %d", len(got))
	}
}

func TestErrorClass(t *testing.T) {
	if ErrorClass("ssh-proxy") != ErrorClassSSH || ErrorClass("db-proxy") != ErrorClassDatasource {
		t.Fatal("wrong class")
	}
}

type stubProxy struct{ Proxy }

func (stubProxy) HealthCheck(context.Context) error { return nil }

func TestRequestErrorReportedThenCleared(t *testing.T) {
	r := NewRegistry()
	r.Register("ssh1", DatasourceEntry{ID: "ssh1", ProxyType: "ssh-proxy"}, stubProxy{})

	r.RecordRequestResult("ssh1", errors.New("dial tcp 10.0.0.5:22: refused"))
	h := r.HealthReport(context.Background())["ssh1"]
	if h.Status != "error" || h.ErrorClass != ErrorClassSSH || strings.Contains(h.Error, "10.0.0.5") {
		t.Fatalf("unexpected: %+v", h)
	}

	r.RecordRequestResult("ssh1", nil)
	if h := r.HealthReport(context.Background())["ssh1"]; h.Status != "healthy" || h.ErrorClass != "" {
		t.Fatalf("not cleared: %+v", h)
	}
}
