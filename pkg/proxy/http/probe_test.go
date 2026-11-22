package http

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func probeServer(t *testing.T, status int) (*httptest.Server, *http.Request) {
	t.Helper()
	var got http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r.Clone(context.Background())
		w.WriteHeader(status)
		_, _ = w.Write([]byte("tenant missing"))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func configureWithProbe(t *testing.T, base string, probe map[string]any, creds map[string]string) *Proxy {
	t.Helper()
	p := New(testLogger())
	cfg := map[string]any{"base_url": base, "auth_type": "bearer", "datasource_type": "grafana_tempo"}
	if probe != nil {
		cfg["probe"] = probe
	}
	if err := p.Configure(cfg, creds); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

// The probe runs with the datasource's own auth plus the spec's headers, and
// a 401 is reported as rejected credentials.
func TestProbe_UsesAuthAndJudgesStatus(t *testing.T) {
	srv, got := probeServer(t, http.StatusOK)
	p := configureWithProbe(t, srv.URL+"/tempo", map[string]any{
		"path": "/api/v2/search/tags", "headers": map[string]any{"X-Scope-OrgID": "team-a"},
	}, map[string]string{"bearer_token": "tk"})

	if err := p.HealthCheck(context.Background()); err != nil {
		t.Fatalf("probe should pass: %v", err)
	}
	if got.URL.Path != "/tempo/api/v2/search/tags" || got.Header.Get("Authorization") != "Bearer tk" || got.Header.Get("X-Scope-OrgID") != "team-a" {
		t.Fatalf("probe request: path=%s auth=%q tenant=%q", got.URL.Path, got.Header.Get("Authorization"), got.Header.Get("X-Scope-OrgID"))
	}

	for status, wantBadCreds := range map[int]bool{http.StatusUnauthorized: true, http.StatusForbidden: true, http.StatusBadRequest: false, http.StatusNotFound: false} {
		srv, _ := probeServer(t, status)
		p := configureWithProbe(t, srv.URL, map[string]any{"path": "/api/v2/search/tags"}, map[string]string{"bearer_token": "wrong"})
		err := p.HealthCheck(context.Background())
		var pe *ProbeError
		if !errors.As(err, &pe) || pe.Status != status || pe.BadCredentials != wantBadCreds {
			t.Fatalf("status %d: got %v", status, err)
		}
	}
}

func TestProbe_CustomStatuses(t *testing.T) {
	srv, _ := probeServer(t, http.StatusNoContent)
	p := configureWithProbe(t, srv.URL, map[string]any{"path": "/x", "ok_statuses": []any{204}}, nil)
	if err := p.HealthCheck(context.Background()); err != nil {
		t.Fatalf("204 listed as ok: %v", err)
	}
	srv2, _ := probeServer(t, http.StatusUnprocessableEntity)
	p2 := configureWithProbe(t, srv2.URL, map[string]any{"path": "/x", "bad_credential_statuses": []any{422}}, nil)
	var pe *ProbeError
	if err := p2.HealthCheck(context.Background()); !errors.As(err, &pe) || !pe.BadCredentials {
		t.Fatalf("422 listed as bad credentials: %v", err)
	}
}

func TestParseProbe_Refusals(t *testing.T) {
	for name, raw := range map[string]any{
		"absolute url":       map[string]any{"path": "https://evil.example/x"},
		"scheme-relative":    map[string]any{"path": "//evil.example/x"},
		"no leading slash":   map[string]any{"path": "api/x"},
		"sets authorization": map[string]any{"path": "/x", "headers": map[string]any{"Authorization": "Bearer x"}},
		"sets host":          map[string]any{"path": "/x", "headers": map[string]any{"Host": "evil"}},
		"wrong shape":        "just a string",
		"dot-dot segment":    map[string]any{"path": "/api/../admin"},
		"encoded dot-dot":    map[string]any{"path": "/api/%2e%2E/admin"},
		"backslash":          map[string]any{"path": `/api/..\admin`},
		"encoded backslash":  map[string]any{"path": "/api/%5c..%5cadmin"},
		"dot segment":        map[string]any{"path": "/./x"},
		"unsupported method": map[string]any{"path": "/x", "method": "DELETE"},
		"body on a GET":      map[string]any{"path": "/x", "body": "{}"},
		"oversized body":     map[string]any{"path": "/x", "method": "POST", "body": strings.Repeat("x", maxProbeBody+1)},
	} {
		if _, err := parseProbe(raw); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if p, err := parseProbe(nil); err != nil || p != nil {
		t.Fatalf("absent probe: %v %v", p, err)
	}
}

// Datadog-style auth: several fixed headers carried as one JSON credential.
func TestInjectAuth_CustomHeaders(t *testing.T) {
	p := New(testLogger())
	req, _ := http.NewRequest("GET", "http://x/", nil)
	p.injectAuthWith(req, "custom_headers", map[string]string{"custom_headers": `{"DD-API-KEY":"a","DD-APPLICATION-KEY":"b"}`})
	if req.Header.Get("DD-API-KEY") != "a" || req.Header.Get("DD-APPLICATION-KEY") != "b" {
		t.Fatalf("headers: %v", req.Header)
	}
	req2, _ := http.NewRequest("GET", "http://x/", nil)
	p.injectAuthWith(req2, "custom_headers", map[string]string{"custom_headers": "not json"})
	if len(req2.Header) != 0 {
		t.Fatalf("malformed custom_headers must add nothing: %v", req2.Header)
	}
}

// An encoded "/" inside a segment stays encoded on the way to the datasource.
func TestResolveTargetURL_KeepsEscapedPath(t *testing.T) {
	p := New(testLogger())
	base, _ := url.Parse("https://gw.internal/tempo/")
	got, err := p.resolveTargetURL(base, "/api/v2/search/tag/resource.app.kubernetes.io%2Fname/values?q=%7B%7D")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://gw.internal/tempo/api/v2/search/tag/resource.app.kubernetes.io%2Fname/values?q=%7B%7D"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

// A malformed custom_headers credential fails the configure instead of sending
// every request without credentials.
func TestConfigure_ValidatesCustomHeaders(t *testing.T) {
	for name, raw := range map[string]string{
		"not json":   "not json",
		"empty":      "{}",
		"empty name": `{" ":"x"}`,
		"missing":    "",
	} {
		err := New(testLogger()).Configure(map[string]any{"base_url": "http://x", "auth_type": "custom_headers"},
			map[string]string{"custom_headers": raw})
		if err == nil {
			t.Errorf("%s: expected Configure to fail", name)
		}
	}
	if err := New(testLogger()).Configure(map[string]any{"base_url": "http://x", "auth_type": "custom_headers"},
		map[string]string{"custom_headers": `{"DD-API-KEY":"a","DD-APPLICATION-KEY":"b"}`}); err != nil {
		t.Fatalf("valid custom_headers: %v", err)
	}
}

// Requests that carry no escapes reach the datasource exactly as before the
// escaped-path change: the Prometheus, Loki and SigNoz shapes already in use.
func TestResolveTargetURL_UnescapedRequestsUnchanged(t *testing.T) {
	p := New(testLogger())
	base, _ := url.Parse("https://metrics.internal:9090/prom")
	for req, want := range map[string]string{
		"/api/v1/query_range?query=sum%28rate%28http_requests_total%7Bjob%3D%22api%22%7D%5B5m%5D%29%29&start=1&end=2&step=60": "https://metrics.internal:9090/prom/api/v1/query_range?query=sum%28rate%28http_requests_total%7Bjob%3D%22api%22%7D%5B5m%5D%29%29&start=1&end=2&step=60",
		"/api/v1/label/__name__/values":                                  "https://metrics.internal:9090/prom/api/v1/label/__name__/values",
		"/loki/api/v1/query_range?query=%7Bapp%3D%22web%22%7D&limit=100": "https://metrics.internal:9090/prom/loki/api/v1/query_range?query=%7Bapp%3D%22web%22%7D&limit=100",
		"/api/v3/query_range":                                            "https://metrics.internal:9090/prom/api/v3/query_range",
		"/-/ready":                                                       "https://metrics.internal:9090/prom/-/ready",
	} {
		got, err := p.resolveTargetURL(base, req)
		if err != nil {
			t.Fatalf("%s: %v", req, err)
		}
		if got != want {
			t.Errorf("%s:\n got  %s\n want %s", req, got, want)
		}
	}
}

// A POST probe sends its fixed body as JSON with the datasource's auth, and
// is judged like a GET (Dynatrace's DQL query:verify).
func TestProbe_PostWithBody(t *testing.T) {
	type seen struct{ method, ctype, body string }
	ch := make(chan seen, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- seen{r.Method, r.Header.Get("Content-Type"), string(b)}
		if r.Header.Get("Authorization") != "Bearer tk" {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)
	probe := map[string]any{"path": "/platform/storage/query/v1/query:verify", "method": "post", "body": `{"query":"fetch logs"}`}

	if err := configureWithProbe(t, srv.URL, probe, map[string]string{"bearer_token": "tk"}).HealthCheck(context.Background()); err != nil {
		t.Fatalf("probe should pass: %v", err)
	}
	if got := <-ch; got.method != http.MethodPost || got.ctype != "application/json" || got.body != `{"query":"fetch logs"}` {
		t.Fatalf("probe request: %+v", got)
	}

	err := configureWithProbe(t, srv.URL, probe, map[string]string{"bearer_token": "wrong"}).HealthCheck(context.Background())
	var pe *ProbeError
	if !errors.As(err, &pe) || !pe.BadCredentials {
		t.Fatalf("wrong token: got %v", err)
	}
	<-ch
}

// A probe without a method stays a bodiless GET.
func TestProbe_DefaultsToGet(t *testing.T) {
	srv, got := probeServer(t, http.StatusOK)
	if err := configureWithProbe(t, srv.URL, map[string]any{"path": "/x"}, nil).HealthCheck(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got.Method != http.MethodGet || got.Header.Get("Content-Type") != "" {
		t.Fatalf("method=%s type=%q", got.Method, got.Header.Get("Content-Type"))
	}
}
