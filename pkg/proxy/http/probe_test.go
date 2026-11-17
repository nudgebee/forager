package http

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
		"dot segment":        map[string]any{"path": "/./x"},
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
