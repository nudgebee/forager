package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

// probeSpec is an authenticated request that proves a datasource's
// credentials work. Nudgebee sends it in config.probe from its provider table
// — never from a tenant's form — so the path is a fixed API endpoint of that
// provider. It runs in the pre-save test (a wrong key is refused before it is
// stored) and in the health report.
type probeSpec struct {
	Path string `json:"path"`
	// Headers are non-secret request headers the endpoint needs (a tenant
	// header, say). Credentials are added from the datasource's own auth.
	Headers map[string]string `json:"headers,omitempty"`
	// OKStatuses default to any 2xx. BadCredentialStatuses default to 401, 403.
	OKStatuses            []int `json:"ok_statuses,omitempty"`
	BadCredentialStatuses []int `json:"bad_credential_statuses,omitempty"`
}

// parseProbe reads config.probe. Absent → nil; malformed → an error, so a
// broken spec fails the configure instead of silently skipping the check.
func parseProbe(raw any) (*probeSpec, error) {
	if raw == nil {
		return nil, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("probe: %w", err)
	}
	var p probeSpec
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("probe: %w", err)
	}
	if !strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "//") {
		return nil, fmt.Errorf("probe.path must be a path relative to base_url, got %q", p.Path)
	}
	pathOnly, _, _ := strings.Cut(p.Path, "?")
	for _, seg := range strings.Split(pathOnly, "/") {
		// A backslash is refused too: some servers and proxies normalise it
		// to "/", which would turn "..\\" or "%5c..%5c" into a dot segment.
		if s, err := url.PathUnescape(seg); err != nil || s == "." || s == ".." || strings.Contains(s, `\`) {
			return nil, fmt.Errorf("probe.path may not contain dot segments, backslashes or bad escapes, got %q", p.Path)
		}
	}
	for name := range p.Headers {
		switch strings.ToLower(name) {
		case "authorization", "proxy-authorization", "host", "cookie":
			return nil, fmt.Errorf("probe.headers may not set %s", name)
		}
	}
	return &p, nil
}

// ProbeError is a probe that reached the datasource and was refused.
type ProbeError struct {
	Status         int
	BadCredentials bool
	Body           string
}

func (e *ProbeError) Error() string {
	if e.BadCredentials {
		return fmt.Sprintf("the datasource rejected the credentials (HTTP %d)", e.Status)
	}
	if e.Body != "" {
		return fmt.Sprintf("probe returned HTTP %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("probe returned HTTP %d", e.Status)
}

// runProbe sends the probe with the datasource's auth and judges the status.
func (p *Proxy) runProbe(ctx context.Context, client *http.Client, spec *probeSpec, authType string, creds map[string]string) error {
	p.mu.RLock()
	base := p.baseParsed
	p.mu.RUnlock()

	target, err := p.resolveTargetURL(base, spec.Path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	for k, v := range spec.Headers {
		req.Header.Set(k, v)
	}
	p.injectAuthWith(req, authType, creds)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("probe failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 300
	if len(spec.OKStatuses) > 0 {
		ok = slices.Contains(spec.OKStatuses, resp.StatusCode)
	}
	if ok {
		return nil
	}
	bad := []int{http.StatusUnauthorized, http.StatusForbidden}
	if len(spec.BadCredentialStatuses) > 0 {
		bad = spec.BadCredentialStatuses
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	return &ProbeError{
		Status:         resp.StatusCode,
		BadCredentials: slices.Contains(bad, resp.StatusCode),
		Body:           strings.TrimSpace(string(body)),
	}
}
