package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// Proxy is a generic HTTP reverse proxy for any HTTP-based datasource.
type Proxy struct {
	baseURL       string
	authType      string // none, basic, bearer, custom_header
	creds         map[string]string
	tlsSkipVerify bool
	client        *http.Client
	logger        *slog.Logger
}

// New creates a new HTTP proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{
		logger: logger,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (p *Proxy) Type() string { return "http-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	if v, ok := config["base_url"].(string); ok {
		p.baseURL = v
	}
	if p.baseURL == "" {
		return fmt.Errorf("base_url is required for http-proxy")
	}

	if v, ok := config["auth_type"].(string); ok {
		p.authType = v
	}

	skipVerify := false
	if v, ok := config["tls_skip_verify"].(bool); ok {
		skipVerify = v
	}
	p.tlsSkipVerify = skipVerify

	p.client = &http.Client{
		Timeout: 120 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify}, // nolint:gosec
		},
	}

	p.creds = creds
	return nil
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	targetURL := p.baseURL + req.URL

	var bodyReader io.Reader
	if req.Body != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Body)
		if err != nil {
			bodyReader = bytes.NewReader([]byte(req.Body))
		} else {
			bodyReader = bytes.NewReader(decoded)
		}
	}

	method := req.Method
	if method == "" {
		method = "GET"
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Copy headers from the original request
	for k, vals := range req.Header {
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}

	// Inject auth
	p.injectAuth(httpReq)

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	// Build response in the same format as the K8s agent HTTPResponse
	httpResp := map[string]any{
		"status_code": resp.StatusCode,
		"header":      resp.Header,
		"body":        base64.StdEncoding.EncodeToString(respBody),
	}

	respData, _ := json.Marshal(httpResp)
	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(respData),
	}, nil
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", p.baseURL, nil)
	if err != nil {
		return err
	}
	p.injectAuth(req)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}
	return nil
}

func (p *Proxy) Close() error {
	p.client.CloseIdleConnections()
	return nil
}

// CollectMetadata returns connection info for the HTTP datasource.
func (p *Proxy) CollectMetadata(_ context.Context) (map[string]any, error) {
	return map[string]any{
		"base_url": p.baseURL,
	}, nil
}

func (p *Proxy) injectAuth(req *http.Request) {
	switch p.authType {
	case "basic":
		req.SetBasicAuth(p.creds["username"], p.creds["password"])
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+p.creds["bearer_token"])
	case "custom_header":
		if name := p.creds["custom_header_name"]; name != "" {
			req.Header.Set(name, p.creds["custom_header_value"])
		}
	}
}
