package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// Proxy forwards MCP (Model Context Protocol) JSON-RPC requests to a local MCP server.
type Proxy struct {
	transport string // "http", "stdio", or "sse"
	url       string // MCP server URL (for http/sse transport)
	authType  string // none, basic, bearer, custom_header, api_key, oauth2
	creds     map[string]string

	// stdio transport
	command    string // Command to run
	args       string // Command args (space-separated)
	env        map[string]string
	workingDir string
	stdio      *stdioProcess

	// oauth2 token cache
	oauthMu    sync.Mutex
	oauthToken string
	oauthExpAt time.Time

	client *http.Client
	logger *slog.Logger
}

// New creates a new MCP proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{
		logger: logger,
		client: &http.Client{
			Timeout: 120 * time.Second,
		},
	}
}

func (p *Proxy) Type() string { return "mcp-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	if v, ok := config["transport"].(string); ok {
		p.transport = v
	}
	if p.transport == "" || p.transport == "streamable_http" {
		p.transport = "http"
	}

	// Auth config (applies to http and sse transports)
	if v, ok := config["auth_type"].(string); ok {
		p.authType = v
	}
	p.creds = creds

	switch p.transport {
	case "http", "sse":
		if v, ok := config["url"].(string); ok {
			p.url = v
		}
		if p.url == "" {
			return fmt.Errorf("url is required for MCP %s transport", p.transport)
		}
	case "stdio":
		if v, ok := config["command"].(string); ok {
			p.command = v
		}
		if p.command == "" {
			return fmt.Errorf("command is required for MCP stdio transport")
		}
		if v, ok := config["args"].(string); ok {
			p.args = v
		}
		if v, ok := config["working_dir"].(string); ok {
			p.workingDir = v
		}
		if v, ok := config["env"].(map[string]any); ok {
			p.env = make(map[string]string, len(v))
			for k, val := range v {
				if s, ok := val.(string); ok {
					p.env[k] = s
				}
			}
		}
	default:
		return fmt.Errorf("unsupported MCP transport: %s", p.transport)
	}

	return nil
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	switch p.transport {
	case "http":
		return p.handleHTTP(ctx, req)
	case "sse":
		return p.handleSSE(ctx, req)
	case "stdio":
		return p.handleStdio(ctx, req)
	default:
		return nil, fmt.Errorf("unsupported transport: %s", p.transport)
	}
}

func (p *Proxy) buildRequestBody(req *proxy.ActionRequest) ([]byte, error) {
	if req.Body != "" {
		return []byte(req.Body), nil
	}
	if req.Params != nil {
		return json.Marshal(req.Params)
	}
	return nil, fmt.Errorf("no request body or params provided")
}

func (p *Proxy) handleHTTP(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	body, err := p.buildRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("building MCP request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating MCP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := p.injectAuth(httpReq); err != nil {
		return nil, fmt.Errorf("MCP auth: %w", err)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("MCP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading MCP response: %w", err)
	}

	return &proxy.ActionResponse{
		StatusCode: resp.StatusCode,
		Data:       string(respBody),
	}, nil
}

func (p *Proxy) handleSSE(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	body, err := p.buildRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("building MCP request body: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating MCP SSE request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if err := p.injectAuth(httpReq); err != nil {
		return nil, fmt.Errorf("MCP SSE auth: %w", err)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("MCP SSE request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Read entire body first to support fallback for non-SSE responses
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading MCP SSE response: %w", err)
	}

	// Parse SSE response — collect all "data:" lines into a single JSON-RPC response
	var result strings.Builder
	scanner := bufio.NewScanner(bytes.NewReader(respBody))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			data := strings.TrimPrefix(line, "data: ")
			if data == "[DONE]" {
				break
			}
			result.WriteString(data)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading MCP SSE stream: %w", err)
	}

	responseData := result.String()
	if responseData == "" {
		// Fallback: use entire response body if no SSE data lines were found
		responseData = string(respBody)
	}

	return &proxy.ActionResponse{
		StatusCode: resp.StatusCode,
		Data:       responseData,
	}, nil
}

func (p *Proxy) handleStdio(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	if p.stdio == nil {
		// Lazy-start the stdio process on first request
		args := parseArgs(p.args)
		envSlice := make([]string, 0, len(p.env))
		for k, v := range p.env {
			envSlice = append(envSlice, k+"="+v)
		}
		p.stdio = &stdioProcess{logger: p.logger}
		if err := p.stdio.start(p.command, args, envSlice, p.workingDir); err != nil {
			p.stdio = nil
			return nil, fmt.Errorf("starting MCP stdio process: %w", err)
		}
	}

	body, err := p.buildRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("building MCP request body: %w", err)
	}

	respBytes, err := p.stdio.send(ctx, body)
	if err != nil {
		return nil, fmt.Errorf("MCP stdio request failed: %w", err)
	}

	return &proxy.ActionResponse{
		StatusCode: 200,
		Data:       string(respBytes),
	}, nil
}

func (p *Proxy) injectAuth(req *http.Request) error {
	switch p.authType {
	case "basic":
		req.SetBasicAuth(p.creds["username"], p.creds["password"])
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+p.creds["bearer_token"])
	case "custom_header":
		if name := p.creds["custom_header_name"]; name != "" {
			req.Header.Set(name, p.creds["custom_header_value"])
		}
	case "api_key":
		if p.creds["api_key_location"] == "query" {
			q := req.URL.Query()
			q.Set(p.creds["api_key_name"], p.creds["api_key_value"])
			req.URL.RawQuery = q.Encode()
		} else {
			name := p.creds["api_key_name"]
			if name == "" {
				name = "X-API-Key"
			}
			req.Header.Set(name, p.creds["api_key_value"])
		}
	case "oauth2":
		token, err := p.getOAuthToken(req.Context())
		if err != nil {
			return fmt.Errorf("oauth2 token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return nil
}

// getOAuthToken returns a cached OAuth 2.0 access token, refreshing via client_credentials grant if expired.
func (p *Proxy) getOAuthToken(ctx context.Context) (string, error) {
	p.oauthMu.Lock()
	defer p.oauthMu.Unlock()

	if p.oauthToken != "" && time.Now().Before(p.oauthExpAt) {
		return p.oauthToken, nil
	}

	tokenURL := p.creds["oauth_token_url"]
	clientID := p.creds["oauth_client_id"]
	clientSecret := p.creds["oauth_client_secret"]
	if tokenURL == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("oauth2 requires oauth_token_url, oauth_client_id, and oauth_client_secret")
	}

	data := url.Values{"grant_type": {"client_credentials"}}
	if scope := p.creds["oauth_scope"]; scope != "" {
		data.Set("scope", scope)
	}
	if audience := p.creds["oauth_audience"]; audience != "" {
		data.Set("audience", audience)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("token endpoint returned empty access_token")
	}

	p.oauthToken = tokenResp.AccessToken
	if tokenResp.ExpiresIn > 0 {
		lifetime := time.Duration(tokenResp.ExpiresIn) * time.Second
		buffer := 30 * time.Second
		if buffer > lifetime/2 {
			buffer = lifetime / 2
		}
		p.oauthExpAt = time.Now().Add(lifetime - buffer)
	} else {
		p.oauthExpAt = time.Now().Add(5 * time.Minute)
	}

	return p.oauthToken, nil
}

func parseArgs(args string) []string {
	if args == "" {
		return nil
	}
	return strings.Fields(args)
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	switch p.transport {
	case "http", "sse":
		body := []byte(`{"jsonrpc":"2.0","id":0,"method":"ping"}`)
		req, err := http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if err := p.injectAuth(req); err != nil {
			return fmt.Errorf("MCP health check auth: %w", err)
		}

		resp, err := p.client.Do(req)
		if err != nil {
			return fmt.Errorf("MCP health check failed: %w", err)
		}
		_ = resp.Body.Close()

		if resp.StatusCode >= 500 {
			return fmt.Errorf("MCP health check returned status %d", resp.StatusCode)
		}
		return nil
	case "stdio":
		if p.stdio == nil {
			return nil // Process not started yet — not an error
		}
		return p.stdio.healthCheck()
	default:
		return nil
	}
}

func (p *Proxy) Close() error {
	p.client.CloseIdleConnections()
	if p.stdio != nil {
		return p.stdio.close()
	}
	return nil
}

// CollectMetadata returns connection info for the MCP server.
func (p *Proxy) CollectMetadata(_ context.Context) (map[string]any, error) {
	meta := map[string]any{
		"transport": p.transport,
	}
	switch p.transport {
	case "http", "sse":
		meta["url"] = p.url
		if p.authType != "" {
			meta["auth_type"] = p.authType
		}
	case "stdio":
		meta["command"] = p.command
		if p.stdio != nil && p.stdio.cmd != nil && p.stdio.cmd.Process != nil {
			meta["pid"] = p.stdio.cmd.Process.Pid
		}
	}
	return meta, nil
}
