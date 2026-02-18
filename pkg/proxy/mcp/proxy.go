package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// Proxy forwards MCP (Model Context Protocol) JSON-RPC requests to a local MCP server.
type Proxy struct {
	transport string // "http" or "stdio"
	url       string // MCP server URL (for http transport)
	command   string // Command to run (for stdio transport)
	args      string // Command args (for stdio transport)
	client    *http.Client
	logger    *slog.Logger
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
	if p.transport == "" {
		p.transport = "http"
	}

	switch p.transport {
	case "http":
		if v, ok := config["url"].(string); ok {
			p.url = v
		}
		if p.url == "" {
			return fmt.Errorf("url is required for MCP http transport")
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
	default:
		return fmt.Errorf("unsupported MCP transport: %s", p.transport)
	}

	return nil
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	switch p.transport {
	case "http":
		return p.handleHTTP(ctx, req)
	case "stdio":
		return nil, fmt.Errorf("stdio transport not yet implemented")
	default:
		return nil, fmt.Errorf("unsupported transport: %s", p.transport)
	}
}

func (p *Proxy) handleHTTP(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	// The request body should contain the MCP JSON-RPC message
	var body []byte
	if req.Body != "" {
		body = []byte(req.Body)
	} else if req.Params != nil {
		var err error
		body, err = json.Marshal(req.Params)
		if err != nil {
			return nil, fmt.Errorf("marshaling MCP request: %w", err)
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating MCP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

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

func (p *Proxy) HealthCheck(ctx context.Context) error {
	if p.transport != "http" {
		return nil // Can't health check stdio
	}

	// Send MCP initialize or tools/list as health check
	body := []byte(`{"jsonrpc":"2.0","id":0,"method":"tools/list"}`)
	req, err := http.NewRequestWithContext(ctx, "POST", p.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("MCP health check failed: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode >= 500 {
		return fmt.Errorf("MCP health check returned status %d", resp.StatusCode)
	}
	return nil
}

func (p *Proxy) Close() error {
	p.client.CloseIdleConnections()
	return nil
}

// CollectMetadata returns connection info for the MCP server.
func (p *Proxy) CollectMetadata(_ context.Context) (map[string]any, error) {
	meta := map[string]any{
		"transport": p.transport,
	}
	if p.transport == "http" {
		meta["url"] = p.url
	}
	return meta, nil
}
