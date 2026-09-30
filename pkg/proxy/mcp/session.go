package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"nudgebee/forager/pkg/proxy"
)

// sessionIdleTTL is how long an upstream MCP session may sit unused before it is
// closed. Each use pushes the deadline out again, so an active conversation
// keeps its session.
const sessionIdleTTL = 30 * time.Minute

const (
	sessionSweepInterval    = 5 * time.Minute
	sessionTerminateTimeout = 10 * time.Second
)

var errProxyClosed = errors.New("MCP proxy is closed")

type mcpSession struct {
	id       string
	lastUsed time.Time
}

// sessionKey scopes the upstream session to the caller's conversation. Callers
// that send no session_id share one session, as before.
func sessionKey(req *proxy.ActionRequest) string {
	if req.Params == nil {
		return ""
	}
	key, _ := req.Params["session_id"].(string)
	return key
}

// handleWithSession runs an HTTP/SSE request inside the upstream MCP session for
// the caller's session_id, opening one with the initialize handshake when
// needed. Stateful MCP servers (browser, shell, database session) keep state per
// session, so without this every conversation would act on the same state.
func (p *Proxy) handleWithSession(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	body, err := p.buildRequestBody(req)
	if err != nil {
		return nil, fmt.Errorf("building MCP request body: %w", err)
	}

	key := sessionKey(req)
	sessionID, err := p.ensureSession(ctx, key)
	if errors.Is(err, errProxyClosed) {
		return nil, err
	}
	if err != nil {
		// Servers that don't implement sessions may reject initialize; the
		// request itself can still succeed without one.
		p.logger.Warn("MCP session init failed, proceeding without session", "error", err)
	}

	resp, err := p.post(ctx, body, sessionID)
	if err != nil {
		return nil, err
	}
	if !sessionGone(resp.ActionResponse, sessionID) {
		return resp.ActionResponse, nil
	}

	p.logger.Info("MCP session expired upstream, re-initializing", "status", resp.StatusCode)
	p.dropSession(key, sessionID)
	sessionID, err = p.ensureSession(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("MCP session re-init failed: %w", err)
	}
	resp, err = p.post(ctx, body, sessionID)
	if err != nil {
		return nil, err
	}
	return resp.ActionResponse, nil
}

// sessionGone reports whether the server no longer knows the session we sent.
// Only 404, as the MCP spec prescribes: guessing from a 400's text would drop a
// live session and replay a tool call on an ordinary tool error.
func sessionGone(resp *proxy.ActionResponse, sessionID string) bool {
	return sessionID != "" && resp.StatusCode == http.StatusNotFound
}

// ensureSession returns the live session for key, extending its idle deadline,
// or opens a new one. It returns "" when the server does not use sessions.
func (p *Proxy) ensureSession(ctx context.Context, key string) (string, error) {
	p.sessionMu.Lock()
	if p.closed {
		p.sessionMu.Unlock()
		return "", errProxyClosed
	}
	if time.Now().Before(p.sessionlessUntil) {
		p.sessionMu.Unlock()
		return "", nil
	}
	if s, ok := p.sessions[key]; ok {
		if time.Since(s.lastUsed) < sessionIdleTTL {
			s.lastUsed = time.Now()
			p.sessionMu.Unlock()
			return s.id, nil
		}
		delete(p.sessions, key)
		go p.terminateSession(s.id)
	}
	p.sessionMu.Unlock()

	// Handshake outside the lock so one slow server doesn't block other sessions.
	id, sessionless, err := p.initializeSession(ctx)
	if sessionless {
		// Remember it, or every request would pay an extra initialize round-trip.
		p.sessionMu.Lock()
		p.sessionlessUntil = time.Now().Add(sessionIdleTTL)
		p.sessionMu.Unlock()
	}
	if err != nil || id == "" {
		return "", err
	}

	p.sessionMu.Lock()
	if p.closed {
		p.sessionMu.Unlock()
		go p.terminateSession(id)
		return "", errProxyClosed
	}
	if s, ok := p.sessions[key]; ok && time.Since(s.lastUsed) < sessionIdleTTL {
		// A concurrent request for the same key won the race: share its
		// session and close the one we just opened.
		s.lastUsed = time.Now()
		p.sessionMu.Unlock()
		go p.terminateSession(id)
		return s.id, nil
	}
	p.sessions[key] = &mcpSession{id: id, lastUsed: time.Now()}
	p.sessionMu.Unlock()
	return id, nil
}

// dropSession forgets key only if it still maps to sessionID, so a session a
// concurrent request has just opened is not discarded.
func (p *Proxy) dropSession(key, sessionID string) {
	p.sessionMu.Lock()
	if s, ok := p.sessions[key]; ok && s.id == sessionID {
		delete(p.sessions, key)
	}
	p.sessionMu.Unlock()
}

// initializeSession performs the MCP initialize handshake and returns the
// server-assigned Mcp-Session-Id. sessionless is true only when the server
// answered definitively without one (success with no id, or a 4xx refusing
// initialize); transport errors and 5xx are not, so a blip can't disable
// sessions for a server that needs them.
func (p *Proxy) initializeSession(ctx context.Context) (id string, sessionless bool, err error) {
	initBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      0,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "forager", "version": "1.0.0"},
		},
	})
	resp, err := p.post(ctx, initBody, "")
	if err != nil {
		return "", false, fmt.Errorf("initialize: %w", err)
	}
	if resp.StatusCode >= 400 {
		return "", resp.StatusCode < 500, fmt.Errorf("initialize returned HTTP %d", resp.StatusCode)
	}
	id = resp.sessionID
	if id == "" {
		return "", true, nil
	}

	// The spec requires this notification before other requests; servers that
	// don't enforce it ignore it, so a failure here is not fatal.
	notify := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if _, err := p.post(ctx, notify, id); err != nil {
		p.logger.Debug("MCP initialized notification failed", "error", err)
	}
	return id, false, nil
}

// terminateSession asks the server to end a session (HTTP DELETE with
// Mcp-Session-Id). Best-effort: servers may answer 404 (already gone) or 405
// (client termination unsupported); the server's own timeout is the backstop.
func (p *Proxy) terminateSession(sessionID string) {
	ctx, cancel := context.WithTimeout(context.Background(), sessionTerminateTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Mcp-Session-Id", sessionID)
	if err := p.injectAuth(req); err != nil {
		p.logger.Debug("MCP session terminate: auth failed", "error", err)
		return
	}
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Debug("MCP session terminate failed", "error", err)
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

// sweepSessions closes sessions idle past sessionIdleTTL until stop is closed.
// Terminations run one at a time, which bounds load on the MCP server.
func (p *Proxy) sweepSessions(stop <-chan struct{}) {
	ticker := time.NewTicker(sessionSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			for _, id := range p.takeSessions(func(s *mcpSession) bool {
				return time.Since(s.lastUsed) >= sessionIdleTTL
			}) {
				p.terminateSession(id)
			}
		}
	}
}

// takeSessions removes and returns the ids of sessions matching match.
func (p *Proxy) takeSessions(match func(*mcpSession) bool) []string {
	p.sessionMu.Lock()
	defer p.sessionMu.Unlock()
	var ids []string
	for key, s := range p.sessions {
		if match(s) {
			delete(p.sessions, key)
			ids = append(ids, s.id)
		}
	}
	return ids
}

// httpResponse is an ActionResponse plus the Mcp-Session-Id header, which the
// initialize handshake needs.
type httpResponse struct {
	*proxy.ActionResponse
	sessionID string
}

// post sends one JSON-RPC message, with the session header when sessionID is
// set, and unwraps an SSE-framed reply into the JSON-RPC payload.
func (p *Proxy) post(ctx context.Context, body []byte, sessionID string) (httpResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return httpResponse{}, fmt.Errorf("creating MCP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Streamable HTTP servers reject requests that don't accept both.
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		httpReq.Header.Set("Mcp-Session-Id", sessionID)
	}
	if err := p.injectAuth(httpReq); err != nil {
		return httpResponse{}, fmt.Errorf("MCP auth: %w", err)
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return httpResponse{}, fmt.Errorf("MCP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return httpResponse{}, fmt.Errorf("reading MCP response: %w", err)
	}

	data := string(respBody)
	if p.transport == "sse" || strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		data, err = parseSSE(respBody)
		if err != nil {
			return httpResponse{}, err
		}
	}

	return httpResponse{
		ActionResponse: &proxy.ActionResponse{StatusCode: resp.StatusCode, Data: data},
		sessionID:      resp.Header.Get("Mcp-Session-Id"),
	}, nil
}
