package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"nudgebee/forager/pkg/proxy"
	dbproxy "nudgebee/forager/pkg/proxy/db"
	httpproxy "nudgebee/forager/pkg/proxy/http"
	kafkaproxy "nudgebee/forager/pkg/proxy/kafka"
	mcpproxy "nudgebee/forager/pkg/proxy/mcp"
	mongoproxy "nudgebee/forager/pkg/proxy/mongodb"
	redisproxy "nudgebee/forager/pkg/proxy/redis"
	sshproxy "nudgebee/forager/pkg/proxy/ssh"
	"nudgebee/forager/pkg/secrets"
	"nudgebee/forager/pkg/signing"
)

// signedActions are actions that require signature verification when signing is enabled.
// All actions that can modify state or execute commands should be listed here.
var signedActions = map[string]bool{
	// Config sync — can push arbitrary datasources including RCE via MCP stdio
	"datasource_config_sync": true,

	// Database — arbitrary SQL execution
	"db_query":    true,
	"db_execute":  true,
	"db_metadata": true,

	// SSH — arbitrary command execution, file read/write
	"ssh_command":  true,
	"ssh_upload":   true,
	"ssh_download": true,
	"ssh_list_dir": true,

	// HTTP — SSRF, credential theft via redirect
	"http_request": true,

	// MCP — arbitrary JSON-RPC to local processes
	"mcp_request": true,

	// MongoDB — arbitrary queries/aggregations
	"mongo_query":     true,
	"mongo_aggregate": true,

	// Redis — arbitrary command execution
	"redis_command": true,
}

// Handler dispatches incoming relay messages to the appropriate proxy module.
type Handler struct {
	registry   *proxy.Registry
	credStore  *secrets.CloudPushStore
	secretsMgr *secrets.Manager
	verifier   *signing.Verifier
	logger     *slog.Logger
}

// NewHandler creates a new message handler.
func NewHandler(registry *proxy.Registry, credStore *secrets.CloudPushStore, secretsMgr *secrets.Manager, verifier *signing.Verifier, logger *slog.Logger) *Handler {
	return &Handler{
		registry:   registry,
		credStore:  credStore,
		secretsMgr: secretsMgr,
		verifier:   verifier,
		logger:     logger,
	}
}

// HandleMessage processes a single message from the relay server.
// All requests use a unified format: {request_id, datasource_id, action, params, ...}
func (h *Handler) HandleMessage(ctx context.Context, msg []byte) ([]byte, error) {
	var envelope struct {
		Action       string `json:"action"`
		RequestID    string `json:"request_id"`
		DatasourceID string `json:"datasource_id"`
		Body         struct {
			ActionName string `json:"action_name"`
		} `json:"body"`
	}
	if err := json.Unmarshal(msg, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	// Resolve the effective action — legacy messages use body.action_name
	effectiveAction := envelope.Action
	if effectiveAction == "" {
		effectiveAction = envelope.Body.ActionName
	}

	// Verify signature for actions that require it
	if signedActions[effectiveAction] {
		if err := h.verifier.Verify(msg); err != nil {
			h.logger.Error("message signature verification failed",
				"action", effectiveAction,
				"request_id", envelope.RequestID,
				"err", err,
			)
			if h.verifier.Enabled() {
				return h.buildErrorResponse(envelope.RequestID, 403, "signature verification failed"), nil
			}
		}
	}
	// Legacy HTTP proxy requests (no action field) also require verification when signing is enabled
	if effectiveAction == "" && h.verifier.Enabled() {
		if err := h.verifier.Verify(msg); err != nil {
			h.logger.Error("unsigned legacy HTTP request rejected",
				"request_id", envelope.RequestID,
				"err", err,
			)
			return h.buildErrorResponse(envelope.RequestID, 403, "signature verification failed"), nil
		}
	}

	switch envelope.Action {
	case "datasource_config_sync":
		return h.handleConfigSync(ctx, msg, envelope.RequestID)
	default:
		return h.handleRequest(ctx, msg, envelope.RequestID, envelope.DatasourceID)
	}
}

// handleRequest routes a request to the proxy identified by datasource_id.
// Falls back to legacy routing if datasource_id is not provided.
func (h *Handler) handleRequest(ctx context.Context, msg []byte, requestID, datasourceID string) ([]byte, error) {
	if datasourceID == "" {
		return h.handleLegacyRequest(ctx, msg, requestID)
	}

	p, ok := h.registry.Get(datasourceID)
	if !ok {
		return h.buildErrorResponse(requestID, 404, fmt.Sprintf("datasource %s not found", datasourceID)), nil
	}

	var req proxy.ActionRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		return h.buildErrorResponse(requestID, 400, "invalid request: "+err.Error()), nil
	}

	resp, err := p.HandleRequest(ctx, &req)
	if err != nil {
		h.logger.Error("proxy request failed", "action", req.Action, "datasource", datasourceID, "err", err)
		return h.buildErrorResponse(requestID, 500, err.Error()), nil
	}

	resp.RequestID = requestID
	return json.Marshal(resp)
}

// handleLegacyRequest handles old-format messages that don't include top-level datasource_id.
// Supports two legacy formats:
//  1. ExternalActionRequest: {body: {action_name, action_params: {datasource_id}}}
//  2. HTTP proxy request: {method, url, header, body} — routes to first http-proxy
func (h *Handler) handleLegacyRequest(ctx context.Context, msg []byte, requestID string) ([]byte, error) {
	// Try as ExternalActionRequest
	var actionReq struct {
		Body struct {
			ActionName   string         `json:"action_name"`
			ActionParams map[string]any `json:"action_params"`
		} `json:"body"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(msg, &actionReq); err == nil && actionReq.Body.ActionName != "" {
		datasourceID, _ := actionReq.Body.ActionParams["datasource_id"].(string)
		if datasourceID == "" {
			return h.buildErrorResponse(requestID, 400, "missing datasource_id"), nil
		}

		p, ok := h.registry.Get(datasourceID)
		if !ok {
			return h.buildErrorResponse(requestID, 404, fmt.Sprintf("datasource %s not found", datasourceID)), nil
		}

		req := &proxy.ActionRequest{
			RequestID:    actionReq.RequestID,
			Action:       actionReq.Body.ActionName,
			DatasourceID: datasourceID,
			Params:       actionReq.Body.ActionParams,
		}

		resp, err := p.HandleRequest(ctx, req)
		if err != nil {
			h.logger.Error("legacy proxy request failed", "action", req.Action, "datasource", datasourceID, "err", err)
			return h.buildErrorResponse(requestID, 500, err.Error()), nil
		}
		resp.RequestID = requestID
		return json.Marshal(resp)
	}

	// Try as HTTP proxy request (no datasource routing — picks first http-proxy)
	var httpReq struct {
		Method string              `json:"method"`
		URL    string              `json:"url"`
		Header map[string][]string `json:"header"`
		Body   string              `json:"body"`
	}
	if err := json.Unmarshal(msg, &httpReq); err == nil && httpReq.URL != "" {
		for _, id := range h.registry.All() {
			p, _ := h.registry.Get(id)
			if p != nil && p.Type() == "http-proxy" {
				req := &proxy.ActionRequest{
					Method: httpReq.Method,
					URL:    httpReq.URL,
					Header: httpReq.Header,
					Body:   httpReq.Body,
				}
				resp, err := p.HandleRequest(ctx, req)
				if err != nil {
					return h.buildErrorResponse(requestID, 500, err.Error()), nil
				}
				resp.RequestID = requestID
				return json.Marshal(resp)
			}
		}
		return h.buildErrorResponse(requestID, 404, "no http-proxy datasource configured"), nil
	}

	return h.buildErrorResponse(requestID, 400, "unrecognized message format"), nil
}

// handleConfigSync processes datasource configuration updates from the cloud.
func (h *Handler) handleConfigSync(ctx context.Context, msg []byte, requestID string) ([]byte, error) {
	var push struct {
		Action      string `json:"action"`
		AccountID   string `json:"account_id"`
		Datasources []struct {
			ID               string            `json:"id"`
			Type             string            `json:"type"`
			ProxyType        string            `json:"proxy_type"`
			Name             string            `json:"name"`
			Config           map[string]any    `json:"config"`
			Credentials      map[string]string `json:"credentials,omitempty"`
			CredentialSource string            `json:"credential_source"`
			CredentialRef    string            `json:"credential_ref,omitempty"`
			AllowedHosts     []string          `json:"allowed_hosts,omitempty"`
		} `json:"datasources"`
	}
	if err := json.Unmarshal(msg, &push); err != nil {
		return nil, fmt.Errorf("unmarshal config push: %w", err)
	}

	h.logger.Info("received datasource config sync",
		"account_id", push.AccountID,
		"datasource_count", len(push.Datasources),
	)

	// Track which datasources are in the new config
	newIDs := make(map[string]bool)

	for _, ds := range push.Datasources {
		newIDs[ds.ID] = true

		// Resolve credentials
		creds := ds.Credentials
		if ds.CredentialSource == "cloud_push" && len(creds) > 0 {
			// Store cloud-pushed credentials
			if err := h.credStore.Set(ds.ID, creds); err != nil {
				h.logger.Error("failed to store credentials", "datasource_id", ds.ID, "err", err)
				continue
			}
		} else if ds.CredentialSource == "cloud_push" {
			// Try to load from stored credentials
			if stored, ok := h.credStore.Get(ds.ID); ok {
				creds = stored
			}
		} else if ds.CredentialSource != "local" {
			// Fetch from secret provider
			resolved, err := h.secretsMgr.Resolve(ctx, ds.CredentialSource, ds.CredentialRef)
			if err != nil {
				h.logger.Error("failed to resolve credentials", "datasource_id", ds.ID, "source", ds.CredentialSource, "err", err)
				continue
			}
			creds = resolved
		}

		// Create or reconfigure the proxy
		var p proxy.Proxy
		switch ds.ProxyType {
		case "http-proxy":
			p = httpproxy.New(h.logger.With("datasource", ds.ID, "type", ds.Type))
		case "db-proxy":
			dbType, _ := ds.Config["db_type"].(string)
			if dbType == "" {
				dbType = ds.Type // fallback for legacy configs
			}
			p = dbproxy.New(dbType, h.logger.With("datasource", ds.ID, "type", ds.Type))
		case "mcp-proxy":
			p = mcpproxy.New(h.logger.With("datasource", ds.ID, "type", ds.Type))
		case "ssh-proxy":
			// Pass allowed_hosts into config for dynamic mode
			if len(ds.AllowedHosts) > 0 {
				ds.Config["allowed_hosts"] = ds.AllowedHosts
			}
			p = sshproxy.New(h.logger.With("datasource", ds.ID, "type", ds.Type))
		case "mongo-proxy":
			p = mongoproxy.New(h.logger.With("datasource", ds.ID, "type", ds.Type))
		case "redis-proxy":
			p = redisproxy.New(h.logger.With("datasource", ds.ID, "type", ds.Type))
		case "kafka-proxy":
			p = kafkaproxy.New(h.logger.With("datasource", ds.ID, "type", ds.Type))
		default:
			h.logger.Warn("unknown proxy type, skipping", "proxy_type", ds.ProxyType, "datasource_id", ds.ID)
			continue
		}

		if err := p.Configure(ds.Config, creds); err != nil {
			h.logger.Error("failed to configure proxy", "datasource_id", ds.ID, "err", err)
			continue
		}

		entry := proxy.DatasourceEntry{
			ID:               ds.ID,
			Type:             ds.Type,
			ProxyType:        ds.ProxyType,
			Name:             ds.Name,
			CredentialSource: ds.CredentialSource,
			CredentialRef:    ds.CredentialRef,
		}
		h.registry.Register(ds.ID, entry, p)
		h.logger.Info("datasource configured", "id", ds.ID, "type", ds.Type, "proxy_type", ds.ProxyType)
	}

	// Remove datasources not in the new config
	for _, id := range h.registry.All() {
		if !newIDs[id] {
			h.logger.Info("removing datasource not in config", "id", id)
			h.registry.Remove(id) // nolint:errcheck
		}
	}

	// Return ACK response
	ack := map[string]any{
		"action":     "datasource_config_sync_ack",
		"status":     "ok",
		"request_id": requestID,
	}
	return json.Marshal(ack)
}

func (h *Handler) buildErrorResponse(requestID string, statusCode int, message string) []byte {
	resp := proxy.ActionResponse{
		StatusCode: statusCode,
		RequestID:  requestID,
		Data:       fmt.Sprintf(`{"error": %q}`, message),
	}
	b, _ := json.Marshal(resp)
	return b
}
