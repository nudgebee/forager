package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

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

	// Config test — creates temporary proxy to test connectivity
	"test_datasource_config": true,
}

// ResyncFunc is called when the relay requests an inventory resync.
type ResyncFunc func(ctx context.Context)

// Handler dispatches incoming relay messages to the appropriate proxy module.
type Handler struct {
	registry   *proxy.Registry
	credStore  *secrets.CloudPushStore
	secretsMgr *secrets.Manager
	verifier   *signing.Verifier
	resyncFn   ResyncFunc
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

// SetResyncFunc sets the callback invoked when the relay requests an inventory resync.
func (h *Handler) SetResyncFunc(fn ResyncFunc) {
	h.resyncFn = fn
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
	case "test_datasource_config":
		return h.handleTestDatasourceConfig(ctx, msg, envelope.RequestID)
	case "resync_inventory":
		if h.resyncFn != nil {
			h.resyncFn(ctx)
			h.logger.Info("inventory resync triggered by relay")
		}
		return json.Marshal(map[string]any{
			"action":     "resync_inventory_ack",
			"request_id": envelope.RequestID,
			"status":     "ok",
		})
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

// normalizeConfigValues walks a config map and coerces string values that
// represent booleans or integers into their native Go types. This is needed
// because the cloud backend sometimes sends bool/int fields as JSON strings.
func normalizeConfigValues(config map[string]any) {
	for k, v := range config {
		s, ok := v.(string)
		if !ok {
			continue
		}
		switch s {
		case "true":
			config[k] = true
		case "false":
			config[k] = false
		default:
			if n, err := strconv.Atoi(s); err == nil {
				config[k] = n
			}
		}
	}
}

// newProxyByType creates a proxy instance for the given proxy type.
// Handles db_type fallback for db-proxy and allowed_hosts injection for ssh-proxy.
func newProxyByType(proxyType, dsType string, config map[string]any, allowedHosts []string, logger *slog.Logger) (proxy.Proxy, error) {
	switch proxyType {
	case "http-proxy":
		return httpproxy.New(logger), nil
	case "db-proxy":
		dbType, _ := config["db_type"].(string)
		if dbType == "" {
			dbType = dsType // fallback for legacy configs
		}
		return dbproxy.New(dbType, logger), nil
	case "mcp-proxy":
		return mcpproxy.New(logger), nil
	case "ssh-proxy":
		if len(allowedHosts) > 0 {
			config["allowed_hosts"] = allowedHosts
		}
		return sshproxy.New(logger), nil
	case "mongo-proxy":
		return mongoproxy.New(logger), nil
	case "redis-proxy":
		return redisproxy.New(logger), nil
	case "kafka-proxy":
		return kafkaproxy.New(logger), nil
	default:
		return nil, fmt.Errorf("unknown proxy type: %s", proxyType)
	}
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

		// Coerce string config values (e.g. "true"/"5432") to native types
		normalizeConfigValues(ds.Config)

		// Create or reconfigure the proxy
		p, proxyErr := newProxyByType(ds.ProxyType, ds.Type, ds.Config, ds.AllowedHosts, h.logger.With("datasource", ds.ID, "type", ds.Type))
		if proxyErr != nil {
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

	// Remove cloud-managed datasources not in the new config.
	// Locally-configured datasources (prefixed with "local:") are never removed by cloud sync.
	for _, id := range h.registry.All() {
		if !newIDs[id] && !strings.HasPrefix(id, "local:") {
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

// handleTestDatasourceConfig creates a temporary proxy to test connectivity
// without registering it. Used to validate credentials before saving an integration.
func (h *Handler) handleTestDatasourceConfig(ctx context.Context, msg []byte, requestID string) ([]byte, error) {
	var req struct {
		Action     string `json:"action"`
		Datasource struct {
			Type             string            `json:"type"`
			ProxyType        string            `json:"proxy_type"`
			Config           map[string]any    `json:"config"`
			Credentials      map[string]string `json:"credentials,omitempty"`
			CredentialSource string            `json:"credential_source"`
			CredentialRef    string            `json:"credential_ref,omitempty"`
			AllowedHosts     []string          `json:"allowed_hosts,omitempty"`
		} `json:"datasource"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return nil, fmt.Errorf("unmarshal test config request: %w", err)
	}

	ds := req.Datasource
	h.logger.Info("testing datasource config", "type", ds.Type, "proxy_type", ds.ProxyType)

	// Resolve credentials (same logic as handleConfigSync)
	creds := ds.Credentials
	if ds.CredentialSource != "local" && ds.CredentialSource != "cloud_push" && ds.CredentialSource != "" {
		resolved, err := h.secretsMgr.Resolve(ctx, ds.CredentialSource, ds.CredentialRef)
		if err != nil {
			return json.Marshal(map[string]any{
				"action":     "test_datasource_config_result",
				"request_id": requestID,
				"success":    false,
				"error":      fmt.Sprintf("failed to resolve credentials: %s", err.Error()),
			})
		}
		creds = resolved
	}

	// Coerce string config values (e.g. "true"/"5432") to native types
	normalizeConfigValues(ds.Config)

	// Create temporary proxy
	logger := h.logger.With("test", true, "type", ds.Type, "proxy_type", ds.ProxyType)
	p, proxyErr := newProxyByType(ds.ProxyType, ds.Type, ds.Config, ds.AllowedHosts, logger)
	if proxyErr != nil {
		return json.Marshal(map[string]any{
			"action":     "test_datasource_config_result",
			"request_id": requestID,
			"success":    false,
			"error":      proxyErr.Error(),
		})
	}

	// Configure tests connectivity (e.g. db ping, ssh dial)
	err := p.Configure(ds.Config, creds)
	_ = p.Close()

	resp := map[string]any{
		"action":     "test_datasource_config_result",
		"request_id": requestID,
		"success":    err == nil,
	}
	if err != nil {
		resp["error"] = err.Error()
		h.logger.Warn("datasource config test failed", "type", ds.Type, "err", err)
	} else {
		h.logger.Info("datasource config test succeeded", "type", ds.Type)
	}
	return json.Marshal(resp)
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
