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
)

// Handler dispatches incoming relay messages to the appropriate proxy module.
type Handler struct {
	registry   *proxy.Registry
	credStore  *secrets.CloudPushStore
	secretsMgr *secrets.Manager
	logger     *slog.Logger
}

// NewHandler creates a new message handler.
func NewHandler(registry *proxy.Registry, credStore *secrets.CloudPushStore, secretsMgr *secrets.Manager, logger *slog.Logger) *Handler {
	return &Handler{
		registry:   registry,
		credStore:  credStore,
		secretsMgr: secretsMgr,
		logger:     logger,
	}
}

// HandleMessage processes a single message from the relay server.
func (h *Handler) HandleMessage(ctx context.Context, msg []byte) ([]byte, error) {
	// Try to determine message type
	var envelope struct {
		Action    string          `json:"action"`
		RequestID string          `json:"request_id"`
		Method    string          `json:"method,omitempty"`
		URL       string          `json:"url,omitempty"`
		Body      json.RawMessage `json:"body,omitempty"`
	}
	if err := json.Unmarshal(msg, &envelope); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	switch envelope.Action {
	case "datasource_config_sync":
		return h.handleConfigSync(ctx, msg)
	default:
		// Could be an HTTP proxy request or an action request
		return h.handleProxyRequest(ctx, msg, envelope.RequestID)
	}
}

// handleConfigSync processes datasource configuration updates from the cloud.
func (h *Handler) handleConfigSync(ctx context.Context, msg []byte) ([]byte, error) {
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
		"request_id": "", // Will be set by caller if needed
	}
	return json.Marshal(ack)
}

// handleProxyRequest routes an action/HTTP request to the right proxy.
func (h *Handler) handleProxyRequest(ctx context.Context, msg []byte, requestID string) ([]byte, error) {
	// Try as ExternalActionRequest first
	var actionReq struct {
		Body struct {
			ActionName   string         `json:"action_name"`
			ActionParams map[string]any `json:"action_params"`
		} `json:"body"`
		RequestID string `json:"request_id"`
	}

	// Also try as HTTP request (for Grafana/Prometheus style requests)
	var httpReq struct {
		Method string              `json:"method"`
		URL    string              `json:"url"`
		Header map[string][]string `json:"header"`
		Body   string              `json:"body"`
	}

	if err := json.Unmarshal(msg, &actionReq); err == nil && actionReq.Body.ActionName != "" {
		return h.handleActionRequest(ctx, actionReq.Body.ActionName, actionReq.Body.ActionParams, actionReq.RequestID)
	}

	if err := json.Unmarshal(msg, &httpReq); err == nil && httpReq.URL != "" {
		return h.handleHTTPRequest(ctx, &httpReq, requestID)
	}

	return h.buildErrorResponse(requestID, 400, "unrecognized message format"), nil
}

func (h *Handler) handleActionRequest(ctx context.Context, actionName string, params map[string]any, requestID string) ([]byte, error) {
	datasourceID, _ := params["datasource_id"].(string)
	if datasourceID == "" {
		return h.buildErrorResponse(requestID, 400, "missing datasource_id"), nil
	}

	p, ok := h.registry.Get(datasourceID)
	if !ok {
		return h.buildErrorResponse(requestID, 404, fmt.Sprintf("datasource %s not found", datasourceID)), nil
	}

	req := &proxy.ActionRequest{
		Action:       actionName,
		DatasourceID: datasourceID,
		Params:       params,
	}

	resp, err := p.HandleRequest(ctx, req)
	if err != nil {
		h.logger.Error("proxy request failed", "action", actionName, "datasource", datasourceID, "err", err)
		return h.buildErrorResponse(requestID, 500, err.Error()), nil
	}

	resp.RequestID = requestID
	return json.Marshal(resp)
}

func (h *Handler) handleHTTPRequest(ctx context.Context, httpReq *struct {
	Method string              `json:"method"`
	URL    string              `json:"url"`
	Header map[string][]string `json:"header"`
	Body   string              `json:"body"`
}, requestID string) ([]byte, error) {
	// Route to the first available http-proxy or by request type header
	// For now, iterate through all HTTP proxies and try the first one
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

func (h *Handler) buildErrorResponse(requestID string, statusCode int, message string) []byte {
	resp := proxy.ActionResponse{
		StatusCode: statusCode,
		RequestID:  requestID,
		Data:       fmt.Sprintf(`{"error": %q}`, message),
	}
	b, _ := json.Marshal(resp)
	return b
}
