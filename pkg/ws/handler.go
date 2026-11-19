package ws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"

	"nudgebee/forager/pkg/proxy"
	dbproxy "nudgebee/forager/pkg/proxy/db"
	discoveryproxy "nudgebee/forager/pkg/proxy/discovery"
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
// All actions that can modify state, execute commands, or query internal infrastructure should be listed here.
var signedActions = map[string]bool{
	// Config sync — can push arbitrary datasources including RCE via MCP stdio
	"datasource_config_sync": true,

	// Database — arbitrary SQL execution & schema inspection
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

	// MongoDB — arbitrary queries, aggregations, server inspection & topology
	"mongo_query":            true,
	"mongo_aggregate":        true,
	"mongo_server_status":    true,
	"mongo_repl_status":      true,
	"mongo_collection_stats": true,
	"mongo_current_ops":      true,
	"mongo_db_stats":         true,
	"mongo_list_databases":   true,
	"mongo_list_collections": true,

	// Redis — arbitrary command execution, slow logs, client lists & server info
	"redis_command":        true,
	"redis_info":           true,
	"redis_info_section":   true,
	"redis_slowlog":        true,
	"redis_client_list":    true,
	"redis_memory_stats":   true,
	"redis_cluster_info":   true,
	"redis_keyspace_stats": true,

	// Kafka — cluster broker topology, topic metadata, offsets & consumer lag
	"kafka_consumer_lag":            true,
	"kafka_consumer_groups":         true,
	"kafka_consumer_group_describe": true,
	"kafka_topics":                  true,
	"kafka_topic_describe":          true,
	"kafka_brokers":                 true,
	"kafka_topic_offsets":           true,

	// Config test — creates temporary proxy to test connectivity
	"test_datasource_config": true,

	// Discovery — inventory executes commands on remote hosts over SSH, the
	// same capability as ssh_command above. The commands themselves come
	// from a signature-verified content pack, but the targets do not: an
	// unsigned action lets a caller choose which hosts we connect to.
	//
	// Sweep sends probes across a network segment. Its scope is bounded by
	// allowed_cidrs, but triggering one is not harmless — an unexpected scan
	// reads as an attack originating from our agent, and some IDS and
	// fail2ban configurations act on it.
	"discovery_sweep":     true,
	"discovery_ldap":      true,
	"discovery_inventory": true,
}

// Handler dispatches incoming relay messages to the appropriate proxy module.
type Handler struct {
	// bindings is the datasourceBinding each registered datasource runs with,
	// so an unbound stored entry is reused only where it already runs.
	bindingsMu sync.Mutex
	bindings   map[string]string

	registry   *proxy.Registry
	credStore  *secrets.CloudPushStore
	secretsMgr *secrets.Manager
	verifier   *signing.Verifier
	logger     *slog.Logger

	// encKeys opens credentials the cloud encrypted to this forager
	// (credentials_enc on a pushed datasource). nil means such a push is
	// refused with no_encryption_key.
	encKeys *secrets.EncKeypair

	// onConfigSynced, if set, runs after a datasource_config_sync is applied
	// so the cloud learns the reachability of new datasources promptly.
	onConfigSynced func()
}

// SetOnConfigSynced registers a callback invoked after each applied config push.
func (h *Handler) SetOnConfigSynced(fn func()) { h.onConfigSynced = fn }

// SetEncKeypair sets the keypair that opens cloud-encrypted credentials.
func (h *Handler) SetEncKeypair(k *secrets.EncKeypair) { h.encKeys = k }

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

	// Verify signature for actions that require it or whenever verification is enabled (defense in depth)
	if h.verifier != nil && (signedActions[effectiveAction] || h.verifier.Enabled()) {
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

	switch envelope.Action {
	case "datasource_config_sync":
		return h.handleConfigSync(ctx, msg, envelope.RequestID)
	case "test_datasource_config":
		return h.handleTestDatasourceConfig(ctx, msg, envelope.RequestID)
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
		return h.buildCodedErrorResponse(requestID, 404, proxy.ErrCodeDatasourceNotFound, fmt.Sprintf("datasource %s not found", datasourceID)), nil
	}

	var req proxy.ActionRequest
	if err := json.Unmarshal(msg, &req); err != nil {
		return h.buildErrorResponse(requestID, 400, "invalid request: "+err.Error()), nil
	}

	resp, err := p.HandleRequest(ctx, &req)
	h.registry.RecordRequestResult(ctx, datasourceID, err)
	if err != nil {
		h.logger.Error("proxy request failed", "action", req.Action, "datasource", datasourceID, "err", err)
		return h.buildProxyErrorResponse(requestID, err), nil
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
			return h.buildCodedErrorResponse(requestID, 404, proxy.ErrCodeDatasourceNotFound, fmt.Sprintf("datasource %s not found", datasourceID)), nil
		}

		// action_params uses the same field names as ActionRequest, so decode it the
		// same way. Otherwise the HTTP fields (method, url, header, body) stay empty
		// and the request goes to the datasource's base URL. Best effort: a param
		// whose type does not match (say a non-string "body" for a db action) is
		// skipped by the decoder, and it is still available in Params.
		var req proxy.ActionRequest
		if raw, err := json.Marshal(actionReq.Body.ActionParams); err == nil {
			_ = json.Unmarshal(raw, &req)
		}
		req.RequestID = actionReq.RequestID
		req.Action = actionReq.Body.ActionName
		req.DatasourceID = datasourceID
		req.Params = actionReq.Body.ActionParams

		resp, err := p.HandleRequest(ctx, &req)
		h.registry.RecordRequestResult(ctx, datasourceID, err)
		if err != nil {
			h.logger.Error("legacy proxy request failed", "action", req.Action, "datasource", datasourceID, "err", err)
			return h.buildProxyErrorResponse(requestID, err), nil
		}
		resp.RequestID = requestID
		return json.Marshal(resp)
	}

	// Try as HTTP proxy request (no datasource routing — only valid when exactly
	// one http-proxy exists; otherwise the target would be arbitrary)
	var httpReq struct {
		Method string              `json:"method"`
		URL    string              `json:"url"`
		Header map[string][]string `json:"header"`
		Body   string              `json:"body"`
	}
	if err := json.Unmarshal(msg, &httpReq); err == nil && httpReq.URL != "" {
		var httpProxies []proxy.Proxy
		for _, id := range h.registry.All() {
			if p, _ := h.registry.Get(id); p != nil && p.Type() == "http-proxy" {
				httpProxies = append(httpProxies, p)
			}
		}
		switch len(httpProxies) {
		case 0:
			return h.buildCodedErrorResponse(requestID, 404, proxy.ErrCodeDatasourceNotFound, "no http-proxy datasource configured"), nil
		case 1:
			req := &proxy.ActionRequest{
				Method: httpReq.Method,
				URL:    httpReq.URL,
				Header: httpReq.Header,
				Body:   httpReq.Body,
			}
			resp, err := httpProxies[0].HandleRequest(ctx, req)
			if err != nil {
				return h.buildProxyErrorResponse(requestID, err), nil
			}
			resp.RequestID = requestID
			return json.Marshal(resp)
		default:
			return h.buildCodedErrorResponse(requestID, 400, proxy.ErrCodeAmbiguousDatasource,
				fmt.Sprintf("%d http-proxy datasources configured; datasource_id is required", len(httpProxies))), nil
		}
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
// Handles db_type fallback for db-proxy and allowed_hosts injection for
// ssh-proxy (as allowed_hosts) and discovery-proxy (as allowed_cidrs).
func newProxyByType(proxyType, dsType string, config map[string]any, allowedHosts []string, logger *slog.Logger) (proxy.Proxy, error) {
	switch proxyType {
	case "http-proxy":
		config["datasource_type"] = dsType
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
	case "discovery-proxy":
		if len(allowedHosts) > 0 {
			if _, set := config["allowed_cidrs"]; !set {
				config["allowed_cidrs"] = allowedHosts
			}
		}
		return discoveryproxy.New(logger), nil
	default:
		return nil, fmt.Errorf("unknown proxy type: %s", proxyType)
	}
}

// pushedDatasource is one datasource in a config sync or test request.
type pushedDatasource struct {
	ID               string            `json:"id"`
	Type             string            `json:"type"`
	ProxyType        string            `json:"proxy_type"`
	Name             string            `json:"name"`
	Config           map[string]any    `json:"config"`
	Credentials      map[string]string `json:"credentials,omitempty"`
	CredentialSource string            `json:"credential_source"`
	CredentialRef    string            `json:"credential_ref,omitempty"`
	AllowedHosts     []string          `json:"allowed_hosts,omitempty"`

	// CredentialsEnc carries the credentials sealed to this forager's
	// encryption key (see secrets.EncKeypair); EncKeyID names that key. When
	// set it replaces Credentials.
	CredentialsEnc string `json:"credentials_enc,omitempty"`
	EncKeyID       string `json:"enc_key_id,omitempty"`
}

// datasourceResult is one datasource's outcome in a config sync ack.
type datasourceResult struct {
	ID        string `json:"id"`
	Status    string `json:"status"` // ok | error
	ErrorCode string `json:"error_code,omitempty"`
	Error     string `json:"error,omitempty"`
	// Warning is set on an ok result when a secondary part of the datasource
	// was not applied (a discovery scope's ssh access).
	Warning string `json:"warning,omitempty"`
}

// Per-datasource error codes in a config sync ack.
const (
	errCodeNoEncryptionKey = "no_encryption_key"
	errCodeKeyMismatch     = "key_mismatch"
	errCodeDecryptFailed   = "decrypt_failed"
	errCodeSealedForOther  = "sealed_for_other_datasource"
	errCodeHostChanged     = "host_changed"
	errCodeStoreFailed     = "store_failed"
	errCodeResolveFailed   = "credential_resolve_failed"
	errCodeUnknownProxy    = "unknown_proxy_type"
	errCodeConfigureFailed = "configure_failed"
)

// tearDownOnFailure are failures that mean the pushed credentials cannot be
// used, so the datasource must stop serving whatever it ran with before.
var tearDownOnFailure = map[string]bool{
	errCodeKeyMismatch:     true,
	errCodeDecryptFailed:   true,
	errCodeSealedForOther:  true,
	errCodeHostChanged:     true,
	errCodeNoEncryptionKey: true,
	errCodeUnknownProxy:    true,
}

// datasourceBinding is what a pushed datasource's credentials are bound to:
// stored credentials are reused only while it stays the same, and sealed
// credentials name it inside the seal (Nudgebee computes the same value; see
// testdata/datasource_binding_vectors.json, mirrored in api-server).
//
//   - http-proxy, mcp-proxy: the URL's origin, scheme://host:port, so moving a
//     token from https to http or to another port on the host is a change.
//   - db, redis, mongo, and ssh with a host: the host.
//   - kafka: the broker list, normalised and sorted (order is not a change).
//   - ssh without a host, discovery: "scope:" and the sorted allowed hosts or
//     CIDRs; see bindingAllows.
//
// Everything is lower-cased. "" means the type has nothing to bind to.
func datasourceBinding(ds pushedDatasource) string {
	config := ds.Config
	plain := func(key string) string {
		v, _ := config[key].(string)
		return strings.ToLower(strings.TrimSpace(v))
	}
	switch ds.ProxyType {
	case "http-proxy":
		return urlOrigin(config["base_url"])
	case "mcp-proxy":
		return urlOrigin(config["url"])
	case "db-proxy", "redis-proxy", "mongo-proxy":
		return plain("host")
	case "ssh-proxy":
		if h := plain("host"); h != "" {
			return h
		}
		return scopeBinding(append(stringList(config["allowed_hosts"]), ds.AllowedHosts...))
	case "discovery-proxy":
		cidrs := stringList(config["allowed_cidrs"])
		if len(cidrs) == 0 {
			cidrs = ds.AllowedHosts
		}
		return scopeBinding(cidrs)
	case "kafka-proxy":
		parts := strings.Split(plain("brokers"), ",")
		out := parts[:0]
		for _, b := range parts {
			if b = strings.TrimSpace(b); b != "" {
				out = append(out, b)
			}
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	return ""
}

// urlOrigin is scheme://host:port of a URL value, lower-cased, with the
// scheme's default port filled in; "" when it is not an absolute URL.
func urlOrigin(v any) string {
	raw, _ := v.(string)
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || u.Scheme == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "https", "wss":
			port = "443"
		case "http", "ws":
			port = "80"
		}
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if port == "" {
		return scheme + "://" + host
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

const scopeBindingPrefix = "scope:"

// scopeBinding binds credentials used against a list of hosts or CIDRs.
func scopeBinding(items []string) string {
	seen := map[string]bool{}
	var out []string
	for _, it := range items {
		it = strings.ToLower(strings.TrimSpace(it))
		if it != "" && !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	if len(out) == 0 {
		return ""
	}
	sort.Strings(out)
	return scopeBindingPrefix + strings.Join(out, ",")
}

// bindingAllows reports whether credentials bound to bound may be reused for
// current. A scope may stay the same or narrow, never grow: a sync that adds
// a host to an ssh or discovery scope must carry the credentials.
func bindingAllows(bound, current string) bool {
	if bound == current {
		return true
	}
	if !strings.HasPrefix(bound, scopeBindingPrefix) || !strings.HasPrefix(current, scopeBindingPrefix) {
		return false
	}
	allowed := map[string]bool{}
	for _, it := range strings.Split(strings.TrimPrefix(bound, scopeBindingPrefix), ",") {
		allowed[it] = true
	}
	for _, it := range strings.Split(strings.TrimPrefix(current, scopeBindingPrefix), ",") {
		if !allowed[it] {
			return false
		}
	}
	return true
}

// stringList reads a config value that is a list of strings.
func stringList(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return strings.Split(t, ",")
	}
	return nil
}

// credentialBinding says what to store once the datasource is configured.
type credentialBinding struct {
	creds map[string]string
	host  string
}

func (h *Handler) registeredBinding(id string) string {
	h.bindingsMu.Lock()
	defer h.bindingsMu.Unlock()
	return h.bindings[id]
}

func (h *Handler) setRegisteredBinding(id, binding string) {
	h.bindingsMu.Lock()
	defer h.bindingsMu.Unlock()
	if h.bindings == nil {
		h.bindings = map[string]string{}
	}
	if binding == "" {
		delete(h.bindings, id)
		return
	}
	h.bindings[id] = binding
}

// resolveCredentials returns the credentials a pushed datasource runs with
// and, when they should be persisted, the binding to store after Configure
// succeeds (storing first would keep credentials a failed configure never
// used). A cloud_push datasource that carries none reuses the stored ones
// only while its binding allows it (see datasourceBinding). An entry stored
// before bindings existed is reused only for the binding the datasource is
// registered with right now — never bound to whatever the first sync names.
func (h *Handler) resolveCredentials(ctx context.Context, ds pushedDatasource) (creds map[string]string, toStore *credentialBinding, code string, err error) {
	host := datasourceBinding(ds)

	switch {
	case ds.CredentialsEnc != "":
		if h.encKeys == nil {
			return nil, nil, errCodeNoEncryptionKey, errors.New("this forager has no encryption key; update it to accept encrypted credentials")
		}
		opened, err := h.encKeys.Open(ds.EncKeyID, ds.CredentialsEnc, ds.ID, host)
		switch {
		case errors.Is(err, secrets.ErrEncKeyMismatch):
			return nil, nil, errCodeKeyMismatch, err
		case errors.Is(err, secrets.ErrSealedForOther):
			return nil, nil, errCodeSealedForOther, err
		case err != nil:
			return nil, nil, errCodeDecryptFailed, err
		}
		return opened, &credentialBinding{creds: opened, host: host}, "", nil

	case ds.CredentialSource == "cloud_push" && len(ds.Credentials) > 0:
		return ds.Credentials, &credentialBinding{creds: ds.Credentials, host: host}, "", nil

	case ds.CredentialSource == "cloud_push":
		stored, ok := h.credStore.Get(ds.ID)
		if !ok {
			return nil, nil, "", nil
		}
		bound := h.credStore.Host(ds.ID)
		switch {
		case bound != "" && !bindingAllows(bound, host):
			return nil, nil, errCodeHostChanged, fmt.Errorf("stored credentials are for %s; a change to %s must carry the credentials", bound, host)
		case bound == "" && host != "":
			if h.registeredBinding(ds.ID) != host {
				return nil, nil, errCodeHostChanged, fmt.Errorf("stored credentials predate host binding and %s is not where this datasource runs now; the push must carry the credentials", host)
			}
			return stored, &credentialBinding{creds: stored, host: host}, "", nil
		}
		return stored, nil, "", nil

	case ds.CredentialSource != "local" && ds.CredentialSource != "":
		resolved, err := h.secretsMgr.Resolve(ctx, ds.CredentialSource, ds.CredentialRef)
		if err != nil {
			return nil, nil, errCodeResolveFailed, err
		}
		return resolved, nil, "", nil
	}

	return ds.Credentials, nil, "", nil
}

// handleConfigSync processes datasource configuration updates from the cloud.
//
// The ack reports every datasource on its own: one that could not be applied
// keeps its previous registration (if any) and is listed with a reason, so a
// save that looks fine on the server cannot silently serve nothing here.
func (h *Handler) handleConfigSync(ctx context.Context, msg []byte, requestID string) ([]byte, error) {
	var push struct {
		Action      string             `json:"action"`
		AccountID   string             `json:"account_id"`
		Datasources []pushedDatasource `json:"datasources"`
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
	results := make([]datasourceResult, 0, len(push.Datasources))
	// A datasource that fails stops serving: a proxy registered by an earlier
	// sync would otherwise keep answering with the configuration and
	// credentials this sync replaced. Its stored credentials stay — the
	// datasource is still in the account, they remain bound to their host,
	// and the next good sync can use them without a re-push.
	// fail reports a datasource that could not be applied. A previously
	// registered proxy is torn down only when keeping it would serve stale
	// credentials: the failure is about the credentials themselves, or the
	// push changed the credentials or the binding (a rotation or a move).
	// A transient failure with nothing changed — a database briefly
	// unreachable during a reconnect sync — keeps the working proxy, as before.
	fail := func(ds pushedDatasource, code string, err error, changed bool) {
		h.logger.Error("datasource not applied", "datasource_id", ds.ID, "type", ds.Type, "error_code", code, "err", err)
		results = append(results, datasourceResult{ID: ds.ID, Status: "error", ErrorCode: code, Error: err.Error()})
		if strings.HasPrefix(ds.ID, "local:") {
			return
		}
		if !changed && !tearDownOnFailure[code] {
			if _, ok := h.registry.Get(ds.ID); ok {
				h.logger.Warn("keeping the previous registration: the push changed nothing and the failure is not about credentials",
					"datasource_id", ds.ID, "error_code", code)
			}
			return
		}
		if _, ok := h.registry.Get(ds.ID); ok {
			h.logger.Warn("removing previously configured datasource after failed reconfigure", "datasource_id", ds.ID)
			if err := h.registry.Remove(ds.ID); err != nil {
				h.logger.Error("failed to close removed datasource", "datasource_id", ds.ID, "err", err)
			}
		}
		h.setRegisteredBinding(ds.ID, "")
		// A push that carried credentials replaced the stored ones: the old
		// credentials (a rotated, possibly leaked token) must not come back on
		// the next sync. A failure without new credentials (host_changed)
		// keeps them for a later clean push.
		if ds.CredentialsEnc != "" || len(ds.Credentials) > 0 {
			if err := h.credStore.Delete(ds.ID); err != nil {
				h.logger.Error("failed to delete replaced credentials", "datasource_id", ds.ID, "err", err)
			}
		}
	}

	// changedFromRunning reports whether a push differs from what the
	// datasource runs with now: another binding, or other credentials.
	changedFromRunning := func(ds pushedDatasource, creds map[string]string) bool {
		if h.registeredBinding(ds.ID) != datasourceBinding(ds) {
			return true
		}
		stored, _ := h.credStore.Get(ds.ID)
		return !maps.Equal(stored, creds)
	}

	for _, ds := range push.Datasources {
		newIDs[ds.ID] = true

		creds, toStore, code, err := h.resolveCredentials(ctx, ds)
		if err != nil {
			fail(ds, code, err, false)
			continue
		}

		// A push without "config" decodes to a nil map, which newProxyByType
		// writes allowed_hosts/allowed_cidrs into.
		if ds.Config == nil {
			ds.Config = map[string]any{}
		}

		// Coerce string config values (e.g. "true"/"5432") to native types
		normalizeConfigValues(ds.Config)

		// Create or reconfigure the proxy
		p, proxyErr := newProxyByType(ds.ProxyType, ds.Type, ds.Config, ds.AllowedHosts, h.logger.With("datasource", ds.ID, "type", ds.Type))
		if proxyErr != nil {
			fail(ds, errCodeUnknownProxy, proxyErr, true)
			continue
		}

		if err := p.Configure(ds.Config, creds); err != nil {
			// Release whatever a partial Configure opened (pools, sockets).
			_ = p.Close()
			fail(ds, errCodeConfigureFailed, err, changedFromRunning(ds, creds))
			continue
		}

		// Persist only credentials a proxy actually accepted.
		if toStore != nil {
			if err := h.credStore.SetBound(ds.ID, toStore.creds, toStore.host); err != nil {
				_ = p.Close()
				fail(ds, errCodeStoreFailed, err, changedFromRunning(ds, creds))
				continue
			}
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
		h.setRegisteredBinding(ds.ID, datasourceBinding(ds))
		h.logger.Info("datasource configured", "id", ds.ID, "type", ds.Type, "proxy_type", ds.ProxyType)

		result := datasourceResult{ID: ds.ID, Status: "ok"}
		if ds.ProxyType == "discovery-proxy" && discoveryproxy.SSHAccessEnabled(ds.Config) {
			sibling, sp, err := discoveryproxy.SSHAccessSibling(entry, ds.Config, creds, h.verifier.Enabled(), h.logger)
			if err != nil {
				// The scope itself is serving; only its ssh access is not. Left
				// out of newIDs, so a previously registered sibling is removed below.
				h.logger.Error("ssh_access not enabled", "datasource_id", ds.ID, "err", err)
				result.Warning = "ssh access not enabled: " + err.Error()
			} else {
				newIDs[sibling.ID] = true
				h.registry.Register(sibling.ID, sibling, sp)
				h.logger.Info("ssh access enabled for discovery scope", "datasource_id", ds.ID, "id", sibling.ID)
			}
		}
		results = append(results, result)
	}

	// Remove cloud-managed datasources not in the new config, and the
	// credentials stored for them — including credentials of a datasource
	// that never registered. Locally-configured datasources (prefixed with
	// "local:") are never removed by cloud sync.
	for _, id := range h.registry.All() {
		if !newIDs[id] && !strings.HasPrefix(id, "local:") {
			h.logger.Info("removing datasource not in config", "id", id)
			h.registry.Remove(id) // nolint:errcheck
			h.setRegisteredBinding(id, "")
		}
	}
	for _, id := range h.credStore.IDs() {
		if !newIDs[id] && !strings.HasPrefix(id, "local:") {
			if err := h.credStore.Delete(id); err != nil {
				h.logger.Error("failed to delete stored credentials", "datasource_id", id, "err", err)
			}
		}
	}

	if h.onConfigSynced != nil {
		h.onConfigSynced()
	}

	// Return ACK response. status is "partial" when any datasource failed;
	// callers that only look at the top-level status still see a change.
	status := "ok"
	for _, r := range results {
		if r.Status != "ok" {
			status = "partial"
			break
		}
	}
	ack := map[string]any{
		"action":      "datasource_config_sync_ack",
		"status":      status,
		"request_id":  requestID,
		"datasources": results,
	}
	return json.Marshal(ack)
}

// handleTestDatasourceConfig creates a temporary proxy to test connectivity
// without registering it. Used to validate credentials before saving an integration.
func (h *Handler) handleTestDatasourceConfig(ctx context.Context, msg []byte, requestID string) ([]byte, error) {
	var req struct {
		Action     string           `json:"action"`
		Datasource pushedDatasource `json:"datasource"`
	}
	if err := json.Unmarshal(msg, &req); err != nil {
		return nil, fmt.Errorf("unmarshal test config request: %w", err)
	}

	ds := req.Datasource
	h.logger.Info("testing datasource config", "type", ds.Type, "proxy_type", ds.ProxyType)

	// Resolve credentials as handleConfigSync does; nothing is stored, so a
	// test leaves nothing behind. A test datasource has no stored entry to
	// fall back on, so a cloud_push test always carries its own.
	creds, _, code, err := h.resolveCredentials(ctx, ds)
	if err != nil {
		return json.Marshal(map[string]any{
			"action":     "test_datasource_config_result",
			"request_id": requestID,
			"success":    false,
			"error_code": code,
			"error":      fmt.Sprintf("failed to resolve credentials: %s", err.Error()),
		})
	}

	// Coerce string config values (e.g. "true"/"5432") to native types
	if ds.Config == nil {
		ds.Config = map[string]any{}
	}
	normalizeConfigValues(ds.Config)

	// Create temporary proxy
	logger := h.logger.With("test", true, "type", ds.Type, "proxy_type", ds.ProxyType)
	p, proxyErr := newProxyByType(ds.ProxyType, ds.Type, ds.Config, ds.AllowedHosts, logger)
	if proxyErr != nil {
		return json.Marshal(map[string]any{
			"action":     "test_datasource_config_result",
			"request_id": requestID,
			"success":    false,
			"error_code": errCodeUnknownProxy,
			"error":      proxyErr.Error(),
		})
	}

	// Configure tests connectivity (e.g. db ping, ssh dial)
	err = p.Configure(ds.Config, creds)
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
	return h.buildCodedErrorResponse(requestID, statusCode, "", message)
}

// buildCodedErrorResponse is buildErrorResponse plus a machine-readable error_code.
func (h *Handler) buildCodedErrorResponse(requestID string, statusCode int, code, message string) []byte {
	resp := proxy.ActionResponse{
		StatusCode: statusCode,
		RequestID:  requestID,
		ErrorCode:  code,
		Data:       fmt.Sprintf(`{"error": %q}`, message),
	}
	b, _ := json.Marshal(resp)
	return b
}

// buildProxyErrorResponse maps a proxy failure to a 500, tagging network-level
// failures so the server can retry on a forager that can reach the target.
func (h *Handler) buildProxyErrorResponse(requestID string, err error) []byte {
	code := ""
	if errors.Is(err, proxy.ErrUpstreamUnreachable) {
		code = proxy.ErrCodeUpstreamUnreachable
	}
	return h.buildCodedErrorResponse(requestID, 500, code, err.Error())
}
