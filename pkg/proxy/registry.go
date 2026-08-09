package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// ActionRequest is an incoming request from the relay server.
// All requests use a unified format with datasource_id for routing.
type ActionRequest struct {
	RequestID    string         `json:"request_id"`
	DatasourceID string         `json:"datasource_id"`
	Action       string         `json:"action"`
	Params       map[string]any `json:"params,omitempty"`

	// HTTP fields (populated when action is "http_request")
	Method string              `json:"method,omitempty"`
	URL    string              `json:"url,omitempty"`
	Header map[string][]string `json:"header,omitempty"`
	Body   string              `json:"body,omitempty"`
}

// ActionResponse is the response sent back to the relay server.
type ActionResponse struct {
	StatusCode int    `json:"status_code"`
	RequestID  string `json:"request_id"`
	Action     string `json:"action,omitempty"`

	// Data carries the payload as an opaque string. It is a string because
	// some actions return things that are not JSON at all — an HTTP response
	// body, raw MCP bytes — and because every existing consumer decodes it
	// as one. Actions that return JSON therefore double-encode it here, and
	// callers parse twice.
	Data string `json:"data,omitempty"`

	// Result carries a structured payload as JSON, parsed once by the
	// caller. New actions should set this instead of Data.
	//
	// Both fields exist because changing Data's type would alter the wire
	// shape for every action and break consumers in lockstep, for the sake
	// of one Unmarshal. Setting both would instead double the payload —
	// a package inventory is megabytes — so an action populates exactly one.
	Result json.RawMessage `json:"result,omitempty"`
}

// Proxy is the interface that all proxy modules must implement.
type Proxy interface {
	// Type returns the proxy module type (e.g. "http-proxy", "db-proxy", "mcp-proxy").
	Type() string

	// Configure applies datasource configuration and credentials.
	Configure(config map[string]any, creds map[string]string) error

	// HandleRequest executes an action and returns a response.
	HandleRequest(ctx context.Context, req *ActionRequest) (*ActionResponse, error)

	// HealthCheck tests connectivity to the target datasource.
	HealthCheck(ctx context.Context) error

	// Close drains connections and releases resources.
	Close() error
}

// Registry manages datasource proxies by their ID.
type Registry struct {
	mu      sync.RWMutex
	proxies map[string]Proxy // datasource ID → Proxy
	configs map[string]DatasourceEntry
}

// DatasourceEntry stores the proxy and its metadata.
type DatasourceEntry struct {
	ID               string
	Type             string // postgresql, mysql, http, mcp
	ProxyType        string // db-proxy, http-proxy, mcp-proxy
	Name             string
	CredentialSource string
	CredentialRef    string
}

// NewRegistry creates a new empty proxy registry.
func NewRegistry() *Registry {
	return &Registry{
		proxies: make(map[string]Proxy),
		configs: make(map[string]DatasourceEntry),
	}
}

// Get returns the proxy for a given datasource ID.
func (r *Registry) Get(datasourceID string) (Proxy, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.proxies[datasourceID]
	return p, ok
}

// Register adds or replaces a proxy for a datasource.
func (r *Registry) Register(id string, entry DatasourceEntry, p Proxy) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Close existing proxy if replacing
	if old, exists := r.proxies[id]; exists {
		old.Close() // nolint:errcheck
	}

	r.proxies[id] = p
	r.configs[id] = entry
}

// Remove removes and closes a proxy by datasource ID.
func (r *Registry) Remove(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if p, exists := r.proxies[id]; exists {
		if err := p.Close(); err != nil {
			return fmt.Errorf("closing proxy %s: %w", id, err)
		}
		delete(r.proxies, id)
		delete(r.configs, id)
	}
	return nil
}

// All returns all registered datasource IDs.
func (r *Registry) All() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	ids := make([]string, 0, len(r.proxies))
	for id := range r.proxies {
		ids = append(ids, id)
	}
	return ids
}

// DatasourceHealth represents the health status of a single datasource.
type DatasourceHealth struct {
	Type      string `json:"type"`
	ProxyType string `json:"proxy_type"`
	Name      string `json:"name"`
	Status    string `json:"status"` // "healthy", "error", "unknown"
	Error     string `json:"error,omitempty"`
	LastCheck string `json:"last_check"` // RFC3339
}

// HealthReport runs health checks on all registered datasources concurrently and returns a map
// of datasource ID → health status. Used for periodic reporting to the cloud.
func (r *Registry) HealthReport(ctx context.Context) map[string]DatasourceHealth {
	r.mu.RLock()
	type target struct {
		id    string
		proxy Proxy
		cfg   DatasourceEntry
	}
	targets := make([]target, 0, len(r.proxies))
	for id, p := range r.proxies {
		if cfg, ok := r.configs[id]; ok {
			targets = append(targets, target{id: id, proxy: p, cfg: cfg})
		}
	}
	r.mu.RUnlock()

	if len(targets) == 0 {
		return make(map[string]DatasourceHealth)
	}

	report := make(map[string]DatasourceHealth, len(targets))
	now := time.Now().UTC().Format(time.RFC3339)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Run health checks concurrently to prevent a single slow or timing-out
	// datasource from blocking the health status of other datasources.
	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			health := DatasourceHealth{
				Type:      t.cfg.Type,
				ProxyType: t.cfg.ProxyType,
				Name:      t.cfg.Name,
				LastCheck: now,
			}

			checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			err := t.proxy.HealthCheck(checkCtx)

			if err != nil {
				health.Status = "error"
				health.Error = err.Error()
			} else {
				health.Status = "healthy"
			}

			mu.Lock()
			report[t.id] = health
			mu.Unlock()
		}(t)
	}

	wg.Wait()
	return report
}

// List returns a copy of all registered datasource entries.
func (r *Registry) List() map[string]DatasourceEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]DatasourceEntry, len(r.configs))
	for id, entry := range r.configs {
		result[id] = entry
	}
	return result
}

// MetadataCollector is an optional interface proxies can implement
// to report version and metadata about the underlying datasource.
type MetadataCollector interface {
	CollectMetadata(ctx context.Context) (map[string]any, error)
}

// CollectAllMetadata runs CollectMetadata on all proxies that implement MetadataCollector,
// in parallel with a per-datasource timeout. Returns datasourceID → metadata map.
func (r *Registry) CollectAllMetadata(ctx context.Context, timeout time.Duration) map[string]map[string]any {
	r.mu.RLock()
	type entry struct {
		id        string
		collector MetadataCollector
	}
	var collectors []entry
	for id, p := range r.proxies {
		if mc, ok := p.(MetadataCollector); ok {
			collectors = append(collectors, entry{id, mc})
		}
	}
	r.mu.RUnlock()

	if len(collectors) == 0 {
		return nil
	}

	result := make(map[string]map[string]any, len(collectors))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, e := range collectors {
		wg.Add(1)
		go func(dsID string, mc MetadataCollector) {
			defer wg.Done()
			collectCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			meta, err := mc.CollectMetadata(collectCtx)
			if err != nil {
				slog.Warn("metadata collection failed", "datasource", dsID, "err", err)
				return
			}
			mu.Lock()
			result[dsID] = meta
			mu.Unlock()
		}(e.id, e.collector)
	}

	wg.Wait()
	return result
}

// CloseAll closes all registered proxies.
func (r *Registry) CloseAll() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for id, p := range r.proxies {
		p.Close() // nolint:errcheck
		delete(r.proxies, id)
		delete(r.configs, id)
	}
}
