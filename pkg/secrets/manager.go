package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// cacheEntry holds a cached secret with expiry.
type cacheEntry struct {
	values  map[string]string
	expires time.Time
}

// Manager resolves credentials from multiple providers with caching.
type Manager struct {
	providers map[string]Provider
	cache     sync.Map // ref → cacheEntry
	cacheTTL  time.Duration
	logger    *slog.Logger
}

// NewManager creates a credential manager with the given providers.
func NewManager(logger *slog.Logger, providers ...Provider) *Manager {
	m := &Manager{
		providers: make(map[string]Provider),
		cacheTTL:  5 * time.Minute,
		logger:    logger,
	}
	for _, p := range providers {
		if p.Available() {
			m.providers[p.Name()] = p
			logger.Info("secret provider registered", "provider", p.Name())
		} else {
			logger.Debug("secret provider not available, skipping", "provider", p.Name())
		}
	}
	return m
}

// Resolve fetches credentials for a datasource based on its credential source.
func (m *Manager) Resolve(ctx context.Context, source, ref string) (map[string]string, error) {
	if source == "cloud_push" || source == "local" {
		// These are handled directly (cloud_push from encrypted file, local from config).
		// Callers should pass credentials directly for these sources.
		return nil, fmt.Errorf("source %q should be resolved by caller, not secret manager", source)
	}

	// Check cache
	cacheKey := source + ":" + ref
	if v, ok := m.cache.Load(cacheKey); ok {
		entry := v.(cacheEntry)
		if time.Now().Before(entry.expires) {
			return entry.values, nil
		}
		m.cache.Delete(cacheKey)
	}

	// Fetch from provider
	provider, ok := m.providers[source]
	if !ok {
		return nil, fmt.Errorf("unknown credential source: %q (available: %v)", source, m.availableProviders())
	}

	m.logger.Debug("fetching secret from provider", "source", source, "ref", ref)
	values, err := provider.GetSecret(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("fetching secret from %s: %w", source, err)
	}

	// Cache the result
	m.cache.Store(cacheKey, cacheEntry{
		values:  values,
		expires: time.Now().Add(m.cacheTTL),
	})

	return values, nil
}

// InvalidateCache removes a cached entry.
func (m *Manager) InvalidateCache(source, ref string) {
	m.cache.Delete(source + ":" + ref)
}

func (m *Manager) availableProviders() []string {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}
