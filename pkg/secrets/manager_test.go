package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"
)

// fakeProvider is a test implementation of the Provider interface.
type fakeProvider struct {
	name      string
	available bool
	secrets   map[string]map[string]string
	callCount int
}

func (f *fakeProvider) Name() string    { return f.name }
func (f *fakeProvider) Available() bool { return f.available }
func (f *fakeProvider) GetSecret(ctx context.Context, ref string) (map[string]string, error) {
	f.callCount++
	if s, ok := f.secrets[ref]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("secret not found: %s", ref)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestManager_ResolveFromProvider(t *testing.T) {
	provider := &fakeProvider{
		name:      "test_sm",
		available: true,
		secrets: map[string]map[string]string{
			"my-secret": {"username": "admin", "password": "pass123"},
		},
	}

	mgr := NewManager(testLogger(), provider)

	creds, err := mgr.Resolve(context.Background(), "test_sm", "my-secret")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if creds["username"] != "admin" || creds["password"] != "pass123" {
		t.Fatalf("unexpected creds: %v", creds)
	}
}

func TestManager_CacheTTL(t *testing.T) {
	provider := &fakeProvider{
		name:      "test_sm",
		available: true,
		secrets: map[string]map[string]string{
			"cached-secret": {"token": "abc"},
		},
	}

	mgr := NewManager(testLogger(), provider)
	mgr.cacheTTL = 50 * time.Millisecond // Short TTL for test

	ctx := context.Background()

	// First call — fetches from provider
	_, err := mgr.Resolve(ctx, "test_sm", "cached-secret")
	if err != nil {
		t.Fatalf("Resolve 1: %v", err)
	}
	if provider.callCount != 1 {
		t.Fatalf("expected 1 call, got %d", provider.callCount)
	}

	// Second call — served from cache
	_, err = mgr.Resolve(ctx, "test_sm", "cached-secret")
	if err != nil {
		t.Fatalf("Resolve 2: %v", err)
	}
	if provider.callCount != 1 {
		t.Fatalf("expected 1 call (cached), got %d", provider.callCount)
	}

	// Wait for TTL to expire
	time.Sleep(60 * time.Millisecond)

	// Third call — cache expired, fetches again
	_, err = mgr.Resolve(ctx, "test_sm", "cached-secret")
	if err != nil {
		t.Fatalf("Resolve 3: %v", err)
	}
	if provider.callCount != 2 {
		t.Fatalf("expected 2 calls after TTL, got %d", provider.callCount)
	}
}

func TestManager_InvalidateCache(t *testing.T) {
	provider := &fakeProvider{
		name:      "test_sm",
		available: true,
		secrets: map[string]map[string]string{
			"inv-secret": {"key": "val"},
		},
	}

	mgr := NewManager(testLogger(), provider)
	ctx := context.Background()

	// Fetch and cache
	_, _ = mgr.Resolve(ctx, "test_sm", "inv-secret")
	if provider.callCount != 1 {
		t.Fatalf("expected 1 call, got %d", provider.callCount)
	}

	// Invalidate
	mgr.InvalidateCache("test_sm", "inv-secret")

	// Should fetch again
	_, _ = mgr.Resolve(ctx, "test_sm", "inv-secret")
	if provider.callCount != 2 {
		t.Fatalf("expected 2 calls after invalidation, got %d", provider.callCount)
	}
}

func TestManager_UnknownSource(t *testing.T) {
	mgr := NewManager(testLogger())
	_, err := mgr.Resolve(context.Background(), "nonexistent", "ref")
	if err == nil {
		t.Fatal("expected error for unknown source")
	}
}

func TestManager_CloudPushReturnsError(t *testing.T) {
	mgr := NewManager(testLogger())
	_, err := mgr.Resolve(context.Background(), "cloud_push", "ref")
	if err == nil {
		t.Fatal("expected error for cloud_push source")
	}
}

func TestManager_LocalReturnsError(t *testing.T) {
	mgr := NewManager(testLogger())
	_, err := mgr.Resolve(context.Background(), "local", "ref")
	if err == nil {
		t.Fatal("expected error for local source")
	}
}

func TestManager_UnavailableProviderSkipped(t *testing.T) {
	provider := &fakeProvider{
		name:      "unavailable_sm",
		available: false,
		secrets:   map[string]map[string]string{},
	}

	mgr := NewManager(testLogger(), provider)

	_, err := mgr.Resolve(context.Background(), "unavailable_sm", "ref")
	if err == nil {
		t.Fatal("expected error for unavailable provider")
	}
}

func TestManager_ProviderReturnsError(t *testing.T) {
	provider := &fakeProvider{
		name:      "err_sm",
		available: true,
		secrets:   map[string]map[string]string{}, // empty — all lookups fail
	}

	mgr := NewManager(testLogger(), provider)

	_, err := mgr.Resolve(context.Background(), "err_sm", "missing-secret")
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
}
