package proxy

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"
)

// fakeProxy is a test implementation of the Proxy interface.
type fakeProxy struct {
	proxyType  string
	configured bool
	closed     bool
	mu         sync.Mutex
}

func (f *fakeProxy) Type() string { return f.proxyType }
func (f *fakeProxy) Configure(config map[string]any, creds map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.configured = true
	return nil
}
func (f *fakeProxy) HandleRequest(ctx context.Context, req *ActionRequest) (*ActionResponse, error) {
	return &ActionResponse{StatusCode: 200, Data: "ok"}, nil
}
func (f *fakeProxy) HealthCheck(ctx context.Context) error { return nil }
func (f *fakeProxy) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestRegistry_RegisterAndGet(t *testing.T) {
	r := NewRegistry()
	p := &fakeProxy{proxyType: "http-proxy"}
	entry := DatasourceEntry{ID: "ds-1", Type: "prometheus", ProxyType: "http-proxy"}

	r.Register("ds-1", entry, p)

	got, ok := r.Get("ds-1")
	if !ok {
		t.Fatal("expected to find ds-1")
	}
	if got.Type() != "http-proxy" {
		t.Fatalf("expected http-proxy, got %s", got.Type())
	}
}

func TestRegistry_GetNonExistent(t *testing.T) {
	r := NewRegistry()
	_, ok := r.Get("does-not-exist")
	if ok {
		t.Fatal("expected false for non-existent key")
	}
}

func TestRegistry_RegisterReplacesAndClosesOld(t *testing.T) {
	r := NewRegistry()
	old := &fakeProxy{proxyType: "http-proxy"}
	new := &fakeProxy{proxyType: "http-proxy"}
	entry := DatasourceEntry{ID: "ds-1"}

	r.Register("ds-1", entry, old)
	r.Register("ds-1", entry, new)

	if !old.closed {
		t.Fatal("old proxy should have been closed")
	}

	got, _ := r.Get("ds-1")
	if got != new {
		t.Fatal("registry should contain the new proxy")
	}
}

func TestRegistry_Remove(t *testing.T) {
	r := NewRegistry()
	p := &fakeProxy{proxyType: "db-proxy"}
	entry := DatasourceEntry{ID: "ds-1"}

	r.Register("ds-1", entry, p)
	if err := r.Remove("ds-1"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if !p.closed {
		t.Fatal("proxy should have been closed on remove")
	}
	if _, ok := r.Get("ds-1"); ok {
		t.Fatal("ds-1 should not exist after remove")
	}
}

func TestRegistry_RemoveNonExistent(t *testing.T) {
	r := NewRegistry()
	// Should not error
	if err := r.Remove("nope"); err != nil {
		t.Fatalf("Remove non-existent: %v", err)
	}
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()
	r.Register("ds-1", DatasourceEntry{ID: "ds-1"}, &fakeProxy{})
	r.Register("ds-2", DatasourceEntry{ID: "ds-2"}, &fakeProxy{})
	r.Register("ds-3", DatasourceEntry{ID: "ds-3"}, &fakeProxy{})

	all := r.All()
	sort.Strings(all)
	if len(all) != 3 || all[0] != "ds-1" || all[1] != "ds-2" || all[2] != "ds-3" {
		t.Fatalf("unexpected All result: %v", all)
	}
}

func TestRegistry_CloseAll(t *testing.T) {
	r := NewRegistry()
	p1 := &fakeProxy{}
	p2 := &fakeProxy{}
	r.Register("ds-1", DatasourceEntry{ID: "ds-1"}, p1)
	r.Register("ds-2", DatasourceEntry{ID: "ds-2"}, p2)

	r.CloseAll()

	if !p1.closed || !p2.closed {
		t.Fatal("all proxies should have been closed")
	}
	if len(r.All()) != 0 {
		t.Fatal("registry should be empty after CloseAll")
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := NewRegistry()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			r.Register(id, DatasourceEntry{ID: id}, &fakeProxy{proxyType: "test"})
		}(string(rune('A' + i%26)))
	}

	// Concurrent reads
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.All()
		}()
	}

	wg.Wait()
	// No race detector failures = pass
}

type fakeHealthProxy struct {
	proxyType string
	healthErr error
	delay     time.Duration
	panicVal  any
}

func (f *fakeHealthProxy) Type() string { return f.proxyType }
func (f *fakeHealthProxy) Configure(config map[string]any, creds map[string]string) error {
	return nil
}
func (f *fakeHealthProxy) HandleRequest(ctx context.Context, req *ActionRequest) (*ActionResponse, error) {
	return &ActionResponse{StatusCode: 200, Data: "ok"}, nil
}
func (f *fakeHealthProxy) HealthCheck(ctx context.Context) error {
	if f.panicVal != nil {
		panic(f.panicVal)
	}
	if f.delay > 0 {
		timer := time.NewTimer(f.delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return f.healthErr
}
func (f *fakeHealthProxy) Close() error { return nil }

func TestRegistry_HealthReportConcurrent(t *testing.T) {
	r := NewRegistry()

	// Register 30 proxies (exceeding defaultHealthCheckConcurrency=16) with mixed results
	for i := 1; i <= 30; i++ {
		id := fmt.Sprintf("ds-%d", i)
		entry := DatasourceEntry{
			ID:        id,
			Type:      "postgresql",
			ProxyType: "db-proxy",
			Name:      fmt.Sprintf("DB %d", i),
		}
		var p Proxy
		if i%5 == 0 {
			p = &fakeHealthProxy{proxyType: "db-proxy", healthErr: fmt.Errorf("connection refused")}
		} else {
			p = &fakeHealthProxy{proxyType: "db-proxy"}
		}
		r.Register(id, entry, p)
	}

	report := r.HealthReport(context.Background())
	if len(report) != 30 {
		t.Fatalf("expected 30 health report entries, got %d", len(report))
	}

	for i := 1; i <= 30; i++ {
		id := fmt.Sprintf("ds-%d", i)
		h, ok := report[id]
		if !ok {
			t.Fatalf("missing report entry for %s", id)
		}
		if i%5 == 0 {
			if h.Status != "error" || h.Error != "connection refused" {
				t.Errorf("expected status 'error' with 'connection refused' for %s, got status=%s err=%s", id, h.Status, h.Error)
			}
		} else {
			if h.Status != "healthy" {
				t.Errorf("expected status 'healthy' for %s, got %s", id, h.Status)
			}
		}
		if h.ProxyType != "db-proxy" {
			t.Errorf("expected proxy_type 'db-proxy' for %s, got %s", id, h.ProxyType)
		}
	}
}

func TestRegistry_HealthReportContextCancelled(t *testing.T) {
	r := NewRegistry()

	// Register proxies with artificial delay
	for i := 1; i <= 10; i++ {
		id := fmt.Sprintf("ds-%d", i)
		entry := DatasourceEntry{
			ID:        id,
			Type:      "http",
			ProxyType: "http-proxy",
			Name:      fmt.Sprintf("HTTP %d", i),
		}
		r.Register(id, entry, &fakeHealthProxy{proxyType: "http-proxy", delay: 200 * time.Millisecond})
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel context

	report := r.HealthReport(ctx)
	if len(report) != 10 {
		t.Fatalf("expected 10 health report entries, got %d", len(report))
	}

	for id, h := range report {
		if h.Status != "error" {
			t.Errorf("expected status 'error' for %s under cancelled context, got %s", id, h.Status)
		}
		if h.Error == "" {
			t.Errorf("expected non-empty error message for %s under cancelled context", id)
		}
	}
}

func TestRegistry_HealthReport_RecoversFromPanic(t *testing.T) {
	r := NewRegistry()

	r.Register("ds-panic", DatasourceEntry{
		ID:        "ds-panic",
		Type:      "postgresql",
		ProxyType: "db-proxy",
		Name:      "Panicking DB",
	}, &fakeHealthProxy{proxyType: "db-proxy", panicVal: "nil pointer dereference"})

	r.Register("ds-ok", DatasourceEntry{
		ID:        "ds-ok",
		Type:      "postgresql",
		ProxyType: "db-proxy",
		Name:      "Healthy DB",
	}, &fakeHealthProxy{proxyType: "db-proxy"})

	report := r.HealthReport(context.Background())
	if len(report) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(report))
	}

	hPanic, ok := report["ds-panic"]
	if !ok {
		t.Fatalf("missing ds-panic entry")
	}
	if hPanic.Status != "error" || hPanic.Error != "panic: nil pointer dereference" {
		t.Errorf("expected status 'error' with 'panic: nil pointer dereference', got status=%q err=%q", hPanic.Status, hPanic.Error)
	}

	hOK, ok := report["ds-ok"]
	if !ok {
		t.Fatalf("missing ds-ok entry")
	}
	if hOK.Status != "healthy" {
		t.Errorf("expected status 'healthy', got %q", hOK.Status)
	}
}
