package proxy

import (
	"context"
	"sort"
	"sync"
	"testing"
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
