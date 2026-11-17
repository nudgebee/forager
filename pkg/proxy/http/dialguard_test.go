package http

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestRefuseMetadataDial(t *testing.T) {
	for addr, refuse := range map[string]bool{
		"169.254.169.254:80": true,
		"169.254.1.1:443":    true,
		"[fe80::1]:80":       true,
		"[fd00:ec2::254]:80": true,
		"168.63.129.16:80":   true,
		"100.100.100.200:80": true,
		"10.0.0.5:9200":      false,
		"127.0.0.1:3200":     false,
		"[::1]:3200":         false,
		"8.8.8.8:443":        false,
	} {
		err := refuseMetadataDial("tcp", addr, nil)
		if (err != nil) != refuse {
			t.Errorf("%s: refused=%v, want %v (%v)", addr, err != nil, refuse, err)
		}
	}
}

// The guard sits on the proxy's transport: a name that resolves to a
// metadata address is refused at dial time, not reached.
func TestProxy_TransportRefusesMetadataDial(t *testing.T) {
	p := New(testLogger())
	if err := p.Configure(map[string]any{"base_url": "http://127.0.0.1:1"}, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "http://169.254.169.254/latest/meta-data/", nil)
	p.mu.RLock()
	client := p.client
	p.mu.RUnlock()
	resp, err := client.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Fatalf("expected a dial refusal, got %v", err)
	}
}

// A base_url that names a metadata endpoint outright is refused at configure
// time, which still holds when an HTTP(S)_PROXY hides the target from the
// dial guard.
func TestProxy_ConfigureRefusesMetadataHost(t *testing.T) {
	for _, u := range []string{
		"http://169.254.169.254",
		"http://[fd00:ec2::254]",
		"http://metadata.google.internal/computeMetadata/v1",
		"http://METADATA.google.internal.",
		"http://100.100.100.200",
	} {
		if err := New(testLogger()).Configure(map[string]any{"base_url": u}, nil); err == nil {
			t.Errorf("%s: expected Configure to refuse", u)
		}
	}
	if err := New(testLogger()).Configure(map[string]any{"base_url": "http://tempo.monitoring:3200"}, nil); err != nil {
		t.Fatalf("ordinary host refused: %v", err)
	}
}

// HTTPS goes through the guarded DialContext even when the default transport
// it is cloned from carries a DialTLSContext of its own.
func TestProxy_TransportClearsDialTLS(t *testing.T) {
	def := http.DefaultTransport.(*http.Transport)
	prev := def.DialTLSContext
	def.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("must not be used")
	}
	t.Cleanup(func() { def.DialTLSContext = prev })

	p := New(testLogger())
	if err := p.Configure(map[string]any{"base_url": "https://127.0.0.1:1"}, nil); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	p.mu.RLock()
	tr, ok := p.client.Transport.(*http.Transport)
	p.mu.RUnlock()
	if !ok {
		t.Fatalf("unexpected transport type %T", p.client.Transport)
	}
	if tr.DialTLSContext != nil {
		t.Fatal("DialTLSContext must be cleared so TLS dials go through the guarded DialContext")
	}
}
