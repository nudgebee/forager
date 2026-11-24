package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
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
		err := RefuseMetadataDial("tcp", addr, nil)
		if (err != nil) != refuse {
			t.Errorf("%s: refused=%v, want %v (%v)", addr, err != nil, refuse, err)
		}
	}
}

func TestRefuseMetadataHost(t *testing.T) {
	for host, refuse := range map[string]bool{
		"169.254.169.254":           true,
		"fd00:ec2::254":             true,
		"metadata.google.internal":  true,
		"METADATA.google.internal.": true,
		"metadata":                  true,
		"100.100.100.200":           true,
		"tempo.monitoring":          false,
		"10.0.0.5":                  false,
	} {
		if err := RefuseMetadataHost(host); (err != nil) != refuse {
			t.Errorf("%s: refused=%v, want %v (%v)", host, err != nil, refuse, err)
		}
	}
}

// A DialTLSContext cloned from the default transport is cleared, so HTTPS
// also dials through the guard.
func TestNewTransport_ClearsDialTLS(t *testing.T) {
	def := http.DefaultTransport.(*http.Transport)
	prev := def.DialTLSContext
	def.DialTLSContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("must not be used")
	}
	t.Cleanup(func() { def.DialTLSContext = prev })

	tr := NewTransport()
	if tr.DialTLSContext != nil || tr.DialContext == nil {
		t.Fatal("NewTransport must set DialContext and clear DialTLSContext")
	}
}

// A replaced DefaultTransport does not panic; the fallback is guarded too.
func TestNewTransport_ReplacedDefaultTransport(t *testing.T) {
	prev := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("unused") })
	t.Cleanup(func() { http.DefaultTransport = prev })

	tr := NewTransport()
	if tr.DialContext == nil {
		t.Fatal("fallback transport must be guarded")
	}
	_, err := tr.DialContext(context.Background(), "tcp", "169.254.169.254:80")
	if err == nil {
		t.Fatal("fallback transport dialled a metadata address")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestEffectivePort(t *testing.T) {
	uHTTP, _ := url.Parse("http://example.com/path")
	if port := EffectivePort(uHTTP); port != "80" {
		t.Fatalf("expected port 80 for http URL, got %q", port)
	}

	uHTTPS, _ := url.Parse("https://example.com/path")
	if port := EffectivePort(uHTTPS); port != "443" {
		t.Fatalf("expected port 443 for https URL, got %q", port)
	}

	uExplicit, _ := url.Parse("http://example.com:8080/path")
	if port := EffectivePort(uExplicit); port != "8080" {
		t.Fatalf("expected port 8080 for explicit port URL, got %q", port)
	}

	uMixedHTTP, _ := url.Parse("HTTP://example.com/path")
	if port := EffectivePort(uMixedHTTP); port != "80" {
		t.Fatalf("expected port 80 for HTTP URL, got %q", port)
	}

	uMixedHTTPS, _ := url.Parse("Https://example.com/path")
	if port := EffectivePort(uMixedHTTPS); port != "443" {
		t.Fatalf("expected port 443 for Https URL, got %q", port)
	}

	if port := EffectivePort(nil); port != "" {
		t.Fatalf("expected empty string for nil URL, got %q", port)
	}
}
