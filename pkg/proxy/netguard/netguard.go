// Package netguard keeps the forager's outbound HTTP clients away from cloud
// instance-metadata endpoints. The forager's own credentials (instance role,
// workload identity) live behind those addresses, so no datasource may reach
// them, whatever its URL says.
package netguard

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// metadataIPs are cloud metadata endpoints that are not link-local: AWS's
// IPv6 endpoint, Azure's wireserver and Alibaba Cloud's metadata service.
// Link-local addresses (169.254.169.254 and the rest) are refused wholesale.
var metadataIPs = []net.IP{
	net.ParseIP("fd00:ec2::254"),
	net.ParseIP("168.63.129.16"),
	net.ParseIP("100.100.100.200"),
}

// metadataHosts are names that resolve to a metadata endpoint. They matter
// when an HTTP(S)_PROXY is set: the outbound proxy then resolves the target,
// so the dial guard below only ever sees the proxy's address.
var metadataHosts = []string{"metadata.google.internal", "metadata"}

// refuseMetadataIP returns an error if ip is a cloud metadata address.
func refuseMetadataIP(ip net.IP) error {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("refusing to connect to link-local address %s (cloud metadata endpoints live there)", ip)
	}
	for _, m := range metadataIPs {
		if ip.Equal(m) {
			return fmt.Errorf("refusing to connect to cloud metadata address %s", ip)
		}
	}
	return nil
}

// RefuseMetadataHost checks a configured URL's host as written, before any
// dial. It catches a literal metadata address or name even when the
// connection goes through an outbound proxy and the dial guard never sees
// the target.
func RefuseMetadataHost(host string) error {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, m := range metadataHosts {
		if h == m {
			return fmt.Errorf("refusing cloud metadata host %s", host)
		}
	}
	if ip := net.ParseIP(h); ip != nil {
		return refuseMetadataIP(ip)
	}
	return nil
}

// RefuseMetadataDial is a net.Dialer Control: it runs on the resolved address
// of every connection, so a URL whose name resolves to an instance-metadata
// address (169.254.169.254, metadata.google.internal, fd00:ec2::254) cannot
// be dialled, however the host is spelled and even if DNS changes after the
// datasource was configured.
func RefuseMetadataDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("dial guard: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("dial guard: unresolved address %q", address)
	}
	return refuseMetadataIP(ip)
}

// EffectivePort is u's port, or its scheme's default (80 for http, 443 for
// https). It is "" for a nil URL or another scheme with no explicit port. The
// proxies compare origins with it, so both fill in default ports the same way.
func EffectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// NewTransport returns a clone of http.DefaultTransport (or an equivalent
// transport when DefaultTransport has been replaced) whose every connection
// goes through RefuseMetadataDial.
func NewTransport() *http.Transport {
	var t *http.Transport
	if def, ok := http.DefaultTransport.(*http.Transport); ok {
		t = def.Clone()
	} else {
		t = &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
	}
	guard(t)
	return t
}

func guard(t *http.Transport) {
	t.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   RefuseMetadataDial,
	}).DialContext
	// HTTPS must dial through DialContext too: a DialTLSContext (or legacy
	// DialTLS) cloned from the default transport would bypass the guard.
	t.DialTLSContext = nil
	t.DialTLS = nil //nolint:staticcheck // cleared on purpose, see above
}
