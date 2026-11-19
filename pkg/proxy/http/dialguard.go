package http

import (
	"fmt"
	"net"
	"strings"
	"syscall"
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

// refuseMetadataHost checks a base_url host as written, before any dial. It
// catches a literal metadata address or name even when the connection goes
// through an outbound proxy and refuseMetadataDial never sees the target.
func refuseMetadataHost(host string) error {
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

// refuseMetadataDial is a net.Dialer Control: it runs on the resolved address
// of every connection the http proxy opens, so a base_url whose name resolves
// to an instance-metadata address (169.254.169.254, metadata.google.internal,
// fd00:ec2::254) cannot be dialled — whatever the host is spelled as, and
// even if DNS changes after the datasource was configured. The forager's own
// credentials (instance role, workload identity) live behind those addresses.
func refuseMetadataDial(_, address string, _ syscall.RawConn) error {
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
