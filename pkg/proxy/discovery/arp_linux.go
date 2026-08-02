//go:build linux

package discovery

import (
	"bufio"
	"os"
	"strings"
)

// readARPTable reads the kernel's neighbour cache from /proc/net/arp.
//
// Reading the cache rather than sending ARP frames keeps the forager free of
// raw sockets and the CAP_NET_RAW capability that goes with them: a discovery
// node that needs elevated privileges is a much harder thing to get deployed
// into a customer's network.
func readARPTable() map[string]string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	table := make(map[string]string)
	scanner := bufio.NewScanner(f)

	// Discard the header: "IP address  HW type  Flags  HW address  Mask  Device"
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		ip, mac := fields[0], strings.ToLower(fields[3])
		// 00:00:00:00:00:00 means the entry is incomplete — the kernel tried
		// and got no answer. Recording it would invent a MAC that isn't there.
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		table[ip] = mac
	}
	return table
}
