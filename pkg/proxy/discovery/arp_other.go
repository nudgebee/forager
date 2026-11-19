//go:build !linux

package discovery

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// arpLine matches `arp -an` output, e.g.
// `? (10.0.1.15) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`
var arpLine = regexp.MustCompile(`\(([0-9.]+)\) at ([0-9a-fA-F:]+)`)

// readARPTable shells out to `arp -an` on platforms without /proc/net/arp.
//
// Production foragers run on Linux; this path exists so the sweep behaves
// sensibly during development on macOS rather than silently returning no MACs.
func readARPTable() map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "arp", "-an").Output()
	if err != nil {
		return nil
	}

	table := make(map[string]string)
	for _, match := range arpLine.FindAllStringSubmatch(string(out), -1) {
		ip, mac := match[1], strings.ToLower(match[2])
		if mac == "" || mac == "00:00:00:00:00:00" {
			continue
		}
		table[ip] = normalizeMAC(mac)
	}
	return table
}

// normalizeMAC pads single-digit octets, which BSD arp prints unpadded
// (`a:b:c:d:e:f`), so MACs compare equal across platforms.
func normalizeMAC(mac string) string {
	parts := strings.Split(mac, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}
