package discovery

import (
	"strings"
)

// factsProbe is the one command the forager runs before consulting the pack.
// It yields the facts that `when` guards are evaluated against, so the pack
// can carry per-distro commands without the binary knowing any distro.
const factsProbe = `cat /etc/os-release 2>/dev/null; echo "---"; uname -m`

// parseFacts derives guard facts from the probe output. Unparseable or absent
// values are left out of the map rather than defaulted — a missing fact makes
// its guards fail loudly (see whenExpr.eval), which is preferable to running
// an rpm command on an unknown OS.
func parseFacts(probeOutput string) map[string]string {
	osRelease, arch, _ := strings.Cut(probeOutput, "\n---\n")

	facts := make(map[string]string, 4)

	if a := strings.TrimSpace(arch); a != "" {
		facts["arch"] = a
	}

	kv := parseOSRelease(osRelease)
	id := kv["ID"]
	if id != "" {
		facts["os_id"] = id
	}
	if v := kv["VERSION_ID"]; v != "" {
		major, _, _ := strings.Cut(v, ".")
		if major != "" {
			facts["os_major"] = major
		}
	}
	if fam := osFamily(id, kv["ID_LIKE"]); fam != "" {
		facts["os_family"] = fam
	}

	return facts
}

// parseOSRelease reads the shell-style KEY=value format of /etc/os-release.
func parseOSRelease(s string) map[string]string {
	kv := make(map[string]string, 12)
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		kv[strings.TrimSpace(key)] = val
	}
	return kv
}

// osFamily maps a distro ID to the family whose package tooling it uses.
// ID_LIKE is the fallback so derivatives we have never heard of still land in
// the right family — the common case for the RHEL rebuilds these fleets run.
func osFamily(id, idLike string) string {
	byID := map[string]string{
		"rhel": "rhel", "centos": "rhel", "rocky": "rhel", "almalinux": "rhel",
		"ol": "rhel", "oracle": "rhel", "amzn": "rhel", "fedora": "rhel",
		"debian": "debian", "ubuntu": "debian", "linuxmint": "debian", "raspbian": "debian",
		"sles": "suse", "sled": "suse", "opensuse": "suse",
		"opensuse-leap": "suse", "opensuse-tumbleweed": "suse",
		"alpine": "alpine",
	}

	if fam, ok := byID[id]; ok {
		return fam
	}
	for _, like := range strings.Fields(idLike) {
		if fam, ok := byID[like]; ok {
			return fam
		}
		// SUSE ships ID_LIKE="suse opensuse" on some releases.
		if strings.HasPrefix(like, "suse") {
			return "suse"
		}
	}
	return ""
}
