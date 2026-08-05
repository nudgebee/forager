package discovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// The example pack in docs/ must stay parseable by the real implementation:
// a sample that no longer loads is worse than no sample.
func TestExamplePackIsValid(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/content-packs/linux-inventory-example.yaml")
	if err != nil {
		t.Fatalf("reading example pack: %v", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sig := ed25519.Sign(priv, SignedBytes(raw))
	signed := append(SignedBytes(raw), []byte("\nsignature: "+b64(sig)+"\n")...)

	pack, err := ParseAndVerify(signed, pub)
	if err != nil {
		t.Fatalf("example pack does not load: %v", err)
	}
	if len(pack.Collectors) == 0 {
		t.Fatal("example pack has no collectors")
	}

	// Every guard must be evaluable against a realistic fact set.
	for _, family := range []string{"rhel", "debian", "suse", "alpine"} {
		facts := map[string]string{"os_family": family, "os_id": "x", "os_major": "9", "arch": "x86_64"}
		run, skipped := pack.Select(facts)
		if len(skipped) != 0 {
			t.Errorf("%s: unexpected skips: %v", family, skipped)
		}
		if len(run) == 0 {
			t.Errorf("%s: no collectors selected", family)
		}
	}
}

// Vulnerability matching resolves advisories against the SOURCE package, so a
// package list without it silently matches almost nothing: measured on a live
// RHEL 9 host, 51 findings with SOURCERPM and 0 without. These assertions exist
// because that failure is invisible — the scan succeeds and reports a clean
// machine — so a well-meaning simplification of these commands would not be
// caught by anything else.
func TestExamplePackCollectsSourcePackage(t *testing.T) {
	pack := loadExamplePack(t)

	for _, tc := range []struct {
		collector string
		want      string
	}{
		{"pkgs-rpm", "%{SOURCERPM}"},
		{"pkgs-dpkg", "${source:Package}"},
		// Alpine's secdb is keyed on the origin package, which lives in the
		// installed database's "o:" field and is absent from `apk info` output
		// at any verbosity.
		{"pkgs-apk", "/lib/apk/db/installed"},
	} {
		cmd := collectorCmd(t, pack, tc.collector)
		if !strings.Contains(cmd, tc.want) {
			t.Errorf("%s must collect the source package (%s); got: %s", tc.collector, tc.want, cmd)
		}
	}
}

// rpm before 4.14 does not know MODULARITYLABEL, and on an unknown tag it
// prints an error, emits NO PACKAGES AT ALL, and still exits 0. Naming the tag
// unconditionally therefore blinds every RHEL/CentOS 7 host silently. The
// command must probe --querytags first. Verified against centos:7 (rpm 4.11.3)
// and ubi8 (rpm 4.14.3).
func TestExamplePackGuardsModularityTagForOldRpm(t *testing.T) {
	cmd := collectorCmd(t, loadExamplePack(t), "pkgs-rpm")

	if !strings.Contains(cmd, "MODULARITYLABEL") {
		t.Fatal("pkgs-rpm must collect MODULARITYLABEL: without it RHEL 8/9 module streams mismatch")
	}
	if !strings.Contains(cmd, "--querytags") {
		t.Error("pkgs-rpm must probe `rpm --querytags` before using MODULARITYLABEL, " +
			"or rpm < 4.14 returns an empty package list and the host looks clean")
	}
}

func loadExamplePack(t *testing.T) *Pack {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/content-packs/linux-inventory-example.yaml")
	if err != nil {
		t.Fatalf("reading example pack: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	sig := ed25519.Sign(priv, SignedBytes(raw))
	pack, err := ParseAndVerify(append(SignedBytes(raw), []byte("\nsignature: "+b64(sig)+"\n")...), pub)
	if err != nil {
		t.Fatalf("example pack does not load: %v", err)
	}
	return pack
}

func collectorCmd(t *testing.T, pack *Pack, id string) string {
	t.Helper()
	for _, c := range pack.Collectors {
		if c.ID == id {
			return c.Cmd
		}
	}
	t.Fatalf("collector %q not found in example pack", id)
	return ""
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
