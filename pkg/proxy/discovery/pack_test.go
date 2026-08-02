package discovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// signPack produces a signed pack document from a body (a pack without its
// signature line), mirroring what the publish pipeline will do in CI.
func signPack(t *testing.T, body string, priv ed25519.PrivateKey) string {
	t.Helper()
	sig := ed25519.Sign(priv, SignedBytes([]byte(body)))
	return body + "\nsignature: " + base64.StdEncoding.EncodeToString(sig) + "\n"
}

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return pub, priv
}

const validBody = `version: 3
kind: inventory
collectors:
  - id: os-release
    cmd: cat /etc/os-release
  - id: pkgs-rpm
    when: os_family == "rhel"
    cmd: rpm -qa
  - id: pkgs-dpkg
    when: os_family == "debian"
    cmd: dpkg-query -W`

func TestParseAndVerify_ValidPack(t *testing.T) {
	pub, priv := testKeys(t)

	pack, err := ParseAndVerify([]byte(signPack(t, validBody, priv)), pub)
	if err != nil {
		t.Fatalf("verifying valid pack: %v", err)
	}
	if pack.Version != 3 {
		t.Errorf("version = %d, want 3", pack.Version)
	}
	if len(pack.Collectors) != 3 {
		t.Errorf("collectors = %d, want 3", len(pack.Collectors))
	}
}

// A pack whose content changed after signing must not run: this is the whole
// point of shipping collection logic as content rather than code.
func TestParseAndVerify_TamperedPackRejected(t *testing.T) {
	pub, priv := testKeys(t)
	signed := signPack(t, validBody, priv)

	tampered := strings.Replace(signed, "rpm -qa", "rm -rf /", 1)
	if tampered == signed {
		t.Fatal("test setup: tampering did not modify the pack")
	}

	if _, err := ParseAndVerify([]byte(tampered), pub); err == nil {
		t.Fatal("tampered pack was accepted")
	}
}

func TestParseAndVerify_WrongKeyRejected(t *testing.T) {
	_, priv := testKeys(t)
	otherPub, _ := testKeys(t)

	if _, err := ParseAndVerify([]byte(signPack(t, validBody, priv)), otherPub); err == nil {
		t.Fatal("pack signed by a different key was accepted")
	}
}

func TestParseAndVerify_UnsignedRejected(t *testing.T) {
	pub, _ := testKeys(t)

	if _, err := ParseAndVerify([]byte(validBody), pub); err == nil {
		t.Fatal("unsigned pack was accepted")
	}
}

func TestParseAndVerify_RejectsBadPacks(t *testing.T) {
	pub, priv := testKeys(t)

	cases := []struct {
		name string
		body string
	}{
		{"no version", "kind: inventory\ncollectors:\n  - id: a\n    cmd: true"},
		{"no collectors", "version: 1\nkind: inventory\ncollectors: []"},
		{"unsupported kind", "version: 1\nkind: remediation\ncollectors:\n  - id: a\n    cmd: true"},
		{"collector without id", "version: 1\nkind: inventory\ncollectors:\n  - cmd: true"},
		{"collector without cmd", "version: 1\nkind: inventory\ncollectors:\n  - id: a"},
		{"duplicate ids", "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    cmd: true\n  - id: a\n    cmd: false"},
		{"unknown fact in guard", "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    when: hostname == \"x\"\n    cmd: true"},
		{"malformed guard", "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    when: os_family\n    cmd: true"},
		{"unquoted guard value", "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    when: os_family == rhel\n    cmd: true"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseAndVerify([]byte(signPack(t, tc.body, priv)), pub); err == nil {
				t.Fatalf("invalid pack accepted: %s", tc.name)
			}
		})
	}
}

// Packs are text files that pass through git checkouts, editors and HTTP,
// any of which may rewrite line endings. A CRLF pack must still verify —
// otherwise a platform difference is indistinguishable from tampering.
func TestParseAndVerify_ToleratesCRLF(t *testing.T) {
	pub, priv := testKeys(t)
	signed := signPack(t, validBody, priv)

	crlf := strings.ReplaceAll(signed, "\n", "\r\n")
	if _, err := ParseAndVerify([]byte(crlf), pub); err != nil {
		t.Fatalf("CRLF pack rejected: %v", err)
	}
}

// Normalizing line endings must not weaken tamper detection.
func TestParseAndVerify_CRLFTamperingStillRejected(t *testing.T) {
	pub, priv := testKeys(t)
	signed := signPack(t, validBody, priv)

	crlf := strings.ReplaceAll(strings.Replace(signed, "rpm -qa", "rm -rf /", 1), "\n", "\r\n")
	if _, err := ParseAndVerify([]byte(crlf), pub); err == nil {
		t.Fatal("tampered CRLF pack was accepted")
	}
}

func TestSelect_RunsMatchingCollectors(t *testing.T) {
	pub, priv := testKeys(t)
	pack, err := ParseAndVerify([]byte(signPack(t, validBody, priv)), pub)
	if err != nil {
		t.Fatalf("verifying pack: %v", err)
	}

	run, skipped := pack.Select(map[string]string{"os_family": "debian"})
	if len(skipped) != 0 {
		t.Errorf("skipped = %v, want none", skipped)
	}

	got := collectorIDs(run)
	want := []string{"os-release", "pkgs-dpkg"}
	if !equalStrings(got, want) {
		t.Errorf("collectors = %v, want %v", got, want)
	}
}

// If we could not determine a host's OS family, guards depending on it must
// be reported as skipped rather than quietly treated as non-matching — an
// uninventoried host has to be visible as a gap.
func TestSelect_MissingFactSkipsWithReason(t *testing.T) {
	pub, priv := testKeys(t)
	pack, err := ParseAndVerify([]byte(signPack(t, validBody, priv)), pub)
	if err != nil {
		t.Fatalf("verifying pack: %v", err)
	}

	run, skipped := pack.Select(map[string]string{"arch": "x86_64"})

	if ids := collectorIDs(run); !equalStrings(ids, []string{"os-release"}) {
		t.Errorf("collectors = %v, want [os-release]", ids)
	}
	if len(skipped) != 2 {
		t.Fatalf("skipped = %d, want 2", len(skipped))
	}
	for _, s := range skipped {
		if !strings.Contains(s.Reason, "os_family") {
			t.Errorf("skip reason %q does not name the missing fact", s.Reason)
		}
	}
}

func TestWhenExpr(t *testing.T) {
	cases := []struct {
		expr  string
		facts map[string]string
		want  bool
	}{
		{`os_family == "rhel"`, map[string]string{"os_family": "rhel"}, true},
		{`os_family == "rhel"`, map[string]string{"os_family": "debian"}, false},
		{`os_family != "rhel"`, map[string]string{"os_family": "debian"}, true},
		{`os_family == "rhel" || os_family == "suse"`, map[string]string{"os_family": "suse"}, true},
		{`os_family == "rhel" || os_family == "suse"`, map[string]string{"os_family": "alpine"}, false},
		{`os_family == "rhel" && os_major != "7"`, map[string]string{"os_family": "rhel", "os_major": "9"}, true},
		{`os_family == "rhel" && os_major != "7"`, map[string]string{"os_family": "rhel", "os_major": "7"}, false},
		{`os_id == 'ubuntu'`, map[string]string{"os_id": "ubuntu"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			expr, err := parseWhen(tc.expr)
			if err != nil {
				t.Fatalf("parsing %q: %v", tc.expr, err)
			}
			got, err := expr.eval(tc.facts)
			if err != nil {
				t.Fatalf("evaluating %q: %v", tc.expr, err)
			}
			if got != tc.want {
				t.Errorf("%q with %v = %v, want %v", tc.expr, tc.facts, got, tc.want)
			}
		})
	}
}

func collectorIDs(cs []Collector) []string {
	ids := make([]string, len(cs))
	for i, c := range cs {
		ids[i] = c.ID
	}
	return ids
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
