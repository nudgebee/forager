package discovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
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

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
