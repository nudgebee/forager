package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

// FuzzParsePublicKey exercises the three accepted public-key encodings
// (OpenSSH authorized_keys, PEM/PKIX, raw base64). The parser must never
// panic, and any key it accepts must be a correctly sized Ed25519 key.
func FuzzParsePublicKey(f *testing.F) {
	pub, _ := generateTestKeypair()
	f.Add(base64.StdEncoding.EncodeToString(pub))
	f.Add("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc comment")
	f.Add("-----BEGIN PUBLIC KEY-----\nzzz\n-----END PUBLIC KEY-----")
	f.Add("not base64 !!!")
	f.Add("")

	f.Fuzz(func(t *testing.T, s string) {
		key, err := parsePublicKey(s)
		if err != nil {
			return
		}
		if len(key) != ed25519.PublicKeySize {
			t.Fatalf("parsePublicKey accepted a %d-byte key, want %d", len(key), ed25519.PublicKeySize)
		}
	})
}

// FuzzCanonicalJSON asserts canonicalJSON never panics on arbitrary bytes
// and is idempotent: re-canonicalizing its own output must be a no-op. The
// anti-substitution check in verifyPayloadMatchesMessage relies on this
// stability when comparing signed fields against the message.
func FuzzCanonicalJSON(f *testing.F) {
	f.Add([]byte(`{"b":1,"a":2}`))
	f.Add([]byte(`[1,"two",{"k":null}]`))
	f.Add([]byte(`"string"`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, raw []byte) {
		out, err := canonicalJSON(raw)
		if err != nil {
			return
		}
		again, err := canonicalJSON(out)
		if err != nil {
			t.Fatalf("canonicalJSON output failed to re-encode: %v", err)
		}
		if string(again) != string(out) {
			t.Fatalf("canonicalJSON not idempotent:\n first: %s\nsecond: %s", out, again)
		}
	})
}

// FuzzVerify feeds mutated envelopes to an enabled Verifier. The contract is
// that Verify never panics on untrusted input. A genuinely signed message is
// confirmed to verify once up front (the mutation engine works outward from
// that seed).
func FuzzVerify(f *testing.F) {
	pub, priv := generateTestKeypair()

	signer, err := NewSigner(base64.StdEncoding.EncodeToString(priv), "test-key")
	if err != nil {
		f.Fatalf("NewSigner: %v", err)
	}
	signed, err := signer.Sign([]byte(`{"action":"db_query","datasource_id":"ds1","params":{"q":"select 1"}}`))
	if err != nil {
		f.Fatalf("Sign: %v", err)
	}

	v, err := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	if err != nil {
		f.Fatalf("NewVerifier: %v", err)
	}
	if err := v.Verify(signed); err != nil {
		f.Fatalf("freshly signed message failed to verify: %v", err)
	}

	f.Add(signed)
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`{"signature":"!!!","signed_payload":"{}","signed_at":"now","nonce":"n"}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Construct the verifier directly to skip per-iteration public-key
		// parsing; a fresh seenNonces map keeps replay state isolated
		// between inputs.
		vv := &Verifier{
			publicKey:  pub,
			enabled:    true,
			logger:     testLogger(),
			seenNonces: make(map[string]time.Time),
		}
		_ = vv.Verify(data) // must not panic on any input
	})
}
