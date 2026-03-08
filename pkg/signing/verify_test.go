package signing

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"os"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func generateTestKeypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return pub, priv
}

func testSigner(t *testing.T, priv ed25519.PrivateKey) *Signer {
	t.Helper()
	s, err := NewSigner(base64.StdEncoding.EncodeToString(priv), "test-key")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

func TestNewVerifier_NoKey(t *testing.T) {
	v, err := NewVerifier("", testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v.Enabled() {
		t.Fatal("expected verifier to be disabled")
	}
}

func TestNewVerifier_ValidKey(t *testing.T) {
	pub, _ := generateTestKeypair()
	v, err := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !v.Enabled() {
		t.Fatal("expected verifier to be enabled")
	}
}

func TestNewVerifier_InvalidKey(t *testing.T) {
	_, err := NewVerifier("not-valid-base64!!!", testLogger())
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}

	_, err = NewVerifier(base64.StdEncoding.EncodeToString([]byte("too-short")), testLogger())
	if err == nil {
		t.Fatal("expected error for wrong key size")
	}
}

func TestNewVerifier_PEMKey(t *testing.T) {
	pub, priv := generateTestKeypair()

	// Encode public key as PEM (PKIX)
	pkixBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixBytes})

	v, err := NewVerifier(string(pubPEM), testLogger())
	if err != nil {
		t.Fatalf("NewVerifier with PEM: %v", err)
	}
	if !v.Enabled() {
		t.Fatal("expected verifier to be enabled with PEM key")
	}

	// Sign with raw key, verify with PEM-parsed key
	signer := testSigner(t, priv)
	msg := []byte(`{"action":"db_query","datasource_id":"ds-1","params":{"query":"SELECT 1"}}`)
	signed, err := signer.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := v.Verify(signed); err != nil {
		t.Fatalf("Verify with PEM key failed: %v", err)
	}
}

func TestVerify_Disabled(t *testing.T) {
	v, _ := NewVerifier("", testLogger())
	err := v.Verify([]byte(`{"action": "datasource_config_sync"}`))
	if err != nil {
		t.Fatalf("expected nil error when disabled, got: %v", err)
	}
}

func TestVerify_ValidSignature(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, priv)

	msg := map[string]any{
		"action":     "datasource_config_sync",
		"account_id": "acc-123",
		"datasources": []any{
			map[string]any{"id": "ds-1", "type": "postgresql"},
		},
	}
	msgBytes, _ := json.Marshal(msg)
	signed, err := s.Sign(msgBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := v.Verify(signed); err != nil {
		t.Fatalf("expected valid signature, got error: %v", err)
	}
}

func TestVerify_ValidSignature_ActionRequest(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, priv)

	msg := map[string]any{
		"action":        "db_query",
		"datasource_id": "ds-postgres-1",
		"params":        map[string]any{"query": "SELECT 1"},
	}
	msgBytes, _ := json.Marshal(msg)
	signed, err := s.Sign(msgBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := v.Verify(signed); err != nil {
		t.Fatalf("expected valid signature, got error: %v", err)
	}
}

func TestVerify_RelayAddsFields_StillValid(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, priv)

	// Original message
	msg := map[string]any{
		"action":        "db_query",
		"datasource_id": "ds-1",
		"params":        map[string]any{"query": "SELECT 1"},
	}
	msgBytes, _ := json.Marshal(msg)
	signed, err := s.Sign(msgBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Simulate relay adding request_id and body.timestamp
	var withRelay map[string]json.RawMessage
	if err := json.Unmarshal(signed, &withRelay); err != nil {
		t.Fatalf("Unmarshal signed: %v", err)
	}
	withRelay["request_id"], _ = json.Marshal("relay-added-req-id")
	withRelay["body"], _ = json.Marshal(map[string]any{"timestamp": 1234567890})
	relayModified, _ := json.Marshal(withRelay)

	// Signature should still be valid — relay-added fields are not in signed_payload
	if err := v.Verify(relayModified); err != nil {
		t.Fatalf("expected valid signature after relay modifications, got: %v", err)
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	pub, _ := generateTestKeypair()
	_, wrongPriv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, wrongPriv)

	msg := map[string]any{"action": "datasource_config_sync", "account_id": "acc-123"}
	msgBytes, _ := json.Marshal(msg)
	signed, _ := s.Sign(msgBytes)

	if err := v.Verify(signed); err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

func TestVerify_MissingSignature(t *testing.T) {
	pub, _ := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())

	msg := []byte(`{"action": "datasource_config_sync", "account_id": "acc-123"}`)
	if err := v.Verify(msg); err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestVerify_ExpiredTimestamp(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())

	msg := map[string]any{"action": "datasource_config_sync", "account_id": "acc-123"}
	msgBytes, _ := json.Marshal(msg)

	// Sign normally, then tamper with signed_at
	s := testSigner(t, priv)
	signed, _ := s.Sign(msgBytes)

	var raw map[string]json.RawMessage
	json.Unmarshal(signed, &raw)
	raw["signed_at"], _ = json.Marshal(time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339))
	tamperedTime, _ := json.Marshal(raw)

	if err := v.Verify(tamperedTime); err == nil {
		t.Fatal("expected error for expired timestamp")
	}
}

func TestVerify_ReplayedNonce(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, priv)

	msg := map[string]any{"action": "datasource_config_sync", "account_id": "acc-123"}
	msgBytes, _ := json.Marshal(msg)
	signed, _ := s.Sign(msgBytes)

	// First call should succeed
	if err := v.Verify(signed); err != nil {
		t.Fatalf("first verify should succeed: %v", err)
	}

	// Same message (same nonce) should fail
	if err := v.Verify(signed); err == nil {
		t.Fatal("expected error for replayed nonce")
	}
}

func TestVerify_TamperedAction(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, priv)

	msg := map[string]any{
		"action":        "db_query",
		"datasource_id": "ds-1",
		"params":        map[string]any{"query": "SELECT 1"},
	}
	msgBytes, _ := json.Marshal(msg)
	signed, _ := s.Sign(msgBytes)

	// Tamper: change action to ssh_exec
	var raw map[string]json.RawMessage
	json.Unmarshal(signed, &raw)
	raw["action"], _ = json.Marshal("ssh_exec")
	tampered, _ := json.Marshal(raw)

	if err := v.Verify(tampered); err == nil {
		t.Fatal("expected error for tampered action")
	}
}

func TestVerify_TamperedParams(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, priv)

	msg := map[string]any{
		"action":        "db_query",
		"datasource_id": "ds-1",
		"params":        map[string]any{"query": "SELECT 1"},
	}
	msgBytes, _ := json.Marshal(msg)
	signed, _ := s.Sign(msgBytes)

	// Tamper: change the query
	var raw map[string]json.RawMessage
	json.Unmarshal(signed, &raw)
	raw["params"], _ = json.Marshal(map[string]any{"query": "DROP TABLE users"})
	tampered, _ := json.Marshal(raw)

	if err := v.Verify(tampered); err == nil {
		t.Fatal("expected error for tampered params")
	}
}

func TestVerify_TamperedDatasourceID(t *testing.T) {
	pub, priv := generateTestKeypair()
	v, _ := NewVerifier(base64.StdEncoding.EncodeToString(pub), testLogger())
	s := testSigner(t, priv)

	msg := map[string]any{
		"action":        "ssh_exec",
		"datasource_id": "ds-staging",
		"params":        map[string]any{"command": "ls"},
	}
	msgBytes, _ := json.Marshal(msg)
	signed, _ := s.Sign(msgBytes)

	// Tamper: redirect to production datasource
	var raw map[string]json.RawMessage
	json.Unmarshal(signed, &raw)
	raw["datasource_id"], _ = json.Marshal("ds-production")
	tampered, _ := json.Marshal(raw)

	if err := v.Verify(tampered); err == nil {
		t.Fatal("expected error for tampered datasource_id")
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	pubB64, privB64, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	signer, err := NewSigner(privB64, "test")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	verifier, err := NewVerifier(pubB64, testLogger())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	msg := map[string]any{
		"action":     "datasource_config_sync",
		"account_id": "acc-456",
		"datasources": []any{
			map[string]any{"id": "ds-1", "type": "postgresql", "proxy_type": "db-proxy"},
		},
	}
	msgBytes, _ := json.Marshal(msg)

	signed, err := signer.Sign(msgBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := verifier.Verify(signed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}
