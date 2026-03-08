package signing

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const (
	// maxTimestampSkew is the maximum allowed difference between signed_at and current time.
	maxTimestampSkew = 5 * time.Minute

	// maxNonces is the maximum number of nonces to track for replay prevention.
	maxNonces = 10000
)

// Verifier validates Ed25519 signatures on relay messages.
// If no public key is configured, verification is skipped with a warning log.
type Verifier struct {
	publicKey ed25519.PublicKey
	enabled   bool
	logger    *slog.Logger

	// Replay prevention: track recently seen nonces.
	seenNonces map[string]time.Time
	nonceMu    sync.Mutex
}

// SignatureEnvelope contains the signature metadata embedded in signed messages.
// The signature covers `signed_payload` — a canonical JSON string of the
// security-critical fields. This design allows intermediaries (like the relay)
// to add metadata (request_id, timestamps) without breaking signatures.
type SignatureEnvelope struct {
	SignedPayload string `json:"signed_payload"` // canonical JSON of signed fields
	Signature     string `json:"signature"`      // base64 Ed25519 signature over signed_payload
	SignedAt      string `json:"signed_at"`      // RFC3339 timestamp
	Nonce         string `json:"nonce"`          // unique ID for replay prevention
	KeyID         string `json:"key_id,omitempty"`
}

// NewVerifier creates a signature verifier.
// Accepts either PEM-encoded PKIX or base64-encoded raw public key (32 bytes).
// If publicKeyStr is empty, the verifier operates in warn-only mode (no enforcement).
func NewVerifier(publicKeyStr string, logger *slog.Logger) (*Verifier, error) {
	v := &Verifier{
		logger:     logger,
		seenNonces: make(map[string]time.Time),
	}

	if publicKeyStr == "" {
		v.enabled = false
		logger.Warn("message signing verification disabled: no signing_public_key configured")
		return v, nil
	}

	pubKey, err := parsePublicKey(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("invalid signing_public_key: %w", err)
	}

	v.publicKey = pubKey
	v.enabled = true
	logger.Info("message signing verification enabled")
	return v, nil
}

// parsePublicKey tries PEM (PKIX) first, then raw base64.
func parsePublicKey(s string) (ed25519.PublicKey, error) {
	// Try PEM
	block, _ := pem.Decode([]byte(s))
	if block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PEM parse failed: %w", err)
		}
		edKey, ok := key.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("PEM key is not Ed25519")
		}
		return edKey, nil
	}

	// Try raw base64
	keyBytes, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("expected %d bytes, got %d", ed25519.PublicKeySize, len(keyBytes))
	}
	return ed25519.PublicKey(keyBytes), nil
}

// Enabled returns true if signature verification is active.
func (v *Verifier) Enabled() bool {
	return v.enabled
}

// Verify checks the Ed25519 signature on a message.
//
// The message must contain a SignatureEnvelope with:
//   - signed_payload: canonical JSON of the security-critical fields
//   - signature: Ed25519 signature over signed_payload bytes
//   - signed_at: timestamp within ±5 minutes
//   - nonce: unique value (not previously seen)
//
// The verifier also checks that the signed_payload content matches the
// actual message fields to prevent payload substitution attacks.
//
// Returns nil if verification passes or is disabled (warn-only mode).
func (v *Verifier) Verify(msg []byte) error {
	if !v.enabled {
		var env SignatureEnvelope
		if err := json.Unmarshal(msg, &env); err == nil && env.Signature != "" {
			v.logger.Debug("signature present but verification disabled, skipping")
		} else {
			v.logger.Warn("unsigned message received, verification disabled — accepting",
				"hint", "configure signing_public_key to enforce signature verification")
		}
		return nil
	}

	var env SignatureEnvelope
	if err := json.Unmarshal(msg, &env); err != nil {
		return fmt.Errorf("signature verification failed: cannot parse envelope: %w", err)
	}

	if env.Signature == "" {
		return fmt.Errorf("signature verification failed: missing signature field")
	}
	if env.SignedPayload == "" {
		return fmt.Errorf("signature verification failed: missing signed_payload field")
	}
	if env.SignedAt == "" {
		return fmt.Errorf("signature verification failed: missing signed_at field")
	}
	if env.Nonce == "" {
		return fmt.Errorf("signature verification failed: missing nonce field")
	}

	// Check timestamp
	signedAt, err := time.Parse(time.RFC3339, env.SignedAt)
	if err != nil {
		return fmt.Errorf("signature verification failed: invalid signed_at format: %w", err)
	}
	if absDuration(time.Since(signedAt)) > maxTimestampSkew {
		return fmt.Errorf("signature verification failed: signed_at %s is outside allowed window (±%s)", env.SignedAt, maxTimestampSkew)
	}

	// Check replay
	if v.isReplayedNonce(env.Nonce) {
		return fmt.Errorf("signature verification failed: nonce %s already seen (replay attack)", env.Nonce)
	}

	// Decode signature
	sigBytes, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("signature verification failed: invalid signature encoding: %w", err)
	}

	// Verify Ed25519 signature over the signed_payload string
	if !ed25519.Verify(v.publicKey, []byte(env.SignedPayload), sigBytes) {
		return fmt.Errorf("signature verification failed: invalid signature")
	}

	// Verify signed_payload matches actual message fields (anti-substitution)
	if err := v.verifyPayloadMatchesMessage(env.SignedPayload, msg); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Record nonce after successful verification
	v.recordNonce(env.Nonce)
	return nil
}

// verifyPayloadMatchesMessage checks that the fields in signed_payload actually
// match the corresponding fields in the full message. This prevents an attacker
// from signing one payload but embedding it in a message with different fields.
func (v *Verifier) verifyPayloadMatchesMessage(signedPayload string, msg []byte) error {
	var payloadFields map[string]json.RawMessage
	if err := json.Unmarshal([]byte(signedPayload), &payloadFields); err != nil {
		return fmt.Errorf("signed_payload is not valid JSON: %w", err)
	}

	var msgFields map[string]json.RawMessage
	if err := json.Unmarshal(msg, &msgFields); err != nil {
		return fmt.Errorf("message is not valid JSON: %w", err)
	}

	// Every field in signed_payload must exist in the message with the same value
	for key, payloadVal := range payloadFields {
		msgVal, ok := msgFields[key]
		if !ok {
			return fmt.Errorf("signed field %q not found in message", key)
		}

		// Compare canonical JSON representations
		payloadCanonical, _ := canonicalJSON(payloadVal)
		msgCanonical, _ := canonicalJSON(msgVal)
		if string(payloadCanonical) != string(msgCanonical) {
			return fmt.Errorf("signed field %q does not match message (payload substitution)", key)
		}
	}

	return nil
}

// canonicalJSON re-marshals a JSON value to produce a deterministic representation.
func canonicalJSON(raw json.RawMessage) ([]byte, error) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

func (v *Verifier) isReplayedNonce(nonce string) bool {
	v.nonceMu.Lock()
	defer v.nonceMu.Unlock()

	if _, seen := v.seenNonces[nonce]; seen {
		return true
	}
	return false
}

func (v *Verifier) recordNonce(nonce string) {
	v.nonceMu.Lock()
	defer v.nonceMu.Unlock()

	v.seenNonces[nonce] = time.Now()

	// Evict old nonces if map is too large
	if len(v.seenNonces) > maxNonces {
		cutoff := time.Now().Add(-maxTimestampSkew * 2)
		for n, t := range v.seenNonces {
			if t.Before(cutoff) {
				delete(v.seenNonces, n)
			}
		}
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
