package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Signer signs messages with an Ed25519 private key.
// This is intended for use by the API server, not the forager agent.
// Included here so both sides share the same canonical payload logic.
type Signer struct {
	privateKey ed25519.PrivateKey
	keyID      string
}

// NewSigner creates a message signer from a base64-encoded Ed25519 private key.
func NewSigner(privateKeyB64, keyID string) (*Signer, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: base64 decode failed: %w", err)
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key: expected %d bytes, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}

	return &Signer{
		privateKey: ed25519.PrivateKey(keyBytes),
		keyID:      keyID,
	}, nil
}

// SigningFields defines which message fields to include in the signed payload.
// These are the security-critical fields that must not be tampered with.
var SigningFields = map[string][]string{
	// Config sync: what datasources are being configured
	"datasource_config_sync": {"action", "account_id", "datasources"},

	// Action requests (new format): what action on which datasource with what params
	"db_query":    {"action", "datasource_id", "params"},
	"db_execute":  {"action", "datasource_id", "params"},
	"db_metadata": {"action", "datasource_id", "params"},

	"ssh_command":  {"action", "datasource_id", "params"},
	"ssh_upload":   {"action", "datasource_id", "params"},
	"ssh_download": {"action", "datasource_id", "params"},
	"ssh_list_dir": {"action", "datasource_id", "params"},

	"http_request": {"action", "datasource_id", "method", "url", "header", "body"},

	"mcp_request":   {"action", "datasource_id", "params"},
	"redis_command": {"action", "datasource_id", "params"},

	"mongo_query":     {"action", "datasource_id", "params"},
	"mongo_aggregate": {"action", "datasource_id", "params"},
}

// DefaultSigningFields is used when the action is not in SigningFields.
var DefaultSigningFields = []string{"action", "datasource_id", "params"}

// Sign adds signature metadata to a JSON message.
//
// It extracts the security-critical fields (based on the action), creates a
// canonical signed_payload, signs it, and adds {signed_payload, signature,
// signed_at, nonce, key_id} to the message.
//
// The relay can add metadata (request_id, timestamps) without breaking the signature.
func (s *Signer) Sign(msg []byte) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(msg, &raw); err != nil {
		return nil, fmt.Errorf("sign: invalid JSON input: %w", err)
	}

	// Determine which fields to sign based on action
	var action string
	if actionRaw, ok := raw["action"]; ok {
		_ = json.Unmarshal(actionRaw, &action)
	}
	// For legacy format, try body.action_name
	if action == "" {
		if bodyRaw, ok := raw["body"]; ok {
			var body map[string]json.RawMessage
			if json.Unmarshal(bodyRaw, &body) == nil {
				if actionNameRaw, ok := body["action_name"]; ok {
					_ = json.Unmarshal(actionNameRaw, &action)
				}
			}
		}
	}

	fields := DefaultSigningFields
	if f, ok := SigningFields[action]; ok {
		fields = f
	}

	// Extract the fields to sign
	signPayload := make(map[string]json.RawMessage)
	for _, field := range fields {
		if val, ok := raw[field]; ok {
			signPayload[field] = val
		}
	}

	// Create canonical signed_payload JSON
	signedPayloadBytes, err := json.Marshal(signPayload)
	if err != nil {
		return nil, fmt.Errorf("sign: marshal signed payload: %w", err)
	}
	signedPayloadStr := string(signedPayloadBytes)

	// Sign the canonical payload
	sig := ed25519.Sign(s.privateKey, signedPayloadBytes)

	// Add signature metadata to the message
	raw["signed_payload"], _ = json.Marshal(signedPayloadStr)
	raw["signature"], _ = json.Marshal(base64.StdEncoding.EncodeToString(sig))
	raw["signed_at"], _ = json.Marshal(time.Now().UTC().Format(time.RFC3339))
	raw["nonce"], _ = json.Marshal(uuid.NewString())
	if s.keyID != "" {
		raw["key_id"], _ = json.Marshal(s.keyID)
	}

	return json.Marshal(raw)
}

// GenerateKeypair creates a new Ed25519 keypair and returns base64-encoded strings.
func GenerateKeypair() (publicKeyB64, privateKeyB64 string, err error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(pub), base64.StdEncoding.EncodeToString(priv), nil
}
