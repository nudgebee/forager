package ws

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"nudgebee/forager/pkg/proxy"
	"nudgebee/forager/pkg/secrets"
	"nudgebee/forager/pkg/signing"
)

// The relay signs a canonical JSON of the security-critical fields per action.
// Discovery actions are not in its explicit SigningFields map, so they fall to
// DefaultSigningFields — these three. This test pins that assumption: if the
// relay's default ever diverges from what the forager verifies, discovery
// actions would be rejected in production and nowhere else.
var relayDefaultSigningFields = []string{"action", "datasource_id", "params"}

// signLikeRelay reproduces the relay's signing so the wire contract can be
// exercised from this side, without the server needing to exist yet.
func signLikeRelay(t *testing.T, msg map[string]any, priv ed25519.PrivateKey) []byte {
	t.Helper()

	signed := make(map[string]any, len(relayDefaultSigningFields))
	for _, f := range relayDefaultSigningFields {
		if v, ok := msg[f]; ok {
			signed[f] = v
		}
	}
	payload, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("marshalling signed payload: %v", err)
	}

	msg["signed_payload"] = string(payload)
	msg["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload))
	msg["signed_at"] = time.Now().UTC().Format(time.RFC3339)
	msg["nonce"] = uuid.NewString()

	full, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshalling message: %v", err)
	}
	return full
}

// A discovery action signed the way the relay signs it must verify and route.
// Neither end of this had been exercised: the testbed drove the proxy API
// directly, and the deployed agent has never been sent an action.
func TestRelaySignedDiscoveryActionIsAcceptedAndRouted(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	logger := slog.New(slog.DiscardHandler)
	verifier, err := signing.NewVerifier(base64.StdEncoding.EncodeToString(pub), logger)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	if !verifier.Enabled() {
		t.Fatal("verifier is not enforcing; the test would prove nothing")
	}

	registry := proxy.NewRegistry()
	spy := &recordingProxy{}
	registry.Register("local:aws-testbed", proxy.DatasourceEntry{
		ID: "local:aws-testbed", Type: "discovery", ProxyType: "discovery-proxy", Name: "aws-testbed",
	}, spy)

	store, err := secrets.NewCloudPushStore(t.TempDir(), "test-secret")
	if err != nil {
		t.Fatalf("cred store: %v", err)
	}
	h := NewHandler(registry, store, secrets.NewManager(logger), verifier, logger)

	for _, action := range []string{"discovery_sweep", "discovery_ldap", "discovery_inventory"} {
		t.Run(action, func(t *testing.T) {
			spy.lastAction = ""

			msg := signLikeRelay(t, map[string]any{
				"request_id":    "req-1",
				"datasource_id": "local:aws-testbed",
				"action":        action,
				"params":        map[string]any{"cidrs": []any{"172.31.0.0/28"}},
			}, priv)

			raw, err := h.HandleMessage(context.Background(), msg)
			if err != nil {
				t.Fatalf("handling: %v", err)
			}

			var resp proxy.ActionResponse
			if err := json.Unmarshal(raw, &resp); err != nil {
				t.Fatalf("parsing response: %v", err)
			}
			if resp.StatusCode != 200 {
				t.Fatalf("status %d (%s) — a relay-signed %s was not accepted", resp.StatusCode, resp.Data, action)
			}
			if spy.lastAction != action {
				t.Errorf("proxy received %q, want %q", spy.lastAction, action)
			}
		})
	}
}

// A tampered discovery action must be refused: the signature is what stops an
// attacker who can reach the relay channel from choosing what we execute.
func TestTamperedDiscoveryActionIsRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	logger := slog.New(slog.DiscardHandler)
	verifier, _ := signing.NewVerifier(base64.StdEncoding.EncodeToString(pub), logger)

	registry := proxy.NewRegistry()
	spy := &recordingProxy{}
	registry.Register("local:aws-testbed", proxy.DatasourceEntry{ID: "local:aws-testbed"}, spy)

	store, _ := secrets.NewCloudPushStore(t.TempDir(), "test-secret")
	h := NewHandler(registry, store, secrets.NewManager(logger), verifier, logger)

	msg := signLikeRelay(t, map[string]any{
		"request_id":    "req-1",
		"datasource_id": "local:aws-testbed",
		"action":        "discovery_sweep",
		"params":        map[string]any{"cidrs": []any{"172.31.0.0/28"}},
	}, priv)

	// Widen the scope after signing — the payload the relay authorised said
	// one /28.
	tampered := strings.Replace(string(msg), `"172.31.0.0/28"`, `"10.0.0.0/8"`, 1)

	if _, err := h.HandleMessage(context.Background(), []byte(tampered)); err == nil && spy.lastAction != "" {
		t.Fatal("a tampered discovery action reached the proxy")
	}
}

type recordingProxy struct {
	lastAction string
}

func (r *recordingProxy) Type() string { return "discovery-proxy" }
func (r *recordingProxy) Configure(map[string]any, map[string]string) error {
	return nil
}
func (r *recordingProxy) HandleRequest(_ context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	r.lastAction = req.Action
	return &proxy.ActionResponse{StatusCode: 200, Action: req.Action, Data: "{}"}, nil
}
func (r *recordingProxy) HealthCheck(context.Context) error { return nil }
func (r *recordingProxy) Close() error                      { return nil }

// signedActions is an opt-in allowlist, so a newly added action is unverified
// by default — which is how all three discovery actions shipped unsigned.
// This pins them, so adding a fourth without registering it fails here rather
// than in production.
func TestEveryDiscoveryActionRequiresSignature(t *testing.T) {
	// Mirrors the actions discovery.Proxy.HandleRequest dispatches on.
	for _, action := range []string{"discovery_sweep", "discovery_ldap", "discovery_inventory"} {
		if !signedActions[action] {
			t.Errorf("%s is not in signedActions — it would bypass signature verification", action)
		}
	}
}

// The allowlist's default is the hazard, so state the invariant that matters:
// anything that reaches a host or a network must be signed.
func TestActionsThatTouchRemoteSystemsAreSigned(t *testing.T) {
	mustBeSigned := []string{
		"ssh_command", "ssh_upload", "ssh_download", "ssh_list_dir",
		"db_query", "db_execute", "db_metadata",
		"http_request", "mcp_request",
		"mongo_query", "mongo_aggregate", "mongo_server_status", "mongo_repl_status",
		"mongo_collection_stats", "mongo_current_ops", "mongo_db_stats",
		"mongo_list_databases", "mongo_list_collections",
		"redis_command", "redis_info", "redis_info_section", "redis_slowlog",
		"redis_client_list", "redis_memory_stats", "redis_cluster_info", "redis_keyspace_stats",
		"kafka_consumer_lag", "kafka_consumer_groups", "kafka_consumer_group_describe",
		"kafka_topics", "kafka_topic_describe", "kafka_brokers", "kafka_topic_offsets",
		"discovery_sweep", "discovery_ldap", "discovery_inventory",
		"datasource_config_sync", "test_datasource_config",
	}
	for _, action := range mustBeSigned {
		if !signedActions[action] {
			t.Errorf("%s executes against a remote system but is not signed", action)
		}
	}
}
