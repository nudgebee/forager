package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadRelayURLScheme(t *testing.T) {
	tests := []struct {
		name      string
		relayURL  string
		wantErr   bool
		errMsg    string
	}{
		{
			name:     "valid wss URL",
			relayURL: "wss://relay.example.com/register",
			wantErr:  false,
		},
		{
			name:     "valid ws URL",
			relayURL: "ws://localhost:8080/register",
			wantErr:  false,
		},
		{
			name:     "invalid https URL",
			relayURL: "https://relay.example.com/register",
			wantErr:  true,
			errMsg:   `relay_url must use ws:// or wss:// scheme`,
		},
		{
			name:     "invalid http URL",
			relayURL: "http://relay.example.com/register",
			wantErr:  true,
			errMsg:   `relay_url must use ws:// or wss:// scheme`,
		},
		{
			name:     "not a URL",
			relayURL: "not-a-url",
			wantErr:  true,
			errMsg:   "relay_url must be a valid URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a temp config file with required fields + relay_url
			tmpDir := t.TempDir()
			configFile := filepath.Join(tmpDir, "forager.yaml")
			content := "relay_url: " + tt.relayURL + "\n" +
				"access_key: testkey\n" +
				"access_secret: testsecret\n"
			if err := os.WriteFile(configFile, []byte(content), 0644); err != nil {
				t.Fatalf("failed to write temp config: %v", err)
			}

			_, err := Load(configFile)
			if (err != nil) != tt.wantErr {
				t.Errorf("Load() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" {
				if err == nil {
					t.Errorf("Load() expected error containing %q, got nil", tt.errMsg)
				} else if !containsString(err.Error(), tt.errMsg) {
					t.Errorf("Load() error = %v, want error containing %q", err, tt.errMsg)
				}
			}
		})
	}
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
