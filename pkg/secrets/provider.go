package secrets

import "context"

// Provider is the interface for secret backends (AWS SM, GCP SM, Azure KV, etc.).
type Provider interface {
	// Name returns the provider identifier (e.g. "aws_sm", "gcp_sm", "azure_kv").
	Name() string

	// GetSecret fetches a secret by reference (secret name, path, or URL).
	// Returns a map of key-value pairs (e.g. {"username": "...", "password": "..."}).
	GetSecret(ctx context.Context, ref string) (map[string]string, error)

	// Available reports whether this provider can work in the current environment.
	Available() bool
}
