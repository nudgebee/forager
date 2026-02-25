package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"google.golang.org/api/option"
)

// GCPSM fetches secrets from GCP Secret Manager.
type GCPSM struct {
	projectID       string
	credentialsFile string
	logger          *slog.Logger
	client          *secretmanager.Client
}

// NewGCPSM creates a GCP Secret Manager provider.
// The client is lazily initialized on first GetSecret call.
func NewGCPSM(projectID, credentialsFile string, logger *slog.Logger) *GCPSM {
	return &GCPSM{
		projectID:       projectID,
		credentialsFile: credentialsFile,
		logger:          logger,
	}
}

func (g *GCPSM) Name() string    { return "gcp_sm" }
func (g *GCPSM) Available() bool { return g.projectID != "" }

func (g *GCPSM) GetSecret(ctx context.Context, ref string) (map[string]string, error) {
	if err := g.ensureClient(ctx); err != nil {
		return nil, fmt.Errorf("gcp_sm: init client: %w", err)
	}

	resp, err := g.client.AccessSecretVersion(ctx, &secretmanagerpb.AccessSecretVersionRequest{
		Name: ref,
	})
	if err != nil {
		return nil, fmt.Errorf("gcp_sm: AccessSecretVersion(%s): %w", ref, err)
	}

	var result map[string]string
	if err := json.Unmarshal(resp.Payload.Data, &result); err != nil {
		return nil, fmt.Errorf("gcp_sm: secret %s is not valid JSON key-value: %w", ref, err)
	}
	return result, nil
}

func (g *GCPSM) ensureClient(ctx context.Context) error {
	if g.client != nil {
		return nil
	}
	var opts []option.ClientOption
	if g.credentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(g.credentialsFile))
	}
	client, err := secretmanager.NewClient(ctx, opts...)
	if err != nil {
		return err
	}
	g.client = client
	return nil
}
