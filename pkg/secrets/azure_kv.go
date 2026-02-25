package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
)

// AzureKV fetches secrets from Azure Key Vault.
type AzureKV struct {
	vaultURL string
	tenantID string
	clientID string // used for user-assigned managed identity (sets AZURE_CLIENT_ID)
	logger   *slog.Logger
	client   *azsecrets.Client
	initOnce sync.Once
	initErr  error
}

// NewAzureKV creates an Azure Key Vault provider.
// The client is lazily initialized on first GetSecret call.
func NewAzureKV(vaultURL, tenantID, clientID string, logger *slog.Logger) *AzureKV {
	return &AzureKV{
		vaultURL: vaultURL,
		tenantID: tenantID,
		clientID: clientID,
		logger:   logger,
	}
}

func (a *AzureKV) Name() string    { return "azure_kv" }
func (a *AzureKV) Available() bool { return a.vaultURL != "" }

func (a *AzureKV) GetSecret(ctx context.Context, ref string) (map[string]string, error) {
	if err := a.ensureClient(); err != nil {
		return nil, fmt.Errorf("azure_kv: init client: %w", err)
	}

	resp, err := a.client.GetSecret(ctx, ref, "", nil)
	if err != nil {
		return nil, fmt.Errorf("azure_kv: GetSecret(%s): %w", ref, err)
	}

	if resp.Value == nil {
		return nil, fmt.Errorf("azure_kv: secret %s has nil value", ref)
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(*resp.Value), &result); err != nil {
		return nil, fmt.Errorf("azure_kv: secret %s is not valid JSON key-value: %w", ref, err)
	}
	return result, nil
}

func (a *AzureKV) ensureClient() error {
	a.initOnce.Do(func() {
		// DefaultAzureCredential picks up AZURE_CLIENT_ID for user-assigned managed identity.
		// Set it from config if provided and not already in the environment.
		if a.clientID != "" && os.Getenv("AZURE_CLIENT_ID") == "" {
			os.Setenv("AZURE_CLIENT_ID", a.clientID)
		}

		cred, err := azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{
			TenantID: a.tenantID,
		})
		if err != nil {
			a.initErr = fmt.Errorf("azure credential: %w", err)
			return
		}

		client, err := azsecrets.NewClient(a.vaultURL, cred, nil)
		if err != nil {
			a.initErr = fmt.Errorf("azure kv client: %w", err)
			return
		}
		a.client = client
	})
	return a.initErr
}
