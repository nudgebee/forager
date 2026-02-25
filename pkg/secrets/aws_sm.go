package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// AWSSM fetches secrets from AWS Secrets Manager.
type AWSSM struct {
	region   string
	logger   *slog.Logger
	client   *secretsmanager.Client
	initOnce sync.Once
	initErr  error
}

// NewAWSSM creates an AWS Secrets Manager provider.
// The client is lazily initialized on first GetSecret call.
func NewAWSSM(region string, logger *slog.Logger) *AWSSM {
	return &AWSSM{region: region, logger: logger}
}

func (a *AWSSM) Name() string    { return "aws_sm" }
func (a *AWSSM) Available() bool { return a.region != "" }

func (a *AWSSM) GetSecret(ctx context.Context, ref string) (map[string]string, error) {
	if err := a.ensureClient(ctx); err != nil {
		return nil, fmt.Errorf("aws_sm: init client: %w", err)
	}

	out, err := a.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &ref,
	})
	if err != nil {
		return nil, fmt.Errorf("aws_sm: GetSecretValue(%s): %w", ref, err)
	}

	if out.SecretString == nil {
		return nil, fmt.Errorf("aws_sm: secret %s has no string value (binary secrets not supported)", ref)
	}

	var result map[string]string
	if err := json.Unmarshal([]byte(*out.SecretString), &result); err != nil {
		return nil, fmt.Errorf("aws_sm: secret %s is not valid JSON key-value: %w", ref, err)
	}
	return result, nil
}

func (a *AWSSM) ensureClient(ctx context.Context) error {
	a.initOnce.Do(func() {
		cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(a.region))
		if err != nil {
			a.initErr = err
			return
		}
		a.client = secretsmanager.NewFromConfig(cfg)
	})
	return a.initErr
}
