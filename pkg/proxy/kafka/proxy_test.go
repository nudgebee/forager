package kafka

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"nudgebee/forager/pkg/proxy"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestProxy_Type(t *testing.T) {
	p := New(testLogger())
	if p.Type() != "kafka-proxy" {
		t.Errorf("expected kafka-proxy, got %s", p.Type())
	}
}

func TestProxy_NotConfigured(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "kafka_topics"})
	if err == nil || err.Error() != "kafka not configured" {
		t.Errorf("expected 'kafka not configured', got %v", err)
	}
}

func TestProxy_HealthCheck_NotConfigured(t *testing.T) {
	p := New(testLogger())
	err := p.HealthCheck(context.Background())
	if err == nil {
		t.Error("expected error for health check on unconfigured proxy")
	}
}

func TestProxy_Close_NoClient(t *testing.T) {
	p := New(testLogger())
	if err := p.Close(); err != nil {
		t.Errorf("Close on nil client should not error: %v", err)
	}
}

func TestProxy_Configure_MissingBrokers(t *testing.T) {
	p := New(testLogger())
	err := p.Configure(map[string]any{}, map[string]string{})
	if err == nil || err.Error() != "missing brokers configuration" {
		t.Errorf("expected missing brokers error, got %v", err)
	}
}

func TestProxy_UnknownAction(t *testing.T) {
	p := New(testLogger())
	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{Action: "kafka_unknown"})
	if err == nil || err.Error() != "kafka not configured" {
		t.Errorf("expected not configured error, got %v", err)
	}
}
