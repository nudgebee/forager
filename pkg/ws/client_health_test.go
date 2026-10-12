package ws

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A config sync that lands during the initial delay reports at once, and the trigger
// is consumed by that report instead of firing a second one behind it.
func TestHealthReportLoop_TriggerDuringInitialDelayReportsOnce(t *testing.T) {
	c := NewClient("ws://unused", "k", "s", nil, testLogger(), 60)
	var reports atomic.Int32
	c.SetHealthReporter(func(context.Context) map[string]any {
		reports.Add(1)
		return nil
	})

	c.TriggerHealthReport()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.healthReportLoop(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for reports.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if reports.Load() != 1 {
		t.Fatalf("expected an immediate report, got %d", reports.Load())
	}
	time.Sleep(200 * time.Millisecond)
	if got := reports.Load(); got != 1 {
		t.Fatalf("trigger fired a duplicate report: %d", got)
	}
}
