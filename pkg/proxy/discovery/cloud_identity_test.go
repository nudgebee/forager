package discovery

import (
	"context"
	"strings"
	"testing"
)

func TestEnrichCloudIdentity_PopulatesFromProbe(t *testing.T) {
	srv := newFakeSSHServer(t, map[string]string{
		cloudIdentityProbeCmd: "provider=aws\ninstance_id=i-0aab26d051729d673\nregion=us-east-1\npublic_ip=\n",
	})
	cfg := testExecConfig(srv.port(), 5)
	hosts := []SweepHost{{IP: "127.0.0.1", OpenPorts: []int{cfg.port}}}

	enrichCloudIdentity(context.Background(), hosts, cfg)

	if !strings.Contains(hosts[0].CloudIdentity, "provider=aws") {
		t.Errorf("expected CloudIdentity to contain the probe output, got %q", hosts[0].CloudIdentity)
	}
}

func TestEnrichCloudIdentity_NoSSHCredsIsNoop(t *testing.T) {
	// sshClientConfig is nil: mirrors a sweep-only datasource with no SSH
	// credentials configured at all — must not attempt anything.
	cfg := execConfig{port: 22}
	hosts := []SweepHost{{IP: "127.0.0.1", OpenPorts: []int{22}}}

	enrichCloudIdentity(context.Background(), hosts, cfg)

	if hosts[0].CloudIdentity != "" {
		t.Error("expected no-op when no SSH credentials are configured")
	}
}

func TestEnrichCloudIdentity_SkipsHostsWithoutSSHPortOpen(t *testing.T) {
	// Registers a truthy response so that if the port filter were broken and
	// this dialed anyway, the test would catch it via a populated CloudIdentity
	// rather than passing vacuously.
	srv := newFakeSSHServer(t, map[string]string{
		cloudIdentityProbeCmd: "provider=aws\ninstance_id=i-abc\n",
	})
	cfg := testExecConfig(srv.port(), 5)
	hosts := []SweepHost{{IP: "127.0.0.1", OpenPorts: []int{3389}}} // RDP only, no SSH port

	enrichCloudIdentity(context.Background(), hosts, cfg)

	if hosts[0].CloudIdentity != "" {
		t.Error("must not probe a host that has no SSH port open")
	}
}

func TestEnrichCloudIdentity_NonCloudHostStaysEmpty(t *testing.T) {
	// Every provider's metadata service timed out on a bare-metal/non-cloud
	// host — the real command prints nothing in that case.
	srv := newFakeSSHServer(t, map[string]string{
		cloudIdentityProbeCmd: "",
	})
	cfg := testExecConfig(srv.port(), 5)
	hosts := []SweepHost{{IP: "127.0.0.1", OpenPorts: []int{cfg.port}}}

	enrichCloudIdentity(context.Background(), hosts, cfg)

	if hosts[0].CloudIdentity != "" {
		t.Error("empty probe output must leave CloudIdentity empty")
	}
}

func TestEnrichCloudIdentity_OneHostFailureDoesNotAffectAnother(t *testing.T) {
	srv := newFakeSSHServer(t, map[string]string{
		cloudIdentityProbeCmd: "provider=gcp\ninstance_id=123\n",
	})
	cfg := testExecConfig(srv.port(), 5)
	hosts := []SweepHost{
		{IP: "127.0.0.1", OpenPorts: []int{cfg.port}},
		{IP: "203.0.113.254", OpenPorts: []int{cfg.port}}, // unreachable (TEST-NET-3)
	}

	enrichCloudIdentity(context.Background(), hosts, cfg)

	if !strings.Contains(hosts[0].CloudIdentity, "provider=gcp") {
		t.Errorf("reachable host must still be enriched, got %q", hosts[0].CloudIdentity)
	}
	if hosts[1].CloudIdentity != "" {
		t.Error("unreachable host must stay empty, not error")
	}
}
