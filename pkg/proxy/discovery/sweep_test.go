package discovery

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"nudgebee/forager/pkg/proxy"
)

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parsing %q: %v", s, err)
		}
		out[i] = p.Masked()
	}
	return out
}

func TestExpandCIDRs_SkipsNetworkAndBroadcast(t *testing.T) {
	addrs, excluded, err := expandCIDRs(mustPrefixes(t, "10.0.1.0/29"), nil)
	if err != nil {
		t.Fatalf("expanding: %v", err)
	}
	if excluded != 0 {
		t.Errorf("excluded = %d, want 0", excluded)
	}

	// /29 is 8 addresses; .0 (network) and .7 (broadcast) are not hosts.
	want := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.5", "10.0.1.6"}
	if len(addrs) != len(want) {
		t.Fatalf("addresses = %v, want %v", addrs, want)
	}
	for i := range want {
		if addrs[i] != want[i] {
			t.Errorf("addrs[%d] = %s, want %s", i, addrs[i], want[i])
		}
	}
}

// A /31 is a point-to-point link where both addresses are usable, so the
// network/broadcast rule must not apply.
func TestExpandCIDRs_PointToPoint(t *testing.T) {
	addrs, _, err := expandCIDRs(mustPrefixes(t, "10.0.1.0/31"), nil)
	if err != nil {
		t.Fatalf("expanding: %v", err)
	}
	if len(addrs) != 2 {
		t.Errorf("addresses = %v, want both /31 addresses", addrs)
	}
}

// Exclusions must be applied during expansion, so an excluded address is never
// handed to a prober at all — filtering after the fact would still have sent
// packets to it.
func TestExpandCIDRs_ExclusionsRemovedBeforeProbing(t *testing.T) {
	exclusions := []netip.Prefix{
		netip.PrefixFrom(netip.MustParseAddr("10.0.1.3"), 32),
	}
	addrs, excluded, err := expandCIDRs(mustPrefixes(t, "10.0.1.0/29"), exclusions)
	if err != nil {
		t.Fatalf("expanding: %v", err)
	}
	if excluded != 1 {
		t.Errorf("excluded count = %d, want 1", excluded)
	}
	for _, a := range addrs {
		if a == "10.0.1.3" {
			t.Fatal("excluded address made it into the probe list")
		}
	}
}

func TestExpandCIDRs_ExclusionRangeRemoved(t *testing.T) {
	addrs, excluded, err := expandCIDRs(mustPrefixes(t, "10.0.1.0/28"), mustPrefixes(t, "10.0.1.8/29"))
	if err != nil {
		t.Fatalf("expanding: %v", err)
	}
	// The exclusion covers .8–.15, but .15 is the /28's broadcast address and
	// is skipped as a non-host before exclusions are consulted, so 7 host
	// addresses are excluded rather than 8.
	if excluded != 7 {
		t.Errorf("excluded = %d, want 7", excluded)
	}
	for _, a := range addrs {
		if a >= "10.0.1.8" && a <= "10.0.1.15" {
			t.Errorf("address %s from the excluded range was kept", a)
		}
	}
}

// Scope has a hard ceiling: an operator pasting a /8 would otherwise queue 16M
// probes and run for days.
func TestExpandCIDRs_RejectsOversizedScope(t *testing.T) {
	if _, _, err := expandCIDRs(mustPrefixes(t, "10.0.0.0/8"), nil); err == nil {
		t.Fatal("accepted a scope far beyond the address ceiling")
	}
}

func TestExpandCIDRs_RejectsIPv6(t *testing.T) {
	p, err := netip.ParsePrefix("2001:db8::/64")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if _, _, err := expandCIDRs([]netip.Prefix{p}, nil); err == nil {
		t.Fatal("accepted an IPv6 CIDR without support for it")
	}
}

// The rate cap is a product requirement, not a tuning knob: an unannounced
// sweep at full speed trips IDS and becomes a security incident. It must hold
// regardless of what the server asks for.
func TestRunSweep_HonoursRateCap(t *testing.T) {
	const ratePPS = 50

	var probes int64
	ln := listenCounting(t, &probes)

	cfg := sweepConfig{
		cidrs:        mustPrefixes(t, "127.0.0.1/32"),
		ports:        []int{ln.port},
		ratePPS:      ratePPS,
		probeTimeout: 500 * time.Millisecond,
		workers:      16,
	}
	// One /32 is a single probe, so widen the scope to make rate observable.
	cfg.cidrs = mustPrefixes(t, "127.0.0.0/26")

	start := time.Now()
	result, err := runSweep(context.Background(), cfg)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	elapsed := time.Since(start)

	// With N probes at R pps the run cannot finish faster than (N-burst)/R.
	minDuration := time.Duration(float64(result.Scanned-burstFor(ratePPS))/float64(ratePPS)*float64(time.Second)) - 100*time.Millisecond
	if elapsed < minDuration {
		t.Errorf("swept %d addresses in %s — faster than the %d pps cap allows (min %s)",
			result.Scanned, elapsed, ratePPS, minDuration)
	}
}

func TestRunSweep_FindsListenerAndReportsPort(t *testing.T) {
	var probes int64
	ln := listenCounting(t, &probes)

	cfg := sweepConfig{
		cidrs:        mustPrefixes(t, "127.0.0.1/32"),
		ports:        []int{ln.port},
		ratePPS:      1000,
		probeTimeout: time.Second,
		workers:      4,
	}

	result, err := runSweep(context.Background(), cfg)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(result.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(result.Hosts))
	}
	h := result.Hosts[0]
	if h.IP != "127.0.0.1" {
		t.Errorf("ip = %s, want 127.0.0.1", h.IP)
	}
	if len(h.OpenPorts) != 1 || h.OpenPorts[0] != ln.port {
		t.Errorf("open_ports = %v, want [%d]", h.OpenPorts, ln.port)
	}
}

// A closed port yields no host: a sweep reports what answered, and inventing
// hosts would corrupt the coverage denominator.
func TestRunSweep_ClosedPortYieldsNoHost(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()

	cfg := sweepConfig{
		cidrs:        mustPrefixes(t, "127.0.0.1/32"),
		ports:        []int{port},
		ratePPS:      1000,
		probeTimeout: 300 * time.Millisecond,
		workers:      4,
	}

	result, err := runSweep(context.Background(), cfg)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(result.Hosts) != 0 {
		t.Errorf("hosts = %v, want none", result.Hosts)
	}
}

func TestParseSweepParams(t *testing.T) {
	t.Run("clamps rate to the module cap", func(t *testing.T) {
		cfg, err := parseSweepParams(map[string]any{
			"cidrs":    []any{"10.0.1.0/24"},
			"rate_pps": float64(100000),
		}, 250)
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		if cfg.ratePPS != 250 {
			t.Errorf("rate_pps = %d, want it clamped to 250", cfg.ratePPS)
		}
	})

	t.Run("defaults", func(t *testing.T) {
		cfg, err := parseSweepParams(map[string]any{"cidrs": []any{"10.0.1.0/24"}}, maxRatePPS)
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		if cfg.ratePPS != defaultRatePPS {
			t.Errorf("rate_pps = %d, want %d", cfg.ratePPS, defaultRatePPS)
		}
		if len(cfg.ports) != 3 {
			t.Errorf("ports = %v, want the default three", cfg.ports)
		}
	})

	t.Run("accepts a bare address as an exclusion", func(t *testing.T) {
		cfg, err := parseSweepParams(map[string]any{
			"cidrs":      []any{"10.0.1.0/24"},
			"exclusions": []any{"10.0.1.250"},
		}, maxRatePPS)
		if err != nil {
			t.Fatalf("parsing: %v", err)
		}
		if len(cfg.exclusions) != 1 || cfg.exclusions[0].Bits() != 32 {
			t.Errorf("exclusions = %v, want a single /32", cfg.exclusions)
		}
	})

	t.Run("rejects bad input", func(t *testing.T) {
		cases := []struct {
			name   string
			params map[string]any
		}{
			{"no cidrs", map[string]any{}},
			{"empty cidrs", map[string]any{"cidrs": []any{}}},
			{"malformed cidr", map[string]any{"cidrs": []any{"not-a-cidr"}}},
			{"malformed exclusion", map[string]any{"cidrs": []any{"10.0.1.0/24"}, "exclusions": []any{"nope"}}},
			{"port out of range", map[string]any{"cidrs": []any{"10.0.1.0/24"}, "ports": []any{float64(70000)}}},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := parseSweepParams(tc.params, maxRatePPS); err == nil {
					t.Fatalf("accepted invalid params: %s", tc.name)
				}
			})
		}
	})
}

// The server chooses which CIDRs to sweep, but the forager refuses any outside
// what its datasource was configured for: a segment collector must not be
// turnable into a general-purpose scanner by a single bad request.
func TestHandleSweep_RefusesCIDROutsideDatasourceScope(t *testing.T) {
	p, _ := newTestProxy(t, map[string]any{
		"allowed_cidrs": []any{"10.0.1.0/24"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	_, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_sweep",
		Params: map[string]any{"cidrs": []any{"192.168.50.0/24"}},
	})
	if err == nil {
		t.Fatal("swept a CIDR outside the datasource's configured scope")
	}
}

func TestHandleSweep_AllowsCIDRWithinScope(t *testing.T) {
	p, _ := newTestProxy(t, map[string]any{
		"allowed_cidrs": []any{"127.0.0.0/8"},
	}, map[string]string{"username": "nudgebee-ro", "password": "x"})

	resp, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_sweep",
		Params: map[string]any{
			"cidrs":      []any{"127.0.0.0/30"},
			"ports":      []any{float64(1)}, // nothing listens; we only need it to complete
			"timeout_ms": float64(200),
		},
	})
	if err != nil {
		t.Fatalf("sweep within scope failed: %v", err)
	}

	var result SweepResult
	if err := json.Unmarshal([]byte(resp.Data), &result); err != nil {
		t.Fatalf("parsing response: %v", err)
	}
	if result.RatePPS != defaultRatePPS {
		t.Errorf("rate_pps = %d, want the default %d reported back", result.RatePPS, defaultRatePPS)
	}
}

func TestPrefixWithinAny(t *testing.T) {
	_, tenNet, _ := net.ParseCIDR("10.0.0.0/8")
	configured := []*net.IPNet{tenNet}

	cases := []struct {
		cidr string
		want bool
	}{
		{"10.0.1.0/24", true},
		{"10.255.255.0/24", true},
		{"10.0.0.0/8", true},
		{"192.168.1.0/24", false},
		{"10.0.0.0/7", false}, // wider than configured: must not be allowed
	}
	for _, tc := range cases {
		got := prefixWithinAny(netip.MustParsePrefix(tc.cidr), configured)
		if got != tc.want {
			t.Errorf("prefixWithinAny(%s) = %v, want %v", tc.cidr, got, tc.want)
		}
	}
}

func TestHandleLDAP_RefusesWhenNoDirectoryConfigured(t *testing.T) {
	p, _ := newTestProxy(t, map[string]any{}, map[string]string{
		"username": "nudgebee-ro", "password": "x",
	})

	if _, err := p.HandleRequest(context.Background(), &proxy.ActionRequest{
		Action: "discovery_ldap",
		Params: map[string]any{"base_dn": "dc=corp,dc=local"},
	}); err == nil {
		t.Fatal("ran an LDAP query with no directory configured")
	}
}

func TestBurstFor(t *testing.T) {
	// Burst must stay well under the rate so a sweep does not open with a
	// spike, which is what an IDS notices first.
	for _, rate := range []int{1, 10, 100, 1000} {
		if got := burstFor(rate); got < 1 || got > rate {
			t.Errorf("burstFor(%d) = %d, want between 1 and %d", rate, got, rate)
		}
	}
}

type countingListener struct {
	port int
}

func listenCounting(t *testing.T, counter *int64) countingListener {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(counter, 1)
			_ = c.Close()
		}
	}()

	return countingListener{port: l.Addr().(*net.TCPAddr).Port}
}
