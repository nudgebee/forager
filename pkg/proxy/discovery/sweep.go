package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	defaultRatePPS        = 100
	maxRatePPS            = 1000
	defaultProbeTimeoutMs = 1000
	defaultSweepWorkers   = 64
	maxSweepWorkers       = 512
	rdnsConcurrency       = 32
	maxSweepAddresses     = 65536 // a /16; larger scopes must be split server-side
)

// SweepHost is one responder found on the network. A sweep establishes that
// something is at an address and what it looks like — never what is installed
// on it. Package data requires credentials, which is discovery_inventory's job.
type SweepHost struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac,omitempty"`
	RDNS      string   `json:"rdns,omitempty"`
	OpenPorts []int    `json:"open_ports,omitempty"`
	Sources   []string `json:"sources"` // tcp, arp
}

// SweepResult is the response to a discovery_sweep action.
type SweepResult struct {
	CIDRs     []string    `json:"cidrs"`
	Scanned   int         `json:"addresses_scanned"`
	RatePPS   int         `json:"rate_pps"`
	Excluded  int         `json:"addresses_excluded"`
	Hosts     []SweepHost `json:"hosts"`
	DurationS float64     `json:"duration_seconds"`
}

// sweepConfig is the validated, rate-capped parameters of one sweep.
type sweepConfig struct {
	cidrs        []netip.Prefix
	exclusions   []netip.Prefix
	ports        []int
	ratePPS      int
	probeTimeout time.Duration
	workers      int
}

// runSweep probes every address in scope with plain TCP connects, rate limited
// and honouring exclusions.
//
// Only well-formed connections are used: no raw or crafted packets. Malformed
// probes of the kind port scanners emit are what destabilize embedded and OT
// gear, and a discovery tool that knocks over a PLC has failed no matter what
// it found. The cost is that a host with no open probed port is invisible to
// the sweep — that is the honest limit of unprivileged scanning, and why the
// hypervisor and directory sources exist.
func runSweep(ctx context.Context, cfg sweepConfig) (*SweepResult, error) {
	start := time.Now()

	addrs, excluded, err := expandCIDRs(cfg.cidrs, cfg.exclusions)
	if err != nil {
		return nil, err
	}

	limiter := rate.NewLimiter(rate.Limit(cfg.ratePPS), burstFor(cfg.ratePPS))

	type probeResult struct {
		ip    string
		ports []int
	}

	work := make(chan string)
	results := make(chan probeResult)

	var wg sync.WaitGroup
	workers := cfg.workers
	if workers > len(addrs) {
		workers = len(addrs)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range work {
				var open []int
				for _, port := range cfg.ports {
					// Every probe passes the rate limiter, so the cap holds
					// across ports as well as addresses. The server asks for a
					// rate; the forager still refuses to exceed its own cap.
					if err := limiter.Wait(ctx); err != nil {
						return
					}
					if probeTCP(ctx, ip, port, cfg.probeTimeout) {
						open = append(open, port)
					}
				}
				if len(open) > 0 {
					select {
					case results <- probeResult{ip: ip, ports: open}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(work)
		for _, ip := range addrs {
			select {
			case work <- ip:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	hosts := make(map[string]*SweepHost)
	for r := range results {
		hosts[r.ip] = &SweepHost{IP: r.ip, OpenPorts: r.ports, Sources: []string{"tcp"}}
	}

	// The probes above populate the kernel's neighbour cache for anything on
	// the local segment, so reading it afterwards yields MACs without sending
	// a single ARP frame of our own — no raw sockets, no privileges.
	enrichFromARP(hosts)
	enrichRDNS(ctx, hosts)

	out := sortHosts(hosts)

	cidrStrings := make([]string, len(cfg.cidrs))
	for i, c := range cfg.cidrs {
		cidrStrings[i] = c.String()
	}

	return &SweepResult{
		CIDRs:     cidrStrings,
		Scanned:   len(addrs),
		RatePPS:   cfg.ratePPS,
		Excluded:  excluded,
		Hosts:     out,
		DurationS: time.Since(start).Seconds(),
	}, nil
}

// burstFor keeps the limiter's burst small relative to the rate so a sweep
// cannot emit a large spike at start-up — the shape of the traffic matters to
// IDS as much as its average.
func burstFor(ratePPS int) int {
	burst := ratePPS / 10
	if burst < 1 {
		burst = 1
	}
	return burst
}

func probeTCP(ctx context.Context, ip string, port int, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// expandCIDRs enumerates host addresses in scope, dropping exclusions before
// any packet is sent. Network and broadcast addresses are skipped for IPv4
// prefixes shorter than /31.
func expandCIDRs(cidrs, exclusions []netip.Prefix) ([]string, int, error) {
	var addrs []string
	excluded := 0

	for _, cidr := range cidrs {
		if !cidr.Addr().Is4() {
			return nil, 0, fmt.Errorf("only IPv4 CIDRs are supported, got %s", cidr)
		}

		// Computed as int64: on a 32-bit platform `1 << 32` overflows int, and
		// a /0 would silently expand to nothing instead of being rejected.
		size64 := int64(1) << (32 - cidr.Bits())
		if int64(len(addrs))+size64 > maxSweepAddresses {
			return nil, 0, fmt.Errorf("sweep scope exceeds %d addresses; split it into smaller CIDRs", maxSweepAddresses)
		}
		size := int(size64)

		addr := cidr.Masked().Addr()
		for i := 0; i < size; i++ {
			if cidr.Bits() <= 30 && (i == 0 || i == size-1) {
				addr = addr.Next() // skip network and broadcast
				continue
			}
			if isExcluded(addr, exclusions) {
				excluded++
			} else {
				addrs = append(addrs, addr.String())
			}
			addr = addr.Next()
		}
	}
	return addrs, excluded, nil
}

func isExcluded(addr netip.Addr, exclusions []netip.Prefix) bool {
	for _, ex := range exclusions {
		if ex.Contains(addr) {
			return true
		}
	}
	return false
}

// enrichRDNS resolves names for responders, bounded so that a sweep finding
// many hosts does not fire an unbounded number of simultaneous queries at the
// customer's resolver — which looks like a DNS flood and is liable to be
// treated as one.
func enrichRDNS(ctx context.Context, hosts map[string]*SweepHost) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, rdnsConcurrency)

	for ip := range hosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			hosts[ip].RDNS = trimTrailingDot(names[0])
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

// sortHosts converts the host map into an IP-sorted slice of SweepHost.
// Pre-parses IP addresses once into netip.Addr to avoid O(N log N) string parses in sort comparator.
// Stores pointers (*SweepHost) to keep sweepHostAddr small (32 bytes) and avoid struct copying overhead.
func sortHosts(hosts map[string]*SweepHost) []SweepHost {
	type sweepHostAddr struct {
		host *SweepHost
		addr netip.Addr
	}
	items := make([]sweepHostAddr, 0, len(hosts))
	for _, h := range hosts {
		if h == nil {
			continue
		}
		addr, err := netip.ParseAddr(h.IP)
		if err != nil {
			items = append(items, sweepHostAddr{host: h})
			continue
		}
		items = append(items, sweepHostAddr{host: h, addr: addr})
	}
	sort.Slice(items, func(i, j int) bool {
		iValid := items[i].addr.IsValid()
		jValid := items[j].addr.IsValid()
		if !iValid && !jValid {
			return items[i].host.IP < items[j].host.IP
		}
		if !iValid {
			return false
		}
		if !jValid {
			return true
		}
		return items[i].addr.Less(items[j].addr)
	})

	out := make([]SweepHost, len(items))
	for i, item := range items {
		out[i] = *item.host
	}
	return out
}

// parseSweepParams validates an action's parameters and clamps them to the
// module's own limits.
func parseSweepParams(params map[string]any, maxRate int) (sweepConfig, error) {
	var cfg sweepConfig

	rawCIDRs, err := stringSliceParam(params, "cidrs")
	if err != nil {
		return cfg, err
	}
	if len(rawCIDRs) == 0 {
		return cfg, fmt.Errorf("cidrs is required")
	}
	for _, c := range rawCIDRs {
		prefix, err := netip.ParsePrefix(c)
		if err != nil {
			return cfg, fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
		cfg.cidrs = append(cfg.cidrs, prefix.Masked())
	}

	if raw, ok := params["exclusions"]; ok && raw != nil {
		rawEx, err := stringSliceParam(params, "exclusions")
		if err != nil {
			return cfg, err
		}
		for _, e := range rawEx {
			prefix, err := parsePrefixOrAddr(e)
			if err != nil {
				return cfg, fmt.Errorf("invalid exclusion %q: %w", e, err)
			}
			cfg.exclusions = append(cfg.exclusions, prefix)
		}
	}

	cfg.ports = defaultSweepPorts()
	if raw, ok := params["ports"]; ok && raw != nil {
		ports, err := intSliceParam(params, "ports")
		if err != nil {
			return cfg, err
		}
		if len(ports) > 0 {
			for _, p := range ports {
				if p < 1 || p > 65535 {
					return cfg, fmt.Errorf("invalid port %d", p)
				}
			}
			cfg.ports = ports
		}
	}

	cfg.ratePPS = defaultRatePPS
	if v, ok := intParam(params, "rate_pps"); ok && v > 0 {
		cfg.ratePPS = v
	}
	if cfg.ratePPS > maxRate {
		cfg.ratePPS = maxRate
	}

	timeoutMs := defaultProbeTimeoutMs
	if v, ok := intParam(params, "timeout_ms"); ok && v > 0 {
		timeoutMs = v
	}
	cfg.probeTimeout = time.Duration(timeoutMs) * time.Millisecond

	// Workers govern how many probes are in flight, not how fast they are
	// sent — the rate limiter owns that. Raising this helps when a scope is
	// mostly dead addresses, where each probe costs a full timeout.
	cfg.workers = defaultSweepWorkers
	if v, ok := intParam(params, "workers"); ok && v > 0 {
		cfg.workers = v
		if cfg.workers > maxSweepWorkers {
			cfg.workers = maxSweepWorkers
		}
	}
	return cfg, nil
}

// parsePrefixOrAddr accepts either a CIDR or a bare address, so exclusions can
// name a single host without the /32 ceremony.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func defaultSweepPorts() []int { return []int{22, 3389, 5985} }

func intSliceParam(params map[string]any, key string) ([]int, error) {
	raw, ok := params[key]
	if !ok {
		return nil, nil
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list of numbers", key)
	}
	out := make([]int, 0, len(items))
	for _, item := range items {
		switch v := item.(type) {
		case float64:
			out = append(out, int(v))
		case int:
			out = append(out, v)
		default:
			return nil, fmt.Errorf("%s must be a list of numbers", key)
		}
	}
	return out, nil
}

// enrichFromARP attaches MAC addresses from the local neighbour cache. Only
// hosts on the same L2 segment appear there; anything routed has the router's
// MAC or none, so a missing MAC is normal and not an error.
func enrichFromARP(hosts map[string]*SweepHost) {
	table := readARPTable()
	if len(table) == 0 {
		return
	}
	for ip, h := range hosts {
		if mac, ok := table[ip]; ok {
			h.MAC = mac
			h.Sources = append(h.Sources, "arp")
		}
	}
}
