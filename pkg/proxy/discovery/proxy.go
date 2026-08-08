package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"nudgebee/forager/pkg/proxy"
	"nudgebee/forager/pkg/signing"
)

const (
	defaultPort           = 22
	defaultConcurrency    = 25
	maxConcurrency        = 200
	defaultHostTimeoutS   = 120
	defaultCommandTimeS   = 60
	defaultMaxOutputBytes = 4 << 20 // 4MB: a full package list on a large host
	defaultDialTimeoutS   = 10
	maxTargetsPerRequest  = 5000
)

// Config is the discovery datasource configuration, pushed from the server
// alongside credentials. Scope lives server-side (see design §9) — the
// forager holds no schedule and no target list of its own.
type Config struct {
	Port           int      `json:"port"`
	Concurrency    int      `json:"concurrency"`
	HostTimeoutS   int      `json:"host_timeout_seconds"`
	CommandTimeS   int      `json:"command_timeout_seconds"`
	DialTimeoutS   int      `json:"dial_timeout_seconds"`
	MaxOutputBytes int      `json:"max_output_bytes"`
	AllowedCIDRs   []string `json:"allowed_cidrs"`

	// PackPublicKey verifies content packs. Defaults to the agent's message
	// signing key when empty, so packs and actions share one trust root.
	PackPublicKey string `json:"pack_public_key"`

	// PackDir caches verified packs on disk, keyed by version.
	PackDir string `json:"pack_dir"`

	// MaxRatePPS caps sweep probe rate regardless of what a request asks for.
	MaxRatePPS int `json:"max_rate_pps"`

	// LDAP configures the directory this datasource can query. Empty host
	// means this datasource does not serve discovery_ldap.
	LDAP ldapConfig `json:"ldap"`

	// KnownHostsFile enables SSH host key verification against an OpenSSH
	// known_hosts file. When set, a host whose key is absent or changed is
	// refused. Discovery finds hosts whose keys we have not seen before, so
	// this cannot be the default yet — but customers who can supply host keys
	// (config management, golden images) should get real verification.
	KnownHostsFile string `json:"known_hosts_file"`
}

// Proxy executes discovery actions against hosts in its network segment.
// It installs nothing on those hosts: every command comes from a signed pack
// and runs over SSH as an unprivileged read-only user.
type Proxy struct {
	mu     sync.RWMutex
	cfg    Config
	logger *slog.Logger

	sshConfig    *ssh.ClientConfig
	packPubKey   ed25519.PublicKey
	allowedNets  []*net.IPNet
	allowedHosts []string

	ldapCfg        ldapConfig
	ldapConfigured bool

	packs map[int]*Pack // version → verified pack
}

func New(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger, packs: make(map[int]*Pack)}
}

func (p *Proxy) Type() string { return "discovery-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	configJSON, _ := json.Marshal(config)
	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing discovery config: %w", err)
	}
	applyConfigDefaults(&cfg)
	p.cfg = cfg

	// SSH credentials are optional: sweeping and directory queries need none.
	// Requiring them up front would force an operator standing up a
	// sweep-only datasource to invent credentials that are never used, which
	// is a bad habit to build into a values file. A datasource without them
	// simply cannot serve discovery_inventory, and says so when asked.
	p.sshConfig = nil
	if username := creds["username"]; username != "" {
		authMethods, err := buildAuthMethods(creds)
		if err != nil {
			return fmt.Errorf("discovery: %w", err)
		}

		hostKeyCallback, err := p.hostKeyCallback(cfg)
		if err != nil {
			return fmt.Errorf("discovery: %w", err)
		}

		p.sshConfig = &ssh.ClientConfig{
			User:            username,
			Auth:            authMethods,
			HostKeyCallback: hostKeyCallback,
			Timeout:         time.Duration(cfg.DialTimeoutS) * time.Second,
		}
	}

	if err := p.parseAllowedCIDRs(cfg.AllowedCIDRs); err != nil {
		return fmt.Errorf("discovery: parsing allowed_cidrs: %w", err)
	}

	// Directory credentials arrive alongside SSH ones; the bind DN and
	// password are kept off the Config struct so they cannot be serialized
	// back out with the rest of the configuration.
	p.ldapCfg = cfg.LDAP
	p.ldapCfg.BindDN = creds["ldap_bind_dn"]
	p.ldapCfg.BindPass = creds["ldap_bind_password"]
	p.ldapConfigured = cfg.LDAP.Host != ""

	packKey := cfg.PackPublicKey
	if packKey == "" {
		packKey = creds["pack_public_key"]
	}
	if packKey != "" {
		pub, err := signing.ParsePublicKey(packKey)
		if err != nil {
			return fmt.Errorf("discovery: invalid pack_public_key: %w", err)
		}
		p.packPubKey = pub
	}

	p.logger.Info("discovery proxy configured",
		"port", cfg.Port,
		"concurrency", cfg.Concurrency,
		"allowed_cidrs", len(cfg.AllowedCIDRs),
		"pack_verification", p.packPubKey != nil,
	)
	return nil
}

// hostKeyCallback returns known_hosts verification when the customer has
// supplied a file, and otherwise accepts unknown keys with a warning.
//
// Discovery's job is finding hosts nobody has catalogued, so their keys are
// unknown on first contact and change whenever a VM is re-imaged — strict
// verification by default would make the product unable to do the one thing
// it exists for. The residual risk is bounded: collection runs read-only
// under an unprivileged credential and executes only signature-verified
// commands, so a spoofed host can feed us false inventory but cannot gain
// anything from us. Recording keys on the server-side asset record and
// pinning on subsequent runs is the real fix and belongs with that work.
func (p *Proxy) hostKeyCallback(cfg Config) (ssh.HostKeyCallback, error) {
	if cfg.KnownHostsFile != "" {
		cb, err := knownhosts.New(cfg.KnownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("loading known_hosts_file %q: %w", cfg.KnownHostsFile, err)
		}
		p.logger.Info("ssh host key verification enabled", "known_hosts", cfg.KnownHostsFile)
		return cb, nil
	}

	p.logger.Warn("ssh host key verification disabled: no known_hosts_file configured",
		"hint", "set known_hosts_file to verify target host keys")
	return ssh.InsecureIgnoreHostKey(), nil // #nosec G106 -- see hostKeyCallback doc comment
}

func applyConfigDefaults(cfg *Config) {
	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultConcurrency
	}
	if cfg.Concurrency > maxConcurrency {
		cfg.Concurrency = maxConcurrency
	}
	if cfg.HostTimeoutS <= 0 {
		cfg.HostTimeoutS = defaultHostTimeoutS
	}
	if cfg.CommandTimeS <= 0 {
		cfg.CommandTimeS = defaultCommandTimeS
	}
	if cfg.DialTimeoutS <= 0 {
		cfg.DialTimeoutS = defaultDialTimeoutS
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = defaultMaxOutputBytes
	}
	if cfg.MaxRatePPS <= 0 || cfg.MaxRatePPS > maxRatePPS {
		cfg.MaxRatePPS = maxRatePPS
	}
}

func buildAuthMethods(creds map[string]string) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if key := creds["private_key"]; key != "" {
		var signer ssh.Signer
		var err error
		if passphrase := creds["passphrase"]; passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(key), []byte(passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(key))
		}
		if err != nil {
			return nil, fmt.Errorf("parsing private key: %w", err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	if password := creds["password"]; password != "" {
		methods = append(methods, ssh.Password(password))
	}
	if len(methods) == 0 {
		return nil, fmt.Errorf("no ssh auth method provided (need private_key or password)")
	}
	return methods, nil
}

func (p *Proxy) parseAllowedCIDRs(cidrs []string) error {
	p.allowedNets = nil
	p.allowedHosts = nil

	for _, c := range cidrs {
		if _, ipNet, err := net.ParseCIDR(c); err == nil {
			p.allowedNets = append(p.allowedNets, ipNet)
			continue
		}
		// A bare address is a single-host network. Treating it as a hostname
		// instead would mean a target given by name that resolves to this
		// address never matches, since name resolution is only compared
		// against the network list.
		if ip := net.ParseIP(c); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			p.allowedNets = append(p.allowedNets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		p.allowedHosts = append(p.allowedHosts, c)
	}
	return nil
}

// isTargetAllowed enforces the segment scope the server configured. An empty
// allowlist means unrestricted, matching the ssh proxy's behaviour.
//
// The allowlist is snapshotted under a short read lock rather than held for
// the whole call: Configure can replace it concurrently, and the DNS lookup
// below is far too slow to hold a lock across.
func (p *Proxy) isTargetAllowed(host string) bool {
	p.mu.RLock()
	allowedNets := p.allowedNets
	allowedHosts := p.allowedHosts
	p.mu.RUnlock()

	if len(allowedNets) == 0 && len(allowedHosts) == 0 {
		return true
	}
	for _, h := range allowedHosts {
		if h == host {
			return true
		}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		addrs, err := net.LookupHost(host)
		if err != nil {
			return false
		}
		for _, a := range addrs {
			if resolved := net.ParseIP(a); resolved != nil {
				for _, n := range allowedNets {
					if n.Contains(resolved) {
						return true
					}
				}
			}
		}
		return false
	}
	for _, n := range allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	switch req.Action {
	case "discovery_inventory":
		return p.handleInventory(ctx, req)
	case "discovery_sweep":
		return p.handleSweep(ctx, req)
	case "discovery_ldap":
		return p.handleLDAP(ctx, req)
	default:
		return nil, fmt.Errorf("unknown discovery action: %s", req.Action)
	}
}

// handleSweep finds hosts that are up. It never authenticates and never
// collects package data — a sweep answers "what is here", and
// discovery_inventory answers "what is on it".
func (p *Proxy) handleSweep(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	p.mu.RLock()
	maxRate := p.cfg.MaxRatePPS
	configuredCIDRs := p.allowedNets
	p.mu.RUnlock()

	cfg, err := parseSweepParams(req.Params, maxRate)
	if err != nil {
		return nil, fmt.Errorf("discovery_sweep: %w", err)
	}

	// Sweeping is the most intrusive thing this module does, so scope is
	// enforced twice: the server picks the CIDRs, and the forager refuses any
	// that fall outside what its datasource was configured for. A compromised
	// or buggy server cannot turn a segment collector into a general scanner.
	if len(configuredCIDRs) > 0 {
		for _, requested := range cfg.cidrs {
			if !prefixWithinAny(requested, configuredCIDRs) {
				return nil, fmt.Errorf("discovery_sweep: %s is outside this datasource's allowed_cidrs", requested)
			}
		}
	}

	result, err := runSweep(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("discovery_sweep: %w", err)
	}

	p.logger.Info("discovery sweep complete",
		"cidrs", result.CIDRs,
		"scanned", result.Scanned,
		"excluded", result.Excluded,
		"found", len(result.Hosts),
		"rate_pps", result.RatePPS,
		"duration", time.Duration(result.DurationS*float64(time.Second)).Round(time.Millisecond),
	)

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("discovery_sweep: marshalling results: %w", err)
	}
	return &proxy.ActionResponse{StatusCode: 200, Action: req.Action, Result: data}, nil
}

// handleLDAP lists computer objects from the configured directory.
func (p *Proxy) handleLDAP(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	p.mu.RLock()
	cfg := p.ldapCfg
	configured := p.ldapConfigured
	p.mu.RUnlock()

	if !configured {
		return nil, fmt.Errorf("discovery_ldap: no directory configured on this datasource")
	}

	if baseDN, ok := req.Params["base_dn"].(string); ok && baseDN != "" {
		cfg.BaseDN = baseDN
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("discovery_ldap: base_dn is required")
	}

	activeWithin := defaultActiveWithinD
	if v, ok := intParam(req.Params, "active_within_days"); ok && v > 0 {
		activeWithin = v
	}

	result, err := runLDAPDiscovery(ctx, cfg, activeWithin)
	if err != nil {
		return nil, fmt.Errorf("discovery_ldap: %w", err)
	}

	p.logger.Info("discovery ldap complete",
		"base_dn", result.BaseDN,
		"returned", result.Returned,
		"skipped_stale", result.SkippedStale,
		"duration", time.Duration(result.DurationS*float64(time.Second)).Round(time.Millisecond),
	)

	data, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("discovery_ldap: marshalling results: %w", err)
	}
	return &proxy.ActionResponse{StatusCode: 200, Action: req.Action, Result: data}, nil
}

// partitionTargetsByScope splits targets into those inside this datasource's
// scope and rejection results for those outside it, resolving names
// concurrently. Order is preserved so results stay comparable across runs.
func (p *Proxy) partitionTargetsByScope(ctx context.Context, targets []string, concurrency int) ([]string, []TargetResult) {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	verdicts := make([]bool, len(targets))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}
			verdicts[idx] = p.isTargetAllowed(target)
		}(i, t)
	}
	wg.Wait()

	var allowed []string
	var rejected []TargetResult
	for i, t := range targets {
		if verdicts[i] {
			allowed = append(allowed, t)
			continue
		}
		rejected = append(rejected, TargetResult{
			Host:   t,
			Status: StatusError,
			Error:  "target is outside this datasource's allowed_cidrs",
		})
	}
	return allowed, rejected
}

// prefixWithinAny reports whether requested is contained by one of the
// configured prefixes.
func prefixWithinAny(requested netip.Prefix, configured []*net.IPNet) bool {
	for _, allowed := range configured {
		ones, _ := allowed.Mask.Size()
		allowedAddr, ok := netip.AddrFromSlice(allowed.IP.To4())
		if !ok {
			continue
		}
		allowedPrefix := netip.PrefixFrom(allowedAddr, ones)
		if allowedPrefix.Contains(requested.Addr()) && requested.Bits() >= allowedPrefix.Bits() {
			return true
		}
	}
	return false
}

// InventoryResponse is what the server receives. content_pack_version travels
// with the results so the server knows which collector semantics produced
// them — a parser change and a pack change must be correlatable after the fact.
type InventoryResponse struct {
	ContentPackVersion int            `json:"content_pack_version"`
	Targets            []TargetResult `json:"targets"`
}

func (p *Proxy) handleInventory(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	targets, err := stringSliceParam(req.Params, "targets")
	if err != nil {
		return nil, fmt.Errorf("discovery_inventory: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("discovery_inventory: targets is required")
	}
	if len(targets) > maxTargetsPerRequest {
		return nil, fmt.Errorf("discovery_inventory: %d targets exceeds limit of %d", len(targets), maxTargetsPerRequest)
	}

	pack, err := p.resolvePack(req.Params)
	if err != nil {
		return nil, fmt.Errorf("discovery_inventory: %w", err)
	}

	p.mu.RLock()
	cfg := p.cfg
	sshCfg := p.sshConfig
	p.mu.RUnlock()

	if sshCfg == nil {
		return nil, fmt.Errorf("discovery_inventory: this datasource has no ssh credentials configured")
	}

	// Out-of-scope targets are rejected as results, not as a batch error: the
	// server asked about them and deserves to see why they were not collected.
	//
	// Checked concurrently because a target given as a hostname costs a DNS
	// lookup: done in sequence, a batch of named hosts would block the handler
	// for as long as the lookups take before a single host was contacted.
	allowed, rejected := p.partitionTargetsByScope(ctx, targets, cfg.Concurrency)

	execCfg := execConfig{
		port:            cfg.Port,
		concurrency:     cfg.Concurrency,
		hostTimeout:     time.Duration(cfg.HostTimeoutS) * time.Second,
		commandTimeout:  time.Duration(cfg.CommandTimeS) * time.Second,
		maxOutputBytes:  cfg.MaxOutputBytes,
		dialTimeout:     time.Duration(cfg.DialTimeoutS) * time.Second,
		sshClientConfig: sshCfg,
	}
	if v, ok := intParam(req.Params, "concurrency"); ok && v > 0 && v <= maxConcurrency {
		execCfg.concurrency = v
	}

	start := time.Now()
	results := runInventory(ctx, allowed, pack, execCfg)
	results = append(results, rejected...)

	var ok int
	for _, r := range results {
		if r.Status == StatusOK {
			ok++
		}
	}
	p.logger.Info("discovery inventory complete",
		"targets", len(results),
		"ok", ok,
		"pack_version", pack.Version,
		"duration", time.Since(start).Round(time.Millisecond),
	)

	data, err := json.Marshal(InventoryResponse{ContentPackVersion: pack.Version, Targets: results})
	if err != nil {
		return nil, fmt.Errorf("discovery_inventory: marshalling results: %w", err)
	}
	return &proxy.ActionResponse{StatusCode: 200, Action: req.Action, Result: data}, nil
}

// resolvePack returns a verified pack for the requested version.
//
// A request selects a pack by version; it cannot carry the pack itself.
// Accepting pack bodies inline would put executable content on the request
// path, and while the signature check would still gate execution, keeping
// commands sourced from locally cached, already-verified files removes that
// exposure entirely. Packs reach pack_dir through the distribution pipeline,
// not through actions.
func (p *Proxy) resolvePack(params map[string]any) (*Pack, error) {
	version, ok := intParam(params, "content_pack_version")
	if !ok {
		return nil, fmt.Errorf("content_pack_version is required")
	}
	if version <= 0 {
		return nil, fmt.Errorf("content_pack_version must be positive, got %d", version)
	}

	p.mu.RLock()
	cached, hit := p.packs[version]
	packDir := p.cfg.PackDir
	p.mu.RUnlock()
	if hit {
		return cached, nil
	}

	if packDir == "" {
		return nil, fmt.Errorf("content pack version %d not cached and no pack_dir configured", version)
	}
	raw, err := os.ReadFile(filepath.Join(packDir, fmt.Sprintf("linux-inventory-v%d.yaml", version)))
	if err != nil {
		return nil, fmt.Errorf("loading content pack version %d: %w", version, err)
	}
	pack, err := p.verifyPack(raw)
	if err != nil {
		return nil, err
	}
	if pack.Version != version {
		return nil, fmt.Errorf("content pack version mismatch: requested %d, pack declares %d", version, pack.Version)
	}

	p.mu.Lock()
	p.packs[version] = pack
	p.mu.Unlock()
	return pack, nil
}

func (p *Proxy) verifyPack(raw []byte) (*Pack, error) {
	p.mu.RLock()
	pubKey := p.packPubKey
	p.mu.RUnlock()

	if pubKey == nil {
		return nil, fmt.Errorf("cannot verify content pack: no pack public key configured")
	}
	return ParseAndVerify(raw, pubKey)
}

// HealthCheck reports whether this datasource can serve at least one action.
// There is no single endpoint to probe — its target is a whole network
// segment — so health here means "configured to do something useful".
//
// A datasource may legitimately serve only some actions: sweeping needs no
// credentials, and inventory needs both SSH credentials and a pack key. The
// error names what is missing so a half-configured datasource is diagnosable
// from the health report rather than only when an action fails.
func (p *Proxy) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var missing []string
	if p.sshConfig == nil {
		missing = append(missing, "ssh credentials")
	}
	if p.packPubKey == nil {
		missing = append(missing, "pack_public_key")
	}
	if p.cfg.PackDir == "" {
		missing = append(missing, "pack_dir")
	}

	// Sweeping needs nothing configured beyond scope, so a datasource is only
	// unhealthy if it cannot do that either.
	if len(missing) > 0 && len(p.allowedNets) == 0 && len(p.allowedHosts) == 0 {
		return fmt.Errorf("discovery datasource is unconfigured: no allowed_cidrs, and inventory is missing %s",
			strings.Join(missing, ", "))
	}
	return nil
}

// Actions reports which discovery actions this datasource can currently
// serve. Surfaced in metadata so the server can route work to a datasource
// that can actually do it, rather than discovering the gap on failure.
func (p *Proxy) Actions() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	actions := []string{"discovery_sweep"}
	if p.ldapConfigured {
		actions = append(actions, "discovery_ldap")
	}
	if p.sshConfig != nil && p.packPubKey != nil {
		actions = append(actions, "discovery_inventory")
	}
	return actions
}

// CollectMetadata satisfies proxy.MetadataCollector so the supported actions
// reach the server alongside the datasource inventory. pack_versions lists
// the content pack versions present in pack_dir so the server can pick a
// version to pin in discovery_inventory requests (content_pack_version is a
// required request param with no "latest" default). Presence means the file
// exists — signature verification still happens at execution time.
func (p *Proxy) CollectMetadata(ctx context.Context) (map[string]any, error) {
	meta := map[string]any{"actions": p.Actions()}
	if versions := p.packVersions(); len(versions) > 0 {
		meta["pack_versions"] = versions
	}
	return meta, nil
}

// packVersionPattern matches cached pack filenames (linux-inventory-v<N>.yaml),
// mirroring the path resolvePack reads.
var packVersionPattern = regexp.MustCompile(`^linux-inventory-v(\d+)\.yaml$`)

// packVersions lists content pack versions available in pack_dir, ascending.
func (p *Proxy) packVersions() []int {
	p.mu.RLock()
	packDir := p.cfg.PackDir
	p.mu.RUnlock()
	if packDir == "" {
		return nil
	}

	entries, err := os.ReadDir(packDir)
	if err != nil {
		// A configured-but-not-yet-created pack_dir is a normal fresh-install
		// state (packs arrive via the distribution pipeline) — don't warn on
		// every metadata cycle for it.
		if !os.IsNotExist(err) {
			p.logger.Warn("discovery: cannot list pack_dir for metadata", "err", err)
		}
		return nil
	}

	var versions []int
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := packVersionPattern.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		v, err := strconv.Atoi(m[1])
		if err != nil || v <= 0 {
			continue
		}
		versions = append(versions, v)
	}
	sort.Ints(versions)
	return versions
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.packs = make(map[int]*Pack)
	return nil
}

func stringSliceParam(params map[string]any, key string) ([]string, error) {
	raw, ok := params[key]
	if !ok {
		return nil, fmt.Errorf("%s is required", key)
	}
	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s must be a list of strings", key)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%s must be a list of strings", key)
	}
}

func intParam(params map[string]any, key string) (int, bool) {
	switch v := params[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}
