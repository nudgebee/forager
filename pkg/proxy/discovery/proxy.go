package discovery

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

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

	username := creds["username"]
	if username == "" {
		return fmt.Errorf("discovery: ssh username is required")
	}
	authMethods, err := buildAuthMethods(creds)
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}

	p.sshConfig = &ssh.ClientConfig{
		User: username,
		Auth: authMethods,
		// Target hosts are discovered, so their keys are unknown on first
		// contact and rotate with re-imaged VMs. Collection is read-only and
		// the credential is unprivileged; host-key pinning belongs with the
		// server-side asset record, not here. Tracked as a follow-up.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(cfg.DialTimeoutS) * time.Second,
	}

	if err := p.parseAllowedCIDRs(cfg.AllowedCIDRs); err != nil {
		return fmt.Errorf("discovery: parsing allowed_cidrs: %w", err)
	}

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
		p.allowedHosts = append(p.allowedHosts, c)
	}
	return nil
}

// isTargetAllowed enforces the segment scope the server configured. An empty
// allowlist means unrestricted, matching the ssh proxy's behaviour.
func (p *Proxy) isTargetAllowed(host string) bool {
	if len(p.allowedNets) == 0 && len(p.allowedHosts) == 0 {
		return true
	}
	for _, h := range p.allowedHosts {
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
				for _, n := range p.allowedNets {
					if n.Contains(resolved) {
						return true
					}
				}
			}
		}
		return false
	}
	for _, n := range p.allowedNets {
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
	default:
		return nil, fmt.Errorf("unknown discovery action: %s", req.Action)
	}
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
		return nil, fmt.Errorf("discovery_inventory: proxy not configured")
	}

	// Out-of-scope targets are rejected as results, not as a batch error: the
	// server asked about them and deserves to see why they were not collected.
	var allowed []string
	var rejected []TargetResult
	for _, t := range targets {
		if p.isTargetAllowed(t) {
			allowed = append(allowed, t)
			continue
		}
		rejected = append(rejected, TargetResult{
			Host:   t,
			Status: StatusError,
			Error:  "target is outside this datasource's allowed_cidrs",
		})
	}

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
	return &proxy.ActionResponse{StatusCode: 200, Action: req.Action, Data: string(data)}, nil
}

// resolvePack returns a verified pack: either inline in the request, or a
// cached one by version. Packs are verified once at load; only verified packs
// enter the cache.
func (p *Proxy) resolvePack(params map[string]any) (*Pack, error) {
	// An inline pack is used for this request only and never enters the
	// version cache: two validly signed packs could declare the same version,
	// and a request-scoped one must not shadow the published pack for later
	// version-only requests.
	if raw, ok := params["content_pack"].(string); ok && raw != "" {
		return p.verifyPack([]byte(raw))
	}

	version, ok := intParam(params, "content_pack_version")
	if !ok {
		return nil, fmt.Errorf("content_pack or content_pack_version is required")
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

// HealthCheck reports configuration validity. There is no single endpoint to
// probe: this datasource's targets are a whole network segment.
func (p *Proxy) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.sshConfig == nil {
		return fmt.Errorf("discovery proxy not configured")
	}
	if p.packPubKey == nil {
		return fmt.Errorf("no pack public key configured: content packs cannot be verified")
	}
	return nil
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
