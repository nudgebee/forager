package ssh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"nudgebee/forager/pkg/proxy"
)

const (
	defaultPort           = 22
	defaultMaxOutputBytes = 1 << 20 // 1MB
	maxTimeoutMs          = 120_000
	defaultTimeoutMs      = 30_000
	dialTimeout           = 10 * time.Second

	// Pool mode defaults
	defaultPoolTTL     = 10 * time.Minute
	defaultPoolMaxSize = 50
	poolCleanupPeriod  = 1 * time.Minute
)

// Config holds SSH connection parameters.
type Config struct {
	Host           string   `json:"host"`
	Port           int      `json:"port"`
	MaxOutputBytes int      `json:"max_output_bytes"`
	AllowedHosts   []string `json:"allowed_hosts"`
	PoolTTL        int      `json:"pool_ttl_seconds"`
	PoolMaxSize    int      `json:"pool_max_size"`

	// Host key verification (optional). When either is set the server's host
	// key is verified, protecting against man-in-the-middle attacks. When both
	// are empty, verification is skipped (insecure, backwards-compatible).
	//   - KnownHosts: path to an OpenSSH known_hosts file.
	//   - HostKey:    a single authorized_keys-style host public key line.
	KnownHosts string `json:"known_hosts"`
	HostKey    string `json:"host_key"`
}

// poolEntry is a cached SSH connection in dynamic mode.
type poolEntry struct {
	client   *ssh.Client
	lastUsed time.Time
}

// Proxy is an SSH proxy supporting command execution and SFTP file operations.
// Operates in two modes:
//   - Static: host is set in config, single persistent connection (backward compatible).
//   - Dynamic: host is empty, connections are made on-demand per request with pooling.
type Proxy struct {
	mu     sync.RWMutex
	client *ssh.Client  // static mode only
	sftp   *sftp.Client // static mode only
	config Config
	logger *slog.Logger

	// Dynamic mode fields
	dynamic      bool
	sshConfig    *ssh.ClientConfig
	pool         map[string]*poolEntry // host:port → entry
	poolMu       sync.Mutex
	allowedNets  []*net.IPNet
	allowedHosts []string // non-CIDR hostnames
	cleanupDone  chan struct{}
}

// New creates a new SSH proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{
		logger: logger,
		pool:   make(map[string]*poolEntry),
	}
}

func (p *Proxy) Type() string { return "ssh-proxy" }

// hostKeyCallback builds the SSH host key verification callback from config.
//
// When known_hosts (a file path) or host_key (an authorized_keys-style line) is
// configured, the server's host key is verified, defending against
// man-in-the-middle attacks. When neither is set, verification is skipped to
// preserve backwards-compatible behavior; this is insecure and is logged so
// operators can opt into verification.
func hostKeyCallback(cfg Config, logger *slog.Logger) (ssh.HostKeyCallback, error) {
	switch {
	case cfg.KnownHosts != "":
		cb, err := knownhosts.New(cfg.KnownHosts)
		if err != nil {
			return nil, fmt.Errorf("loading known_hosts %q: %w", cfg.KnownHosts, err)
		}
		return cb, nil
	case cfg.HostKey != "":
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.HostKey))
		if err != nil {
			return nil, fmt.Errorf("parsing host_key: %w", err)
		}
		return ssh.FixedHostKey(key), nil
	default:
		logger.Warn("ssh host key verification disabled: set known_hosts or host_key to enable",
			"hint", "without verification the connection is not protected against MITM")
		return ssh.InsecureIgnoreHostKey(), nil // #nosec G106 -- opt-out fallback, see doc comment
	}
}

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close existing connections
	_ = p.closeAllLocked()

	// Parse config
	configJSON, _ := json.Marshal(config)
	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing ssh config: %w", err)
	}

	if cfg.Port == 0 {
		cfg.Port = defaultPort
	}
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = defaultMaxOutputBytes
	}
	p.config = cfg

	// Build auth methods
	authMethods, err := buildAuthMethods(creds)
	if err != nil {
		return fmt.Errorf("building ssh auth: %w", err)
	}

	username := creds["username"]
	if username == "" {
		return fmt.Errorf("ssh username is required")
	}

	hostKeyCB, err := hostKeyCallback(cfg, p.logger)
	if err != nil {
		return fmt.Errorf("configuring ssh host key verification: %w", err)
	}

	sshCfg := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCB,
		Timeout:         dialTimeout,
	}

	if cfg.Host == "" {
		// Dynamic mode: store config, don't dial
		p.dynamic = true
		p.sshConfig = sshCfg
		p.pool = make(map[string]*poolEntry)

		// Parse allowed hosts
		if err := p.parseAllowedHosts(cfg.AllowedHosts); err != nil {
			return fmt.Errorf("parsing allowed_hosts: %w", err)
		}

		// Start pool cleanup goroutine
		p.cleanupDone = make(chan struct{})
		go p.poolCleanupLoop()

		p.logger.Info("ssh proxy configured in dynamic mode",
			"port", cfg.Port,
			"allowed_hosts", len(cfg.AllowedHosts),
		)
		return nil
	}

	// Static mode: dial immediately
	p.dynamic = false
	p.sshConfig = nil

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	p.client = client
	p.logger.Info("ssh connection established", "host", cfg.Host, "port", cfg.Port)
	return nil
}

// parseAllowedHosts parses CIDR ranges and hostnames from the allowed_hosts list.
func (p *Proxy) parseAllowedHosts(hosts []string) error {
	p.allowedNets = nil
	p.allowedHosts = nil

	for _, h := range hosts {
		_, ipNet, err := net.ParseCIDR(h)
		if err == nil {
			p.allowedNets = append(p.allowedNets, ipNet)
			continue
		}
		// Not a CIDR — treat as hostname or IP
		p.allowedHosts = append(p.allowedHosts, h)
	}
	return nil
}

// isHostAllowed checks if a host is in the allowlist. If no allowlist is configured, all hosts are allowed.
func (p *Proxy) isHostAllowed(host string) bool {
	if len(p.allowedNets) == 0 && len(p.allowedHosts) == 0 {
		return true // no restrictions
	}

	// Check direct hostname/IP match
	for _, h := range p.allowedHosts {
		if h == host {
			return true
		}
	}

	// Check CIDR match
	ip := net.ParseIP(host)
	if ip == nil {
		// Host is a hostname, resolve it
		addrs, err := net.LookupHost(host)
		if err != nil {
			return false
		}
		for _, addr := range addrs {
			resolved := net.ParseIP(addr)
			if resolved != nil {
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

// getClient returns an SSH client for the given request.
// In static mode, returns the single persistent client.
// In dynamic mode, returns a pooled or newly created client for the target host.
func (p *Proxy) getClient(req *proxy.ActionRequest) (*ssh.Client, error) {
	p.mu.RLock()
	isDynamic := p.dynamic
	staticClient := p.client
	p.mu.RUnlock()

	if !isDynamic {
		if staticClient == nil {
			return nil, fmt.Errorf("not connected")
		}
		return staticClient, nil
	}

	// Dynamic mode: get host from request params
	host, _ := req.Params["host"].(string)
	if host == "" {
		return nil, fmt.Errorf("host is required in dynamic mode (no static host configured)")
	}

	if !p.isHostAllowed(host) {
		return nil, fmt.Errorf("host %s is not in the allowed hosts list", host)
	}

	port := p.config.Port
	if v, ok := req.Params["port"].(float64); ok && v > 0 {
		port = int(v)
	}

	addr := net.JoinHostPort(host, strconv.Itoa(port))
	return p.getPooledClient(addr)
}

// getPooledClient gets or creates a pooled SSH connection.
func (p *Proxy) getPooledClient(addr string) (*ssh.Client, error) {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	// Check pool
	if entry, ok := p.pool[addr]; ok {
		// Verify connection is still alive
		_, _, err := entry.client.SendRequest("keepalive@openssh.com", true, nil)
		if err == nil {
			entry.lastUsed = time.Now()
			return entry.client, nil
		}
		// Connection dead, remove it
		_ = entry.client.Close()
		delete(p.pool, addr)
		p.logger.Debug("removed dead pooled connection", "addr", addr)
	}

	// Enforce pool size limit
	maxSize := p.config.PoolMaxSize
	if maxSize == 0 {
		maxSize = defaultPoolMaxSize
	}
	if len(p.pool) >= maxSize {
		// Evict oldest entry
		p.evictOldestLocked()
	}

	// Dial new connection
	p.mu.RLock()
	sshCfg := p.sshConfig
	p.mu.RUnlock()

	if sshCfg == nil {
		return nil, fmt.Errorf("ssh config not initialized")
	}

	client, err := ssh.Dial("tcp", addr, sshCfg)
	if err != nil {
		return nil, fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	p.pool[addr] = &poolEntry{
		client:   client,
		lastUsed: time.Now(),
	}
	p.logger.Info("new pooled ssh connection", "addr", addr, "pool_size", len(p.pool))
	return client, nil
}

// evictOldestLocked removes the least recently used pool entry. Caller must hold poolMu.
func (p *Proxy) evictOldestLocked() {
	var oldestAddr string
	var oldestTime time.Time
	first := true

	for addr, entry := range p.pool {
		if first || entry.lastUsed.Before(oldestTime) {
			oldestAddr = addr
			oldestTime = entry.lastUsed
			first = false
		}
	}

	if oldestAddr != "" {
		if entry, ok := p.pool[oldestAddr]; ok && entry.client != nil {
			_ = entry.client.Close()
		}
		delete(p.pool, oldestAddr)
		p.logger.Debug("evicted oldest pooled connection", "addr", oldestAddr)
	}
}

// poolCleanupLoop periodically removes expired connections from the pool.
func (p *Proxy) poolCleanupLoop() {
	// Capture channel locally to avoid racing with closeAllLocked setting it to nil.
	p.mu.RLock()
	done := p.cleanupDone
	p.mu.RUnlock()

	ticker := time.NewTicker(poolCleanupPeriod)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			p.cleanupExpiredConnections()
		}
	}
}

func (p *Proxy) cleanupExpiredConnections() {
	ttl := time.Duration(p.config.PoolTTL) * time.Second
	if ttl == 0 {
		ttl = defaultPoolTTL
	}
	cutoff := time.Now().Add(-ttl)

	p.poolMu.Lock()
	defer p.poolMu.Unlock()

	for addr, entry := range p.pool {
		if entry.lastUsed.Before(cutoff) {
			if entry.client != nil {
				_ = entry.client.Close()
			}
			delete(p.pool, addr)
			p.logger.Debug("cleaned up expired connection", "addr", addr)
		}
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

func (p *Proxy) HandleRequest(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	switch req.Action {
	case "ssh_command":
		return p.handleExec(ctx, req)
	case "ssh_upload":
		return p.handleUpload(ctx, req)
	case "ssh_download":
		return p.handleDownload(ctx, req)
	case "ssh_list_dir":
		return p.handleListDir(ctx, req)
	default:
		return nil, fmt.Errorf("unknown ssh action: %s", req.Action)
	}
}

func (p *Proxy) handleExec(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	command, _ := req.Params["command"].(string)
	if command == "" {
		return nil, fmt.Errorf("ssh_command: command is required")
	}

	timeoutMs := defaultTimeoutMs
	if v, ok := req.Params["timeout_ms"].(float64); ok && v > 0 {
		timeoutMs = int(v)
		if timeoutMs > maxTimeoutMs {
			timeoutMs = maxTimeoutMs
		}
	}

	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	client, err := p.getClient(req)
	if err != nil {
		return nil, fmt.Errorf("ssh_command: %w", err)
	}

	p.mu.RLock()
	maxOut := p.config.MaxOutputBytes
	p.mu.RUnlock()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh_command: new session: %w", err)
	}
	defer func() { _ = session.Close() }()

	// Capture stdout and stderr with size limits
	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh_command: stdout pipe: %w", err)
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh_command: stderr pipe: %w", err)
	}

	// Start command
	if err := session.Start(command); err != nil {
		return nil, fmt.Errorf("ssh_command: start: %w", err)
	}

	// Read output with limits
	stdout, _ := io.ReadAll(io.LimitReader(stdoutPipe, int64(maxOut)))
	stderr, _ := io.ReadAll(io.LimitReader(stderrPipe, int64(maxOut)))

	// Wait for command with context cancellation
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- session.Wait()
	}()

	var exitCode int
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return nil, fmt.Errorf("ssh_command: command timed out")
	case waitErr := <-doneCh:
		if waitErr != nil {
			if exitErr, ok := waitErr.(*ssh.ExitError); ok {
				exitCode = exitErr.ExitStatus()
			} else {
				return nil, fmt.Errorf("ssh_command: wait: %w", waitErr)
			}
		}
	}

	result := map[string]any{
		"stdout":    string(stdout),
		"stderr":    string(stderr),
		"exit_code": exitCode,
	}
	data, _ := json.Marshal(result)
	return &proxy.ActionResponse{StatusCode: 200, Data: string(data)}, nil
}

func (p *Proxy) handleUpload(ctx context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	remotePath, _ := req.Params["remote_path"].(string)
	if remotePath == "" {
		return nil, fmt.Errorf("ssh_upload: remote_path is required")
	}
	contentB64, _ := req.Params["content"].(string)
	if contentB64 == "" {
		return nil, fmt.Errorf("ssh_upload: content is required")
	}

	content, err := base64.StdEncoding.DecodeString(contentB64)
	if err != nil {
		return nil, fmt.Errorf("ssh_upload: invalid base64 content: %w", err)
	}

	mode := 0644
	if v, ok := req.Params["mode"].(float64); ok && v > 0 {
		mode = int(v)
	}

	sftpClient, err := p.getSFTP(req)
	if err != nil {
		return nil, fmt.Errorf("ssh_upload: %w", err)
	}

	f, err := sftpClient.Create(remotePath)
	if err != nil {
		return nil, fmt.Errorf("ssh_upload: create %s: %w", remotePath, err)
	}
	defer func() { _ = f.Close() }()

	n, err := f.Write(content)
	if err != nil {
		return nil, fmt.Errorf("ssh_upload: write: %w", err)
	}

	if err := sftpClient.Chmod(remotePath, parseFileMode(mode)); err != nil {
		p.logger.Warn("ssh_upload: chmod failed", "path", remotePath, "err", err)
	}

	result := map[string]any{
		"bytes_written": n,
		"remote_path":   remotePath,
	}
	data, _ := json.Marshal(result)
	return &proxy.ActionResponse{StatusCode: 200, Data: string(data)}, nil
}

func (p *Proxy) handleDownload(_ context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	remotePath, _ := req.Params["remote_path"].(string)
	if remotePath == "" {
		return nil, fmt.Errorf("ssh_download: remote_path is required")
	}

	p.mu.RLock()
	maxOut := p.config.MaxOutputBytes
	p.mu.RUnlock()

	sftpClient, err := p.getSFTP(req)
	if err != nil {
		return nil, fmt.Errorf("ssh_download: %w", err)
	}

	f, err := sftpClient.Open(remotePath)
	if err != nil {
		return nil, fmt.Errorf("ssh_download: open %s: %w", remotePath, err)
	}
	defer func() { _ = f.Close() }()

	content, err := io.ReadAll(io.LimitReader(f, int64(maxOut)))
	if err != nil {
		return nil, fmt.Errorf("ssh_download: read: %w", err)
	}

	result := map[string]any{
		"content":     base64.StdEncoding.EncodeToString(content),
		"size":        len(content),
		"remote_path": remotePath,
	}
	data, _ := json.Marshal(result)
	return &proxy.ActionResponse{StatusCode: 200, Data: string(data)}, nil
}

func (p *Proxy) handleListDir(_ context.Context, req *proxy.ActionRequest) (*proxy.ActionResponse, error) {
	remotePath, _ := req.Params["remote_path"].(string)
	if remotePath == "" {
		return nil, fmt.Errorf("ssh_list_dir: remote_path is required")
	}

	sftpClient, err := p.getSFTP(req)
	if err != nil {
		return nil, fmt.Errorf("ssh_list_dir: %w", err)
	}

	entries, err := sftpClient.ReadDir(remotePath)
	if err != nil {
		return nil, fmt.Errorf("ssh_list_dir: readdir %s: %w", remotePath, err)
	}

	type dirEntry struct {
		Name    string `json:"name"`
		Size    int64  `json:"size"`
		Mode    string `json:"mode"`
		ModTime string `json:"mod_time"`
		IsDir   bool   `json:"is_dir"`
	}

	items := make([]dirEntry, 0, len(entries))
	for _, e := range entries {
		items = append(items, dirEntry{
			Name:    e.Name(),
			Size:    e.Size(),
			Mode:    e.Mode().String(),
			ModTime: e.ModTime().UTC().Format(time.RFC3339),
			IsDir:   e.IsDir(),
		})
	}

	data, _ := json.Marshal(items)
	return &proxy.ActionResponse{StatusCode: 200, Data: string(data)}, nil
}

// getSFTP returns an SFTP client. In static mode, reuses a single client.
// In dynamic mode, creates a new SFTP client per request (since the underlying SSH connection varies).
func (p *Proxy) getSFTP(req *proxy.ActionRequest) (*sftp.Client, error) {
	p.mu.RLock()
	isDynamic := p.dynamic
	p.mu.RUnlock()

	if isDynamic {
		client, err := p.getClient(req)
		if err != nil {
			return nil, err
		}
		// Create a new SFTP client for this connection.
		// The caller is responsible for the file handle, but sftp.Client
		// itself is tied to the SSH connection lifecycle managed by the pool.
		sc, err := sftp.NewClient(client)
		if err != nil {
			return nil, fmt.Errorf("sftp client: %w", err)
		}
		return sc, nil
	}

	// Static mode: reuse single sftp client
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client == nil {
		return nil, fmt.Errorf("not connected")
	}
	if p.sftp != nil {
		return p.sftp, nil
	}

	sc, err := sftp.NewClient(p.client)
	if err != nil {
		return nil, fmt.Errorf("sftp client: %w", err)
	}
	p.sftp = sc
	return sc, nil
}

func (p *Proxy) HealthCheck(ctx context.Context) error {
	p.mu.RLock()
	isDynamic := p.dynamic
	client := p.client
	p.mu.RUnlock()

	if isDynamic {
		// In dynamic mode, credentials are valid if sshConfig is set.
		// We can't health-check without a target host.
		p.mu.RLock()
		hasCfg := p.sshConfig != nil
		p.mu.RUnlock()
		if !hasCfg {
			return fmt.Errorf("ssh config not initialized")
		}
		return nil
	}

	// Static mode: check persistent connection
	if client == nil {
		return fmt.Errorf("not connected")
	}

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("health check session: %w", err)
	}
	defer func() { _ = session.Close() }()

	if err := session.Run("echo ok"); err != nil {
		return fmt.Errorf("health check run: %w", err)
	}
	return nil
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closeAllLocked()
}

// closeAllLocked closes all connections. Caller must hold p.mu.
func (p *Proxy) closeAllLocked() error {
	// Stop cleanup goroutine
	if p.cleanupDone != nil {
		select {
		case <-p.cleanupDone:
			// already closed
		default:
			close(p.cleanupDone)
		}
		p.cleanupDone = nil
	}

	// Close static mode connections
	if p.sftp != nil {
		_ = p.sftp.Close()
		p.sftp = nil
	}
	var staticErr error
	if p.client != nil {
		staticErr = p.client.Close()
		p.client = nil
	}

	// Close all pooled connections
	p.poolMu.Lock()
	for addr, entry := range p.pool {
		if entry.client != nil {
			_ = entry.client.Close()
		}
		delete(p.pool, addr)
	}
	p.poolMu.Unlock()

	p.sshConfig = nil
	return staticErr
}

// CollectMetadata returns connection info for the SSH server.
func (p *Proxy) CollectMetadata(_ context.Context) (map[string]any, error) {
	p.mu.RLock()
	cfg := p.config
	isDynamic := p.dynamic
	p.mu.RUnlock()

	if isDynamic {
		meta := map[string]any{
			"mode":          "dynamic",
			"port":          cfg.Port,
			"allowed_hosts": cfg.AllowedHosts,
		}

		p.poolMu.Lock()
		meta["active_connections"] = len(p.pool)
		p.poolMu.Unlock()

		return meta, nil
	}

	return map[string]any{
		"mode": "static",
		"host": cfg.Host,
		"port": cfg.Port,
	}, nil
}

func parseFileMode(mode int) (m os.FileMode) {
	return os.FileMode(mode)
}
