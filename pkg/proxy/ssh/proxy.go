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

	"nudgebee/forager/pkg/proxy"
)

const (
	defaultPort           = 22
	defaultMaxOutputBytes = 1 << 20 // 1MB
	maxTimeoutMs          = 120_000
	defaultTimeoutMs      = 30_000
	dialTimeout           = 10 * time.Second
)

// Config holds SSH connection parameters.
type Config struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	MaxOutputBytes int    `json:"max_output_bytes"`
}

// Proxy is an SSH proxy supporting command execution and SFTP file operations.
type Proxy struct {
	mu     sync.RWMutex
	client *ssh.Client
	sftp   *sftp.Client
	config Config
	logger *slog.Logger
}

// New creates a new SSH proxy.
func New(logger *slog.Logger) *Proxy {
	return &Proxy{logger: logger}
}

func (p *Proxy) Type() string { return "ssh-proxy" }

func (p *Proxy) Configure(config map[string]any, creds map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Close existing connections
	if p.sftp != nil {
		_ = p.sftp.Close()
		p.sftp = nil
	}
	if p.client != nil {
		_ = p.client.Close()
		p.client = nil
	}

	// Coerce string port to int (relay may send "22" instead of 22)
	if s, ok := config["port"].(string); ok {
		if v, err := strconv.Atoi(s); err == nil {
			config["port"] = v
		}
	}

	// Parse config
	configJSON, _ := json.Marshal(config)
	var cfg Config
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return fmt.Errorf("parsing ssh config: %w", err)
	}

	if cfg.Host == "" {
		return fmt.Errorf("ssh host is required")
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

	sshConfig := &ssh.ClientConfig{
		User:            username,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: support known_hosts
		Timeout:         dialTimeout,
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return fmt.Errorf("ssh dial %s: %w", addr, err)
	}

	p.client = client
	p.logger.Info("ssh connection established", "host", cfg.Host, "port", cfg.Port)
	return nil
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

	p.mu.RLock()
	client := p.client
	maxOut := p.config.MaxOutputBytes
	p.mu.RUnlock()

	if client == nil {
		return nil, fmt.Errorf("ssh_command: not connected")
	}

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

	sftpClient, err := p.getSFTP()
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

	sftpClient, err := p.getSFTP()
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

	sftpClient, err := p.getSFTP()
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

func (p *Proxy) getSFTP() (*sftp.Client, error) {
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
	client := p.client
	p.mu.RUnlock()

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

	if p.sftp != nil {
		_ = p.sftp.Close()
		p.sftp = nil
	}
	if p.client != nil {
		err := p.client.Close()
		p.client = nil
		return err
	}
	return nil
}

// CollectMetadata returns connection info for the SSH server.
func (p *Proxy) CollectMetadata(_ context.Context) (map[string]any, error) {
	p.mu.RLock()
	cfg := p.config
	p.mu.RUnlock()

	return map[string]any{
		"host": cfg.Host,
		"port": cfg.Port,
	}, nil
}

func parseFileMode(mode int) (m os.FileMode) {
	return os.FileMode(mode)
}
