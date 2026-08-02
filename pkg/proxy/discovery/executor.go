package discovery

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Target status values. These are the forager's view of what happened; the
// server maps them onto asset coverage states and gap reasons.
const (
	StatusOK            = "ok"
	StatusSSHRefused    = "ssh-refused"
	StatusSSHAuthFailed = "ssh-auth-failed"
	StatusTimeout       = "timeout"
	StatusError         = "error"
)

// TargetResult is the per-host outcome of an inventory run. Collector output
// is returned raw: parsing lives server-side so that fixing a parser never
// requires touching the agent.
type TargetResult struct {
	Host      string             `json:"host"`
	Status    string             `json:"status"`
	Error     string             `json:"error,omitempty"`
	Facts     map[string]string  `json:"facts,omitempty"`
	Collected map[string]string  `json:"collectors,omitempty"`
	Failed    map[string]string  `json:"collector_errors,omitempty"`
	Skipped   []SkippedCollector `json:"skipped_collectors,omitempty"`
	DurationS float64            `json:"duration_seconds"`
}

// execConfig is the tunable part of an inventory run.
type execConfig struct {
	port            int
	concurrency     int
	hostTimeout     time.Duration
	commandTimeout  time.Duration
	maxOutputBytes  int
	dialTimeout     time.Duration
	sshClientConfig *ssh.ClientConfig
}

// runInventory collects from every target concurrently, bounded by
// cfg.concurrency. One target's failure never fails the batch: an unreachable
// host is a coverage gap to report, not an error to abort on.
func runInventory(ctx context.Context, targets []string, pack *Pack, cfg execConfig) []TargetResult {
	results := make([]TargetResult, len(targets))
	sem := make(chan struct{}, cfg.concurrency)
	var wg sync.WaitGroup

	for i, host := range targets {
		wg.Add(1)
		go func(idx int, h string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results[idx] = TargetResult{Host: h, Status: StatusTimeout, Error: "batch cancelled before start"}
				return
			}

			hostCtx, cancel := context.WithTimeout(ctx, cfg.hostTimeout)
			defer cancel()
			results[idx] = inventoryHost(hostCtx, h, pack, cfg)
		}(i, host)
	}

	wg.Wait()
	return results
}

func inventoryHost(ctx context.Context, host string, pack *Pack, cfg execConfig) TargetResult {
	start := time.Now()
	res := TargetResult{Host: host}
	defer func() { res.DurationS = time.Since(start).Seconds() }()

	client, err := dial(ctx, host, cfg)
	if err != nil {
		res.Status = classifyDialError(err)
		res.Error = err.Error()
		return res
	}
	defer func() { _ = client.Close() }()

	// Probe facts first: the pack's guards are evaluated against them.
	probeOut, _, err := runCommand(ctx, client, factsProbe, cfg)
	if err != nil {
		res.Status = StatusError
		res.Error = fmt.Sprintf("facts probe: %v", err)
		return res
	}
	res.Facts = parseFacts(probeOut)

	collectors, skipped := pack.Select(res.Facts)
	res.Skipped = skipped
	res.Collected = make(map[string]string, len(collectors))

	for _, c := range collectors {
		if ctx.Err() != nil {
			res.Status = StatusTimeout
			res.Error = "host timeout during collection"
			return res
		}
		out, stderr, err := runCommand(ctx, client, c.Cmd, cfg)
		if err != nil {
			if res.Failed == nil {
				res.Failed = make(map[string]string, 1)
			}
			res.Failed[c.ID] = err.Error()
			continue
		}
		// A non-zero exit is not an error here: `dnf needs-restarting -r`
		// signals its answer through the exit code, and stderr is useful
		// context for the server-side parser either way.
		if stderr != "" {
			out = out + "\n[stderr]\n" + stderr
		}
		res.Collected[c.ID] = out
	}

	res.Status = StatusOK
	return res
}

func dial(ctx context.Context, host string, cfg execConfig) (*ssh.Client, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(cfg.port))

	d := net.Dialer{Timeout: cfg.dialTimeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	// Bound the handshake too: a TCP-reachable host that never completes the
	// SSH handshake would otherwise hold a slot for the whole host timeout.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg.sshClientConfig)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	return ssh.NewClient(c, chans, reqs), nil
}

// classifyDialError maps a connection failure onto a status the server can
// turn into a gap reason. "Why can't we see this host" is the product
// question Phase 0 answers, so the distinction matters.
func classifyDialError(err error) string {
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unable to authenticate"),
		strings.Contains(msg, "no supported methods remain"),
		strings.Contains(msg, "permission denied"):
		return StatusSSHAuthFailed
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "connection reset"):
		return StatusSSHRefused
	case strings.Contains(msg, "timeout"), strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "i/o timeout"):
		return StatusTimeout
	default:
		return StatusError
	}
}

// runCommand executes one command and returns stdout and stderr, each capped
// at cfg.maxOutputBytes. A package list on a large host is big but bounded;
// an unbounded read here would let one host exhaust the forager's memory.
func runCommand(ctx context.Context, client *ssh.Client, cmd string, cfg execConfig) (string, string, error) {
	cmdCtx, cancel := context.WithTimeout(ctx, cfg.commandTimeout)
	defer cancel()

	session, err := client.NewSession()
	if err != nil {
		return "", "", fmt.Errorf("new session: %w", err)
	}
	defer func() { _ = session.Close() }()

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		return "", "", fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := session.StderrPipe()
	if err != nil {
		return "", "", fmt.Errorf("stderr pipe: %w", err)
	}

	if err := session.Start(cmd); err != nil {
		return "", "", fmt.Errorf("start: %w", err)
	}

	type readResult struct{ stdout, stderr []byte }
	readCh := make(chan readResult, 1)
	go func() {
		out, _ := io.ReadAll(io.LimitReader(stdoutPipe, int64(cfg.maxOutputBytes)))
		errOut, _ := io.ReadAll(io.LimitReader(stderrPipe, int64(cfg.maxOutputBytes)))
		readCh <- readResult{out, errOut}
	}()

	waitCh := make(chan error, 1)
	go func() { waitCh <- session.Wait() }()

	var read readResult
	select {
	case read = <-readCh:
	case <-cmdCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", "", fmt.Errorf("command timed out")
	}

	select {
	case waitErr := <-waitCh:
		// Non-zero exit is reported through output, not as a Go error.
		var exitErr *ssh.ExitError
		if waitErr != nil && !asExitError(waitErr, &exitErr) {
			return "", "", fmt.Errorf("wait: %w", waitErr)
		}
	case <-cmdCtx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", "", fmt.Errorf("command timed out")
	}

	return string(read.stdout), string(read.stderr), nil
}

func asExitError(err error, target **ssh.ExitError) bool {
	e, ok := err.(*ssh.ExitError)
	if ok {
		*target = e
	}
	return ok
}
