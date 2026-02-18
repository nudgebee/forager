package mcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// stdioProcess manages a long-lived MCP server subprocess communicating via stdin/stdout.
type stdioProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	mu     sync.Mutex
	logger *slog.Logger
}

// start launches the MCP server process.
func (s *stdioProcess) start(command string, args []string, env []string, workingDir string) error {
	s.cmd = exec.Command(command, args...)

	if workingDir != "" {
		s.cmd.Dir = workingDir
	}

	// Inherit current env and add custom env vars
	s.cmd.Env = append(os.Environ(), env...)

	// Capture stderr for logging
	s.cmd.Stderr = &logWriter{logger: s.logger, level: slog.LevelWarn}

	var err error
	s.stdin, err = s.cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("creating stdin pipe: %w", err)
	}

	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("creating stdout pipe: %w", err)
	}
	s.reader = bufio.NewReader(stdout)

	if err := s.cmd.Start(); err != nil {
		return fmt.Errorf("starting MCP process %q: %w", command, err)
	}

	s.logger.Info("MCP stdio process started", "pid", s.cmd.Process.Pid, "command", command)
	return nil
}

// send writes a JSON-RPC request to stdin and reads the response from stdout.
// Requests are serialized with a mutex since stdio is a single channel.
func (s *stdioProcess) send(ctx context.Context, request []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check process is still alive
	if s.cmd.ProcessState != nil && s.cmd.ProcessState.Exited() {
		return nil, fmt.Errorf("MCP stdio process has exited: %s", s.cmd.ProcessState.String())
	}

	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)

	go func() {
		// Write request as a single line (JSON-RPC messages are newline-delimited in stdio transport)
		if _, err := s.stdin.Write(append(request, '\n')); err != nil {
			ch <- result{err: fmt.Errorf("writing to MCP stdin: %w", err)}
			return
		}

		// Read response line
		line, err := s.reader.ReadBytes('\n')
		if err != nil {
			ch <- result{err: fmt.Errorf("reading from MCP stdout: %w", err)}
			return
		}

		ch <- result{data: line}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.data, r.err
	}
}

// healthCheck verifies the process is still running.
func (s *stdioProcess) healthCheck() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return fmt.Errorf("MCP stdio process not started")
	}
	// Signal 0 checks if process exists without sending a signal
	if err := s.cmd.Process.Signal(syscall.Signal(0)); err != nil {
		return fmt.Errorf("MCP stdio process not running: %w", err)
	}
	return nil
}

// close gracefully shuts down the stdio process.
func (s *stdioProcess) close() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	// Close stdin to signal EOF
	if s.stdin != nil {
		_ = s.stdin.Close()
	}

	// Try graceful shutdown with SIGTERM
	_ = s.cmd.Process.Signal(syscall.SIGTERM)

	// Wait with timeout
	done := make(chan error, 1)
	go func() {
		done <- s.cmd.Wait()
	}()

	select {
	case err := <-done:
		s.logger.Info("MCP stdio process exited", "pid", s.cmd.Process.Pid)
		return err
	case <-time.After(5 * time.Second):
		// Force kill
		pid := s.cmd.Process.Pid
		s.logger.Warn("MCP stdio process force-killed", "pid", pid)
		_ = s.cmd.Process.Kill()
		waitErr := <-done
		return fmt.Errorf("process %d force-killed: %w", pid, waitErr)
	}
}

// logWriter is an io.Writer that logs each line at the specified level.
type logWriter struct {
	logger *slog.Logger
	level  slog.Level
	buf    []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		idx := -1
		for i, b := range w.buf {
			if b == '\n' {
				idx = i
				break
			}
		}
		if idx < 0 {
			break
		}
		line := string(w.buf[:idx])
		w.buf = w.buf[idx+1:]
		if line != "" {
			w.logger.Log(context.Background(), w.level, "MCP stderr", "output", line)
		}
	}
	return len(p), nil
}
