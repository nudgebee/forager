package mcp

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// stdioProcess manages a long-lived MCP server subprocess communicating via stdin/stdout.
type stdioProcess struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	mu     sync.Mutex
	logger *slog.Logger
}

// validateCommand sanitizes the command used to launch the MCP subprocess.
//
// The command originates from trusted operator-supplied datasource
// configuration rather than end-user request data, but we still defend against
// malformed or injected values: reject control characters that have no place in
// an executable path, and require that the command resolve to a real executable
// on PATH (or as an explicit path). This bounds the subprocess-launch surface to
// genuine, resolvable executables. The resolved absolute path is returned and
// used for the launch.
//
// A relative command containing a path separator (e.g. "./bin/mcp-server") is
// resolved relative to workingDir, matching where the process will actually run,
// rather than the parent process's current directory.
func validateCommand(command, workingDir string) (string, error) {
	if command == "" {
		return "", fmt.Errorf("command is empty")
	}
	if strings.ContainsAny(command, "\x00\n\r") {
		return "", fmt.Errorf("command contains illegal control characters")
	}

	pathToCheck := command
	// Only rewrite path-qualified relative commands; bare names (no separator)
	// must still be looked up on PATH.
	if workingDir != "" && filepath.Base(command) != command && !filepath.IsAbs(command) {
		pathToCheck = filepath.Join(workingDir, command)
	}

	resolved, err := exec.LookPath(pathToCheck)
	if err != nil {
		return "", fmt.Errorf("resolving command %q: %w", command, err)
	}
	return resolved, nil
}

// start launches the MCP server process.
func (s *stdioProcess) start(command string, args []string, env []string, workingDir string) error {
	resolved, err := validateCommand(command, workingDir)
	if err != nil {
		return fmt.Errorf("invalid MCP command: %w", err)
	}

	// #nosec G204 -- resolved is produced by validateCommand (real executable
	// resolved via LookPath, control characters rejected) and the command
	// originates from trusted operator configuration, not end-user request data.
	s.cmd = exec.Command(resolved, args...)

	if workingDir != "" {
		s.cmd.Dir = workingDir
	}

	// Inherit current env and add custom env vars
	s.cmd.Env = append(os.Environ(), env...)

	// Capture stderr for logging
	s.cmd.Stderr = &logWriter{logger: s.logger, level: slog.LevelWarn}

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
