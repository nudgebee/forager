//go:build !windows

package mcp

import (
	"fmt"
	"syscall"
	"time"
)

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
