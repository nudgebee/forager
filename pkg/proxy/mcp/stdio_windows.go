//go:build windows

package mcp

import (
	"fmt"
	"time"
)

// healthCheck verifies the process is still running.
func (s *stdioProcess) healthCheck() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return fmt.Errorf("MCP stdio process not started")
	}
	// On Windows, Signal(0) is not supported. Check if ProcessState indicates exit.
	if s.cmd.ProcessState != nil && s.cmd.ProcessState.Exited() {
		return fmt.Errorf("MCP stdio process not running")
	}
	return nil
}

// close gracefully shuts down the stdio process.
func (s *stdioProcess) close() error {
	if s.cmd == nil || s.cmd.Process == nil {
		return nil
	}

	// Close stdin to signal EOF (graceful signal for well-behaved processes)
	if s.stdin != nil {
		_ = s.stdin.Close()
	}

	// Windows has no SIGTERM. Wait for process to exit after stdin EOF, then force kill.
	done := make(chan error, 1)
	go func() {
		done <- s.cmd.Wait()
	}()

	select {
	case err := <-done:
		s.logger.Info("MCP stdio process exited", "pid", s.cmd.Process.Pid)
		return err
	case <-time.After(5 * time.Second):
		pid := s.cmd.Process.Pid
		s.logger.Warn("MCP stdio process force-killed", "pid", pid)
		_ = s.cmd.Process.Kill()
		waitErr := <-done
		return fmt.Errorf("process %d force-killed: %w", pid, waitErr)
	}
}
