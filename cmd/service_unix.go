//go:build !windows

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func runService(logger *slog.Logger) {
	a, err := newApp(*configPath, logger)
	if err != nil {
		logger.Error("failed to initialize", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	if err := a.run(ctx); err != nil && err != context.Canceled {
		logger.Error("exited with error", "err", err)
		os.Exit(1)
	}
	logger.Info("forager stopped")
}
