//go:build windows

package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"golang.org/x/sys/windows/svc"
)

func runService(logger *slog.Logger) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		logger.Error("failed to detect service mode", "err", err)
		os.Exit(1)
	}

	if isService {
		if err := svc.Run("NudgebeeForager", &foragerService{logger: logger}); err != nil {
			logger.Error("service run failed", "err", err)
			os.Exit(1)
		}
		return
	}

	// Interactive mode (console)
	a, err := newApp(*configPath, logger)
	if err != nil {
		logger.Error("failed to initialize", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	go func() {
		<-sigCh
		logger.Info("received interrupt, shutting down")
		cancel()
	}()

	if err := a.run(ctx); err != nil && err != context.Canceled {
		logger.Error("exited with error", "err", err)
		os.Exit(1)
	}
	logger.Info("forager stopped")
}

// foragerService implements svc.Handler for Windows Service Control Manager.
type foragerService struct {
	logger *slog.Logger
}

func (s *foragerService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.StartPending}

	a, err := newApp(*configPath, s.logger)
	if err != nil {
		s.logger.Error("failed to initialize", "err", err)
		return true, 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- a.run(ctx) }()

	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-errCh:
				case <-time.After(30 * time.Second):
					s.logger.Warn("shutdown timed out")
				}
				return false, 0
			case svc.Interrogate:
				changes <- c.CurrentStatus
			}
		case err := <-errCh:
			if err != nil && err != context.Canceled {
				s.logger.Error("app exited with error", "err", err)
				return true, 1
			}
			return false, 0
		}
	}
}
