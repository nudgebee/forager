package main

import (
	"flag"
	"log/slog"
	"os"
)

var configPath = flag.String("config", "", "path to config file")

func main() {
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("starting forager")
	runService(logger)
}
