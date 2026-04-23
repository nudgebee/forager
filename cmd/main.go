package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"

	"nudgebee/forager/pkg/version"
)

var (
	configPath  = flag.String("config", "", "path to config file")
	showVersion = flag.Bool("version", false, "print version and exit")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Println("nudgebee-forager", version.String())
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	logger.Info("starting forager",
		"version", version.Version,
		"commit", version.Commit,
		"build_time", version.BuildTime,
	)
	runService(logger)
}
