//go:build windows

package config

import (
	"os"
	"path/filepath"
)

var (
	DefaultDataDir   = filepath.Join(os.Getenv("ProgramData"), "Nudgebee")
	DefaultConfigDir = filepath.Join(os.Getenv("ProgramData"), "Nudgebee")
)
