// Package version exposes build-time metadata for the forager binary.
// Values are injected by the linker via -ldflags "-X nudgebee/forager/pkg/version.Version=...".
package version

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// String returns a one-line version descriptor suitable for CLI output.
func String() string {
	return Version + " (commit " + Commit + ", built " + BuildTime + ")"
}
