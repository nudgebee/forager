package main

// Standalone subcommands: run discovery from the command line, with no relay,
// no agent identity and no server.
//
// Without these the only way to see discovery do anything is to register an
// agent in the product, point it at a relay, sign a content pack, and dispatch
// an action through an internal endpoint. That makes the agent impossible to
// evaluate before onboarding, impossible to debug on a customer's machine, and
// impossible to try at all from the public repo.
//
// These call the same proxy the agent calls, through the same exported API, so
// what they exercise is the real path rather than a parallel one.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"nudgebee/forager/pkg/proxy"
	proxydiscovery "nudgebee/forager/pkg/proxy/discovery"
)

// runStandalone dispatches a subcommand. Returns false if args[0] is not one,
// so the agent keeps its existing invocation.
func runStandalone(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "sweep":
		exitOn(cmdSweep(args[1:]))
	case "inventory":
		exitOn(cmdInventory(args[1:]))
	case "pack":
		exitOn(cmdPack(args[1:]))
	case "help":
		printStandaloneUsage(os.Stdout)
	default:
		return false
	}
	return true
}

func exitOn(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func printStandaloneUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `nudgebee-forager — VM discovery

Run as an agent (default):
  nudgebee-forager --config /etc/nudgebee/forager.yaml

Run discovery directly, without a relay or an account:
  nudgebee-forager sweep     --cidr 10.0.1.0/24 [--ports 22] [--rate-pps 100] \
                             [--user nudgebee-ro --key ~/.ssh/id_ed25519]
  nudgebee-forager inventory --cidr 10.0.1.0/24 --targets 10.0.1.5,10.0.1.6 \
                             --user nudgebee-ro --key ~/.ssh/id_ed25519 \
                             --pack ./linux-inventory-v2.yaml --pack-key <base64>

Content packs:
  nudgebee-forager pack keygen
  nudgebee-forager pack sign ./pack.yaml --key <base64 private key>

Results are printed to stdout as JSON.
`)
}

// stderrLogger keeps logs off stdout so results stay pipeable into jq.
func stderrLogger(verbose bool) *slog.Logger {
	level := slog.LevelWarn
	if verbose {
		level = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func emit(v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// runAction configures a discovery proxy and runs one action against it,
// exactly as the agent does when the relay sends one.
func runAction(cfg map[string]any, creds map[string]string, action string, params map[string]any, verbose bool) error {
	p := proxydiscovery.New(stderrLogger(verbose))
	if err := p.Configure(cfg, creds); err != nil {
		return err
	}
	defer func() { _ = p.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	resp, err := p.HandleRequest(ctx, &proxy.ActionRequest{Action: action, Params: params})
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s failed: %s", action, resp.Data)
	}

	var out any
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return fmt.Errorf("parsing result: %w", err)
	}
	return emit(out)
}

func cmdSweep(args []string) error {
	fs := flag.NewFlagSet("sweep", flag.ExitOnError)
	cidr := fs.String("cidr", "", "CIDR to sweep, e.g. 10.0.1.0/24 (required)")
	ports := fs.String("ports", "22", "comma-separated ports to probe")
	ratePPS := fs.Int("rate-pps", 100, "probes per second")
	timeoutMs := fs.Int("timeout-ms", 1000, "per-probe timeout")
	exclude := fs.String("exclude", "", "comma-separated addresses or CIDRs to skip")
	// SSH credentials are optional here, unlike inventory: a sweep with none
	// still reports presence/MAC/RDNS, just without the cloud-identity probe
	// (see pkg/proxy/discovery/cloud_identity.go) that needs to log in.
	user := fs.String("user", "nudgebee-ro", "SSH username, enables the cloud-identity probe when set alongside --key/--password-env")
	keyFile := fs.String("key", "", "path to SSH private key, enables the cloud-identity probe")
	passwordEnv := fs.String("password-env", "", "environment variable holding the SSH password, enables the cloud-identity probe")
	sshPort := fs.Int("ssh-port", 22, "SSH port the cloud-identity probe connects on")
	verbose := fs.Bool("v", false, "log progress to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cidr == "" {
		return fmt.Errorf("--cidr is required")
	}
	if *keyFile != "" && *passwordEnv != "" {
		return fmt.Errorf("--key and --password-env are mutually exclusive")
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		return err
	}

	params := map[string]any{
		"cidrs":      []any{*cidr},
		"ports":      portList,
		"rate_pps":   float64(*ratePPS),
		"timeout_ms": float64(*timeoutMs),
	}
	if *exclude != "" {
		params["exclusions"] = toAnySlice(splitList(*exclude))
	}

	creds := map[string]string{}
	if *keyFile != "" || *passwordEnv != "" {
		creds["username"] = *user
		if *keyFile != "" {
			key, err := os.ReadFile(*keyFile)
			if err != nil {
				return fmt.Errorf("reading --key: %w", err)
			}
			creds["private_key"] = string(key)
		}
		if *passwordEnv != "" {
			pw := os.Getenv(*passwordEnv)
			if pw == "" {
				return fmt.Errorf("environment variable %s is empty", *passwordEnv)
			}
			creds["password"] = pw
		}
	}

	// The swept CIDR is also the scope ceiling, so a standalone run cannot
	// reach further than what was asked for.
	return runAction(map[string]any{
		"allowed_cidrs": []any{*cidr},
		"max_rate_pps":  float64(*ratePPS),
		"port":          float64(*sshPort),
	}, creds, "discovery_sweep", params, *verbose)
}

func cmdInventory(args []string) error {
	fs := flag.NewFlagSet("inventory", flag.ExitOnError)
	cidr := fs.String("cidr", "", "scope the targets must fall within (required)")
	targets := fs.String("targets", "", "comma-separated hosts to inventory (required)")
	user := fs.String("user", "nudgebee-ro", "SSH username")
	keyFile := fs.String("key", "", "path to SSH private key (required unless --password-env)")
	passwordEnv := fs.String("password-env", "", "environment variable holding the SSH password")
	packFile := fs.String("pack", "", "path to a signed content pack (required)")
	packKey := fs.String("pack-key", "", "base64 Ed25519 public key the pack is signed with (required)")
	port := fs.Int("port", 22, "SSH port")
	concurrency := fs.Int("concurrency", 25, "hosts to inventory in parallel")
	knownHosts := fs.String("known-hosts", "", "known_hosts file for host key verification")
	verbose := fs.Bool("v", false, "log progress to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}

	switch {
	case *cidr == "":
		return fmt.Errorf("--cidr is required: it bounds which hosts may be contacted")
	case *targets == "":
		return fmt.Errorf("--targets is required")
	case *packFile == "":
		return fmt.Errorf("--pack is required")
	case *packKey == "":
		return fmt.Errorf("--pack-key is required: a pack that cannot be verified is not run")
	case *keyFile == "" && *passwordEnv == "":
		return fmt.Errorf("one of --key or --password-env is required")
	}

	// The pack is read here and its version taken from the file, so the caller
	// does not have to know it. It is still verified inside the proxy.
	packDir, packVersion, err := stagePack(*packFile)
	if err != nil {
		return err
	}
	// The staged copy is ours and nothing else reads it after this call.
	defer func() { _ = os.RemoveAll(packDir) }()

	creds := map[string]string{"username": *user}
	if *keyFile != "" {
		key, err := os.ReadFile(*keyFile)
		if err != nil {
			return fmt.Errorf("reading --key: %w", err)
		}
		creds["private_key"] = string(key)
	}
	if *passwordEnv != "" {
		pw := os.Getenv(*passwordEnv)
		if pw == "" {
			return fmt.Errorf("environment variable %s is empty", *passwordEnv)
		}
		creds["password"] = pw
	}

	cfg := map[string]any{
		"allowed_cidrs":   []any{*cidr},
		"pack_public_key": *packKey,
		"pack_dir":        packDir,
		"port":            float64(*port),
		"concurrency":     float64(*concurrency),
	}
	if *knownHosts != "" {
		cfg["known_hosts_file"] = *knownHosts
	}

	return runAction(cfg, creds, "discovery_inventory", map[string]any{
		"targets":              toAnySlice(splitList(*targets)),
		"content_pack_version": float64(packVersion),
	}, *verbose)
}

// stagePack copies a pack into a temporary directory under the name the proxy
// expects, and reports the version it declares. Nothing here verifies the
// signature; the proxy still does that.
func stagePack(path string) (dir string, version int, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", 0, fmt.Errorf("reading --pack: %w", err)
	}

	// Parse the YAML rather than scanning for a "version:" line. Line
	// scanning matches indented occurrences inside multi-line commands or
	// comments, and a regex anchored at column 0 still only approximates the
	// structure. The parser knows it.
	var head struct {
		Version int `yaml:"version"`
	}
	if err := yaml.Unmarshal(raw, &head); err != nil {
		return "", 0, fmt.Errorf("pack is not valid YAML: %w", err)
	}
	if head.Version <= 0 {
		return "", 0, fmt.Errorf("pack does not declare a positive version")
	}
	version = head.Version

	dir, err = os.MkdirTemp("", "forager-pack-")
	if err != nil {
		return "", 0, err
	}
	dest := fmt.Sprintf("%s/linux-inventory-v%d.yaml", dir, version)
	if err := os.WriteFile(dest, raw, 0o600); err != nil {
		return "", 0, err
	}
	return dir, version, nil
}

func parsePorts(s string) ([]any, error) {
	var out []any
	for _, p := range splitList(s) {
		var n int
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		out = append(out, float64(n))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports given")
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func toAnySlice(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
