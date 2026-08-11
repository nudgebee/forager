package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Subcommands must not swallow the agent's own invocation. Existing systemd
// units run `nudgebee-forager --config ...`, and anything unrecognised has to
// fall through to agent mode rather than erroring.
func TestRunStandalone_LeavesAgentInvocationAlone(t *testing.T) {
	agentArgs := [][]string{
		{},
		{"--config", "/etc/nudgebee/forager.yaml"},
		{"--version"},
		{"-config=/tmp/x.yaml"},
	}
	for _, args := range agentArgs {
		if runStandalone(args) {
			t.Errorf("args %v were treated as a subcommand; agent mode would never run", args)
		}
	}
}

// Go's flag package stops at the first non-flag argument, so a file given
// before its flags would silently lose them. Both orders must work.
func TestSplitPositional(t *testing.T) {
	cases := []struct {
		name           string
		args           []string
		wantPositional []string
		wantFlags      []string
	}{
		{"file first", []string{"p.yaml", "--key", "K"}, []string{"p.yaml"}, []string{"--key", "K"}},
		{"flags first", []string{"--key", "K", "p.yaml"}, []string{"p.yaml"}, []string{"--key", "K"}},
		{"equals form", []string{"--key=K", "p.yaml"}, []string{"p.yaml"}, []string{"--key=K"}},
		{"no flags", []string{"p.yaml"}, []string{"p.yaml"}, nil},
		{"boolean flag then file", []string{"-v", "p.yaml"}, nil, []string{"-v", "p.yaml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, flags := splitPositional(tc.args)
			if strings.Join(pos, ",") != strings.Join(tc.wantPositional, ",") {
				t.Errorf("positional = %v, want %v", pos, tc.wantPositional)
			}
			if strings.Join(flags, ",") != strings.Join(tc.wantFlags, ",") {
				t.Errorf("flags = %v, want %v", flags, tc.wantFlags)
			}
		})
	}
}

// The scope ceiling is not optional in standalone mode either: without it a
// mistyped target would be contacted rather than refused.
func TestCmdInventory_RequiresScopeAndPackKey(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(pack, []byte("version: 1\nkind: inventory\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	key := filepath.Join(dir, "k")
	if err := os.WriteFile(key, []byte("x"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	cases := map[string][]string{
		"no cidr":     {"--targets", "10.0.0.1", "--pack", pack, "--pack-key", "K", "--key", key},
		"no targets":  {"--cidr", "10.0.0.0/24", "--pack", pack, "--pack-key", "K", "--key", key},
		"no pack":     {"--cidr", "10.0.0.0/24", "--targets", "10.0.0.1", "--pack-key", "K", "--key", key},
		"no pack key": {"--cidr", "10.0.0.0/24", "--targets", "10.0.0.1", "--pack", pack, "--key", key},
		"no creds":    {"--cidr", "10.0.0.0/24", "--targets", "10.0.0.1", "--pack", pack, "--pack-key", "K"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cmdInventory(args); err == nil {
				t.Fatalf("accepted invocation missing %s", name)
			}
		})
	}
}

func TestCmdSweep_RequiresCIDR(t *testing.T) {
	if err := cmdSweep([]string{"--ports", "22"}); err == nil {
		t.Fatal("swept without a CIDR, which would have no bound at all")
	}
}

// --key and --password-env both name an auth method; accepting both silently
// picking one would surprise whichever one lost.
func TestCmdSweep_RejectsBothKeyAndPasswordEnv(t *testing.T) {
	err := cmdSweep([]string{"--cidr", "10.0.0.0/24", "--key", "/dev/null", "--password-env", "SSH_PW"})
	if err == nil {
		t.Fatal("accepted both --key and --password-env")
	}
}

// The pack version comes from the file so the caller does not have to repeat
// it, and a mismatch would make the proxy refuse the pack.
func TestStagePack(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "whatever-name.yaml")
	if err := os.WriteFile(pack, []byte("version: 7\nkind: inventory\ncollectors: []\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	stagedDir, version, err := stagePack(pack)
	if err != nil {
		t.Fatalf("staging: %v", err)
	}
	if version != 7 {
		t.Errorf("version = %d, want 7", version)
	}
	// The proxy looks for a specific filename regardless of what the user
	// called the file.
	if _, err := os.Stat(filepath.Join(stagedDir, "linux-inventory-v7.yaml")); err != nil {
		t.Errorf("pack not staged under the expected name: %v", err)
	}
}

func TestStagePack_RejectsVersionlessPack(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(pack, []byte("kind: inventory\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	if _, _, err := stagePack(pack); err == nil {
		t.Fatal("accepted a pack with no version")
	}
}

func TestParsePorts(t *testing.T) {
	if got, err := parsePorts("22,3389"); err != nil || len(got) != 2 {
		t.Errorf("parsePorts = %v, %v", got, err)
	}
	for _, bad := range []string{"", "0", "70000", "abc"} {
		if _, err := parsePorts(bad); err == nil {
			t.Errorf("accepted invalid ports %q", bad)
		}
	}
}

// "--" ends flag parsing and a bare "-" is a value, both by long-standing
// convention. Getting either wrong silently loses an argument.
func TestSplitPositional_CLIConventions(t *testing.T) {
	cases := []struct {
		name           string
		args           []string
		wantPositional []string
		wantFlags      []string
	}{
		{"double dash ends flags", []string{"--key", "K", "--", "-weird-name.yaml"},
			[]string{"-weird-name.yaml"}, []string{"--key", "K"}},
		{"double dash with several positionals", []string{"--", "a.yaml", "-b.yaml"},
			[]string{"a.yaml", "-b.yaml"}, nil},
		{"bare dash is a value", []string{"-", "--key", "K"},
			[]string{"-"}, []string{"--key", "K"}},
		{"bare dash is not consumed by a preceding flag", []string{"--out", "-"},
			[]string{"-"}, []string{"--out"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pos, flags := splitPositional(tc.args)
			if strings.Join(pos, ",") != strings.Join(tc.wantPositional, ",") {
				t.Errorf("positional = %v, want %v", pos, tc.wantPositional)
			}
			if strings.Join(flags, ",") != strings.Join(tc.wantFlags, ",") {
				t.Errorf("flags = %v, want %v", flags, tc.wantFlags)
			}
		})
	}
}

// The pack version has to be read the way YAML defines it, not by matching
// text. `version : 3` is valid YAML and means the same thing, but a
// HasPrefix("version:") scan misses it entirely and reports the pack as
// having no version at all.
func TestStagePack_ReadsVersionAsYAMLNotText(t *testing.T) {
	cases := map[string]string{
		"plain":              "version: 3\nkind: inventory\ncollectors: []\n",
		"space before colon": "version : 3\nkind: inventory\ncollectors: []\n",
		"tab before colon":   "version\t: 3\nkind: inventory\ncollectors: []\n",
		"after another key":  "kind: inventory\nversion: 3\ncollectors: []\n",
		"quoted key":         "\"version\": 3\nkind: inventory\ncollectors: []\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			pack := filepath.Join(dir, "p.yaml")
			if err := os.WriteFile(pack, []byte(body), 0o600); err != nil {
				t.Fatalf("writing: %v", err)
			}

			stagedDir, version, err := stagePack(pack)
			if err != nil {
				t.Fatalf("staging %s: %v", name, err)
			}
			defer func() { _ = os.RemoveAll(stagedDir) }()

			if version != 3 {
				t.Errorf("version = %d, want 3", version)
			}
		})
	}
}

// The staged copy is a temporary directory the caller owns; leaking one per
// invocation would litter the host.
func TestCmdInventory_RemovesStagedPack(t *testing.T) {
	before, _ := filepath.Glob(filepath.Join(os.TempDir(), "forager-pack-*"))

	dir := t.TempDir()
	pack := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(pack, []byte("version: 1\nkind: inventory\ncollectors: []\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	key := filepath.Join(dir, "k")
	if err := os.WriteFile(key, []byte("not-a-real-key"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	// Fails at configure time (the key is not parseable), which is the point:
	// cleanup must happen on the error path too.
	_ = cmdInventory([]string{
		"--cidr", "10.0.0.0/24", "--targets", "10.0.0.1",
		"--pack", pack, "--pack-key", "AAAA", "--key", key,
	})

	after, _ := filepath.Glob(filepath.Join(os.TempDir(), "forager-pack-*"))
	if len(after) > len(before) {
		t.Errorf("staged pack directories leaked: %d before, %d after", len(before), len(after))
	}
}
