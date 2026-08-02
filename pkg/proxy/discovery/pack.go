package discovery

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Pack is a signed, versioned set of collection commands. The forager binary
// carries no per-distro logic: it verifies the signature, evaluates each
// collector's `when` guard against facts probed from the host, and runs the
// commands verbatim. Adding a distro or fixing a command ships as a new pack
// version, never a new binary.
type Pack struct {
	Version    int         `yaml:"version"`
	Kind       string      `yaml:"kind"` // inventory (probe/remediation reserved for later tracks)
	Collectors []Collector `yaml:"collectors"`

	// Signature is base64 Ed25519 over the pack body: the document with the
	// signature line removed. Excluded from the signed bytes itself.
	Signature string `yaml:"signature"`
}

// Collector is one command to run on a matching host.
type Collector struct {
	ID   string `yaml:"id"`
	When string `yaml:"when,omitempty"` // empty = run on every host
	Cmd  string `yaml:"cmd"`
}

// KindInventory is the only pack kind Phase 0 executes.
const KindInventory = "inventory"

// maxPackBytes bounds a fetched pack before parsing.
const maxPackBytes = 1 << 20 // 1MB

// ParseAndVerify parses a YAML pack and checks its Ed25519 signature against
// pubKey. Any failure means the pack does not run: an unverified pack is
// indistinguishable from an attacker-supplied one.
func ParseAndVerify(raw []byte, pubKey ed25519.PublicKey) (*Pack, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty pack")
	}
	if len(raw) > maxPackBytes {
		return nil, fmt.Errorf("pack too large: %d bytes (max %d)", len(raw), maxPackBytes)
	}

	var p Pack
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parsing pack: %w", err)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("pack verification requires an Ed25519 public key")
	}
	if p.Signature == "" {
		return nil, fmt.Errorf("pack is unsigned")
	}
	sig, err := base64.StdEncoding.DecodeString(p.Signature)
	if err != nil {
		return nil, fmt.Errorf("pack signature is not valid base64: %w", err)
	}
	if !ed25519.Verify(pubKey, SignedBytes(raw), sig) {
		return nil, fmt.Errorf("pack signature verification failed")
	}

	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// SignedBytes returns the bytes a signature covers: the pack document with
// its top-level `signature:` line removed, trailing whitespace trimmed.
// Publishers sign this; verifiers reconstruct it. Keeping the signature inside
// the same document (rather than a detached file) means a pack cannot be
// separated from its signature in transit or on disk. Trailing whitespace is
// normalized so that appending the signature line — which necessarily changes
// the document's tail — does not invalidate the signature.
func SignedBytes(raw []byte) []byte {
	lines := strings.Split(string(raw), "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "signature:") {
			continue
		}
		kept = append(kept, line)
	}
	return []byte(strings.TrimRight(strings.Join(kept, "\n"), " \t\r\n"))
}

func (p *Pack) validate() error {
	if p.Version <= 0 {
		return fmt.Errorf("pack version must be positive, got %d", p.Version)
	}
	if p.Kind != KindInventory {
		return fmt.Errorf("unsupported pack kind %q (this build runs %q packs only)", p.Kind, KindInventory)
	}
	if len(p.Collectors) == 0 {
		return fmt.Errorf("pack has no collectors")
	}

	seen := make(map[string]bool, len(p.Collectors))
	for i, c := range p.Collectors {
		if c.ID == "" {
			return fmt.Errorf("collector %d has no id", i)
		}
		if seen[c.ID] {
			return fmt.Errorf("duplicate collector id %q", c.ID)
		}
		seen[c.ID] = true

		if strings.TrimSpace(c.Cmd) == "" {
			return fmt.Errorf("collector %q has no cmd", c.ID)
		}
		// Reject unparseable guards at load time rather than per host, so a
		// malformed pack fails once and loudly.
		if c.When != "" {
			if _, err := parseWhen(c.When); err != nil {
				return fmt.Errorf("collector %q: %w", c.ID, err)
			}
		}
	}
	return nil
}

// Select returns the collectors whose `when` guard matches the given facts,
// in pack order. A guard referencing an unknown fact does not match — see
// evalWhen.
func (p *Pack) Select(facts map[string]string) ([]Collector, []SkippedCollector) {
	var run []Collector
	var skipped []SkippedCollector

	for _, c := range p.Collectors {
		if c.When == "" {
			run = append(run, c)
			continue
		}
		expr, err := parseWhen(c.When)
		if err != nil {
			// validate() already rejected these; defensive.
			skipped = append(skipped, SkippedCollector{ID: c.ID, Reason: err.Error()})
			continue
		}
		match, err := expr.eval(facts)
		if err != nil {
			skipped = append(skipped, SkippedCollector{ID: c.ID, Reason: err.Error()})
			continue
		}
		if match {
			run = append(run, c)
		}
	}
	return run, skipped
}

// SkippedCollector records a collector that could not be evaluated. Skips are
// reported rather than silently dropped: a guard we cannot evaluate is a gap
// in the inventory, and the server must be able to see it.
type SkippedCollector struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}
