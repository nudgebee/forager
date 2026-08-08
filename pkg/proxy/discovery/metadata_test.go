package discovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// pack_versions must list every linux-inventory-v<N>.yaml in pack_dir,
// ascending, ignoring unrelated files — the server picks a version from this
// list to pin in discovery_inventory requests, since content_pack_version is
// a required request param with no "latest" default.
func TestCollectMetadata_ReportsPackVersions(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{
		"linux-inventory-v2.yaml",
		"linux-inventory-v10.yaml",
		"linux-inventory-vX.yaml", // non-numeric — ignored
		"windows-inventory-v1.yaml",
		"README.md",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	p, _ := newTestProxy(t, map[string]any{"pack_dir": dir}, nil)

	meta, err := p.CollectMetadata(context.Background())
	if err != nil {
		t.Fatalf("CollectMetadata: %v", err)
	}
	versions, ok := meta["pack_versions"].([]int)
	if !ok {
		t.Fatalf("pack_versions missing or wrong type: %#v", meta["pack_versions"])
	}
	if len(versions) != 2 || versions[0] != 2 || versions[1] != 10 {
		t.Fatalf("pack_versions = %v, want [2 10]", versions)
	}
}

// Without a pack_dir there is nothing to report — the key must be absent,
// not an empty list, so the server treats it the same as an older agent
// that predates the field.
func TestCollectMetadata_NoPackDirOmitsPackVersions(t *testing.T) {
	p, _ := newTestProxy(t, map[string]any{}, nil)

	meta, err := p.CollectMetadata(context.Background())
	if err != nil {
		t.Fatalf("CollectMetadata: %v", err)
	}
	if _, present := meta["pack_versions"]; present {
		t.Fatalf("pack_versions should be absent without pack_dir, got %#v", meta["pack_versions"])
	}
}
