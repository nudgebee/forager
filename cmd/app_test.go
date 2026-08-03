package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Credentials may name a file instead of inlining key material, so a private
// key can stay out of config entirely — mounted as a Kubernetes Secret, say.
func TestResolveKeyFiles(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "id_ed25519")
	const keyMaterial = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc123\n-----END OPENSSH PRIVATE KEY-----\n"
	if err := os.WriteFile(keyPath, []byte(keyMaterial), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	got, err := resolveKeyFiles(map[string]string{
		"username":         "nudgebee-ro",
		"private_key_file": keyPath,
	})
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if got["private_key"] != keyMaterial {
		t.Errorf("private_key = %q, want the file contents", got["private_key"])
	}
	if _, present := got["private_key_file"]; present {
		t.Error("private_key_file survived resolution; proxies would see an unknown credential")
	}
	if got["username"] != "nudgebee-ro" {
		t.Error("unrelated credentials were not carried through")
	}
}

// The input map comes from parsed config that may be shared; rewriting a
// caller's map in place is a poor trade for saving an allocation.
func TestResolveKeyFiles_DoesNotMutateInput(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte("material"), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	in := map[string]string{"private_key_file": keyPath}
	if _, err := resolveKeyFiles(in); err != nil {
		t.Fatalf("resolving: %v", err)
	}

	if in["private_key_file"] != keyPath || in["private_key"] != "" {
		t.Errorf("input map was mutated: %v", in)
	}
}

// Setting both forms would make the effective credential depend on map
// iteration order, so it is rejected rather than silently resolved one way.
func TestResolveKeyFiles_RejectsBothForms(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, []byte("from-file"), 0o600); err != nil {
		t.Fatalf("writing key: %v", err)
	}

	_, err := resolveKeyFiles(map[string]string{
		"private_key":      "inline",
		"private_key_file": keyPath,
	})
	if err == nil {
		t.Fatal("accepted both private_key and private_key_file")
	}
	if !strings.Contains(err.Error(), "provide one") {
		t.Errorf("error = %q, want it to say which to provide", err)
	}
}

func TestResolveKeyFiles_Errors(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}

	cases := map[string]string{
		"missing file": filepath.Join(dir, "nope"),
		// An empty key file means a broken mount or a failed secret
		// injection; passing "" to the proxy would fail far less clearly.
		"empty file": empty,
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := resolveKeyFiles(map[string]string{"private_key_file": path}); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

// Credentials with no *_file entries must pass through untouched, including
// the common case of an inline key.
func TestResolveKeyFiles_PassesThroughUnchanged(t *testing.T) {
	in := map[string]string{"username": "u", "private_key": "inline", "password": "p"}
	got, err := resolveKeyFiles(in)
	if err != nil {
		t.Fatalf("resolving: %v", err)
	}
	if len(got) != len(in) {
		t.Fatalf("credentials = %v, want %v", got, in)
	}
	for k, v := range in {
		if got[k] != v {
			t.Errorf("credentials[%q] = %q, want %q", k, got[k], v)
		}
	}
}
