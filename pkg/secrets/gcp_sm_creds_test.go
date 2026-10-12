package secrets

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCredentialsFile_RequiresType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte(`{"client_email":"x"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCredentialsFile(path); err == nil || !strings.Contains(err.Error(), "type") {
		t.Fatalf("err = %v, want missing type error", err)
	}
}

func TestLoadCredentialsFile_MissingFile(t *testing.T) {
	if _, err := loadCredentialsFile(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
