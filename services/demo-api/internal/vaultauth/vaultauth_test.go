package vaultauth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approle.env")
	contents := "# generated\nVAULT_ROLE_ID=role-id\nVAULT_SECRET_ID=secret=id\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	creds, err := LoadEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if creds.RoleID != "role-id" || creds.SecretID != "secret=id" {
		t.Fatalf("unexpected credentials: %#v", creds)
	}
}

func TestLoadEnvFileRejectsMissingCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "approle.env")
	if err := os.WriteFile(path, []byte("VAULT_ROLE_ID=role-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadEnvFile(path); err == nil {
		t.Fatal("expected missing secret ID to be rejected")
	}
}
