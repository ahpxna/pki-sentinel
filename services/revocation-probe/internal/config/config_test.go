package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	content := `
poll_interval: 2s
max_wait: 30s
max_attempts: 12
profiles:
  - name: curl-default
    enabled: true
    timeout: 5s
  - name: chromium-headless
    enabled: false
    timeout: 10s
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollInterval != 2*time.Second {
		t.Errorf("expected poll_interval=2s, got %s", cfg.PollInterval)
	}
	if cfg.MaxAttempts != 12 {
		t.Errorf("expected max_attempts=12, got %d", cfg.MaxAttempts)
	}
	if cfg.TimeoutFor("curl-default") != 5*time.Second {
		t.Errorf("unexpected profile timeout: %s", cfg.TimeoutFor("curl-default"))
	}
	if !cfg.IsEnabled("curl-default") {
		t.Errorf("expected curl-default to be enabled")
	}
	if cfg.IsEnabled("chromium-headless") {
		t.Errorf("expected chromium-headless to be disabled")
	}
	names := cfg.EnabledNames()
	if len(names) != 1 || names[0] != "curl-default" {
		t.Errorf("unexpected EnabledNames: %v", names)
	}
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte("profiles: []\n"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PollInterval != 2*time.Second || cfg.MaxWait != 180*time.Second || cfg.MaxAttempts != 90 {
		t.Errorf("expected defaults, got poll_interval=%s max_wait=%s max_attempts=%d", cfg.PollInterval, cfg.MaxWait, cfg.MaxAttempts)
	}
}

func TestLoadRejectsEnabledProfileWithoutTimeout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte("profiles:\n  - name: broken\n    enabled: true\n"), 0o644); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected enabled profile without timeout to be rejected")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	content := "poll_interval: 2s\nunexpected_security_knob: true\nprofiles: []\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown YAML field to be rejected")
	}
}

func TestLoadRejectsDuplicateProfiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	content := "profiles:\n  - name: curl-default\n    enabled: false\n  - name: curl-default\n    enabled: false\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected duplicate profile to be rejected")
	}
}

func TestValidateEnabledProfilesRejectsUnknownEnabledName(t *testing.T) {
	cfg := &Config{Profiles: []ProfileConfig{
		{Name: "curl-default", Enabled: true, Timeout: time.Second},
		{Name: "chromium-headless", Enabled: false, Timeout: time.Second},
	}}
	if err := cfg.ValidateEnabledProfiles([]string{"curl-default"}); err != nil {
		t.Fatalf("disabled roadmap placeholder should be allowed: %v", err)
	}
	cfg.Profiles[1].Enabled = true
	if err := cfg.ValidateEnabledProfiles([]string{"curl-default"}); err == nil {
		t.Fatal("enabled unknown profile was accepted")
	}
}

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.yaml")
	if err := os.WriteFile(path, []byte("profiles: []\n---\nprofiles: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected multiple YAML documents to be rejected")
	}
}
