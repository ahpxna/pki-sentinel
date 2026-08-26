// Package config loads profiles.yaml and probe-wide runtime settings.
package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ProfileConfig is one entry under `profiles:` in profiles.yaml.
type ProfileConfig struct {
	Name    string        `yaml:"name" json:"name"`
	Enabled bool          `yaml:"enabled" json:"enabled"`
	Timeout time.Duration `yaml:"timeout" json:"timeout_ns"`
}

// Config is the full profiles.yaml document.
type Config struct {
	PollInterval  time.Duration       `yaml:"poll_interval"`
	MaxWait       time.Duration       `yaml:"max_wait"`
	MaxAttempts   int                 `yaml:"max_attempts"`
	Profiles      []ProfileConfig     `yaml:"profiles"`
	OCSPFreshness OCSPFreshnessConfig `yaml:"ocsp_freshness"`
	Policy        PolicyConfig        `yaml:"policy"`

	// Cycle interval and Vault/service wiring are supplied via flags/env in
	// cmd/probe rather than profiles.yaml, since they're deployment-specific.
}

// OCSPFreshnessConfig makes temporal status-acceptance assumptions explicit
// in every experiment configuration.
type OCSPFreshnessConfig struct {
	MaxClockSkew            time.Duration `yaml:"max_clock_skew" json:"max_clock_skew_ns"`
	RequireNextUpdate       bool          `yaml:"require_next_update" json:"require_next_update"`
	MaxAgeWithoutNextUpdate time.Duration `yaml:"max_age_without_next_update" json:"max_age_without_next_update_ns"`
}

// PolicyConfig controls whether policy violations block an otherwise
// baseline-conformant cycle.
type PolicyConfig struct {
	Enforce bool `yaml:"enforce" json:"enforce"`
}

// Load reads and parses profiles.yaml from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var c Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("config: parsing %s: multiple YAML documents are not allowed", path)
		}
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	if c.PollInterval == 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.MaxWait == 0 {
		c.MaxWait = 180 * time.Second
	}
	if c.MaxAttempts == 0 {
		c.MaxAttempts = 90
	}
	if c.PollInterval < 0 || c.MaxWait < 0 || c.MaxAttempts < 0 {
		return nil, fmt.Errorf("config: poll_interval, max_wait, and max_attempts must be positive")
	}
	if c.OCSPFreshness.MaxClockSkew <= 0 {
		c.OCSPFreshness.MaxClockSkew = 5 * time.Minute
	}
	if c.OCSPFreshness.MaxAgeWithoutNextUpdate <= 0 {
		c.OCSPFreshness.MaxAgeWithoutNextUpdate = time.Hour
	}
	seenProfiles := make(map[string]struct{}, len(c.Profiles))
	enabledProfiles := 0
	for _, profile := range c.Profiles {
		if profile.Name == "" {
			return nil, fmt.Errorf("config: profile name must not be empty")
		}
		if _, duplicate := seenProfiles[profile.Name]; duplicate {
			return nil, fmt.Errorf("config: duplicate profile %q", profile.Name)
		}
		seenProfiles[profile.Name] = struct{}{}
		if profile.Enabled {
			enabledProfiles++
			if profile.Timeout <= 0 {
				return nil, fmt.Errorf("config: enabled profile %q must have a positive timeout", profile.Name)
			}
		}
	}
	if enabledProfiles == 0 {
		return nil, fmt.Errorf("config: at least one profile must be enabled")
	}
	return &c, nil
}

// Digest returns a content digest of the effective execution configuration.
// Defaults have already been applied by Load; hashing the typed in-memory
// representation makes comments and YAML formatting irrelevant while binding
// every runtime knob and profile selection that can affect a cycle.
func (c *Config) Digest() (string, error) {
	if c == nil {
		return "", fmt.Errorf("config: cannot digest nil config")
	}
	type canonicalConfig struct {
		PollInterval  time.Duration       `json:"poll_interval_ns"`
		MaxWait       time.Duration       `json:"max_wait_ns"`
		MaxAttempts   int                 `json:"max_attempts"`
		Profiles      []ProfileConfig     `json:"profiles"`
		OCSPFreshness OCSPFreshnessConfig `json:"ocsp_freshness"`
		Policy        PolicyConfig        `json:"policy"`
	}
	enabledProfiles := make([]ProfileConfig, 0, len(c.Profiles))
	for _, profile := range c.Profiles {
		if profile.Enabled {
			enabledProfiles = append(enabledProfiles, profile)
		}
	}
	canonical, err := json.Marshal(canonicalConfig{
		PollInterval: c.PollInterval, MaxWait: c.MaxWait, MaxAttempts: c.MaxAttempts,
		Profiles: enabledProfiles, OCSPFreshness: c.OCSPFreshness, Policy: c.Policy,
	})
	if err != nil {
		return "", fmt.Errorf("config: marshal canonical config: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ValidateEnabledProfiles rejects misspelled or stale enabled profile names.
// Disabled names may remain in the file as documented roadmap placeholders,
// but an enabled profile must map to a real executor contract.
func (c *Config) ValidateEnabledProfiles(knownNames []string) error {
	known := make(map[string]struct{}, len(knownNames))
	for _, name := range knownNames {
		known[name] = struct{}{}
	}
	for _, profile := range c.Profiles {
		if !profile.Enabled {
			continue
		}
		if _, ok := known[profile.Name]; !ok {
			return fmt.Errorf("config: enabled profile %q is not implemented", profile.Name)
		}
	}
	return nil
}

// TimeoutFor returns the configured timeout for a profile. The fallback is
// intentionally bounded so a missing optional profile entry cannot hang a
// cycle indefinitely.
func (c *Config) TimeoutFor(name string) time.Duration {
	for _, p := range c.Profiles {
		if p.Name == name && p.Timeout > 0 {
			return p.Timeout
		}
	}
	return 5 * time.Second
}

// EnabledNames returns the names of all enabled profiles, in file order.
func (c *Config) EnabledNames() []string {
	var names []string
	for _, p := range c.Profiles {
		if p.Enabled {
			names = append(names, p.Name)
		}
	}
	return names
}

// IsEnabled reports whether the named profile is enabled in this config.
func (c *Config) IsEnabled(name string) bool {
	for _, p := range c.Profiles {
		if p.Name == name && p.Enabled {
			return true
		}
	}
	return false
}
