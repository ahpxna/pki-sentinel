// Package config loads profiles.yaml and probe-wide runtime settings.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// ProfileConfig is one entry under `profiles:` in profiles.yaml.
type ProfileConfig struct {
	Name    string        `yaml:"name"`
	Enabled bool          `yaml:"enabled"`
	Timeout time.Duration `yaml:"timeout"`
}

// Config is the full profiles.yaml document.
type Config struct {
	PollInterval time.Duration   `yaml:"poll_interval"`
	MaxWait      time.Duration   `yaml:"max_wait"`
	Profiles     []ProfileConfig `yaml:"profiles"`

	// Cycle interval and Vault/service wiring are supplied via flags/env in
	// cmd/probe rather than profiles.yaml, since they're deployment-specific.
}

// Load reads and parses profiles.yaml from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}
	if c.PollInterval == 0 {
		c.PollInterval = 2 * time.Second
	}
	if c.MaxWait == 0 {
		c.MaxWait = 180 * time.Second
	}
	return &c, nil
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
