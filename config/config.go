// Package config loads and validates proofx.yaml.
package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk proofx configuration. `proofx init` writes a
// default Config and `proofx collect` consumes it.
type Config struct {
	Version   string   `yaml:"version" json:"version"`
	Project   string   `yaml:"project" json:"project"`
	Artifacts []string `yaml:"artifacts" json:"artifacts"`
	Lockfiles []string `yaml:"lockfiles" json:"lockfiles"`
	Claims    []string `yaml:"claims" json:"claims"`
	Signing   Signing  `yaml:"signing" json:"signing"`
}

// Signing controls local key management.
type Signing struct {
	KeyFile string `yaml:"keyFile" json:"keyFile"`
}

// Default returns a sensible starting configuration.
func Default(project string) *Config {
	if project == "" {
		project = "my-project"
	}
	return &Config{
		Version:   "1.0",
		Project:   project,
		Artifacts: []string{"README.md"},
		Lockfiles: []string{},
		Claims: []string{
			"Built from the recorded commit",
			"Artifacts have known sha256 digests",
		},
		Signing: Signing{KeyFile: ".proofx/key.pem"},
	}
}

// Load reads proofx.yaml from dir. Missing file returns (nil, nil).
func Load(dir string) (*Config, error) {
	p := filepath.Join(dir, "proofx.yaml")
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", p, err)
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	if c.Version == "" {
		c.Version = "1.0"
	}
	if c.Signing.KeyFile == "" {
		c.Signing.KeyFile = ".proofx/key.pem"
	}
	return &c, nil
}

// Find walks upward from start to locate the nearest proofx.yaml.
func Find(start string) (string, *Config, error) {
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", nil, err
	}
	for {
		c, err := Load(dir)
		if err != nil {
			return "", nil, err
		}
		if c != nil {
			return dir, c, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", nil, nil
}
