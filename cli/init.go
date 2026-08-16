// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"crypto/ed25519"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"github.com/EslaM-X/proofx/config"
	"github.com/EslaM-X/proofx/proof"
)

// cmdInit scaffolds a proofx.yaml using the git repo name as project name.
func (c *CLI) cmdInit(args []string) int {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	project := projectName(dir)
	cfg := config.Default(project)
	if err := os.MkdirAll(filepath.Join(dir, ".proofx"), 0o755); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: init: %v\n", err)
		return 1
	}
	if _, err := os.Stat(filepath.Join(dir, "proofx.yaml")); err == nil {
		fmt.Fprintf(c.Stdout, "✓ proofx.yaml already exists — keeping it\n")
	} else {
		if err := writeYAML(filepath.Join(dir, "proofx.yaml"), cfg); err != nil {
			fmt.Fprintf(c.Stderr, "proofx: init: %v\n", err)
			return 1
		}
		fmt.Fprintf(c.Stdout, "✓ created proofx.yaml\n")
	}
	fmt.Fprintf(c.Stdout, "✓ initialized proofx for project %q\n", project)
	fmt.Fprintf(c.Stdout, "  next: proofx collect && proofx prove\n")
	return 0
}

func projectName(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	// derive from the origin remote for nicer naming when possible
	if rem := gitOriginName(dir); rem != "" {
		return rem
	}
	return filepath.Base(abs)
}

func gitOriginName(dir string) string {
	rem, err := evidenceGitRemote(dir)
	if err != nil {
		return ""
	}
	return rem
}

// cmdKeygen generates an ed25519 key pair into .proofx/key.pem and prints
// the matching public key (base64 raw) for embedding in CI/badges.
func (c *CLI) cmdKeygen(args []string) int {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	cfg, err := config.Load(dir)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: keygen: %v\n", err)
		return 1
	}
	if cfg == nil {
		cfg = config.Default(projectName(dir))
	}
	if err := os.MkdirAll(filepath.Join(dir, ".proofx"), 0o755); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: keygen: %v\n", err)
		return 1
	}
	pub, priv, err := proof.GenerateKey()
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: keygen: %v\n", err)
		return 1
	}
	keyPath := filepath.Join(dir, cfg.Signing.KeyFile)
	if err := writeKeyPEM(keyPath, priv); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: keygen: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.Stdout, "✓ ed25519 key pair generated\n  private: %s\n  public : %s\n",
		keyPath, proof.EncodePublicKey(pub))
	return 0
}

func writeKeyPEM(path string, priv ed25519.PrivateKey) error {
	privBytes, err := x509Marshal(priv)
	if err != nil {
		return err
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}
