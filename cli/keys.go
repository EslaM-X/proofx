// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"

	"github.com/EslaM-X/proofx/config"
	"github.com/EslaM-X/proofx/model"
)

// loadKey reads the configured private key PEM file.
func loadKey(dir string, cfg *config.Config) (ed25519.PrivateKey, error) {
	path := filepath.Join(dir, cfg.Signing.KeyFile)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("proofx: key file is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("proofx: key is not ed25519")
	}
	return priv, nil
}

// gitSubject reads commit/branch/repository for the proof subject.
func gitSubject(dir string) (model.Subject, error) {
	head, err := gitHeadSHA(dir)
	if err != nil {
		return model.Subject{}, err
	}
	branch := gitBranchName(dir)
	repo := ""
	if r, err := evidenceGitRemote(dir); err == nil {
		repo = r
	}
	return model.Subject{Commit: head, Branch: branch, Repository: repo}, nil
}

func gitHeadSHA(dir string) (string, error) {
	out, err := gitCmd(dir, "rev-parse", "HEAD")
	if err != nil {
		return "", err
	}
	return out, nil
}

func gitBranchName(dir string) string {
	out, err := gitCmd(dir, "branch", "--show-current")
	if err != nil {
		return ""
	}
	return out
}
