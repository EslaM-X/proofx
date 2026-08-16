package cli

import (
	"crypto/ed25519"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

// writeYAML serializes v to path as indented YAML.
func writeYAML(path string, v any) error {
	b, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// x509Marshal encodes a private key to PKCS#8 bytes (works for ed25519).
func x509Marshal(priv ed25519.PrivateKey) ([]byte, error) {
	return x509.MarshalPKCS8PrivateKey(priv)
}

// evidenceGitRemote shells out to git to read the origin remote name.
func evidenceGitRemote(dir string) (string, error) {
	url, err := gitCmd(dir, "remote", "get-url", "origin")
	if err != nil {
		return "", err
	}
	// github.com/owner/repo(.git) -> owner/repo
	url = strings.TrimSuffix(url, ".git")
	if i := strings.Index(url, "github.com/"); i >= 0 {
		url = url[i+len("github.com/"):]
	}
	return url, nil
}

// gitCmd runs git with the given args and returns trimmed stdout.
func gitCmd(dir string, args ...string) (string, error) {
	cmdArgs := append([]string{"-C", dir}, args...)
	out, err := exec.Command("git", cmdArgs...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// mustGitDir ensures dir is inside a git working tree.
func mustGitDir(dir string) error {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "--is-inside-work-tree").Output()
	if err != nil {
		return fmt.Errorf("not a git repository: %w", err)
	}
	if strings.TrimSpace(string(out)) != "true" {
		return fmt.Errorf("not a git working tree")
	}
	return nil
}
