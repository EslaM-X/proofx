package evidence

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// gitHead returns the full commit sha of HEAD.
func gitHead(dir string) (string, error) {
	out, err := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// gitBranch returns the current branch name (empty when detached).
func gitBranch(dir string) string {
	out, err := exec.Command("git", "-C", dir, "branch", "--show-current").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gitRemote returns the origin remote URL, if any.
func gitRemote(dir string) string {
	out, err := exec.Command("git", "-C", dir, "remote", "get-url", "origin").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// gitCommitTime returns the committer date of HEAD in RFC3339.
func gitCommitTime(dir string) string {
	out, err := exec.Command("git", "-C", dir, "log", "-1", "--format=%cI").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// GitCollector returns an evidence collector reading the local git state.
func GitCollector(dir string) func() (any, error) {
	return func() (any, error) {
		head, err := gitHead(dir)
		if err != nil {
			return nil, err
		}
		payload := map[string]any{
			"commit":      head,
			"branch":      gitBranch(dir),
			"repository":  gitRemote(dir),
			"commit_time": gitCommitTime(dir),
			"dirty":       isDirty(dir),
		}
		return payload, nil
	}
}

// isDirty reports whether the working tree has uncommitted changes.
func isDirty(dir string) bool {
	out, err := exec.Command("git", "-C", dir, "status", "--porcelain").Output()
	if err != nil {
		return true // unknown -> treat as dirty to be safe
	}
	return len(strings.TrimSpace(string(out))) > 0
}

// ArtifactsCollector hashes the configured artifact files.
func ArtifactsCollector(dir string, paths []string) func() (any, error) {
	return func() (any, error) {
		entries := map[string]string{}
		for _, p := range paths {
			full := filepath.Join(dir, p)
			sum, err := HashFile(full)
			if err != nil {
				// skip missing artifacts but keep going; verification of a
				// declared artifact that disappears must fail loudly, so we
				// record an empty digest and let the verifier flag it.
				entries[p] = ""
				continue
			}
			entries[p] = sum
		}
		if len(entries) == 0 {
			return nil, nil
		}
		return map[string]any{"files": entries}, nil
	}
}

// LockfilesCollector hashes dependency lockfiles and captures tool counts.
func LockfilesCollector(dir string, paths []string) func() (any, error) {
	return func() (any, error) {
		entries := map[string]string{}
		for _, p := range paths {
			full := filepath.Join(dir, p)
			sum, err := HashFile(full)
			if err != nil {
				entries[p] = ""
				continue
			}
			entries[p] = sum
		}
		if len(entries) == 0 {
			return nil, nil
		}
		return map[string]any{"lockfiles": entries}, nil
	}
}

// TestsCollector digests a test summary file (JSON: passed/failed/skipped).
func TestsCollector(dir, summaryFile string) func() (any, error) {
	return func() (any, error) {
		if summaryFile == "" {
			return nil, nil
		}
		full := filepath.Join(dir, summaryFile)
		b, err := os.ReadFile(full)
		if err != nil {
			return nil, err
		}
		payload := map[string]any{
			"file":    summaryFile,
			"digest":  HashBytes(b),
			"content": string(b),
		}
		return payload, nil
	}
}

// EnvCollector captures the toolchain and OS the proof was produced on.
func EnvCollector(dir string) func() (any, error) {
	return func() (any, error) {
		payload := map[string]any{
			"go_version":   execVersion("go", "version"),
			"node_version": execVersion("node", "--version"),
			"os":           osName(),
			"working_dir":  dir,
		}
		return payload, nil
	}
}

func execVersion(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func osName() string {
	if g, err := exec.Command("go", "env", "GOOS").Output(); err == nil {
		return strings.TrimSpace(string(g))
	}
	return "unknown"
}
