package proof_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/EslaM-X/proofx/config"
	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

func gitCmd(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

func TestGenerateDemoProof(t *testing.T) {
	if os.Getenv("GENERATE_DEMO") != "1" {
		t.Skip("set GENERATE_DEMO=1 to generate demo proof")
	}

	dir, cfg, err := config.Find(".")
	if err != nil {
		t.Fatalf("find config: %v", err)
	}
	if cfg == nil {
		t.Fatal("no proofx.yaml found")
	}

	col := &evidence.Collectors{
		Git:       evidence.GitCollector(dir),
		Artifacts: evidence.ArtifactsCollector(dir, cfg.Artifacts),
		Depends:   evidence.LockfilesCollector(dir, cfg.Lockfiles),
		Tests:     evidence.TestsCollector(dir, ""),
		Env:       evidence.EnvCollector(dir),
	}
	results := evidence.Collect(col, time.Now())
	evs := make([]model.Evidence, 0)
	for _, r := range results {
		if r.Err == nil {
			evs = append(evs, r.Evidence)
		}
	}
	if len(evs) == 0 {
		t.Fatal("no evidence collected")
	}

	entries := proof.BindingEntries(evs)
	root := proof.Root(entries)

	_, priv, err := proof.GenerateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	claims := make([]model.Claim, 0, len(cfg.Claims))
	for i, c := range cfg.Claims {
		claims = append(claims, model.Claim{
			ID:     fmt.Sprintf("c%d", i+1),
			Text:   c,
			Status: "evidenced",
		})
	}

	commit := gitCmd(t, dir, "rev-parse", "HEAD")
	branch := gitCmd(t, dir, "branch", "--show-current")
	repo := gitCmd(t, dir, "remote", "get-url", "origin")

	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: cfg.Project, Repository: repo},
		Subject:      model.Subject{Commit: commit, Branch: branch, Repository: repo},
		Claims:       claims,
		Evidence:     evs,
		Binding:      model.Binding{Algorithm: proof.BindingAlgorithm, Root: root, Entries: entries},
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
		Builder:      model.Builder{Name: "proofx-demo", Version: "0.3.0"},
	}
	p.ID = "PX-" + root[:8]

	if err := proof.Sign(p, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}

	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	out := dir + "/proof.json"
	if err := os.WriteFile(out, b, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Logf("Proof created: %s", p.ID)
	t.Logf("Project: %s", cfg.Project)
	t.Logf("Commit: %s", commit)
	t.Logf("Claims: %d", len(claims))
	t.Logf("Evidence: %d nodes", len(evs))
	t.Logf("Binding root: %s", root[:16]+"...")
	t.Logf("Signature: %s", p.Signature.Algorithm)
	t.Logf("Written to: %s", out)
}
