// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/EslaM-X/proofx/config"
	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

const outDir = ".proofx"

// evidencePath is where collect writes its evidence document.
func evidencePath(dir string) string {
	return filepath.Join(dir, outDir, "evidence.json")
}

// cmdCollect gathers evidence nodes into .proofx/evidence.json.
func (c *CLI) cmdCollect(args []string) int {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	cfg, err := config.Load(dir)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: collect: %v\n", err)
		return 1
	}
	if cfg == nil {
		fmt.Fprintf(c.Stderr, "proofx: collect: no proofx.yaml found (run `proofx init` first)\n")
		return 1
	}
	col := &evidence.Collectors{
		Git:       evidence.GitCollector(dir),
		Artifacts: evidence.ArtifactsCollector(dir, cfg.Artifacts),
		Depends:   evidence.LockfilesCollector(dir, cfg.Lockfiles),
		Tests:     evidence.TestsCollector(dir, testsSummaryFile(dir)),
		Env:       evidence.EnvCollector(dir),
	}
	results := evidence.Collect(col, time.Now())
	evs := make([]model.Evidence, 0, len(results))
	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(c.Stderr, "proofx: collect: warning: %v\n", r.Err)
			continue
		}
		evs = append(evs, r.Evidence)
		fmt.Fprintf(c.Stdout, "  ✓ %-12s %s\n", r.Evidence.ID, r.Evidence.Source)
	}
	if err := os.MkdirAll(filepath.Join(dir, outDir), 0o755); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: collect: %v\n", err)
		return 1
	}
	b, err := json.MarshalIndent(evs, "", "  ")
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: collect: %v\n", err)
		return 1
	}
	if err := os.WriteFile(evidencePath(dir), b, 0o644); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: collect: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.Stdout, "✓ collected %d evidence nodes -> %s\n", len(evs), evidencePath(dir))
	return 0
}

// testsSummaryFile returns a standard CI test-summary.json if present,
// otherwise "" (tests evidence will be skipped, not failed).
func testsSummaryFile(dir string) string {
	candidates := []string{
		filepath.Join(outDir, "test-summary.json"),
		"test-summary.json",
		"build/test-summary.json",
	}
	for _, p := range candidates {
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			return p
		}
	}
	return ""
}

// cmdProve binds + signs evidence into proof.json.
func (c *CLI) cmdProve(args []string) int {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	cfg, err := config.Load(dir)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}
	if cfg == nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: no proofx.yaml found (run `proofx init` first)\n")
		return 1
	}
	evB, err := os.ReadFile(evidencePath(dir))
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v (run `proofx collect` first)\n", err)
		return 1
	}
	var evs []model.Evidence
	if err := json.Unmarshal(evB, &evs); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}
	entries := proof.BindingEntries(evs)
	root := proof.Root(entries)

	priv, err := loadKey(dir, cfg)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v (run `proofx keygen` first)\n", err)
		return 1
	}
	subject, err := gitSubject(dir)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}

	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		Project: model.Project{
			Name:       cfg.Project,
			Repository: subject.Repository,
		},
		Subject:   subject,
		Claims:    claimsOf(cfg.Claims),
		Evidence:  evs,
		Binding:   model.Binding{Algorithm: proof.BindingAlgorithm, Root: root, Entries: entries},
		CreatedAt: nowUTC(),
		Builder:   model.Builder{Name: model.BuilderName, Version: Version},
	}
	p.ID = "PX-" + shortID(root)
	if err := proof.Sign(p, priv); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}
	p.Coverage = coverageOf(p)

	out := filepath.Join(dir, "proof.json")
	b, err := proof.MarshalProof(p)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.Stdout, "✓ proof %s written to %s\n", p.ID, out)
	fmt.Fprintf(c.Stdout, "  binding root  : %s\n", p.Binding.Root)
	fmt.Fprintf(c.Stdout, "  signature     : %s\n", p.Signature.Algorithm)
	fmt.Fprintf(c.Stdout, "  public key    : %s\n", p.Signature.PublicKey)
	return 0
}

func claimsOf(claims []string) []model.Claim {
	out := make([]model.Claim, 0, len(claims))
	for i, txt := range claims {
		out = append(out, model.Claim{ID: fmt.Sprintf("c%d", i+1), Text: txt, Status: "evidenced"})
	}
	return out
}

func coverageOf(p *model.Proof) model.Coverage {
	total := len(p.Evidence)
	verified := 0
	for _, e := range p.Evidence {
		if e.Digest != "" {
			verified++
		}
	}
	score := 0
	if total > 0 {
		score = int(float64(verified) / float64(total) * 100)
	}
	return model.Coverage{Total: total, Verified: verified, Score: score}
}

func shortID(root string) string {
	if len(root) < 8 {
		return root
	}
	return root[:8]
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
