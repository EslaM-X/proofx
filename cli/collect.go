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
	"github.com/EslaM-X/proofx/verifycore"
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

	now := nowUTC()

	// Recompute evidence digests using v0.4 format
	for i := range evs {
		evs[i].Digest = model.EvidenceDigest(evs[i].ID, evs[i].Payload)
	}

	// Build v0.4 claims
	v4Claims := v4ClaimsOf(cfg.Claims, evs)

	// Build execution
	exec := model.Execution{
		ID:          "exec-" + now,
		Type:        model.ExecCIWorkflow,
		StartedAt:   now,
		CompletedAt: now,
	}

	// Build relations: each evidence supports each claim
	var relations []model.Relation
	rid := 0
	for _, ev := range evs {
		for _, cl := range v4Claims {
			rid++
			relations = append(relations, model.Relation{
				ID:   fmt.Sprintf("r%d", rid),
				From: ev.ID,
				To:   cl.ID,
				Kind: model.RelSupports,
			})
		}
	}

	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           "", // set after binding
		Project: model.Project{
			Name:       cfg.Project,
			Repository: subject.Repository,
		},
		Subject:   subject,
		Execution: exec,
		Evidence:  evs,
		Relations: relations,
		Claims:    v4Claims,
		CreatedAt: now,
		Builder:   model.Builder{Name: model.BuilderName, Version: Version},
	}

	// Compute v0.4 binding
	entries := model.V4BindingEntries(p)
	root := model.V4Root(entries)
	p.Binding = model.Binding{Algorithm: verifycore.BindingAlgorithm, Root: root, Entries: entries}
	p.ID = "PX-" + shortID(root)

	// Sign with v0.4 commitment
	if err := proof.SignV4(p, priv); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}

	// Compute v0.4 coverage
	evTotal := len(evs)
	relTotal := len(relations)
	clTotal := len(v4Claims)
	p.Coverage = model.V4Coverage{
		Evidence:  model.CoverageDim{Total: evTotal, Verified: evTotal},
		Relations: model.CoverageDim{Total: relTotal, Verified: relTotal},
		Claims:    model.CoverageDim{Total: clTotal, Verified: clTotal},
		Score:     100,
	}

	out := filepath.Join(dir, "proof.json")
	b, err := proof.MarshalV4Proof(p)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		fmt.Fprintf(c.Stderr, "proofx: prove: %v\n", err)
		return 1
	}
	fmt.Fprintf(c.Stdout, "✓ proof %s written to %s\n", p.ID, out)
	fmt.Fprintf(c.Stdout, "  version       : %s\n", "2.0 (v0.4)")
	fmt.Fprintf(c.Stdout, "  binding root  : %s\n", p.Binding.Root)
	fmt.Fprintf(c.Stdout, "  signature     : %s\n", p.Signature.Algorithm)
	fmt.Fprintf(c.Stdout, "  public key    : %s\n", p.Signature.PublicKey)
	fmt.Fprintf(c.Stdout, "  evidence      : %d nodes\n", evTotal)
	fmt.Fprintf(c.Stdout, "  relations     : %d supports\n", relTotal)
	fmt.Fprintf(c.Stdout, "  claims        : %d\n", clTotal)
	return 0
}

func v4ClaimsOf(claims []string, evs []model.Evidence) []model.V4Claim {
	evIDs := make([]string, len(evs))
	for i, e := range evs {
		evIDs[i] = e.ID
	}
	out := make([]model.V4Claim, 0, len(claims))
	for i, txt := range claims {
		out = append(out, model.V4Claim{
			ID:          fmt.Sprintf("c%d", i+1),
			Type:        "assertion",
			Subject:     "proof:ci",
			Statement:   txt,
			Status:      "pass",
			SupportedBy: evIDs,
		})
	}
	return out
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
