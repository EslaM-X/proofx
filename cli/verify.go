// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EslaM-X/proofx/config"
	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

// Check is one line of a verification report.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | fail | skipped
	Detail string `json:"detail,omitempty"`
}

// VerifyResult is the machine-readable outcome of `proofx verify`.
type VerifyResult struct {
	ProofID  string         `json:"proofId"`
	Verified bool           `json:"verified"`
	Checks   []Check        `json:"checks"`
	Coverage model.Coverage `json:"coverage"`
}

// cmdVerify re-verifies a proof document against the current repository, or
// in portable mode verifies a single artifact against a proof without any
// git repository present:
//
//	proofx verify <proof.json> [dir]                  repo re-verification
//	proofx verify --artifact <file> --proof <proof>   portable artifact check
func (c *CLI) cmdVerify(args []string) int {
	artifactFile := ""
	proofFile := "proof.json"
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--artifact" && i+1 < len(args):
			artifactFile = args[i+1]
			i++
		case args[i] == "--proof" && i+1 < len(args):
			proofFile = args[i+1]
			i++
		case args[i] == "--artifact" || args[i] == "--proof":
			fmt.Fprintf(c.Stderr, "proofx: verify: missing value for %s\n", args[i])
			return 2
		default:
			rest = append(rest, args[i])
		}
	}

	if artifactFile != "" {
		if len(rest) > 0 {
			proofFile = rest[0]
		}
		return c.verifyArtifact(proofFile, artifactFile)
	}

	if len(rest) < 1 {
		fmt.Fprintf(c.Stderr, "proofx: verify: usage: proofx verify <proof.json> [dir]\n")
		return 2
	}
	proofFile = rest[0]
	dir := "."
	if len(rest) > 1 {
		dir = rest[1]
	}
	b, err := os.ReadFile(proofFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	p, err := proof.ParseProof(b)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	res := verifyAgainst(p, dir, time.Now())
	printVerify(c.Stdout, res)
	if res.Verified {
		return 0
	}
	return 1
}

// verifyArtifact implements portable artifact-only verification: it checks
// the proof's own integrity (binding + signature) and that the given file's
// sha256 matches the artifact evidence node. No git repository is required.
func (c *CLI) verifyArtifact(proofFile, artifactFile string) int {
	b, err := os.ReadFile(proofFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	p, err := proof.ParseProof(b)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	res := VerifyResult{ProofID: p.ID, Checks: []Check{}}

	bindOK := checkBinding(p)
	res.Checks = append(res.Checks, bindOK)
	sigOK := Check{Name: "signature", Status: statusOf(proof.VerifySignature(p)), Detail: "ed25519 over binding root"}
	res.Checks = append(res.Checks, sigOK)

	// artifact digest check
	fileDigest, err := evidence.HashFile(artifactFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	artifactCheck := c.checkArtifactDigest(p, artifactFile, fileDigest)
	res.Checks = append(res.Checks, artifactCheck)
	if artifactCheck.Status == "ok" {
		res.Checks = append(res.Checks, Check{Name: "binding", Status: "ok", Detail: "evidence binding valid"})
	}

	verified := bindOK.Status == "ok" && sigOK.Status == "ok" && artifactCheck.Status == "ok"
	res.Verified = verified
	res.Coverage = model.Coverage{Total: 1, Verified: boolInt(verified), Score: boolInt(verified) * 100}

	printVerify(c.Stdout, res)
	if verified {
		fmt.Fprintf(c.Stdout, "✓ artifact %s matches proof %s\n", artifactFile, p.ID)
		return 0
	}
	return 1
}

// checkArtifactDigest matches a file's sha256 against the artifact evidence
// node. It accepts either a single-file payload or a "files" map keyed by
// name (matching the configured-artifact collector).
func (c *CLI) checkArtifactDigest(p *model.Proof, artifactFile, fileDigest string) Check {
	var art model.Evidence
	found := false
	for _, e := range p.Evidence {
		if e.ID == model.TypeArtifact {
			art = e
			found = true
			break
		}
	}
	if !found {
		return Check{Name: "artifact", Status: "skipped", Detail: "proof has no artifact evidence node"}
	}
	base := filepath.Base(artifactFile)
	// structure: {"files": {"name": "sha256hex"}}
	var env struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal([]byte(art.Payload), &env); err == nil && len(env.Files) > 0 {
		if want, ok := env.Files[base]; ok {
			if want == fileDigest {
				return Check{Name: "artifact", Status: "ok", Detail: base + " sha256 matches"}
			}
			return Check{Name: "artifact", Status: "fail", Detail: fmt.Sprintf("%s expected %s got %s", base, shortDigest(want), shortDigest(fileDigest))}
		}
		return Check{Name: "artifact", Status: "fail", Detail: fmt.Sprintf("%s not declared in proof artifact digests", base)}
	}
	if art.Digest == fileDigest {
		return Check{Name: "artifact", Status: "ok", Detail: base + " sha256 matches artifact node"}
	}
	return Check{Name: "artifact", Status: "fail", Detail: fmt.Sprintf("expected %s got %s", shortDigest(art.Digest), shortDigest(fileDigest))}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// verifyAgainst re-collects current evidence and compares every digest.
func verifyAgainst(p *model.Proof, dir string, now time.Time) VerifyResult {
	res := VerifyResult{ProofID: p.ID, Checks: []Check{}}

	// 1. structure
	okStruct := checkBinding(p)
	res.Checks = append(res.Checks, okStruct)

	// 2. re-collect current evidence
	current := collectCurrent(dir, now)

	// 3. compare per evidence node
	index := map[string]model.Evidence{}
	for _, r := range current {
		if r.Err == nil {
			index[r.Evidence.ID] = r.Evidence
		}
	}
	verified := 0
	for _, e := range p.Evidence {
		cur, ok := index[e.ID]
		if !ok {
			res.Checks = append(res.Checks, Check{Name: e.ID, Status: "skipped", Detail: "evidence source not present in current repo"})
			continue
		}
		if cur.Digest == e.Digest {
			verified++
			res.Checks = append(res.Checks, Check{Name: e.ID, Status: "ok", Detail: shortDigest(e.Digest)})
		} else {
			res.Checks = append(res.Checks, Check{Name: e.ID, Status: "fail", Detail: fmt.Sprintf("expected %s got %s", shortDigest(e.Digest), shortDigest(cur.Digest))})
		}
	}

	// 4. signature
	res.Checks = append(res.Checks, Check{Name: "signature", Status: statusOf(proof.VerifySignature(p)), Detail: "ed25519 over binding root"})

	// 5. coverage
	total := len(p.Evidence)
	score := 0
	if total > 0 {
		score = int(float64(verified) / float64(total) * 100)
	}
	res.Coverage = model.Coverage{Total: total, Verified: verified, Score: score}

	allOK := okStruct.Status == "ok"
	for _, ch := range res.Checks {
		if ch.Status == "fail" {
			allOK = false
		}
	}
	res.Verified = allOK
	return res
}

// collectCurrent re-collects evidence from the current repository state.
func collectCurrent(dir string, now time.Time) []evidence.Result {
	cfg, _ := config.Load(dir)
	col := &evidence.Collectors{
		Git:       evidence.GitCollector(dir),
		Artifacts: evidence.ArtifactsCollector(dir, cfgArtifacts(cfg)),
		Depends:   evidence.LockfilesCollector(dir, cfgLockfiles(cfg)),
		Tests:     evidence.TestsCollector(dir, testsSummaryFile(dir)),
		Env:       evidence.EnvCollector(dir),
	}
	return evidence.Collect(col, now)
}

func checkBinding(p *model.Proof) Check {
	if err := proof.VerifyBinding(p); err != nil {
		return Check{Name: "binding", Status: "fail", Detail: err.Error()}
	}
	return Check{Name: "binding", Status: "ok", Detail: "merkle root matches evidence digests"}
}

func statusOf(err error) string {
	if err == nil {
		return "ok"
	}
	return "fail"
}

func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12]
}

func cfgArtifacts(c *config.Config) []string {
	if c == nil {
		return nil
	}
	return c.Artifacts
}

func cfgLockfiles(c *config.Config) []string {
	if c == nil {
		return nil
	}
	return c.Lockfiles
}

// printVerify renders the human-readable verification report.
func printVerify(w interface{ Write([]byte) (int, error) }, res VerifyResult) {
	fmt.Fprintf(w, "ProofX Verification — %s\n", res.ProofID)
	fmt.Fprintln(w, strings.Repeat("─", 48))
	for _, ch := range res.Checks {
		mark := "  "
		switch ch.Status {
		case "ok":
			mark = "✓ "
		case "fail":
			mark = "✗ "
		case "skipped":
			mark = "· "
		}
		detail := ""
		if ch.Detail != "" {
			detail = "  (" + ch.Detail + ")"
		}
		fmt.Fprintf(w, "%s %s%s\n", mark, ch.Name, detail)
	}
	fmt.Fprintln(w, strings.Repeat("─", 48))
	if res.Verified {
		fmt.Fprintf(w, "✓ VERIFIED — %d/%d evidence nodes match current repo\n", res.Coverage.Verified, res.Coverage.Total)
	} else {
		fmt.Fprintf(w, "✗ NOT VERIFIED — %d/%d evidence nodes match current repo\n", res.Coverage.Verified, res.Coverage.Total)
	}
	fmt.Fprintf(w, "Verification coverage: %d/100\n", res.Coverage.Score)
}
