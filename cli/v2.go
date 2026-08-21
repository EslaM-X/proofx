// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package cli implements the v0.4 CLI commands.
// These commands are thin wrappers over verifycore.V4Verify.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
	"github.com/EslaM-X/proofx/verifycore"
)

// loadV4Proof reads a proof file and determines if it's v0.3 or v0.4.
// Returns the v0.4 representation and whether it was converted from v0.3.
func loadV4Proof(path string) (*model.V4Proof, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}

	// Try v0.4 first
	p, err := verifycore.V4ParseProof(b)
	if err == nil {
		return p, false, nil
	}

	// Try v0.3 → v0.4 conversion
	p, err = model.V3ToV4(b)
	if err != nil {
		return nil, false, fmt.Errorf("proofx: %w", err)
	}
	return p, true, nil
}

// cmdVerifyV4 performs v0.4 verification.
func (c *CLI) cmdVerifyV4(args []string) int {
	artifactFile := ""
	proofFile := ""
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
		if proofFile == "" && len(rest) > 0 {
			proofFile = rest[0]
		}
		if proofFile == "" {
			proofFile = "proof.json"
		}
		return c.verifyArtifactV4(proofFile, artifactFile)
	}

	if len(rest) < 1 {
		fmt.Fprintf(c.Stderr, "proofx: verify: usage: proofx verify <proof.json>\n")
		return 2
	}
	proofFile = rest[0]

	p, wasV3, err := loadV4Proof(proofFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}

	if wasV3 {
		fmt.Fprintf(c.Stderr, "note: v0.3 proof detected, verifying with v0.4 rules\n")
	}

	res := verifycore.V4Verify(p)
	printV4Verify(c.Stdout, res)

	if res.Valid {
		return 0
	}
	return 1
}

func printV4Verify(w interface{ Write([]byte) (int, error) }, res verifycore.V4VerifyResult) {
	fmt.Fprintf(w, "ProofX Verification — %s\n", res.ProofID)
	fmt.Fprintln(w, "────────────────────────────────────────────────")

	for _, ch := range res.Checks {
		mark := "  "
		switch ch.Status {
		case verifycore.StatusOK:
			mark = "✓ "
		case verifycore.StatusFail:
			mark = "✗ "
		case verifycore.StatusSkipped:
			mark = "· "
		}
		detail := ""
		if ch.Detail != "" {
			detail = "  (" + ch.Detail + ")"
		}
		fmt.Fprintf(w, "%s %s%s\n", mark, ch.Name, detail)
	}

	fmt.Fprintln(w, "────────────────────────────────────────────────")

	// Claims
	if len(res.Claims) > 0 {
		verified := 0
		for _, cr := range res.Claims {
			if cr.Valid {
				verified++
			}
		}
		fmt.Fprintf(w, "Claims: %d/%d verified\n", verified, len(res.Claims))
	}

	// Coverage
	fmt.Fprintf(w, "Evidence: %d/%d\n", res.Coverage.Evidence.Verified, res.Coverage.Evidence.Total)
	fmt.Fprintf(w, "Relations: %d/%d\n", res.Coverage.Relations.Verified, res.Coverage.Relations.Total)
	fmt.Fprintf(w, "Score: %d\n", res.Coverage.Score)

	if res.Valid {
		fmt.Fprintf(w, "\n✓ PROOF VERIFIED\n")
	} else {
		fmt.Fprintf(w, "\n✗ PROOF NOT VERIFIED\n")
	}
}

// verifyArtifactV4 implements portable artifact-only verification for v0.4 proofs.
func (c *CLI) verifyArtifactV4(proofFile, artifactFile string) int {
	b, err := os.ReadFile(proofFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}

	// Try v0.3 first — artifact mode on v0.3 uses the original pipeline
	if isV3Proof(b) {
		p, err := proof.ParseProof(b)
		if err != nil {
			fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
			return 1
		}
		return c.verifyArtifactLegacy(p, artifactFile)
	}

	// v0.4 path
	p, _, err := loadV4Proof(proofFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}

	res := verifycore.V4Verify(p)

	// Add artifact digest check
	fileDigest, err := evidence.HashFile(artifactFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}

	artifactCheck := verifycore.Check{Name: "artifact", Status: verifycore.StatusOK, Detail: "digest match"}
	// Find artifact evidence node
	found := false
	for _, e := range p.Evidence {
		if e.ID == "artifact" || e.Type == "artifact" {
			found = true
			// Check the files map in payload
			var env struct {
				Files map[string]string `json:"files"`
			}
			if err := json.Unmarshal([]byte(e.Payload), &env); err == nil && len(env.Files) > 0 {
				base := filepath.Base(artifactFile)
				if want, ok := env.Files[base]; ok {
					if want != fileDigest {
						artifactCheck = verifycore.Check{Name: "artifact", Status: verifycore.StatusFail, Detail: fmt.Sprintf("expected %s got %s", shortDigest(want), shortDigest(fileDigest))}
					}
				}
			} else {
				if e.Digest != fileDigest {
					artifactCheck = verifycore.Check{Name: "artifact", Status: verifycore.StatusFail, Detail: fmt.Sprintf("expected %s got %s", shortDigest(e.Digest), shortDigest(fileDigest))}
				}
			}
			break
		}
	}
	if !found {
		artifactCheck = verifycore.Check{Name: "artifact", Status: verifycore.StatusSkipped, Detail: "no artifact evidence in proof"}
	}

	res.Checks = append(res.Checks, artifactCheck)
	res.Valid = res.Valid && artifactCheck.Status == verifycore.StatusOK

	printV4Verify(c.Stdout, res)
	if res.Valid {
		fmt.Fprintf(c.Stdout, "\n✓ artifact %s matches proof %s\n", artifactFile, p.ID)
		return 0
	}
	return 1
}

func isV3Proof(b []byte) bool {
	var v struct {
		ProofVersion string `json:"proofVersion"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return false
	}
	return v.ProofVersion == model.ProofVersion
}

func (c *CLI) verifyArtifactLegacy(p *model.Proof, artifactFile string) int {
	res := VerifyResult{ProofID: p.ID, Checks: []Check{}}

	bindOK := checkBinding(p)
	res.Checks = append(res.Checks, bindOK)
	sigOK := Check{Name: "signature", Status: statusOf(proof.VerifySignature(p)), Detail: "ed25519 over binding root"}
	res.Checks = append(res.Checks, sigOK)

	fileDigest, err := evidence.HashFile(artifactFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: verify: %v\n", err)
		return 1
	}
	artifactCheck := c.checkArtifactDigest(p, artifactFile, fileDigest)
	res.Checks = append(res.Checks, artifactCheck)
	if artifactCheck.Status == verifycore.StatusOK {
		res.Checks = append(res.Checks, Check{Name: "binding", Status: verifycore.StatusOK, Detail: "evidence binding valid"})
	}

	verified := bindOK.Status == verifycore.StatusOK && sigOK.Status == verifycore.StatusOK && artifactCheck.Status == verifycore.StatusOK
	res.Verified = verified
	res.Coverage = model.Coverage{Total: 1, Verified: boolInt(verified), Score: boolInt(verified) * 100}

	printVerify(c.Stdout, res)
	if verified {
		fmt.Fprintf(c.Stdout, "✓ artifact %s matches proof %s\n", artifactFile, p.ID)
		return 0
	}
	return 1
}

// cmdClaimsV4 displays claim verification results.
func (c *CLI) cmdClaimsV4(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(c.Stderr, "proofx: claims: usage: proofx claims <proof.json>\n")
		return 2
	}

	p, _, err := loadV4Proof(args[0])
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: claims: %v\n", err)
		return 1
	}

	res := verifycore.V4Verify(p)

	fmt.Fprintf(c.Stdout, "CLAIMS - %s\n\n", res.ProofID)

	if len(res.Claims) == 0 {
		fmt.Fprintln(c.Stdout, "No claims in this proof.")
		return 0
	}

	verified := 0
	for _, cr := range res.Claims {
		mark := "PASS"
		if !cr.Valid {
			mark = "FAIL"
		}
		fmt.Fprintf(c.Stdout, "%s %s\n", mark, cr.ID)
		if cr.Detail != "" {
			fmt.Fprintf(c.Stdout, "  %s\n", cr.Detail)
		}
		if len(cr.SupportedBy) > 0 {
			fmt.Fprintf(c.Stdout, "  Supported by: %s\n", joinStrs(cr.SupportedBy))
		}
		fmt.Fprintln(c.Stdout)
		if cr.Valid {
			verified++
		}
	}

	fmt.Fprintf(c.Stdout, "Claims: %d/%d verified\n", verified, len(res.Claims))
	return 0
}

func joinStrs(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	r := ss[0]
	for _, s := range ss[1:] {
		r += ", " + s
	}
	return r
}

// cmdExplainV4 explains why a proof passes or fails.
func (c *CLI) cmdExplainV4(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(c.Stderr, "proofx: explain: usage: proofx explain <proof.json>\n")
		return 2
	}

	p, _, err := loadV4Proof(args[0])
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: explain: %v\n", err)
		return 1
	}

	res := verifycore.V4Verify(p)

	fmt.Fprintf(c.Stdout, "PROOFX EXPLAIN — %s\n\n", res.ProofID)

	if res.Valid {
		c.explainValid(p, res)
	} else {
		c.explainInvalid(p, res)
	}
	return 0
}

func (c *CLI) explainValid(p *model.V4Proof, res verifycore.V4VerifyResult) {
	fmt.Fprintln(c.Stdout, "Why is this proof valid?")

	step := 1
	fmt.Fprintf(c.Stdout, "\n%d. Execution %s (%s) ran from %s to %s.\n", step, p.Execution.ID, p.Execution.Type, p.Execution.StartedAt, p.Execution.CompletedAt)
	step++

	fmt.Fprintf(c.Stdout, "%d. The execution produced %d evidence nodes: %s.\n", step, len(p.Evidence), evidenceIDs(p.Evidence))
	step++

	fmt.Fprintf(c.Stdout, "%d. Git evidence is bound to commit %s on branch %s.\n", step, shortHash(p.Subject.Commit), p.Subject.Branch)
	step++

	fmt.Fprintf(c.Stdout, "%d. %d claims are supported by the collected evidence.\n", step, len(p.Claims))
	step++

	fmt.Fprintf(c.Stdout, "%d. All evidence, relations, and claims are bound in a Merkle root.\n", step)
	step++

	fmt.Fprintf(c.Stdout, "%d. The Merkle root is signed with Ed25519.\n", step)

	fmt.Fprintln(c.Stdout, "\nConclusion:")
	fmt.Fprintln(c.Stdout, "The supplied claims are cryptographically bound to the supplied evidence.")
	fmt.Fprintln(c.Stdout, "The proof establishes that these claims were made about this execution")
	fmt.Fprintln(c.Stdout, "and are supported by the referenced evidence.")
	fmt.Fprintln(c.Stdout, "")
	fmt.Fprintln(c.Stdout, "ProofX does not independently establish that the claims are")
	fmt.Fprintln(c.Stdout, "semantically true beyond the captured evidence. It proves")
	fmt.Fprintln(c.Stdout, "integrity, binding, and declared semantics - not absolute truth.")
}

func (c *CLI) explainInvalid(p *model.V4Proof, res verifycore.V4VerifyResult) {
	fmt.Fprintln(c.Stdout, "")
	fmt.Fprintln(c.Stdout, "Why did this proof fail?")
	fmt.Fprintln(c.Stdout, "")

	for _, ch := range res.Checks {
		if ch.Status == verifycore.StatusFail {
			fmt.Fprintf(c.Stdout, "  %s: %s\n\n", ch.Name, ch.Detail)
		}
	}

	// Separate cryptographic vs semantic failures
	cryptoFailed := false
	semanticFailed := false
	for _, ch := range res.Checks {
		if ch.Status == verifycore.StatusFail {
			switch ch.Name {
			case "binding", "signature", "commitment":
				cryptoFailed = true
			default:
				semanticFailed = true
			}
		}
	}

	if cryptoFailed {
		fmt.Fprintln(c.Stdout, "Cryptographic integrity: FAILED")
		fmt.Fprintln(c.Stdout, "The proof may have been tampered with.")
	}
	if semanticFailed {
		fmt.Fprintln(c.Stdout, "Semantic verification: FAILED")
		fmt.Fprintln(c.Stdout, "The proof is cryptographically valid but claims are not supported.")
	}

	fmt.Fprintln(c.Stdout, "\nConclusion:")
	fmt.Fprintln(c.Stdout, "This proof does not establish the claimed relationship between")
	fmt.Fprintln(c.Stdout, "evidence and claims.")
}

func evidenceIDs(evs []model.Evidence) string {
	ids := ""
	for i, e := range evs {
		if i > 0 {
			ids += ", "
		}
		ids += e.ID
	}
	return ids
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// cmdInspectGraph displays the evidence graph visually.
func (c *CLI) cmdInspectGraph(args []string) int {
	jsonOutput := false
	proofPath := ""
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json":
			jsonOutput = true
		default:
			proofPath = args[i]
		}
	}

	if proofPath == "" {
		fmt.Fprintf(c.Stderr, "proofx: inspect: usage: proofx inspect <proof.json> [--json]\n")
		return 2
	}

	p, _, err := loadV4Proof(proofPath)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: inspect: %v\n", err)
		return 1
	}

	if jsonOutput {
		if err := c.printGraphJSON(p); err != nil {
			fmt.Fprintf(c.Stderr, "proofx: inspect: %v\n", err)
			return 1
		}
		return 0
	}
	return c.printGraphVisual(p)
}

func (c *CLI) printGraphJSON(p *model.V4Proof) error {
	graph := map[string]interface{}{
		"execution": p.Execution,
		"evidence":  p.Evidence,
		"relations": p.Relations,
		"claims":    p.Claims,
		"binding":   p.Binding,
		"signature": p.Signature,
		"coverage":  p.Coverage,
	}
	b, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Stdout, string(b))
	return nil
}

func (c *CLI) printGraphVisual(p *model.V4Proof) int {
	fmt.Fprintf(c.Stdout, "execution:%s (%s)\n", p.Execution.ID, p.Execution.Type)
	fmt.Fprintln(c.Stdout, "|")

	// Evidence nodes
	for i, e := range p.Evidence {
		connector := "+--"
		if i == len(p.Evidence)-1 && len(p.Claims) == 0 {
			connector = "`--"
		}
		fmt.Fprintf(c.Stdout, "%s %s\n", connector, e.ID)
	}

	// Claims
	if len(p.Claims) > 0 {
		fmt.Fprintln(c.Stdout, "|")
		fmt.Fprintln(c.Stdout, "`-- Claims")
		for i, cl := range p.Claims {
			connector := "    +--"
			if i == len(p.Claims)-1 {
				connector = "    `--"
			}
			mark := "ok"
			// Quick validity check
			supported := false
			for _, r := range p.Relations {
				if r.Kind == model.RelSupports && r.To == cl.ID {
					supported = true
					break
				}
			}
			if !supported {
				mark = "MISSING"
			}
			fmt.Fprintf(c.Stdout, "%s [%s] %s\n", connector, mark, cl.ID)
		}
	}

	return 0
}
