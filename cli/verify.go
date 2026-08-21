// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
	"github.com/EslaM-X/proofx/verifycore"
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

func checkBinding(p *model.Proof) Check {
	if err := proof.VerifyBinding(p); err != nil {
		return Check{Name: "binding", Status: verifycore.StatusFail, Detail: err.Error()}
	}
	return Check{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"}
}

func statusOf(err error) string {
	if err == nil {
		return verifycore.StatusOK
	}
	return verifycore.StatusFail
}

func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12]
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// checkArtifactDigest matches a file's sha256 against the artifact evidence
// node. Used by the v0.3 legacy artifact verification path.
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
		return Check{Name: "artifact", Status: verifycore.StatusSkipped, Detail: "proof has no artifact evidence node"}
	}
	base := filepath.Base(artifactFile)
	var env struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal([]byte(art.Payload), &env); err == nil && len(env.Files) > 0 {
		if want, ok := env.Files[base]; ok {
			if want == fileDigest {
				return Check{Name: "artifact", Status: verifycore.StatusOK, Detail: base + " sha256 matches"}
			}
			return Check{Name: "artifact", Status: verifycore.StatusFail, Detail: fmt.Sprintf("%s expected %s got %s", base, shortDigest(want), shortDigest(fileDigest))}
		}
		return Check{Name: "artifact", Status: verifycore.StatusFail, Detail: fmt.Sprintf("%s not declared in proof artifact digests", base)}
	}
	if art.Digest == fileDigest {
		return Check{Name: "artifact", Status: verifycore.StatusOK, Detail: base + " sha256 matches artifact node"}
	}
	return Check{Name: "artifact", Status: verifycore.StatusFail, Detail: fmt.Sprintf("expected %s got %s", shortDigest(art.Digest), shortDigest(fileDigest))}
}

// printVerify renders the human-readable verification report.
func printVerify(w interface{ Write([]byte) (int, error) }, res VerifyResult) {
	fmt.Fprintf(w, "ProofX Verification — %s\n", res.ProofID)
	fmt.Fprintln(w, strings.Repeat("─", 48))
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
	fmt.Fprintln(w, strings.Repeat("─", 48))
	if res.Verified {
		fmt.Fprintf(w, "✓ VERIFIED — %d/%d evidence nodes match current repo\n", res.Coverage.Verified, res.Coverage.Total)
	} else {
		fmt.Fprintf(w, "✗ NOT VERIFIED — %d/%d evidence nodes match current repo\n", res.Coverage.Verified, res.Coverage.Total)
	}
	fmt.Fprintf(w, "Verification coverage: %d/100\n", res.Coverage.Score)
}
