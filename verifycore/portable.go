// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package verifycore

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/EslaM-X/proofx/model"
)

// VerifyArtifact performs portable artifact verification: proof integrity
// (binding + signature) plus matching a file digest against the artifact
// evidence node. No filesystem access — the caller provides the digest.
func VerifyArtifact(p *model.Proof, artifactName string, fileDigest string) VerifyResult {
	res := VerifyResult{ProofID: p.ID, Checks: make([]Check, 0, 4)}

	bindErr := VerifyBinding(p)
	res.Checks = append(res.Checks, Check{
		Name:   "binding",
		Status: statusOf(bindErr),
		Detail: detailOf(bindErr, "merkle root matches evidence digests"),
	})

	sigErr := VerifySignature(p)
	res.Checks = append(res.Checks, Check{
		Name:   "signature",
		Status: statusOf(sigErr),
		Detail: detailOf(sigErr, "ed25519 over full commitment"),
	})

	artifactCheck := CheckArtifactDigest(p, artifactName, fileDigest)
	res.Checks = append(res.Checks, artifactCheck)

	allOK := bindErr == nil && sigErr == nil && artifactCheck.Status == StatusOK
	if allOK {
		res.Checks = append(res.Checks, Check{
			Name:   "binding",
			Status: StatusOK,
			Detail: "evidence binding valid",
		})
	}

	res.Valid = allOK
	res.Coverage = model.Coverage{Total: 1, Verified: boolInt(allOK), Score: boolInt(allOK) * 100}
	return res
}

// CheckArtifactDigest matches a file's sha256 against the artifact evidence
// node. It accepts either a single-file payload or a "files" map keyed by
// name (matching the configured-artifact collector).
func CheckArtifactDigest(p *model.Proof, artifactFile, fileDigest string) Check {
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
		return Check{Name: "artifact", Status: StatusSkipped, Detail: "proof has no artifact evidence node"}
	}
	base := filepath.Base(artifactFile)
	var env struct {
		Files map[string]string `json:"files"`
	}
	if err := json.Unmarshal([]byte(art.Payload), &env); err == nil && len(env.Files) > 0 {
		if want, ok := env.Files[base]; ok {
			if want == fileDigest {
				return Check{Name: "artifact", Status: StatusOK, Detail: base + " sha256 matches"}
			}
			return Check{Name: "artifact", Status: StatusFail, Detail: fmt.Sprintf("%s expected %s got %s", base, shortDigest(want), shortDigest(fileDigest))}
		}
		return Check{Name: "artifact", Status: StatusFail, Detail: fmt.Sprintf("%s not declared in proof artifact digests", base)}
	}
	if art.Digest == fileDigest {
		return Check{Name: "artifact", Status: StatusOK, Detail: base + " sha256 matches artifact node"}
	}
	return Check{Name: "artifact", Status: StatusFail, Detail: fmt.Sprintf("expected %s got %s", shortDigest(art.Digest), shortDigest(fileDigest))}
}

func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12]
}
