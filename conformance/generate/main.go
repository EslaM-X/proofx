// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package main generates the conformance corpus and expected results.
//
// Run: go run ./conformance/generate
//
// Output:
//
//	conformance/corpus/valid/*.json       — valid proof documents
//	conformance/corpus/invalid/*.json     — structurally valid but semantically invalid
//	conformance/corpus/malformed/*.json   — not valid JSON or missing required fields
//	conformance/expected/*.json           — expected verifycore.Verify() results
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
	"github.com/EslaM-X/proofx/verifycore"
)

type Case struct {
	Name        string
	Description string
	Proof       *model.Proof
	Malformed   []byte // for malformed cases: raw bytes to write instead of JSON
	Expect      verifycore.VerifyResult
}

func main() {
	cases := buildCases()
	corpusDir := filepath.Join("conformance", "corpus")
	expectedDir := filepath.Join("conformance", "expected")

	for _, c := range cases {
		var dir string
		switch {
		case c.Malformed != nil && c.Proof == nil && (c.Name == "malformed-empty" || c.Name == "malformed-random-bytes" || c.Name == "malformed-partial-json"):
			dir = filepath.Join(corpusDir, "malformed")
		case c.Expect.Valid:
			dir = filepath.Join(corpusDir, "valid")
		default:
			dir = filepath.Join(corpusDir, "invalid")
		}
		os.MkdirAll(dir, 0o755)
		os.MkdirAll(expectedDir, 0o755)

		proofPath := filepath.Join(dir, c.Name+".json")
		expectedPath := filepath.Join(expectedDir, c.Name+".json")

		if c.Malformed != nil {
			if err := os.WriteFile(proofPath, c.Malformed, 0o644); err != nil {
				panic(err)
			}
		} else {
			b, err := json.MarshalIndent(c.Proof, "", "  ")
			if err != nil {
				panic(err)
			}
			if err := os.WriteFile(proofPath, b, 0o644); err != nil {
				panic(err)
			}
		}

		eb, err := json.MarshalIndent(c.Expect, "", "  ")
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(expectedPath, eb, 0o644); err != nil {
			panic(err)
		}
		fmt.Printf("  %s → %s\n", c.Name, proofPath)
	}
	fmt.Printf("Generated %d conformance cases\n", len(cases))
}

func buildCases() []Case {
	var cases []Case

	// --- Valid cases ---
	cases = append(cases, validMinimal())
	cases = append(cases, validMultiEvidence())
	cases = append(cases, validMaxClaims())
	cases = append(cases, validUnicodeProject())
	cases = append(cases, validEmptySubjectBranch())

	// --- Invalid cases (structurally valid JSON, semantically wrong) ---
	cases = append(cases, invalidTamperedRoot())
	cases = append(cases, invalidTamperedSignature())
	cases = append(cases, invalidWrongVersion())
	cases = append(cases, invalidMissingSignature())
	cases = append(cases, invalidWrongAlgorithm())
	cases = append(cases, invalidSwappedPublicKey())
	cases = append(cases, invalidModifiedClaimText())
	cases = append(cases, invalidModifiedClaimStatus())
	cases = append(cases, invalidModifiedProject())
	cases = append(cases, invalidModifiedSubject())

	// --- Malformed cases (not valid JSON or structurally broken) ---
	cases = append(cases, malformedEmptyJSON())
	cases = append(cases, malformedRandomBytes())
	cases = append(cases, malformedPartialJSON())

	return cases
}

func validMinimal() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "valid-minimal",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	return Case{
		Name:        "valid-minimal",
		Description: "minimal valid proof with one evidence node",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "valid-minimal",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

func validMultiEvidence() Case {
	ev := []model.Evidence{
		{ID: "git", Digest: "aabb1122"},
		{ID: "deps", Digest: "ccdd3344"},
		{ID: "tests", Digest: "eeff5566"},
	}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "valid-multi-evidence",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "multi", Repository: "https://example.com/multi"},
		Subject:      model.Subject{Commit: "def456", Branch: "develop", Repository: "https://example.com/multi"},
		Claims: []model.Claim{
			{ID: "build", Text: "Build passes", Status: "pass"},
			{ID: "tests", Text: "Tests pass", Status: "pass"},
		},
		Evidence: ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	return Case{
		Name:        "valid-multi-evidence",
		Description: "proof with three evidence nodes",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "valid-multi-evidence",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 3, Verified: 3, Score: 100},
		},
	}
}

func validMaxClaims() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	claims := make([]model.Claim, 5)
	for i := range claims {
		claims[i] = model.Claim{
			ID:     fmt.Sprintf("claim-%d", i),
			Text:   fmt.Sprintf("Claim %d text", i),
			Status: "pass",
		}
	}
	p := &model.Proof{
		ID:           "valid-max-claims",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "maxclaims", Repository: "https://example.com/maxclaims"},
		Subject:      model.Subject{Commit: "aaa111", Branch: "main", Repository: "https://example.com/maxclaims"},
		Claims:       claims,
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	return Case{
		Name:        "valid-max-claims",
		Description: "proof with five claims",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "valid-max-claims",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

func validUnicodeProject() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "valid-unicode-project",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "прое́кт", Repository: "https://example.com/unicode"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/unicode"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	return Case{
		Name:        "valid-unicode-project",
		Description: "proof with unicode project name",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "valid-unicode-project",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

func validEmptySubjectBranch() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "valid-empty-branch",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "nobranch", Repository: "https://example.com/nobranch"},
		Subject:      model.Subject{Commit: "abc123", Branch: "", Repository: "https://example.com/nobranch"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	return Case{
		Name:        "valid-empty-branch",
		Description: "proof with empty subject branch",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "valid-empty-branch",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

// --- Invalid cases ---

func invalidTamperedRoot() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-tampered-root",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Binding.Root = "deadbeef00000000"
	return Case{
		Name:        "invalid-tampered-root",
		Description: "binding root tampered after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-tampered-root",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusFail},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func invalidTamperedSignature() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-tampered-sig",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Signature.Value = "deadbeef"
	return Case{
		Name:        "invalid-tampered-sig",
		Description: "signature value corrupted",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-tampered-sig",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func invalidWrongVersion() Case {
	return Case{
		Name:        "invalid-wrong-version",
		Description: "unsupported proof version",
		Malformed:   []byte(`{"id":"x","proof_version":"99.0","project":{"name":"t","repository":"r"},"subject":{"commit":"a","branch":"b","repository":"r"},"claims":[],"evidence":[],"binding":{"algorithm":"sha256","root":"","entries":[]},"signature":{"algorithm":"ed25519","public_key":"","value":""}}`),
		Expect: verifycore.VerifyResult{
			ProofID:  "x",
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func invalidMissingSignature() Case {
	return Case{
		Name:        "invalid-missing-sig",
		Description: "proof without signature",
		Malformed:   []byte(`{"id":"no-sig","proof_version":"proofx.v1","project":{"name":"t","repository":"r"},"subject":{"commit":"a","branch":"b","repository":"r"},"claims":[],"evidence":[],"binding":{"algorithm":"sha256","root":"","entries":[]}}`),
		Expect: verifycore.VerifyResult{
			ProofID: "no-sig",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 0, Verified: 0, Score: 0},
		},
	}
}

func invalidWrongAlgorithm() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-wrong-algo",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Signature.Algorithm = "sha256"
	return Case{
		Name:        "invalid-wrong-algo",
		Description: "signature algorithm changed to sha256",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-wrong-algo",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func invalidSwappedPublicKey() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	otherPub, _, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-swapped-key",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Signature.PublicKey = proof.EncodePublicKey(otherPub)
	return Case{
		Name:        "invalid-swapped-key",
		Description: "public key swapped to different keypair",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-swapped-key",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func invalidModifiedClaimText() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-modified-claim-text",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Claims[0].Text = "Build FAILS"
	return Case{
		Name:        "invalid-modified-claim-text",
		Description: "claim text modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-modified-claim-text",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func invalidModifiedClaimStatus() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-modified-claim-status",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Claims[0].Status = "fail"
	return Case{
		Name:        "invalid-modified-claim-status",
		Description: "claim status modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-modified-claim-status",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func invalidModifiedProject() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-modified-project",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Project.Name = "evil"
	return Case{
		Name:        "invalid-modified-project",
		Description: "project name modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-modified-project",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func invalidModifiedSubject() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := proof.GenerateKey()
	p := &model.Proof{
		ID:           "invalid-modified-subject",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	proof.Sign(p, priv)
	p.Subject.Commit = "tampered"
	return Case{
		Name:        "invalid-modified-subject",
		Description: "subject commit modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "invalid-modified-subject",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

// --- Malformed cases ---

func malformedEmptyJSON() Case {
	return Case{
		Name:        "malformed-empty",
		Description: "empty JSON object",
		Malformed:   []byte(`{}`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func malformedRandomBytes() Case {
	return Case{
		Name:        "malformed-random-bytes",
		Description: "completely random bytes",
		Malformed:   []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04},
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func malformedPartialJSON() Case {
	return Case{
		Name:        "malformed-partial-json",
		Description: "truncated JSON",
		Malformed:   []byte(`{"id":"partial","proof_version":"proofx.v1","project":{"name":`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}
