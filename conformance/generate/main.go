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
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
	"github.com/EslaM-X/proofx/verifycore"
)

// deterministicReader produces a fixed byte stream so that key generation
// in the conformance generator is reproducible across runs and platforms.
type deterministicReader struct{ n byte }

func (d *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		d.n++
		p[i] = d.n
	}
	return len(p), nil
}

// sharedDeterministicSource is the single reader used by all generateDeterministicKey
// calls so that each call produces a different key.
var sharedDeterministicSource = &deterministicReader{n: 0}

// generateDeterministicKey produces a stable ed25519 keypair for conformance.
func generateDeterministicKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(sharedDeterministicSource)
}

// ============================================================================
// v0.3 cases
// ============================================================================

type Case struct {
	Name        string
	Description string
	Proof       *model.Proof
	Malformed   []byte
	Expect      verifycore.VerifyResult
}

func buildCasesV3() []Case {
	var cases []Case

	cases = append(cases, v3ValidMinimal())
	cases = append(cases, v3ValidMultiEvidence())
	cases = append(cases, v3ValidMaxClaims())
	cases = append(cases, v3ValidUnicodeProject())
	cases = append(cases, v3ValidEmptySubjectBranch())

	cases = append(cases, v3InvalidTamperedRoot())
	cases = append(cases, v3InvalidTamperedSignature())
	cases = append(cases, v3InvalidWrongVersion())
	cases = append(cases, v3InvalidMissingSignature())
	cases = append(cases, v3InvalidWrongAlgorithm())
	cases = append(cases, v3InvalidSwappedPublicKey())
	cases = append(cases, v3InvalidModifiedClaimText())
	cases = append(cases, v3InvalidModifiedClaimStatus())
	cases = append(cases, v3InvalidModifiedProject())
	cases = append(cases, v3InvalidModifiedSubject())

	return cases
}

// ============================================================================
// v0.4 cases
// ============================================================================

type CaseV4 struct {
	Name        string
	Description string
	Proof       *model.V4Proof
	Malformed   []byte
	Expect      verifycore.V4VerifyResult
}

func buildCasesV4() []CaseV4 {
	var cases []CaseV4

	cases = append(cases, v4ValidMinimal())
	cases = append(cases, v4ValidMultiEvidence())
	cases = append(cases, v4ValidWithRelations())
	cases = append(cases, v4ValidEmptyBranch())
	cases = append(cases, v4ValidUnicodeProject())
	cases = append(cases, v4ValidPendingClaims())
	cases = append(cases, v4ValidCustomExecType())
	cases = append(cases, v4ValidTenEvidence())
	cases = append(cases, v4ValidFiveClaims())
	cases = append(cases, v4ValidSpecialChars())
	cases = append(cases, v4ValidLongStrings())
	cases = append(cases, v4ValidAllRelationKinds())
	cases = append(cases, v4ValidEmptyEnvironment())
	cases = append(cases, v4ValidNotApplicableClaims())

	cases = append(cases, v4InvalidTamperedRoot())
	cases = append(cases, v4InvalidTamperedSignature())
	cases = append(cases, v4InvalidWrongVersion())
	cases = append(cases, v4InvalidMissingSignature())
	cases = append(cases, v4InvalidModifiedExecution())
	cases = append(cases, v4InvalidModifiedRelation())
	cases = append(cases, v4InvalidEvidenceDigestMismatch())
	cases = append(cases, v4InvalidEvidencePayloadTamper())
	cases = append(cases, v4InvalidRelationFromTamper())
	cases = append(cases, v4InvalidRelationToTamper())
	cases = append(cases, v4InvalidClaimSupportedByMissing())
	cases = append(cases, v4InvalidClaimStatusTamper())
	cases = append(cases, v4InvalidClaimTypeTamper())
	cases = append(cases, v4InvalidBindingAlgorithm())
	cases = append(cases, v4InvalidSignatureAlgorithm())
	cases = append(cases, v4InvalidProjectNameTamper())
	cases = append(cases, v4InvalidSubjectCommitTamper())
	cases = append(cases, v4InvalidSubjectBranchTamper())
	cases = append(cases, v4InvalidEmptyEvidenceArray())
	cases = append(cases, v4InvalidWrongBindingRoot())

	cases = append(cases, v4ExtraValidCases()...)
	cases = append(cases, v4ExtraInvalidCases()...)
	cases = append(cases, v4ExtraValidCases2()...)
	cases = append(cases, v4ExtraInvalidCases2()...)

	return cases
}

// ============================================================================
// WASM security edge cases (malformed bytes — same for both v0.3 and v0.4)
// ============================================================================

func buildCasesWasmSecurity() []Case {
	var cases []Case

	cases = append(cases, wasmEmptyJSON())
	cases = append(cases, wasmRandomBytes())
	cases = append(cases, wasmPartialJSON())
	cases = append(cases, wasmNullJSON())
	cases = append(cases, wasmArrayJSON())
	cases = append(cases, wasmDeeplyNestedJSON())
	cases = append(cases, wasmHugeArrayJSON())
	cases = append(cases, wasmDuplicateFieldsJSON())

	return cases
}

// ============================================================================
// main
// ============================================================================

func main() {
	corpusDir := filepath.Join("conformance", "corpus")
	expectedDir := filepath.Join("conformance", "expected")

	v3Cases := buildCasesV3()
	v4Cases := buildCasesV4()
	wasmCases := buildCasesWasmSecurity()
	total := len(v3Cases) + len(v4Cases) + len(wasmCases)

	// Write v0.3 cases
	for _, c := range v3Cases {
		var dir string
		switch {
		case c.Malformed != nil && c.Proof == nil:
			dir = filepath.Join(corpusDir, "malformed")
		case c.Expect.Valid:
			dir = filepath.Join(corpusDir, "valid")
		default:
			dir = filepath.Join(corpusDir, "invalid")
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		if err := os.MkdirAll(expectedDir, 0o755); err != nil {
			panic(err)
		}

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

	// Write v0.4 cases
	for _, c := range v4Cases {
		var dir string
		switch {
		case c.Malformed != nil && c.Proof == nil:
			dir = filepath.Join(corpusDir, "malformed")
		case c.Expect.Valid:
			dir = filepath.Join(corpusDir, "valid")
		default:
			dir = filepath.Join(corpusDir, "invalid")
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		if err := os.MkdirAll(expectedDir, 0o755); err != nil {
			panic(err)
		}

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

	// Write WASM security cases (malformed bytes)
	for _, c := range wasmCases {
		dir := filepath.Join(corpusDir, "malformed")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			panic(err)
		}
		if err := os.MkdirAll(expectedDir, 0o755); err != nil {
			panic(err)
		}

		proofPath := filepath.Join(dir, c.Name+".json")
		expectedPath := filepath.Join(expectedDir, c.Name+".json")

		if c.Malformed != nil {
			if err := os.WriteFile(proofPath, c.Malformed, 0o644); err != nil {
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

	fmt.Printf("Generated %d conformance cases (v0.3=%d, v0.4=%d, wasm-sec=%d)\n", total, len(v3Cases), len(v4Cases), len(wasmCases))
}

// ============================================================================
// v0.3 cases — helpers
// ============================================================================

func v3MakeProof(id string, ev []model.Evidence, claims []model.Claim, priv ed25519.PrivateKey) *model.Proof {
	p := &model.Proof{
		ID:           id,
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       claims,
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	if err := proof.Sign(p, priv); err != nil {
		panic(err)
	}
	return p
}

func v3ValidMinimal() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	return Case{
		Name:        "v3-valid-minimal",
		Description: "v0.3 minimal valid proof with one evidence node",
		Proof:       v3MakeProof("v3-valid-minimal", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv),
		Expect: verifycore.VerifyResult{
			ProofID: "v3-valid-minimal",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

func v3ValidMultiEvidence() Case {
	ev := []model.Evidence{
		{ID: "git", Digest: "aabb1122"},
		{ID: "deps", Digest: "ccdd3344"},
		{ID: "tests", Digest: "eeff5566"},
	}
	_, priv, _ := generateDeterministicKey()
	claims := []model.Claim{
		{ID: "build", Text: "Build passes", Status: "pass"},
		{ID: "tests", Text: "Tests pass", Status: "pass"},
	}
	return Case{
		Name:        "v3-valid-multi-evidence",
		Description: "v0.3 proof with three evidence nodes",
		Proof:       v3MakeProof("v3-valid-multi-evidence", ev, claims, priv),
		Expect: verifycore.VerifyResult{
			ProofID: "v3-valid-multi-evidence",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 3, Verified: 3, Score: 100},
		},
	}
}

func v3ValidMaxClaims() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	claims := make([]model.Claim, 5)
	for i := range claims {
		claims[i] = model.Claim{
			ID:     fmt.Sprintf("claim-%d", i),
			Text:   fmt.Sprintf("Claim %d text", i),
			Status: "pass",
		}
	}
	return Case{
		Name:        "v3-valid-max-claims",
		Description: "v0.3 proof with five claims",
		Proof:       v3MakeProof("v3-valid-max-claims", ev, claims, priv),
		Expect: verifycore.VerifyResult{
			ProofID: "v3-valid-max-claims",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

func v3ValidUnicodeProject() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := &model.Proof{
		ID:           "v3-valid-unicode-project",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "прое́кт", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	if err := proof.Sign(p, priv); err != nil {
		panic(err)
	}
	return Case{
		Name:        "v3-valid-unicode-project",
		Description: "v0.3 proof with unicode project name",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-valid-unicode-project",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

func v3ValidEmptySubjectBranch() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := &model.Proof{
		ID:           "v3-valid-empty-branch",
		ProofVersion: model.ProofVersion,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "", Repository: "https://example.com/test"},
		Claims:       []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}},
		Evidence:     ev,
		Binding: model.Binding{
			Algorithm: verifycore.BindingAlgorithm,
			Root:      proof.Root(proof.BindingEntries(ev)),
			Entries:   proof.BindingEntries(ev),
		},
	}
	if err := proof.Sign(p, priv); err != nil {
		panic(err)
	}
	return Case{
		Name:        "v3-valid-empty-branch",
		Description: "v0.3 proof with empty subject branch",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-valid-empty-branch",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusOK, Detail: "ed25519 over full commitment"},
			},
			Coverage: model.Coverage{Total: 1, Verified: 1, Score: 100},
		},
	}
}

func v3InvalidTamperedRoot() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-tampered-root", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Binding.Root = "deadbeef00000000"
	return Case{
		Name:        "v3-invalid-tampered-root",
		Description: "v0.3 binding root tampered after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-tampered-root",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusFail},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func v3InvalidTamperedSignature() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-tampered-sig", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Signature.Value = "deadbeef"
	return Case{
		Name:        "v3-invalid-tampered-sig",
		Description: "v0.3 signature value corrupted",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-tampered-sig",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func v3InvalidWrongVersion() Case {
	return Case{
		Name:        "v3-invalid-wrong-version",
		Description: "v0.3 unsupported proof version",
		Malformed:   []byte(`{"id":"x","proofVersion":"99.0","project":{"name":"t","repository":"r"},"subject":{"commit":"a","branch":"b","repository":"r"},"claims":[],"evidence":[],"binding":{"algorithm":"sha256","root":"","entries":[]},"signature":{"algorithm":"ed25519","publicKey":"","value":""}}`),
		Expect: verifycore.VerifyResult{
			ProofID:  "x",
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func v3InvalidMissingSignature() Case {
	return Case{
		Name:        "v3-invalid-missing-sig",
		Description: "v0.3 proof without signature",
		Malformed:   []byte(`{"id":"no-sig","proofVersion":"1.0","project":{"name":"t","repository":"r"},"subject":{"commit":"a","branch":"b","repository":"r"},"claims":[],"evidence":[],"binding":{"algorithm":"sha256","root":"","entries":[]}}`),
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

func v3InvalidWrongAlgorithm() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-wrong-algo", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Signature.Algorithm = "sha256"
	return Case{
		Name:        "v3-invalid-wrong-algo",
		Description: "v0.3 signature algorithm changed to sha256",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-wrong-algo",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func v3InvalidSwappedPublicKey() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	otherPub, _, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-swapped-key", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Signature.PublicKey = proof.EncodePublicKey(otherPub)
	return Case{
		Name:        "v3-invalid-swapped-key",
		Description: "v0.3 public key swapped to different keypair",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-swapped-key",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK, Detail: "merkle root matches evidence digests"},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func v3InvalidModifiedClaimText() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-modified-claim-text", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Claims[0].Text = "Build FAILS"
	return Case{
		Name:        "v3-invalid-modified-claim-text",
		Description: "v0.3 claim text modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-modified-claim-text",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func v3InvalidModifiedClaimStatus() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-modified-claim-status", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Claims[0].Status = "fail"
	return Case{
		Name:        "v3-invalid-modified-claim-status",
		Description: "v0.3 claim status modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-modified-claim-status",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func v3InvalidModifiedProject() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-modified-project", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Project.Name = "evil"
	return Case{
		Name:        "v3-invalid-modified-project",
		Description: "v0.3 project name modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-modified-project",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

func v3InvalidModifiedSubject() Case {
	ev := []model.Evidence{{ID: "git", Digest: "aabb1122"}}
	_, priv, _ := generateDeterministicKey()
	p := v3MakeProof("v3-invalid-modified-subject", ev, []model.Claim{{ID: "build", Text: "Build passes", Status: "pass"}}, priv)
	p.Subject.Commit = "tampered"
	return Case{
		Name:        "v3-invalid-modified-subject",
		Description: "v0.3 subject commit modified after signing",
		Proof:       p,
		Expect: verifycore.VerifyResult{
			ProofID: "v3-invalid-modified-subject",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.Coverage{Total: 1, Verified: 0, Score: 0},
		},
	}
}

// ============================================================================
// v0.4 cases
// ============================================================================

func v4MakeProof(id string, ev []model.Evidence, rels []model.Relation, claims []model.V4Claim, priv ed25519.PrivateKey) *model.V4Proof {
	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           id,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Execution:    model.Execution{ID: "exec-001", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z", Environment: model.Environment{OS: "ubuntu-24.04", Arch: "amd64", Runtime: "go1.26.5"}},
		Evidence:     ev,
		Relations:    rels,
		Claims:       claims,
		Coverage:     model.V4Coverage{Evidence: model.CoverageDim{Total: len(ev), Verified: len(ev)}, Relations: model.CoverageDim{Total: len(rels), Verified: len(rels)}, Claims: model.CoverageDim{Total: len(claims), Verified: len(claims)}, Score: 100},
		CreatedAt:    "2026-08-21T02:05:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.4.0"},
	}
	entries := model.V4BindingEntries(p)
	p.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	sigPayload := model.V4SigningPayload(p)
	sig, _ := proof.SignBytes(sigPayload, priv)
	pub := proof.PublicKeyOf(priv)
	p.Signature = model.Signature{Algorithm: "ed25519", PublicKey: proof.EncodePublicKey(pub), Value: sig}
	return p
}

func v4MakeProofWithProject(id, projectName string, ev []model.Evidence, rels []model.Relation, claims []model.V4Claim, priv ed25519.PrivateKey) *model.V4Proof {
	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           id,
		Project:      model.Project{Name: projectName, Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Execution:    model.Execution{ID: "exec-001", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z", Environment: model.Environment{OS: "ubuntu-24.04", Arch: "amd64", Runtime: "go1.26.5"}},
		Evidence:     ev,
		Relations:    rels,
		Claims:       claims,
		Coverage:     model.V4Coverage{Evidence: model.CoverageDim{Total: len(ev), Verified: len(ev)}, Relations: model.CoverageDim{Total: len(rels), Verified: len(rels)}, Claims: model.CoverageDim{Total: len(claims), Verified: len(claims)}, Score: 100},
		CreatedAt:    "2026-08-21T02:05:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.4.0"},
	}
	entries := model.V4BindingEntries(p)
	p.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	sigPayload := model.V4SigningPayload(p)
	sig, _ := proof.SignBytes(sigPayload, priv)
	pub := proof.PublicKeyOf(priv)
	p.Signature = model.Signature{Algorithm: "ed25519", PublicKey: proof.EncodePublicKey(pub), Value: sig}
	return p
}

func v4MakeProofWithType(id, execType string, ev []model.Evidence, rels []model.Relation, claims []model.V4Claim, priv ed25519.PrivateKey) *model.V4Proof {
	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           id,
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://example.com/test"},
		Execution:    model.Execution{ID: "exec-001", Type: execType, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z", Environment: model.Environment{OS: "ubuntu-24.04", Arch: "amd64", Runtime: "go1.26.5"}},
		Evidence:     ev,
		Relations:    rels,
		Claims:       claims,
		Coverage:     model.V4Coverage{Evidence: model.CoverageDim{Total: len(ev), Verified: len(ev)}, Relations: model.CoverageDim{Total: len(rels), Verified: len(rels)}, Claims: model.CoverageDim{Total: len(claims), Verified: len(claims)}, Score: 100},
		CreatedAt:    "2026-08-21T02:05:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.4.0"},
	}
	entries := model.V4BindingEntries(p)
	p.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	sigPayload := model.V4SigningPayload(p)
	sig, _ := proof.SignBytes(sigPayload, priv)
	pub := proof.PublicKeyOf(priv)
	p.Signature = model.Signature{Algorithm: "ed25519", PublicKey: proof.EncodePublicKey(pub), Value: sig}
	return p
}

func v4ValidMinimal() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "claim.build", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return CaseV4{
		Name:        "v4-valid-minimal",
		Description: "v0.4 minimal valid proof with execution, one evidence, one relation, one claim",
		Proof:       v4MakeProof("v4-valid-minimal", ev, rels, claims, priv),
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-valid-minimal",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusOK},
				{Name: "claims", Status: verifycore.StatusOK},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 1, Verified: 1},
				Relations: model.CoverageDim{Total: 2, Verified: 2},
				Claims:    model.CoverageDim{Total: 1, Verified: 1},
				Score:     100,
			},
			Claims: []verifycore.V4ClaimResult{
				{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			},
		},
	}
}

func v4ValidMultiEvidence() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
		{ID: "deps", Type: "deps", Source: "npm", Payload: `{"lockfile":"sha256:abcd"}`, Digest: ""},
		{ID: "tests", Type: "tests", Source: "jest", Payload: `{"passed":42,"failed":0}`, Digest: ""},
	}
	for i := range ev {
		ev[i].Digest = model.EvidenceDigest(ev[i].ID, ev[i].Payload)
	}
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "exec-001", To: "deps", Kind: model.RelProduces},
		{ID: "r3", From: "exec-001", To: "tests", Kind: model.RelProduces},
		{ID: "r4", From: "git", To: "claim.build", Kind: model.RelSupports},
		{ID: "r5", From: "deps", To: "claim.deps", Kind: model.RelSupports},
		{ID: "r6", From: "tests", To: "claim.tests", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "claim.deps", Type: "deps_locked", Subject: "execution:exec-001", Statement: "Dependencies locked", Status: model.ClaimPass, SupportedBy: []string{"deps"}},
		{ID: "claim.tests", Type: "tests_passed", Subject: "execution:exec-001", Statement: "All tests passed", Status: model.ClaimPass, SupportedBy: []string{"tests"}},
	}
	_, priv, _ := generateDeterministicKey()
	return CaseV4{
		Name:        "v4-valid-multi-evidence",
		Description: "v0.4 proof with three evidence nodes, three relations, three claims",
		Proof:       v4MakeProof("v4-valid-multi-evidence", ev, rels, claims, priv),
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-valid-multi-evidence",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusOK},
				{Name: "claims", Status: verifycore.StatusOK},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 3, Verified: 3},
				Relations: model.CoverageDim{Total: 6, Verified: 6},
				Claims:    model.CoverageDim{Total: 3, Verified: 3},
				Score:     100,
			},
			Claims: []verifycore.V4ClaimResult{
				{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
				{ID: "claim.deps", Type: "deps_locked", Statement: "Dependencies locked", Status: "pass", SupportedBy: []string{"deps"}, Valid: true},
				{ID: "claim.tests", Type: "tests_passed", Statement: "All tests passed", Status: "pass", SupportedBy: []string{"tests"}, Valid: true},
			},
		},
	}
}

func v4ValidWithRelations() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
		{ID: "tests", Type: "tests", Source: "jest", Payload: `{"passed":42,"failed":0}`, Digest: ""},
	}
	for i := range ev {
		ev[i].Digest = model.EvidenceDigest(ev[i].ID, ev[i].Payload)
	}
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "exec-001", To: "tests", Kind: model.RelProduces},
		{ID: "r3", From: "tests", To: "claim.tests_passed", Kind: model.RelSupports},
		{ID: "r4", From: "git", To: "claim.exec_bound", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.tests_passed", Type: "tests_passed", Subject: "execution:exec-001", Statement: "All tests passed", Status: model.ClaimPass, SupportedBy: []string{"tests"}},
		{ID: "claim.exec_bound", Type: "execution_bound", Subject: "execution:exec-001", Statement: "Bound to commit abc123", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	return CaseV4{
		Name:        "v4-valid-with-relations",
		Description: "v0.4 proof with supports relations between evidence and claims",
		Proof:       v4MakeProof("v4-valid-with-relations", ev, rels, claims, priv),
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-valid-with-relations",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusOK},
				{Name: "claims", Status: verifycore.StatusOK},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 2, Verified: 2},
				Relations: model.CoverageDim{Total: 4, Verified: 4},
				Claims:    model.CoverageDim{Total: 2, Verified: 2},
				Score:     100,
			},
			Claims: []verifycore.V4ClaimResult{
				{ID: "claim.tests_passed", Type: "tests_passed", Statement: "All tests passed", Status: "pass", SupportedBy: []string{"tests"}, Valid: true},
				{ID: "claim.exec_bound", Type: "execution_bound", Statement: "Bound to commit abc123", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			},
		},
	}
}

func v4ValidEmptyBranch() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "git", To: "claim.build", Kind: model.RelSupports},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           "v4-valid-empty-branch",
		Project:      model.Project{Name: "test", Repository: "https://example.com/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "", Repository: "https://example.com/test"},
		Execution:    model.Execution{ID: "exec-001", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z", Environment: model.Environment{OS: "ubuntu-24.04", Arch: "amd64", Runtime: "go1.26.5"}},
		Evidence:     ev,
		Relations:    rels,
		Claims:       claims,
		Coverage:     model.V4Coverage{Evidence: model.CoverageDim{Total: 1, Verified: 1}, Relations: model.CoverageDim{Total: 2, Verified: 2}, Claims: model.CoverageDim{Total: 1, Verified: 1}, Score: 100},
		CreatedAt:    "2026-08-21T02:05:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.4.0"},
	}
	entries := model.V4BindingEntries(p)
	p.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	sigPayload := model.V4SigningPayload(p)
	sig, _ := proof.SignBytes(sigPayload, priv)
	pub := proof.PublicKeyOf(priv)
	p.Signature = model.Signature{Algorithm: "ed25519", PublicKey: proof.EncodePublicKey(pub), Value: sig}
	return CaseV4{
		Name:        "v4-valid-empty-branch",
		Description: "v0.4 proof with empty subject branch",
		Proof:       p,
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-valid-empty-branch",
			Valid:   true,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusOK},
				{Name: "claims", Status: verifycore.StatusOK},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 1, Verified: 1},
				Relations: model.CoverageDim{Total: 2, Verified: 2},
				Claims:    model.CoverageDim{Total: 1, Verified: 1},
				Score:     100,
			},
			Claims: []verifycore.V4ClaimResult{
				{ID: "claim.build", Type: "build_passed", Statement: "Build passed", Status: "pass", SupportedBy: []string{"git"}, Valid: true},
			},
		},
	}
}

func v4InvalidTamperedRoot() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-tampered-root", ev, rels, claims, priv)
	p.Binding.Root = "deadbeef00000000"
	return CaseV4{
		Name:        "v4-invalid-tampered-root",
		Description: "v0.4 binding root tampered after signing",
		Proof:       p,
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-invalid-tampered-root",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusFail},
				{Name: "commitment", Status: verifycore.StatusFail},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 1, Verified: 1},
				Relations: model.CoverageDim{Total: 1, Verified: 0},
				Claims:    model.CoverageDim{Total: 1, Verified: 0},
				Score:     0,
			},
		},
	}
}

func v4InvalidTamperedSignature() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-tampered-sig", ev, rels, claims, priv)
	p.Signature.Value = "deadbeef"
	return CaseV4{
		Name:        "v4-invalid-tampered-sig",
		Description: "v0.4 signature value corrupted",
		Proof:       p,
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-invalid-tampered-sig",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 1, Verified: 1},
				Relations: model.CoverageDim{Total: 1, Verified: 1},
				Claims:    model.CoverageDim{Total: 1, Verified: 0},
				Score:     0,
			},
		},
	}
}

func v4InvalidWrongVersion() CaseV4 {
	return CaseV4{
		Name:        "v4-invalid-wrong-version",
		Description: "v0.4 unsupported proof version",
		Malformed:   []byte(`{"id":"x","proofVersion":"99.0","project":{"name":"t","repository":"r"},"subject":{"commit":"a","branch":"b","repository":"r"},"execution":{"id":"e","type":"ci"},"evidence":[],"relations":[],"claims":[],"binding":{"algorithm":"sha256","root":"","entries":[]},"signature":{"algorithm":"ed25519","publicKey":"","value":""},"coverage":{"evidence":{"total":0,"verified":0},"relations":{"total":0,"verified":0},"claims":{"total":0,"verified":0},"score":0}}`),
		Expect: verifycore.V4VerifyResult{
			Valid: false,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusFail, Detail: "unsupported proof version \"99.0\" (expected \"2.0\")"},
			},
		},
	}
}

func v4InvalidMissingSignature() CaseV4 {
	return CaseV4{
		Name:        "v4-invalid-missing-sig",
		Description: "v0.4 proof without signature",
		Malformed:   []byte(`{"id":"no-sig","proofVersion":"2.0","project":{"name":"t","repository":"r"},"subject":{"commit":"a","branch":"b","repository":"r"},"execution":{"id":"e","type":"ci"},"evidence":[],"relations":[],"claims":[],"binding":{"algorithm":"sha256","root":"","entries":[]}}`),
		Expect: verifycore.V4VerifyResult{
			Valid: false,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
		},
	}
}

func v4InvalidModifiedExecution() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-modified-exec", ev, rels, claims, priv)
	p.Execution.Type = model.ExecLocalBuild
	return CaseV4{
		Name:        "v4-invalid-modified-exec",
		Description: "v0.4 execution type modified after signing",
		Proof:       p,
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-invalid-modified-exec",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 1, Verified: 1},
				Relations: model.CoverageDim{Total: 1, Verified: 1},
				Claims:    model.CoverageDim{Total: 1, Verified: 0},
				Score:     0,
			},
		},
	}
}

func v4InvalidModifiedRelation() CaseV4 {
	ev := []model.Evidence{
		{ID: "git", Type: "git", Source: "git", Payload: `{"commit":"abc123"}`, Digest: ""},
	}
	ev[0].Digest = model.EvidenceDigest(ev[0].ID, ev[0].Payload)
	rels := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
	}
	claims := []model.V4Claim{
		{ID: "claim.build", Type: "build_passed", Subject: "execution:exec-001", Statement: "Build passed", Status: model.ClaimPass, SupportedBy: []string{"git"}},
	}
	_, priv, _ := generateDeterministicKey()
	p := v4MakeProof("v4-invalid-modified-relation", ev, rels, claims, priv)
	p.Relations[0].Kind = model.RelDependsOn
	return CaseV4{
		Name:        "v4-invalid-modified-relation",
		Description: "v0.4 relation kind modified after signing",
		Proof:       p,
		Expect: verifycore.V4VerifyResult{
			ProofID: "v4-invalid-modified-relation",
			Valid:   false,
			Checks: []verifycore.Check{
				{Name: "version", Status: verifycore.StatusOK},
				{Name: "evidence", Status: verifycore.StatusOK},
				{Name: "binding", Status: verifycore.StatusOK},
				{Name: "commitment", Status: verifycore.StatusOK},
				{Name: "signature", Status: verifycore.StatusFail},
			},
			Coverage: model.V4Coverage{
				Evidence:  model.CoverageDim{Total: 1, Verified: 1},
				Relations: model.CoverageDim{Total: 1, Verified: 0},
				Claims:    model.CoverageDim{Total: 1, Verified: 0},
				Score:     0,
			},
		},
	}
}

// ============================================================================
// WASM security edge cases
// ============================================================================

func wasmEmptyJSON() Case {
	return Case{
		Name:        "wasm-empty-json",
		Description: "WASM security: empty JSON object",
		Malformed:   []byte(`{}`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func wasmRandomBytes() Case {
	return Case{
		Name:        "wasm-random-bytes",
		Description: "WASM security: completely random bytes",
		Malformed:   []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04},
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func wasmPartialJSON() Case {
	return Case{
		Name:        "wasm-partial-json",
		Description: "WASM security: truncated JSON",
		Malformed:   []byte(`{"id":"partial","proofVersion":"2.0","project":{"name":`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func wasmNullJSON() Case {
	return Case{
		Name:        "wasm-null-json",
		Description: "WASM security: JSON null",
		Malformed:   []byte(`null`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func wasmArrayJSON() Case {
	return Case{
		Name:        "wasm-array-json",
		Description: "WASM security: JSON array instead of object",
		Malformed:   []byte(`[1,2,3]`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func wasmDeeplyNestedJSON() Case {
	return Case{
		Name:        "wasm-deeply-nested",
		Description: "WASM security: deeply nested JSON",
		Malformed:   []byte(`{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{"i":{"j":1}}}}}}}}}}`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func wasmHugeArrayJSON() Case {
	// Generate a 1000-element array to test WASM memory handling
	arr := "["
	for i := 0; i < 1000; i++ {
		if i > 0 {
			arr += ","
		}
		arr += fmt.Sprintf(`{"id":"%d","digest":"%s"}`, i, strings.Repeat("a", 64))
	}
	arr += "]"
	return Case{
		Name:        "wasm-huge-array",
		Description: "WASM security: huge JSON array (1000 elements)",
		Malformed:   []byte(arr),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}

func wasmDuplicateFieldsJSON() Case {
	return Case{
		Name:        "wasm-duplicate-fields",
		Description: "WASM security: JSON with duplicate fields",
		Malformed:   []byte(`{"id":"dup","id":"dup2","proofVersion":"2.0","proofVersion":"99.0"}`),
		Expect: verifycore.VerifyResult{
			Valid:    false,
			Checks:   []verifycore.Check{},
			Coverage: model.Coverage{},
		},
	}
}
