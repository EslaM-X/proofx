// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package proof

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
)

// securityCorpusDir is the directory under proof/ containing attack-proofs.
const securityCorpusDir = "testdata/security"

// TestSecurityCorpusGeneration creates the security corpus files in
// testdata/security/ for regression testing. Each subdir contains a JSON
// proof that exercises a specific attack vector.
func TestSecurityCorpusGeneration(t *testing.T) {
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, attackerPriv, _ := GenerateKey()

	base := buildCorpusProof()
	_ = Sign(base, priv)

	cases := []struct {
		name   string
		subdir string
		mutate func(p *model.Proof)
	}{
		{
			name:   "valid baseline",
			subdir: "valid-baseline",
			mutate: func(p *model.Proof) {},
		},
		{
			name:   "modified claim text",
			subdir: "modified-claims-text",
			mutate: func(p *model.Proof) { p.Claims[0].Text = "TAMPERED" },
		},
		{
			name:   "modified claim status",
			subdir: "modified-claims-status",
			mutate: func(p *model.Proof) { p.Claims[0].Status = "invalid" },
		},
		{
			name:   "modified claim ID",
			subdir: "modified-claims-id",
			mutate: func(p *model.Proof) { p.Claims[0].ID = "hacked" },
		},
		{
			name:   "modified project name",
			subdir: "modified-project",
			mutate: func(p *model.Proof) { p.Project.Name = "evil" },
		},
		{
			name:   "modified subject commit",
			subdir: "modified-subject",
			mutate: func(p *model.Proof) { p.Subject.Commit = "deadbeef" },
		},
		{
			name:   "modified proof version",
			subdir: "modified-version",
			mutate: func(p *model.Proof) { p.ProofVersion = "proofx/v99.99" },
		},
		{
			name:   "modified binding root",
			subdir: "modified-root",
			mutate: func(p *model.Proof) { p.Binding.Root = "aabbccdd" },
		},
		{
			name:   "modified binding algorithm",
			subdir: "modified-algo",
			mutate: func(p *model.Proof) { p.Binding.Algorithm = "sha512" },
		},
		{
			name:   "forged signature with different key",
			subdir: "forged-signature",
			mutate: func(p *model.Proof) {
				_ = Sign(p, attackerPriv)
				p.Signature.PublicKey = base.Signature.PublicKey
			},
		},
		{
			name:   "tampered evidence digest",
			subdir: "modified-evidence-digest",
			mutate: func(p *model.Proof) { p.Evidence[0].Digest = "deadbeef" },
		},
		{
			name:   "mismatched evidence payload and digest",
			subdir: "evidence-payload-digest-mismatch",
			mutate: func(p *model.Proof) {
				p.Evidence[0].Payload = `{"tampered":true}`
				p.Evidence[0].Digest = evidence.EvidenceDigest(`{"tampered":true}`)
			},
		},
		{
			name:   "missing signature",
			subdir: "missing-signature",
			mutate: func(p *model.Proof) {
				p.Signature = model.Signature{}
			},
		},
		{
			name:   "empty proof",
			subdir: "empty-proof",
			mutate: func(p *model.Proof) {
				*p = model.Proof{}
			},
		},
		{
			name:   "wrong signature algorithm",
			subdir: "wrong-sig-algo",
			mutate: func(p *model.Proof) {
				p.Signature.Algorithm = "rsa-sha256"
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			p := cloneProof(base)
			tc.mutate(p)

			dir := filepath.Join(securityCorpusDir, tc.subdir)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}

			raw, err := json.MarshalIndent(p, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "proof.json")
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("wrote %s (%d bytes)", path, len(raw))
		})
	}
}

// TestSecurityCorpusRejection loads every proof in testdata/security/ and
// verifies that non-baseline proofs are rejected by VerifySignature and/or
// VerifyBinding.
func TestSecurityCorpusRejection(t *testing.T) {
	entries, err := os.ReadDir(securityCorpusDir)
	if err != nil {
		t.Skipf("corpus dir %s not found; run TestSecurityCorpusGeneration first", securityCorpusDir)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			path := filepath.Join(securityCorpusDir, entry.Name(), "proof.json")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("cannot read %s: %v", path, err)
			}

			p, err := ParseProof(raw)
			if err != nil {
				if entry.Name() == "valid-baseline" {
					t.Fatalf("valid baseline: ParseProof failed: %v", err)
				}
				t.Logf("attack proof %q rejected at parse: %v", entry.Name(), err)
				return
			}

			sigErr := VerifySignature(p)
			bindErr := VerifyBinding(p)

			if entry.Name() == "valid-baseline" {
				if sigErr != nil {
					t.Errorf("valid baseline: signature should pass, got %v", sigErr)
				}
				if bindErr != nil {
					t.Errorf("valid baseline: binding should pass, got %v", bindErr)
				}
				return
			}

			if sigErr == nil && bindErr == nil {
				t.Errorf("attack proof %q was not rejected by either signature or binding", entry.Name())
			}
		})
	}
}

func buildCorpusProof() *model.Proof {
	ev := model.Evidence{
		ID: "git", Type: "git", Source: "git metadata",
		Timestamp: "2026-01-01T00:00:00Z",
		Payload:   `{"commit":"abc123","branch":"main","repository":"https://github.com/test/test"}`,
		Digest:    evidence.EvidenceDigest(`{"commit":"abc123","branch":"main","repository":"https://github.com/test/test"}`),
	}
	return &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-security-corpus-001",
		Project:      model.Project{Name: "testproject", Repository: "https://github.com/test/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://github.com/test/test"},
		Claims: []model.Claim{
			{ID: "code-quality", Text: "meets standards", Status: "verified"},
		},
		Evidence: []model.Evidence{ev},
		Binding: model.Binding{
			Algorithm: "sha256",
			Root:      Root(BindingEntries([]model.Evidence{ev})),
		},
	}
}
