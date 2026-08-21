// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package verifycore contains the v0.4 tamper matrix tests.
//
// Every row proves that a specific mutation invalidates the proof.
// This is the security invariant: any change to committed data
// MUST break verification.
package verifycore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/EslaM-X/proofx/model"
)

// --- Test fixture ---

func signProof(p *model.V4Proof, priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	p.Signature = model.Signature{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, model.V4SigningPayload(p))),
	}
}

func validV4Fixture() *model.V4Proof {
	payloadGit := `{"branch":"main","commit":"abc123def456789012345678901234567890abcd","repository":"https://github.com/test/repo"}`
	payloadArtifact := `{"files":{"binary":"aabbccdd"}}`
	payloadTests := `{"passed":42,"failed":0}`
	payloadEnv := `{"os":"ubuntu-24.04","arch":"amd64","runtime":"go1.26.5"}`

	evGit := model.Evidence{ID: "git", Type: "git", Source: "git", Payload: payloadGit, Digest: model.EvidenceDigest("git", payloadGit)}
	evArtifact := model.Evidence{ID: "artifact", Type: "artifact", Source: "build", Payload: payloadArtifact, Digest: model.EvidenceDigest("artifact", payloadArtifact)}
	evTests := model.Evidence{ID: "tests", Type: "tests", Source: "test-runner", Payload: payloadTests, Digest: model.EvidenceDigest("tests", payloadTests)}
	evEnv := model.Evidence{ID: "environment", Type: "environment", Source: "detect", Payload: payloadEnv, Digest: model.EvidenceDigest("environment", payloadEnv)}

	evs := []model.Evidence{evGit, evArtifact, evTests, evEnv}

	relations := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "exec-001", To: "artifact", Kind: model.RelProduces},
		{ID: "r3", From: "exec-001", To: "tests", Kind: model.RelProduces},
		{ID: "r4", From: "exec-001", To: "environment", Kind: model.RelProduces},
		{ID: "r5", From: "tests", To: "claim.tests_passed", Kind: model.RelSupports},
		{ID: "r6", From: "artifact", To: "claim.artifact_integrity", Kind: model.RelSupports},
		{ID: "r7", From: "git", To: "claim.execution_bound", Kind: model.RelSupports},
		{ID: "r8", From: "environment", To: "claim.environment_recorded", Kind: model.RelSupports},
	}

	claims := []model.V4Claim{
		{ID: "claim.tests_passed", Type: "tests_passed", Subject: "execution:exec-001", Statement: "All tests passed", Status: model.ClaimPass, SupportedBy: []string{"tests"}},
		{ID: "claim.artifact_integrity", Type: "artifact_integrity", Subject: "execution:exec-001", Statement: "Artifact digests verified", Status: model.ClaimPass, SupportedBy: []string{"artifact"}},
		{ID: "claim.execution_bound", Type: "execution_bound", Subject: "execution:exec-001", Statement: "Bound to commit abc123", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "claim.environment_recorded", Type: "environment_recorded", Subject: "execution:exec-001", Statement: "Build environment documented", Status: model.ClaimPass, SupportedBy: []string{"environment"}},
	}

	entries := model.V4BindingEntries(&model.V4Proof{
		Evidence:  evs,
		Relations: relations,
		Claims:    claims,
	})
	root := model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           "PX-" + root[:8],
		Project:      model.Project{Name: "test-project", Repository: "https://github.com/test/repo"},
		Subject:      model.Subject{Commit: "abc123def456789012345678901234567890abcd", Branch: "main", Repository: "https://github.com/test/repo"},
		Execution:    model.Execution{ID: "exec-001", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z", Environment: model.Environment{OS: "ubuntu-24.04", Arch: "amd64", Runtime: "go1.26.5"}},
		Evidence:     evs,
		Relations:    relations,
		Claims:       claims,
		Binding:      model.Binding{Algorithm: "sha256", Root: root, Entries: entries},
		Signature:    model.Signature{},
		Coverage: model.V4Coverage{
			Evidence:  model.CoverageDim{Total: 4, Verified: 4},
			Relations: model.CoverageDim{Total: 8, Verified: 8},
			Claims:    model.CoverageDim{Total: 4, Verified: 4},
			Score:     100,
		},
		CreatedAt: "2026-08-21T02:05:00Z",
		Builder:   model.Builder{Name: "proofx", Version: "0.4.0"},
	}

	signProof(p, priv)
	return p
}

func cloneProof(p *model.V4Proof) *model.V4Proof {
	b, _ := json.Marshal(p)
	var c model.V4Proof
	json.Unmarshal(b, &c)
	return &c
}

// --- Valid proof must verify ---

func TestV4Verify_ValidProof(t *testing.T) {
	p := validV4Fixture()
	res := V4Verify(p)
	if !res.Valid {
		t.Fatalf("valid proof failed verification: %v", res.Checks)
	}
	if res.Coverage.Score != 100 {
		t.Errorf("expected coverage 100, got %d", res.Coverage.Score)
	}
}

// --- Tamper Matrix ---
//
// Every mutation MUST produce Valid=false.

type tamperCase struct {
	name   string
	mutate func(p *model.V4Proof)
}

func tamperMatrix() []tamperCase {
	return []tamperCase{
		// Execution
		{"execution.id", func(p *model.V4Proof) { p.Execution.ID = "mutated" }},
		{"execution.type", func(p *model.V4Proof) { p.Execution.Type = "mutated" }},
		{"execution.startedAt", func(p *model.V4Proof) { p.Execution.StartedAt = "2000-01-01T00:00:00Z" }},
		{"execution.completedAt", func(p *model.V4Proof) { p.Execution.CompletedAt = "2000-01-01T00:00:00Z" }},

		// Project / Subject
		{"project.name", func(p *model.V4Proof) { p.Project.Name = "mutated" }},
		{"project.repository", func(p *model.V4Proof) { p.Project.Repository = "mutated" }},
		{"subject.commit", func(p *model.V4Proof) { p.Subject.Commit = strings.Repeat("0", 40) }},
		{"subject.branch", func(p *model.V4Proof) { p.Subject.Branch = "mutated" }},
		{"subject.repository", func(p *model.V4Proof) { p.Subject.Repository = "mutated" }},

		// Evidence
		{"evidence[0].id", func(p *model.V4Proof) { p.Evidence[0].ID = "mutated" }},
		{"evidence[0].payload", func(p *model.V4Proof) { p.Evidence[0].Payload = "mutated" }},
		{"evidence[0].digest", func(p *model.V4Proof) { p.Evidence[0].Digest = strings.Repeat("0", 64) }},
		{"evidence[1].digest", func(p *model.V4Proof) { p.Evidence[1].Digest = strings.Repeat("0", 64) }},

		// Relations
		{"relations[0].from", func(p *model.V4Proof) { p.Relations[0].From = "mutated" }},
		{"relations[0].to", func(p *model.V4Proof) { p.Relations[0].To = "mutated" }},
		{"relations[0].kind", func(p *model.V4Proof) { p.Relations[0].Kind = "mutated" }},
		{"relations[4].kind", func(p *model.V4Proof) { p.Relations[4].Kind = "mutated" }},

		// Claims
		{"claims[0].type", func(p *model.V4Proof) { p.Claims[0].Type = "mutated" }},
		{"claims[0].statement", func(p *model.V4Proof) { p.Claims[0].Statement = "mutated" }},
		{"claims[0].status", func(p *model.V4Proof) { p.Claims[0].Status = model.ClaimFail }},
		{"claims[0].supportedBy", func(p *model.V4Proof) { p.Claims[0].SupportedBy = []string{"mutated"} }},
		{"claims[0].subject", func(p *model.V4Proof) { p.Claims[0].Subject = "mutated" }},

		// Binding / Signature
		{"binding.root", func(p *model.V4Proof) { p.Binding.Root = strings.Repeat("0", 64) }},
		{"binding.algorithm", func(p *model.V4Proof) { p.Binding.Algorithm = "sha512" }},
		{"signature.value", func(p *model.V4Proof) { p.Signature.Value = hex.EncodeToString(make([]byte, 64)) }},
		{"signature.algorithm", func(p *model.V4Proof) { p.Signature.Algorithm = "rsa" }},
		{"proofVersion", func(p *model.V4Proof) { p.ProofVersion = "1.0" }},
	}
}

func TestV4Verify_TamperMatrix(t *testing.T) {
	for _, tc := range tamperMatrix() {
		t.Run(tc.name, func(t *testing.T) {
			p := validV4Fixture()
			tc.mutate(p)
			res := V4Verify(p)
			if res.Valid {
				t.Errorf("SECURITY VIOLATION: mutation %q did not invalidate proof", tc.name)
			}
		})
	}
}

// --- Tamper matrix count ---

func TestV4Verify_TamperMatrixCount(t *testing.T) {
	cases := tamperMatrix()
	t.Logf("Tamper matrix: %d mutation cases", len(cases))

	// Ensure we have comprehensive coverage
	if len(cases) < 25 {
		t.Errorf("tamper matrix too small: %d cases (expected >= 25)", len(cases))
	}
}

// --- Claims verification ---

func TestV4Verify_ClaimsVerified(t *testing.T) {
	p := validV4Fixture()
	res := V4Verify(p)
	if len(res.Claims) != 4 {
		t.Fatalf("expected 4 claim results, got %d", len(res.Claims))
	}
	for _, cr := range res.Claims {
		if !cr.Valid {
			t.Errorf("claim %q should be valid: %s", cr.ID, cr.Detail)
		}
	}
}

func TestV4Verify_ClaimWithNoSupportingEvidence(t *testing.T) {
	p := validV4Fixture()
	// Add a claim with empty supportedBy
	p.Claims = append(p.Claims, model.V4Claim{
		ID:          "claim.unsupported",
		Type:        "custom",
		Subject:     "execution:exec-001",
		Statement:   "Unsupported claim",
		Status:      model.ClaimPending,
		SupportedBy: []string{},
	})
	// Need a supports relation too
	p.Relations = append(p.Relations, model.Relation{
		ID:   "r-unsup",
		From: "git",
		To:   "claim.unsupported",
		Kind: model.RelSupports,
	})
	res := V4Verify(p)
	if res.Valid {
		t.Error("proof with unsupported claim should fail")
	}
}

func TestV4Verify_ClaimReferencesMissingEvidence(t *testing.T) {
	p := validV4Fixture()
	p.Claims[0].SupportedBy = []string{"nonexistent-evidence"}
	res := V4Verify(p)
	if res.Valid {
		t.Error("proof with claim referencing missing evidence should fail")
	}
}

// --- Evidence digest tampering ---

func TestV4Verify_EvidenceDigestMismatch(t *testing.T) {
	p := validV4Fixture()
	// Change payload but keep old digest
	p.Evidence[0].Payload = `{"mutated":true}`
	res := V4Verify(p)
	if res.Valid {
		t.Error("proof with tampered evidence payload should fail")
	}
	checkFound := false
	for _, c := range res.Checks {
		if c.Name == "evidence" && c.Status == StatusFail {
			checkFound = true
		}
	}
	if !checkFound {
		t.Error("expected 'evidence' check to fail")
	}
}

// --- Schema validation ---

func TestV4Verify_EmptyExecutionID(t *testing.T) {
	p := validV4Fixture()
	p.Execution.ID = ""
	res := V4Verify(p)
	if res.Valid {
		t.Error("proof with empty execution ID should fail")
	}
}

func TestV4Verify_DuplicateEvidenceIDs(t *testing.T) {
	p := validV4Fixture()
	p.Evidence = append(p.Evidence, p.Evidence[0])
	res := V4Verify(p)
	if res.Valid {
		t.Error("proof with duplicate evidence IDs should fail")
	}
}

// --- Coverage computation ---

func TestV4Verify_CoverageDimensions(t *testing.T) {
	p := validV4Fixture()
	res := V4Verify(p)

	if res.Coverage.Evidence.Total != 4 {
		t.Errorf("evidence total: got %d, want 4", res.Coverage.Evidence.Total)
	}
	if res.Coverage.Relations.Total != 8 {
		t.Errorf("relations total: got %d, want 8", res.Coverage.Relations.Total)
	}
	if res.Coverage.Claims.Total != 4 {
		t.Errorf("claims total: got %d, want 4", res.Coverage.Claims.Total)
	}
	if res.Coverage.Score != 100 {
		t.Errorf("score: got %d, want 100", res.Coverage.Score)
	}
}

// --- v0.3 compatibility ---

func TestV4Verify_V3ProofRejected(t *testing.T) {
	v3json := `{"proofVersion":"1.0","id":"PX-test","project":{"name":"x","repository":"x"},"subject":{"commit":"abc123def456789012345678901234567890abcd","branch":"main","repository":"x"},"evidence":[],"binding":{"algorithm":"sha256","root":"","entries":[]},"signature":{"algorithm":"ed25519","publicKey":"","value":""},"coverage":{"total":0,"verified":0,"score":0},"createdAt":"2026-01-01T00:00:00Z","builder":{"name":"test","version":"0.3"}}`
	_, err := V4ParseProof([]byte(v3json))
	if err == nil {
		t.Error("v0.3 proof should be rejected by v0.4 parser")
	}
}

// --- Check names ---

func TestV4Verify_CheckNames(t *testing.T) {
	p := validV4Fixture()
	res := V4Verify(p)

	expectedChecks := []string{"schema", "evidence", "binding", "commitment", "signature", "claims"}
	if len(res.Checks) != len(expectedChecks) {
		t.Fatalf("expected %d checks, got %d", len(expectedChecks), len(res.Checks))
	}
	for i, name := range expectedChecks {
		if res.Checks[i].Name != name {
			t.Errorf("check[%d].Name = %q, want %q", i, res.Checks[i].Name, name)
		}
	}
}

// --- Graph validation through verifycore ---

func TestV4Verify_OrphanEvidenceDetected(t *testing.T) {
	p := validV4Fixture()
	// Add evidence with no relation pointing to it
	p.Evidence = append(p.Evidence, model.Evidence{
		ID:      "orphan",
		Type:    "custom",
		Payload: `{"orphan":true}`,
		Digest:  model.EvidenceDigest("orphan", `{"orphan":true}`),
	})
	res := V4Verify(p)
	// Schema validation should catch orphan evidence (no relation produces it)
	if res.Valid {
		t.Error("proof with orphan evidence should fail schema validation")
	}
}

// --- Property: 10k mutations ---

func TestV4Verify_Property_10kMutations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping property test in short mode")
	}

	p := validV4Fixture()

	for i := 0; i < 10000; i++ {
		mut := cloneProof(p)
		switch i % 8 {
		case 0:
			mut.Execution.ID = fmt.Sprintf("mut-%d", i)
		case 1:
			mut.Evidence[0].Digest = fmt.Sprintf("%064x", i)
		case 2:
			mut.Project.Name = fmt.Sprintf("mut-%d", i)
		case 3:
			mut.Subject.Commit = fmt.Sprintf("%040x", i)
		case 4:
			mut.Claims[0].Statement = fmt.Sprintf("mut-%d", i)
		case 5:
			mut.Binding.Root = fmt.Sprintf("%064x", i)
		case 6:
			mut.Execution.Type = fmt.Sprintf("mut-%d", i)
		case 7:
			mut.Claims[0].Status = model.ClaimFail
		}

		res := V4Verify(mut)
		if res.Valid {
			t.Fatalf("SECURITY: mutation %d did not break proof", i)
		}
	}

	t.Log("SECURITY: 10,000 mutations all produced Invalid proofs")
}

// --- Fuzz ---

func FuzzV4Verify(f *testing.F) {
	p := validV4Fixture()
	b, _ := json.Marshal(p)
	f.Add(b)
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))

	f.Fuzz(func(t *testing.T, data []byte) {
		proof, err := V4ParseProof(data)
		if err != nil {
			return
		}
		res := V4Verify(proof)
		// Should never panic, and Valid should be deterministic
		res2 := V4Verify(proof)
		if res.Valid != res2.Valid {
			t.Fatalf("non-deterministic verification: %v != %v", res.Valid, res2.Valid)
		}
	})
}

// ============================================================================
// Positive Tests — valid proofs MUST NOT be rejected
// ============================================================================

func TestV4Verify_AcceptsEmptyMetadata(t *testing.T) {
	// v0.3 evidence has no Metadata field — this is fine
	p := validV4Fixture()
	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsEmptyArtifactType(t *testing.T) {
	// v0.3 evidence has no ArtifactType field — this is fine
	p := validV4Fixture()
	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsManyEvidence(t *testing.T) {
	p := validV4Fixture()
	for i := 0; i < 50; i++ {
		payload := fmt.Sprintf(`{"extra":%d}`, i)
		id := fmt.Sprintf("extra-%d", i)
		p.Evidence = append(p.Evidence, model.Evidence{
			ID:      id,
			Type:    "custom",
			Payload: payload,
			Digest:  model.EvidenceDigest(id, payload),
		})
		// Need a produces relation
		p.Relations = append(p.Relations, model.Relation{
			ID:   fmt.Sprintf("r-extra-%d", i),
			From: "exec-001",
			To:   id,
			Kind: model.RelProduces,
		})
	}
	// Recompute binding
	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)

	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof with 54 evidence nodes rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsManyClaims(t *testing.T) {
	p := validV4Fixture()
	for i := 0; i < 20; i++ {
		id := fmt.Sprintf("claim.custom-%d", i)
		p.Claims = append(p.Claims, model.V4Claim{
			ID:          id,
			Type:        "custom",
			Subject:     "execution:exec-001",
			Statement:   fmt.Sprintf("Custom claim %d", i),
			Status:      model.ClaimPass,
			SupportedBy: []string{"tests"},
		})
		p.Relations = append(p.Relations, model.Relation{
			ID:   fmt.Sprintf("r-claim-%d", i),
			From: "tests",
			To:   id,
			Kind: model.RelSupports,
		})
	}

	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)

	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof with 24 claims rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsMultipleRelationKinds(t *testing.T) {
	p := validV4Fixture()
	p.Relations = append(p.Relations, model.Relation{
		ID:   "r-derived",
		From: "artifact",
		To:   "git",
		Kind: model.RelDerivedFrom,
	})

	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)

	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof with mixed relation kinds rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsClaimPendingStatus(t *testing.T) {
	p := validV4Fixture()
	p.Claims[0].Status = model.ClaimPending

	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)

	// Pending claim is still cryptographically valid
	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof with pending claim rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsNotApplicableClaim(t *testing.T) {
	p := validV4Fixture()
	p.Claims[0].Status = model.ClaimNotApplicable

	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)

	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof with not_applicable claim rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsV3ConvertedProof(t *testing.T) {
	// A v0.3 proof converted to v0.4 should be parseable
	// (but won't verify because binding/signature use v1 domain labels)
	v3json := `{"proofVersion":"1.0","id":"PX-test","project":{"name":"x","repository":"x"},"subject":{"commit":"abc123def456789012345678901234567890abcd","branch":"main","repository":"x"},"evidence":[],"binding":{"algorithm":"sha256","root":"","entries":[]},"signature":{"algorithm":"ed25519","publicKey":"","value":""},"coverage":{"total":0,"verified":0,"score":0},"createdAt":"2026-01-01T00:00:00Z","builder":{"name":"test","version":"0.3"}}`

	converted, err := model.V3ToV4([]byte(v3json))
	if err != nil {
		t.Fatalf("V3ToV4 failed: %v", err)
	}
	if converted.ProofVersion != model.ProofVersionV2 {
		t.Errorf("converted proof should have v2 version, got %q", converted.ProofVersion)
	}
}

func TestV4Verify_AcceptsCustomExecutionType(t *testing.T) {
	p := validV4Fixture()
	p.Execution.Type = model.ExecCustom

	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)

	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof with custom execution type rejected: %v", res.Checks)
	}
}

func TestV4Verify_AcceptsLongStatements(t *testing.T) {
	p := validV4Fixture()
	longStmt := strings.Repeat("This is a detailed claim statement. ", 100)
	p.Claims[0].Statement = longStmt

	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)

	res := V4Verify(p)
	if !res.Valid {
		t.Errorf("valid proof with long claim statement rejected: %v", res.Checks)
	}
}
