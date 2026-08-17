// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package proof

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
)

const propertyMutations = 10000

func cloneProof(p *model.Proof) *model.Proof {
	b, _ := json.Marshal(p)
	var c model.Proof
	_ = json.Unmarshal(b, &c)
	return &c
}

func randBytes(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
	return b
}

func randPrintable(rng *rand.Rand, minLen, maxLen int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_- .#@!"
	n := minLen + rng.Intn(maxLen-minLen+1)
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rng.Intn(len(chars))]
	}
	return string(b)
}

func randHex(rng *rand.Rand, nibbles int) string {
	const hx = "0123456789abcdef"
	b := make([]byte, nibbles)
	for i := range b {
		b[i] = hx[rng.Intn(16)]
	}
	return string(b)
}

func b64enc(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func createFullSignedProof(t *testing.T) *model.Proof {
	t.Helper()
	ev1 := model.Evidence{
		ID: "git", Type: "git", Source: "git metadata",
		Timestamp: "2026-01-01T00:00:00Z",
		Payload:   `{"commit":"abc123","branch":"main","repository":"https://github.com/test/test"}`,
		Digest:    evidence.EvidenceDigest(`{"commit":"abc123","branch":"main","repository":"https://github.com/test/test"}`),
	}
	ev2 := model.Evidence{
		ID: "tests", Type: "tests", Source: "test result summary",
		Timestamp: "2026-01-01T00:00:00Z",
		Payload:   `{"pass":10,"fail":0}`,
		Digest:    evidence.EvidenceDigest(`{"pass":10,"fail":0}`),
	}
	ev3 := model.Evidence{
		ID: "artifact", Type: "artifact", Source: "sha256 of configured artifacts",
		Timestamp: "2026-01-01T00:00:00Z",
		Payload:   `{"files":{"dist.zip":"abcdef1234567890"}}`,
		Digest:    evidence.EvidenceDigest(`{"files":{"dist.zip":"abcdef1234567890"}}`),
	}
	evs := []model.Evidence{ev1, ev2, ev3}
	entries := BindingEntries(evs)
	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-security-test-001",
		Project:      model.Project{Name: "test-project", Repository: "https://github.com/test/test"},
		Subject:      model.Subject{Commit: "abc123def456789", Branch: "main", Repository: "https://github.com/test/test"},
		Claims: []model.Claim{
			{ID: "c1", Text: "Built from recorded commit", Status: "evidenced"},
			{ID: "c2", Text: "All tests pass", Status: "verified"},
		},
		Evidence:  evs,
		Binding:   model.Binding{Algorithm: "sha256", Root: Root(entries), Entries: entries},
		Coverage:  model.Coverage{Total: 3, Verified: 3, Score: 100},
		CreatedAt: "2026-01-01T00:00:00Z",
		Builder:   model.Builder{Name: "proofx", Version: "0.2.1"},
	}
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	return p
}

func signWithFreshKey(t *testing.T, p *model.Proof) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustVerifyBoth(t *testing.T, p *model.Proof) {
	t.Helper()
	if err := VerifyBinding(p); err != nil {
		t.Fatalf("baseline binding must pass: %v", err)
	}
	if err := VerifySignature(p); err != nil {
		t.Fatalf("baseline signature must pass: %v", err)
	}
}

func TestPropertyValidProofVerifies(t *testing.T) {
	p := createFullSignedProof(t)
	mustVerifyBoth(t, p)
	b, err := MarshalProof(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProof(b)
	if err != nil {
		t.Fatal(err)
	}
	mustVerifyBoth(t, parsed)
}

func TestPropertyClaimsTextMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(42))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		idx := rng.Intn(len(p.Claims))
		switch rng.Intn(4) {
		case 0:
			p.Claims[idx].Text = randPrintable(rng, 1, 200)
		case 1:
			p.Claims[idx].Text = ""
		case 2:
			p.Claims[idx].Text = "TAMPERED"
		case 3:
			p.Claims[idx].Text = original.Claims[idx].Text + "X"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified claim text", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("claim text: %d mutations, all rejected", propertyMutations)
}

func TestPropertyClaimsStatusMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(43))
	failures := 0
	statuses := []string{"pending", "verified", "evidenced", "invalid", "", "PENDING", "x"}
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		idx := rng.Intn(len(p.Claims))
		var newStatus string
		if rng.Intn(2) == 0 {
			newStatus = statuses[rng.Intn(len(statuses))]
		} else {
			newStatus = randPrintable(rng, 1, 50)
		}
		if newStatus == original.Claims[idx].Status {
			continue
		}
		p.Claims[idx].Status = newStatus
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified claim status", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("claim status: %d mutations, all rejected", propertyMutations)
}

func TestPropertyClaimsIDMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(44))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		idx := rng.Intn(len(p.Claims))
		switch rng.Intn(3) {
		case 0:
			p.Claims[idx].ID = randPrintable(rng, 1, 50)
		case 1:
			p.Claims[idx].ID = ""
		case 2:
			p.Claims[idx].ID = original.Claims[idx].ID + "X"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified claim id", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("claim id: %d mutations, all rejected", propertyMutations)
}

func TestPropertyClaimsReorderMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(45))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		n := len(p.Claims)
		if n < 2 {
			continue
		}
		a, b := rng.Intn(n), rng.Intn(n)
		if a != b {
			p.Claims[a], p.Claims[b] = p.Claims[b], p.Claims[a]
		} else {
			p.Claims[a].Text = p.Claims[a].Text + "X"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for reordered/modified claims", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("claims reorder: %d mutations, all rejected", propertyMutations)
}

func TestPropertyClaimsAddRemoveMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(46))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Claims = append(p.Claims, model.Claim{ID: "x", Text: "extra", Status: "evidenced"})
		case 1:
			if len(p.Claims) > 1 {
				p.Claims = p.Claims[:1]
			}
		case 2:
			p.Claims = []model.Claim{}
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for add/remove claim", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("claims add/remove: %d mutations, all rejected", propertyMutations)
}

func TestPropertyProjectNameMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(47))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Project.Name = randPrintable(rng, 1, 100)
		case 1:
			p.Project.Name = ""
		case 2:
			p.Project.Name = "TAMPERED_PROJECT"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified project name", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("project name: %d mutations, all rejected", propertyMutations)
}

func TestPropertyProjectRepoMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(48))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Project.Repository = randPrintable(rng, 1, 200)
		case 1:
			p.Project.Repository = ""
		case 2:
			p.Project.Repository = "https://evil.com/steal"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified project repo", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("project repo: %d mutations, all rejected", propertyMutations)
}

func TestPropertySubjectCommitMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(49))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Subject.Commit = randHex(rng, 40)
		case 1:
			p.Subject.Commit = ""
		case 2:
			p.Subject.Commit = "deadbeef0000000000000000"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified subject commit", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("subject commit: %d mutations, all rejected", propertyMutations)
}

func TestPropertySubjectBranchMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(50))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Subject.Branch = randPrintable(rng, 1, 50)
		case 1:
			p.Subject.Branch = ""
		case 2:
			p.Subject.Branch = "evil-branch"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified subject branch", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("subject branch: %d mutations, all rejected", propertyMutations)
}

func TestPropertySubjectRepoMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(51))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Subject.Repository = randPrintable(rng, 1, 200)
		case 1:
			p.Subject.Repository = ""
		case 2:
			p.Subject.Repository = "https://evil.com/fork"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified subject repo", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("subject repo: %d mutations, all rejected", propertyMutations)
}

func TestPropertyVersionMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(52))
	failures := 0
	versions := []string{"", "0.1", "2.0", "9.9", "1.0 ", " 1.0"}
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		if rng.Intn(2) == 0 {
			p.ProofVersion = versions[rng.Intn(len(versions))]
		} else {
			p.ProofVersion = randPrintable(rng, 1, 20)
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified version", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("version: %d mutations, all rejected", propertyMutations)
}

func TestPropertyAlgoMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(53))
	failures := 0
	algos := []string{"", "sha512", "md5", "sha1", "sha256 ", "SHA256", "none"}
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		if rng.Intn(2) == 0 {
			p.Binding.Algorithm = algos[rng.Intn(len(algos))]
		} else {
			p.Binding.Algorithm = randPrintable(rng, 1, 30)
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified algo", i)
			failures++
		}
		if p.Binding.Algorithm != "sha256" {
			if err := VerifyBinding(p); err == nil {
				t.Errorf("mutation %d: binding passed for non-sha256 algo", i)
				failures++
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("algo: %d mutations, all rejected", propertyMutations)
}

func TestPropertyRootMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(54))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(4) {
		case 0:
			p.Binding.Root = randHex(rng, 64)
		case 1:
			p.Binding.Root = ""
		case 2:
			p.Binding.Root = "0000000000000000000000000000000000000000000000000000000000000000"
		case 3:
			p.Binding.Root = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified root", i)
			failures++
		}
		if err := VerifyBinding(p); err == nil {
			t.Errorf("mutation %d: binding passed for modified root", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("root: %d mutations, all rejected", propertyMutations)
}

func TestPropertySignatureValueMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(55))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(4) {
		case 0:
			p.Signature.Value = ""
		case 1:
			p.Signature.Value = "AAAA"
		case 2:
			p.Signature.Value = b64enc(randBytes(rng, 64))
		case 3:
			p.Signature.Value = "not-valid-base64!!!"
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified signature value", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("sig value: %d mutations, all rejected", propertyMutations)
}

func TestPropertySignatureKeyMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(56))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(4) {
		case 0:
			other, _, _ := GenerateKey()
			p.Signature.PublicKey = EncodePublicKey(other)
		case 1:
			p.Signature.PublicKey = ""
		case 2:
			p.Signature.PublicKey = b64enc(randBytes(rng, 16))
		case 3:
			p.Signature.PublicKey = b64enc(randBytes(rng, 64))
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified public key", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("sig key: %d mutations, all rejected", propertyMutations)
}

func TestPropertySignatureAlgoMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(57))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Signature.Algorithm = ""
		case 1:
			p.Signature.Algorithm = "rsa"
		case 2:
			p.Signature.Algorithm = randPrintable(rng, 1, 20)
		}
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified sig algo", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("sig algo: %d mutations, all rejected", propertyMutations)
}

func TestPropertyForgedSignatureDifferentKey(t *testing.T) {
	original := createFullSignedProof(t)
	originalPubkey := original.Signature.PublicKey
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		_, otherPriv, _ := GenerateKey()
		_ = Sign(p, otherPriv)
		p.Signature.PublicKey = originalPubkey
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: forged signature with different key passed", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("forged sig: %d mutations, all rejected", propertyMutations)
}

func TestPropertyEvidenceDigestMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(59))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		idx := rng.Intn(len(p.Evidence))
		switch rng.Intn(3) {
		case 0:
			p.Evidence[idx].Digest = randHex(rng, 64)
		case 1:
			p.Evidence[idx].Digest = ""
		case 2:
			p.Evidence[idx].Digest = "deadbeef"
		}
		if err := VerifyBinding(p); err == nil {
			t.Errorf("mutation %d: binding passed for modified evidence digest", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("evidence digest: %d mutations, all rejected", propertyMutations)
}

func TestPropertyEvidencePayloadDigestMismatch(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(60))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		idx := rng.Intn(len(p.Evidence))
		p.Evidence[idx].Payload = `{"tampered":true}`
		p.Evidence[idx].Digest = evidence.EvidenceDigest(p.Evidence[idx].Payload)
		p.Binding.Root = Root(BindingEntries(p.Evidence))
		if err := VerifySignature(p); err == nil {
			t.Errorf("mutation %d: sig passed for modified payload+digest+root", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("payload+digest+root: %d mutations, all rejected", propertyMutations)
}

func TestPropertyEvidenceIDMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(61))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		idx := rng.Intn(len(p.Evidence))
		switch rng.Intn(3) {
		case 0:
			p.Evidence[idx].ID = randPrintable(rng, 1, 30)
		case 1:
			p.Evidence[idx].ID = ""
		case 2:
			p.Evidence[idx].ID = "forged-" + p.Evidence[idx].ID
		}
		if err := VerifyBinding(p); err == nil {
			t.Errorf("mutation %d: binding passed for modified evidence id", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("evidence id: %d mutations, all rejected", propertyMutations)
}

func TestPropertyEvidenceAddRemoveMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(62))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		switch rng.Intn(3) {
		case 0:
			p.Evidence = append(p.Evidence, model.Evidence{
				ID: "extra", Type: "git", Payload: "{}", Digest: "deadbeef",
			})
		case 1:
			if len(p.Evidence) > 1 {
				p.Evidence = p.Evidence[:1]
			}
		case 2:
			p.Evidence = []model.Evidence{}
		}
		if err := VerifyBinding(p); err == nil {
			t.Errorf("mutation %d: binding passed for add/remove evidence", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("evidence add/remove: %d mutations, all rejected", propertyMutations)
}

func TestPropertyArtifactDigestMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(63))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		for j := range p.Evidence {
			if p.Evidence[j].ID == "artifact" {
				fakeDigest := randHex(rng, 64)
				p.Evidence[j].Payload = `{"files":{"dist.zip":"` + fakeDigest + `"}}`
				p.Evidence[j].Digest = evidence.EvidenceDigest(p.Evidence[j].Payload)
				break
			}
		}
		if err := VerifyBinding(p); err == nil {
			t.Errorf("mutation %d: binding passed for modified artifact digest", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("artifact digest: %d mutations, all rejected", propertyMutations)
}

func TestPropertyArtifactFileMutations(t *testing.T) {
	original := createFullSignedProof(t)
	rng := rand.New(rand.NewSource(64))
	failures := 0
	for i := 0; i < propertyMutations; i++ {
		p := cloneProof(original)
		for j := range p.Evidence {
			if p.Evidence[j].ID == "artifact" {
				newName := randPrintable(rng, 1, 30) + ".zip"
				p.Evidence[j].Payload = `{"files":{"` + newName + `":"abcdef1234567890"}}`
				p.Evidence[j].Digest = evidence.EvidenceDigest(p.Evidence[j].Payload)
				break
			}
		}
		if err := VerifyBinding(p); err == nil {
			t.Errorf("mutation %d: binding passed for modified artifact file", i)
			failures++
		}
	}
	if failures > 0 {
		t.Fatalf("%d mutations out of %d were not rejected", failures, propertyMutations)
	}
	t.Logf("artifact file: %d mutations, all rejected", propertyMutations)
}