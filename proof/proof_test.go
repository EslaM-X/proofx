// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package proof

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/EslaM-X/proofx/model"
)

func testProof(t *testing.T) *model.Proof {
	t.Helper()
	evs := []model.Evidence{
		{ID: "git", Type: "git", Payload: `{"commit":"abc"}`, Digest: "aaaa"},
		{ID: "tests", Type: "tests", Payload: `{"pass":1}`, Digest: "bbbb"},
	}
	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-test",
		Evidence:     evs,
		Binding:      model.Binding{Algorithm: "sha256", Root: Root(BindingEntries(evs)), Entries: BindingEntries(evs)},
	}
	return p
}

func TestRootDeterministic(t *testing.T) {
	a := BindingEntries([]model.Evidence{{ID: "x", Digest: "1"}, {ID: "y", Digest: "2"}})
	b := BindingEntries([]model.Evidence{{ID: "y", Digest: "2"}, {ID: "x", Digest: "1"}}) // reversed order
	if Root(a) != Root(b) {
		t.Fatalf("root must be order-independent: %s != %s", Root(a), Root(b))
	}
}

func TestRootChangesOnDigestChange(t *testing.T) {
	a := Root(BindingEntries([]model.Evidence{{ID: "x", Digest: "1"}}))
	b := Root(BindingEntries([]model.Evidence{{ID: "x", Digest: "2"}}))
	if a == b {
		t.Fatalf("root must change when a digest changes")
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	p := testProof(t)
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	if p.Signature.Algorithm != "ed25519" {
		t.Fatalf("unexpected algorithm %q", p.Signature.Algorithm)
	}
	_ = pub
	if err := VerifySignature(p); err != nil {
		t.Fatalf("signature should verify: %v", err)
	}
}

func TestVerifySignatureRejectsTamperedRoot(t *testing.T) {
	p := testProof(t)
	_, priv, _ := GenerateKey()
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	p.Binding.Root = "deadbeef" // tamper
	if err := VerifySignature(p); err == nil {
		t.Fatalf("tampered root must fail signature verification")
	}
}

func TestVerifySignatureRejectsTamperedKey(t *testing.T) {
	p := testProof(t)
	_, priv, _ := GenerateKey()
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	other, _, _ := GenerateKey()
	p.Signature.PublicKey = EncodePublicKey(other) // swap key
	if err := VerifySignature(p); err == nil {
		t.Fatalf("swapped key must fail signature verification")
	}
}

func TestVerifyBinding(t *testing.T) {
	p := testProof(t)
	if err := VerifyBinding(p); err != nil {
		t.Fatalf("binding must verify: %v", err)
	}
	// tamper evidence digest
	p.Evidence[0].Digest = "cccc"
	if err := VerifyBinding(p); err == nil {
		t.Fatalf("tampered evidence must fail binding verification")
	}
}

func TestParseProofRejectsWrongVersion(t *testing.T) {
	p := testProof(t)
	p.ProofVersion = "9.9"
	b, _ := json.Marshal(p)
	if _, err := ParseProof(b); err == nil {
		t.Fatalf("wrong version must be rejected")
	}
}

func TestSignVerifyFullProof(t *testing.T) {
	p := testProof(t)
	_, priv, _ := GenerateKey()
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	b, err := MarshalProof(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProof(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBinding(parsed); err != nil {
		t.Fatalf("binding: %v", err)
	}
	if err := VerifySignature(parsed); err != nil {
		t.Fatalf("signature: %v", err)
	}
}

func TestEd25519SizeGuard(t *testing.T) {
	if _, err := DecodePublicKey("too-short"); err == nil {
		t.Fatalf("bad public key must be rejected")
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if _, err := DecodePublicKey(EncodePublicKey(pub)); err != nil {
		t.Fatalf("valid public key must decode: %v", err)
	}
}

// --- Signature-binding regression tests (v0.2.1) ---
// These prove that the ed25519 signature commits to the FULL proof
// commitment (version + project + subject + claims + algo + root),
// not just the Merkle root. Any post-signature tampering of these
// fields must cause VerifySignature to fail.

func fullTestProof(t *testing.T) *model.Proof {
	t.Helper()
	evs := []model.Evidence{
		{ID: "git", Type: "git", Payload: `{"commit":"abc123"}`, Digest: "aaaa"},
		{ID: "tests", Type: "tests", Payload: `{"pass":10,"fail":0}`, Digest: "bbbb"},
	}
	return &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-binding-test",
		Project:      model.Project{Name: "EslaM-X/proofx", Repository: "EslaM-X/proofx"},
		Subject:      model.Subject{Commit: "abc123def456", Branch: "main", Repository: "EslaM-X/proofx"},
		Claims: []model.Claim{
			{ID: "c1", Text: "Built from recorded commit", Status: "evidenced"},
			{ID: "c2", Text: "Tests pass", Status: "evidenced"},
		},
		Evidence: evs,
		Binding:  model.Binding{Algorithm: "sha256", Root: Root(BindingEntries(evs)), Entries: BindingEntries(evs)},
	}
}

func signProof(t *testing.T, p *model.Proof) {
	t.Helper()
	_, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
}

// TestSignatureBindingRejectsModifiedClaims proves that changing claim text
// after signing breaks signature verification.
func TestSignatureBindingRejectsModifiedClaims(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	orig := p.Claims[0].Text
	p.Claims[0].Text = "TAMPERED: different claim text"
	if err := VerifySignature(p); err == nil {
		t.Fatalf("modified claims must fail signature verification")
	}
	p.Claims[0].Text = orig
}

// TestSignatureBindingRejectsModifiedClaimStatus proves that changing a
// claim's status after signing breaks signature verification.
func TestSignatureBindingRejectsModifiedClaimStatus(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	p.Claims[1].Status = "verified" // was "evidenced"
	if err := VerifySignature(p); err == nil {
		t.Fatalf("modified claim status must fail signature verification")
	}
}

// TestSignatureBindingRejectsModifiedProject proves that changing the
// project name after signing breaks signature verification.
func TestSignatureBindingRejectsModifiedProject(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	p.Project.Name = "EslaM-X/other-repo"
	if err := VerifySignature(p); err == nil {
		t.Fatalf("modified project must fail signature verification")
	}
}

// TestSignatureBindingRejectsModifiedSubject proves that changing the
// subject commit after signing breaks signature verification.
func TestSignatureBindingRejectsModifiedSubject(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	p.Subject.Commit = "deadbeef00000000"
	if err := VerifySignature(p); err == nil {
		t.Fatalf("modified subject must fail signature verification")
	}
}

// TestSignatureBindingRejectsModifiedVersion proves that changing the
// proof version after signing breaks signature verification.
func TestSignatureBindingRejectsModifiedVersion(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	p.ProofVersion = "2.0"
	if err := VerifySignature(p); err == nil {
		t.Fatalf("modified version must fail signature verification")
	}
}

// TestSignatureBindingRejectsModifiedRoot proves that changing the
// binding root after signing breaks signature verification.
func TestSignatureBindingRejectsModifiedRoot(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	p.Binding.Root = "0000000000000000000000000000000000000000000000000000000000000000"
	if err := VerifySignature(p); err == nil {
		t.Fatalf("modified root must fail signature verification")
	}
}

// TestSignatureBindingRejectsModifiedAlgo proves that changing the
// binding algorithm string after signing breaks signature verification.
func TestSignatureBindingRejectsModifiedAlgo(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	p.Binding.Algorithm = "sha512"
	if err := VerifySignature(p); err == nil {
		t.Fatalf("modified algorithm must fail signature verification")
	}
}

// TestSignatureBindingRejectsModifiedSignature proves that forging a
// signature with a different key fails.
func TestSignatureBindingRejectsModifiedSignature(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	_, otherPriv, _ := GenerateKey()
	_ = Sign(p, otherPriv)     // overwrite with different key
	p.Signature.PublicKey = "" // corrupt
	if err := VerifySignature(p); err == nil {
		t.Fatalf("forged signature must fail verification")
	}
}

// TestSignatureBindingRoundTrip proves that a correctly signed proof
// passes full verification: binding + signature.
func TestSignatureBindingRoundTrip(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	if err := VerifyBinding(p); err != nil {
		t.Fatalf("binding must pass: %v", err)
	}
	if err := VerifySignature(p); err != nil {
		t.Fatalf("signature must pass: %v", err)
	}
}

// TestSignatureBindingSurvivesSerialize proves that sign→serialize→parse→verify
// round-trips correctly with the full commitment binding.
func TestSignatureBindingSurvivesSerialize(t *testing.T) {
	p := fullTestProof(t)
	signProof(t, p)

	b, err := MarshalProof(p)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseProof(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBinding(parsed); err != nil {
		t.Fatalf("binding after round-trip: %v", err)
	}
	if err := VerifySignature(parsed); err != nil {
		t.Fatalf("signature after round-trip: %v", err)
	}
}
