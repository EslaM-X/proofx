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
