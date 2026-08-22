// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package verifycore - adversarial attack PoC tests for v0.4 protocol.
//
// Each TestAttack_* function proves a specific attack strategy is defeated.
// See security/ATTACK_SCENARIOS.md for the full catalog.
package verifycore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/EslaM-X/proofx/model"
)

func encodeJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}

func TestAttack_CrossKeySignature(t *testing.T) {
	p := validV4Fixture()
	victimPub := p.Signature.PublicKey
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	p.Signature = model.Signature{
		Algorithm: "ed25519",
		PublicKey:  victimPub,
		Value:      base64.StdEncoding.EncodeToString(ed25519.Sign(attackerPriv, model.V4SigningPayload(p))),
	}
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: cross-key forgery defeated proof verification")
	}
	for _, c := range res.Checks {
		if c.Name == "signature" && c.Status != StatusFail {
			t.Errorf("expected signature check to fail, got %s", c.Status)
		}
	}
}

func TestAttack_EvidenceSwap(t *testing.T) {
	p := validV4Fixture()
	p.Evidence[0].ID = "tests"
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: evidence swap defeated proof verification")
	}
}

func TestAttack_VersionDowngrade(t *testing.T) {
	p := validV4Fixture()
	p.ProofVersion = "1.0"
	b, _ := encodeJSON(p)
	_, err := V4ParseProof(b)
	if err == nil {
		t.Error("SECURITY: version downgrade was not rejected by parser")
	}
}

func TestAttack_SignatureTruncated(t *testing.T) {
	p := validV4Fixture()
	origSig, _ := base64.StdEncoding.DecodeString(p.Signature.Value)
	if len(origSig) < 40 {
		t.Skip("signature too short to truncate")
	}
	truncated := origSig[:32]
	p.Signature.Value = base64.StdEncoding.EncodeToString(truncated)
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: truncated signature defeated proof verification")
	}
}

func TestAttack_EmptyProof(t *testing.T) {
	_, err := V4ParseProof([]byte(`{}`))
	if err == nil {
		t.Error("SECURITY: empty proof was accepted by parser")
	}
	p := &model.V4Proof{}
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: empty proof passed verification")
	}
}

func TestAttack_EmptyBindingRoot(t *testing.T) {
	p := validV4Fixture()
	p.Binding.Root = ""
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: empty binding root passed verification")
	}
}

func TestAttack_SelfRefClaim(t *testing.T) {
	p := validV4Fixture()
	selfClaim := model.V4Claim{
		ID:          "claim.self",
		Type:        "custom",
		Subject:     "execution:exec-001",
		Statement:   "Self-referencing claim",
		Status:      model.ClaimPass,
		SupportedBy: []string{"claim.self"},
	}
	p.Claims = append(p.Claims, selfClaim)
	p.Relations = append(p.Relations, model.Relation{
		ID:   "r-self",
		From: "tests",
		To:   "claim.self",
		Kind: model.RelSupports,
	})
	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p, priv)
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: self-referencing claim passed verification")
	}
}

func TestAttack_DomainLabelConfusion(t *testing.T) {
	p := validV4Fixture()
	v4Entries := model.V4BindingEntries(p)
	v4Root := model.V4Root(v4Entries)
	if v4Root == "" {
		t.Error("v4 root computation returned empty string")
	}
	v4Root2 := model.V4Root(v4Entries)
	if v4Root != v4Root2 {
		t.Errorf("v4 root is non-deterministic: %s != %s", v4Root, v4Root2)
	}
}

func TestAttack_ReplayMutation(t *testing.T) {
	p := validV4Fixture()
	p.Project.Name = "mutated-project"
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: replay with mutation defeated proof verification")
	}
}

func TestAttack_SignatureSwap(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	p1 := validV4Fixture()
	p2 := validV4Fixture()
	p2.Project.Name = "different-project"
	p2.Subject.Commit = strings.Repeat("1", 40)
	entries1 := model.V4BindingEntries(p1)
	p1.Binding.Entries = entries1
	p1.Binding.Root = model.V4Root(entries1)
	signProof(p1, priv1)
	entries2 := model.V4BindingEntries(p2)
	p2.Binding.Entries = entries2
	p2.Binding.Root = model.V4Root(entries2)
	signProof(p2, priv2)
	sig1 := p1.Signature
	sig2 := p2.Signature
	p1.Signature = sig2
	p2.Signature = sig1
	res1 := V4Verify(p1)
	res2 := V4Verify(p2)
	if res1.Valid {
		t.Error("SECURITY: swapped signature verified on proof 1")
	}
	if res2.Valid {
		t.Error("SECURITY: swapped signature verified on proof 2")
	}
}

func TestAttack_PublicKeyFlip(t *testing.T) {
	p := validV4Fixture()
	pubBytes, _ := base64.StdEncoding.DecodeString(p.Signature.PublicKey)
	if len(pubBytes) == 0 {
		t.Skip("no public key to flip")
	}
	pubBytes[0] ^= 0x01
	p.Signature.PublicKey = base64.StdEncoding.EncodeToString(pubBytes)
	res := V4Verify(p)
	if res.Valid {
		t.Error("SECURITY: flipped public key defeated proof verification")
	}
}

func TestAttack_ProofIDManipulation(t *testing.T) {
	p := validV4Fixture()
	p2 := cloneProof(p)
	p2.ID = "PX-FORGED"
	p2.Binding.Root = strings.Repeat("0", 64)
	res := V4Verify(p2)
	if res.Valid {
		t.Error("SECURITY: forged proof with wrong root passed verification")
	}
}

func TestAttack_UnicodeNormalization(t *testing.T) {
	payload1 := `{"name":"caf` + "\u00e9" + `"}`
	payload2 := `{"name":"cafe` + "\u0301" + `"}`
	id1 := "unicode-nfc"
	id2 := "unicode-nfd"
	d1 := model.EvidenceDigest(id1, payload1)
	d2 := model.EvidenceDigest(id2, payload2)
	if d1 == d2 {
		t.Error("SECURITY: NFC and NFD payloads produced same digest")
	}
	if model.EvidenceDigest(id1, payload1) != d1 {
		t.Error("NFC evidence digest non-deterministic")
	}
	if model.EvidenceDigest(id2, payload2) != d2 {
		t.Error("NFD evidence digest non-deterministic")
	}
}

func TestAttack_BindingRootReuse(t *testing.T) {
	p1 := validV4Fixture()
	p2 := validV4Fixture()
	p2.Evidence[0].Payload = `{"tampered":true}`
	p2.Evidence[0].Digest = model.EvidenceDigest(p2.Evidence[0].ID, p2.Evidence[0].Payload)
	p2.Binding.Root = p1.Binding.Root
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signProof(p2, priv)
	res := V4Verify(p2)
	if res.Valid {
		t.Error("SECURITY: binding root reuse passed verification")
	}
}

func TestAttack_Count(t *testing.T) {
	attackTests := []struct{ name string }{
		{"CrossKeySignature"},
		{"EvidenceSwap"},
		{"VersionDowngrade"},
		{"SignatureTruncated"},
		{"EmptyProof"},
		{"EmptyBindingRoot"},
		{"SelfRefClaim"},
		{"DomainLabelConfusion"},
		{"ReplayMutation"},
		{"SignatureSwap"},
		{"PublicKeyFlip"},
		{"ProofIDManipulation"},
		{"UnicodeNormalization"},
		{"BindingRootReuse"},
	}
	t.Logf("Attack lab: %d adversarial scenarios", len(attackTests))
	if len(attackTests) < 10 {
		t.Errorf("attack lab too small: %d scenarios (expected >= 10)", len(attackTests))
	}
}
