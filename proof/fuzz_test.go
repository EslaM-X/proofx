// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package proof

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
)

// FuzzVerifyBytes feeds arbitrary public keys and signatures into ed25519
// verification. Must never panic.
func FuzzVerifyBytes(f *testing.F) {
	_, priv, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	pub := EncodePublicKey(PublicKeyOf(priv))
	f.Add([]byte("hello"), pub, "badsig")
	f.Add([]byte(""), pub, "")
	f.Add([]byte("test"), "short", "also-short")
	f.Fuzz(func(t *testing.T, msg []byte, pubKey string, sig string) {
		pk, err := DecodePublicKey(pubKey)
		if err != nil {
			return
		}
		_ = VerifyBytes(msg, sig, pk)
	})
}

// FuzzRoot feeds arbitrary binding entries into Root. Must never panic.
func FuzzRoot(f *testing.F) {
	f.Add("a", "d1")
	f.Add("b", "d2")
	f.Add("", "")
	f.Add("node-a", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	f.Fuzz(func(t *testing.T, id string, digest string) {
		entries := []model.BindingEntry{{ID: id, Digest: digest}}
		_ = Root(entries)
	})
}

// FuzzEvidenceDigest feeds arbitrary payload strings into EvidenceDigest.
// Must never panic and always return a 64-hex string.
func FuzzEvidenceDigest(f *testing.F) {
	f.Add(`{"commit":"abc","branch":"main","repository":"https://github.com/test/test"}`)
	f.Add(`{"pass":10,"fail":0}`)
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`"just a string"`)
	f.Add(`12345`)
	f.Add(``)
	f.Fuzz(func(t *testing.T, payload string) {
		d := evidence.EvidenceDigest(payload)
		if len(d) != 64 {
			t.Fatalf("digest length %d, want 64", len(d))
		}
	})
}

// FuzzFullVerify feeds arbitrary bytes through Parse + VerifySignature +
// VerifyBinding. Must never panic on untrusted input.
func FuzzFullVerify(f *testing.F) {
	_, priv, err := GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	raw, _ := json.Marshal(buildFuzzProof(priv))
	f.Add(raw)
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`[]`))
	f.Add(raw[:len(raw)/2])
	f.Add(corruptedJSON())
	f.Add(corruptedSignatureBytes(priv))
	f.Add(wrongKeyBytes())
	f.Fuzz(func(t *testing.T, data []byte) {
		proof, perr := ParseProof(data)
		if perr != nil {
			return
		}
		_ = VerifySignature(proof)
		_ = VerifyBinding(proof)
	})
}

func buildFuzzProof(priv ed25519.PrivateKey) *model.Proof {
	ev := model.Evidence{
		ID: "git", Type: "git", Source: "git metadata",
		Timestamp: "2026-01-01T00:00:00Z",
		Payload:   `{"commit":"abc123","branch":"main","repository":"https://github.com/test/test"}`,
		Digest:    evidence.EvidenceDigest(`{"commit":"abc123","branch":"main","repository":"https://github.com/test/test"}`),
	}
	p := &model.Proof{
		ProofVersion: "proofx/v0.2.1",
		ID:           "PX-fuzz-001",
		Project:      model.Project{Name: "fuzz", Repository: "https://github.com/test/test"},
		Subject:      model.Subject{Commit: "abc123", Branch: "main", Repository: "https://github.com/test/test"},
		Claims: []model.Claim{
			{ID: "code-quality", Text: "meets standards", Status: "verified"},
		},
		Evidence: []model.Evidence{ev},
		Binding: model.Binding{
			Algorithm: "merkle-sha256",
			Root:      Root(BindingEntries([]model.Evidence{ev})),
		},
	}
	if priv != nil {
		_ = Sign(p, priv)
	}
	return p
}

func corruptedJSON() []byte {
	return []byte(`{"proofVersion": "1.0", "evidence": [`)
}

func corruptedSignatureBytes(priv ed25519.PrivateKey) []byte {
	p := buildFuzzProof(priv)
	p.Signature.Value = "deadbeef"
	raw, _ := json.Marshal(p)
	return raw
}

func wrongKeyBytes() []byte {
	_, otherPriv, _ := GenerateKey()
	p := buildFuzzProof(otherPriv)
	raw, _ := json.Marshal(p)
	return raw
}
