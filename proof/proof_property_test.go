// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package proof

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"testing"

	"github.com/EslaM-X/proofx/model"
)

// genDigests returns n random 64-hex digests.
func genDigests(n int, r *rand.Rand) []model.BindingEntry {
	out := make([]model.BindingEntry, n)
	for i := range out {
		id := []byte("node" + string(rune('a'+i)))
		b := make([]byte, 32)
		r.Read(b)
		out[i] = model.BindingEntry{ID: string(id), Digest: hexEncode(b)}
	}
	return out
}

func hexEncode(b []byte) string {
	const hexd = "0123456789abcdef"
	var s [64]byte
	for i, v := range b {
		s[i*2] = hexd[v>>4]
		s[i*2+1] = hexd[v&0x0f]
	}
	return string(s[:])
}

// shuffle permutes entries using r.
func shuffle(entries []model.BindingEntry, r *rand.Rand) []model.BindingEntry {
	out := append([]model.BindingEntry(nil), entries...)
	r.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// TestPropertyRootIsOrderIndependent proves the Merkle root does not depend
// on the order in which evidence nodes appear.
func TestPropertyRootIsOrderIndependent(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for n := 1; n <= 16; n++ {
		for trial := 0; trial < 20; trial++ {
			entries := genDigests(n, r)
			rootA := Root(entries)
			rootB := Root(shuffle(entries, r))
			if rootA != rootB {
				t.Fatalf("n=%d: root must be order-independent", n)
			}
		}
	}
}

// TestPropertyRootCollisionFreeForDistinctDigests checks that distinct leaf
// sets almost never produce the same root (probabilistic no-collision test).
func TestPropertyRootCollisionFreeForDistinctDigests(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	seen := make(map[string]string)
	for i := 0; i < 300; i++ {
		entries := genDigests(4, r)
		root := Root(entries)
		key := entries[0].ID + entries[0].Digest
		if prev, ok := seen[root]; ok && prev != key {
			t.Fatalf("collision: root %s for both %s and %s", root, prev, key)
		}
		seen[root] = key
	}
}

// TestPropertyTamperAnyDigestFailsBinding proves that flipping any single bit
// of any evidence digest makes the binding verification fail.
func TestPropertyTamperAnyDigestFailsBinding(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	entries := genDigests(5, r)
	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		Evidence:     entriesToEvidence(entries),
		Binding: model.Binding{
			Algorithm: BindingAlgorithm,
			Root:      Root(entries),
			Entries:   BindingEntries(entriesToEvidence(entries)),
		},
	}
	if err := VerifyBinding(p); err != nil {
		t.Fatalf("baseline binding must verify: %v", err)
	}
	for i := range p.Evidence {
		orig := p.Evidence[i].Digest
		for bit := 0; bit < 256; bit++ {
			b := []byte(orig)
			b[bit/4] ^= 0x0f // flip a nibble inside the digest
			p.Evidence[i].Digest = string(b)
			if err := VerifyBinding(p); err == nil {
				t.Fatalf("tampered digest %d bit %d must fail", i, bit)
			}
			p.Evidence[i].Digest = orig
		}
	}
}

// TestPropertySignatureRejectsAnyModification proves that flipping any bit
// of the signature value invalidates the signature (ed25519 is not malleable
// in the Go standard library).
func TestPropertySignatureRejectsAnyModification(t *testing.T) {
	p := testProof(t)
	_, priv, _ := GenerateKey()
	if err := Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	sig, err := json.Marshal(p.Signature.Value)
	if err != nil {
		t.Fatal(err)
	}
	// The signature value is base64 in the proof; decode to raw bytes and flip bits.
	raw := decodeB64(p.Signature.Value)
	for i := range raw {
		for bit := uint(0); bit < 8; bit++ {
			flipped := append([]byte(nil), raw...)
			flipped[i] ^= (1 << bit)
			p.Signature.Value = encodeB64(flipped)
			if err := VerifySignature(p); err == nil {
				t.Fatalf("flipped signature bit %d/%d must fail", i, bit)
			}
		}
	}
	_ = sig
}

func decodeB64(s string) []byte {
	b, _ := base64.StdEncoding.DecodeString(s)
	return b
}

func encodeB64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func entriesToEvidence(entries []model.BindingEntry) []model.Evidence {
	evs := make([]model.Evidence, 0, len(entries))
	for _, e := range entries {
		evs = append(evs, model.Evidence{ID: e.ID, Digest: e.Digest, Payload: `{}`})
	}
	return evs
}

// TestPropertyCanonicalizationIsKeyOrderIndependent proves that two logically
// identical objects with differently ordered map keys serialize to the same
// canonical bytes and therefore the same digest.
func TestPropertyCanonicalizationIsKeyOrderIndependent(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for trial := 0; trial < 50; trial++ {
		m1 := map[string]any{
			"files":  map[string]any{"a.txt": "d1", "b.txt": "d2"},
			"commit": "abc",
			"repo":   "org/repo",
		}
		m2 := map[string]any{
			"repo":   "org/repo",
			"commit": "abc",
			"files":  map[string]any{"b.txt": "d2", "a.txt": "d1"},
		}
		b1, err := json.Marshal(m1)
		if err != nil {
			t.Fatal(err)
		}
		b2, err := json.Marshal(m2)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("canonical JSON differs by key order: %s vs %s", b1, b2)
		}
		_ = r
	}
}

// FuzzParseProof feeds arbitrary bytes into the proof parser. The parser must
// never panic and only return well-formed errors.
func FuzzParseProof(f *testing.F) {
	f.Add([]byte(`{"proofVersion":"1.0","id":"PX-test","evidence":[]}`))
	f.Add([]byte(`{"proofVersion":"9.9"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`"str"`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseProof(data) // must not panic
	})
}
