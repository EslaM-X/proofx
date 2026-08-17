// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package proof builds, signs and verifies ProofX proof documents.
//
// The cryptographic design reuses standard primitives only:
//   - sha256 for every digest (evidence payloads and the binding root)
//   - ed25519 (RFC 8032) for signatures over the binding root
//   - a Merkle-style root computed over the sorted evidence digests
//
// ProofX does NOT invent cryptography; it makes existing standards easy
// to use and human-readable.
package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/EslaM-X/proofx/model"
)

// BindingAlgorithm is the single supported binding hash.
const BindingAlgorithm = "sha256"

// SigningAlgorithm is the single supported signature scheme.
const SigningAlgorithm = "ed25519"

// Domain-separation labels (see docs/CRYPTOGRAPHY.md). Every hash step in
// the protocol commits a fixed prefix so no hash output can be confused
// with a hash of different data (domain separation).
const (
	DomainLeaf = "proofx/leaf/v1\x00"
	DomainNode = "proofx/node/v1\x00"
	DomainSign = "proofx/sign/v1\x00"
)

// ErrSignatureInvalid is returned when a proof signature does not verify.
var ErrSignatureInvalid = errors.New("proofx: signature invalid")

// BindingEntries derives the canonical ordered (id, digest) leaf list.
func BindingEntries(evs []model.Evidence) []model.BindingEntry {
	entries := make([]model.BindingEntry, 0, len(evs))
	for _, e := range evs {
		entries = append(entries, model.BindingEntry{ID: e.ID, Digest: e.Digest})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

// Root computes the Merkle-style root over the evidence digests. Leaves are
// sorted by id, then each leaf is the domain-separated hash of "id:digest";
// adjacent pairs are hashed together upward until one root remains. A single
// leaf roots to itself.
func Root(entries []model.BindingEntry) string {
	if len(entries) == 0 {
		return ""
	}
	sorted := append([]model.BindingEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	level := make([][]byte, 0, len(sorted))
	for _, e := range sorted {
		h := sha256.Sum256([]byte(DomainLeaf + e.ID + ":" + e.Digest))
		level = append(level, h[:])
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				h := sha256.Sum256([]byte(DomainNode + string(level[i]) + string(level[i+1])))
				next = append(next, h[:])
			} else {
				next = append(next, level[i])
			}
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

// SignBytes signs data with the ed25519 key and returns base64.
func SignBytes(data []byte, key ed25519.PrivateKey) (string, error) {
	sig := ed25519.Sign(key, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyBytes verifies a base64 ed25519 signature over data.
func VerifyBytes(data []byte, sigB64 string, pub ed25519.PublicKey) error {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	if !ed25519.Verify(pub, data, sig) {
		return ErrSignatureInvalid
	}
	return nil
}

// PublicKeyOf returns the raw public key bytes from a private key.
func PublicKeyOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

// GenerateKey creates a fresh ed25519 key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

// EncodePublicKey returns the base64 (raw) public key for embedding in a proof.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// DecodePublicKey parses a base64 raw ed25519 public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, errors.New("proofx: bad public key length")
	}
	return ed25519.PublicKey(b), nil
}

// commitmentDigest computes a stable digest over the non-redundant proof
// commitment (version + project + subject + claims + binding root). This
// ensures the signature commits to the full semantic content of the proof,
// not just the evidence root.
func commitmentDigest(p *model.Proof) string {
	h := sha256.New()
	h.Write([]byte(p.ProofVersion))
	h.Write([]byte{0})
	h.Write([]byte(p.Project.Name))
	h.Write([]byte{0})
	h.Write([]byte(p.Project.Repository))
	h.Write([]byte{0})
	h.Write([]byte(p.Subject.Commit))
	h.Write([]byte{0})
	h.Write([]byte(p.Subject.Branch))
	h.Write([]byte{0})
	h.Write([]byte(p.Subject.Repository))
	h.Write([]byte{0})
	for _, c := range p.Claims {
		h.Write([]byte(c.ID))
		h.Write([]byte{0})
		h.Write([]byte(c.Text))
		h.Write([]byte{0})
		h.Write([]byte(c.Status))
		h.Write([]byte{0})
	}
	h.Write([]byte(p.Binding.Algorithm))
	h.Write([]byte{0})
	h.Write([]byte(p.Binding.Root))
	return hex.EncodeToString(h.Sum(nil))
}

// bindingPayload is the exact byte string signed: domain label + commitment hash.
func bindingPayload(p *model.Proof) []byte {
	return []byte(DomainSign + commitmentDigest(p))
}

// Sign attaches an ed25519 signature over the binding root.
func Sign(p *model.Proof, priv ed25519.PrivateKey) error {
	sig, err := SignBytes(bindingPayload(p), priv)
	if err != nil {
		return err
	}
	p.Signature = model.Signature{
		Algorithm: SigningAlgorithm,
		PublicKey: EncodePublicKey(PublicKeyOf(priv)),
		Value:     sig,
	}
	return nil
}

// VerifySignature re-checks the proof's signature over its binding root.
func VerifySignature(p *model.Proof) error {
	if p.Signature.Algorithm != SigningAlgorithm {
		return fmt.Errorf("proofx: unsupported signature algorithm %q", p.Signature.Algorithm)
	}
	pub, err := DecodePublicKey(p.Signature.PublicKey)
	if err != nil {
		return fmt.Errorf("proofx: %w", err)
	}
	return VerifyBytes(bindingPayload(p), p.Signature.Value, pub)
}

// VerifyBinding recomputes the binding root from the proof's evidence and
// compares it to the recorded root.
func VerifyBinding(p *model.Proof) error {
	if p.Binding.Algorithm != BindingAlgorithm {
		return fmt.Errorf("proofx: unsupported binding algorithm %q", p.Binding.Algorithm)
	}
	want := Root(BindingEntries(p.Evidence))
	if want != p.Binding.Root {
		return fmt.Errorf("proofx: binding root mismatch: proof=%s recomputed=%s", p.Binding.Root, want)
	}
	return nil
}

// MarshalProof renders a proof as indented JSON.
func MarshalProof(p *model.Proof) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// ParseProof decodes a proof document.
func ParseProof(b []byte) (*model.Proof, error) {
	var p model.Proof
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if p.ProofVersion != model.ProofVersion {
		return nil, fmt.Errorf("proofx: unsupported proof version %q", p.ProofVersion)
	}
	return &p, nil
}
