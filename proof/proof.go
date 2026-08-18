// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package proof builds, signs and verifies ProofX proof documents.
//
// The verification logic lives in verifycore. This package re-exports
// verifycore's API for backward compatibility and provides signing
// functions that are not part of the verification core.
package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/verifycore"
)

// Re-exported constants from verifycore.
const (
	BindingAlgorithm = verifycore.BindingAlgorithm
	SigningAlgorithm = verifycore.SigningAlgorithm
	DomainLeaf       = verifycore.DomainLeaf
	DomainNode       = verifycore.DomainNode
	DomainSign       = verifycore.DomainSign
)

// Re-exported errors from verifycore.
var ErrSignatureInvalid = verifycore.ErrSignatureInvalid

// Re-exported functions from verifycore.

func BindingEntries(evs []model.Evidence) []model.BindingEntry {
	return verifycore.BindingEntries(evs)
}

func Root(entries []model.BindingEntry) string {
	return verifycore.Root(entries)
}

func ParseProof(b []byte) (*model.Proof, error) {
	return verifycore.ParseProof(b)
}

func VerifyBinding(p *model.Proof) error {
	return verifycore.VerifyBinding(p)
}

func VerifySignature(p *model.Proof) error {
	return verifycore.VerifySignature(p)
}

func VerifyBytes(data []byte, sigB64 string, pub ed25519.PublicKey) error {
	return verifycore.VerifyBytes(data, sigB64, pub)
}

func EncodePublicKey(pub ed25519.PublicKey) string {
	return verifycore.EncodePublicKey(pub)
}

func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	return verifycore.DecodePublicKey(s)
}

// Signing functions remain in proof (not part of verification core).

func SignBytes(data []byte, key ed25519.PrivateKey) (string, error) {
	sig := ed25519.Sign(key, data)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func PublicKeyOf(priv ed25519.PrivateKey) ed25519.PublicKey {
	return priv.Public().(ed25519.PublicKey)
}

func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return pub, priv, nil
}

func Sign(p *model.Proof, priv ed25519.PrivateKey) error {
	sig, err := SignBytes(signingPayload(p), priv)
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

func MarshalProof(p *model.Proof) ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// signingPayload computes the signed payload for a proof.
// This mirrors verifycore's bindingPayload but is kept here for the
// signing path (verifycore only verifies, never signs).
func signingPayload(p *model.Proof) []byte {
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
	commitment := fmt.Sprintf("%x", h.Sum(nil))
	return []byte(DomainSign + commitment)
}

// Unused but kept for potential future use in tests.
var _ = errors.New
