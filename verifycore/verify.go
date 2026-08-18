// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package verifycore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/EslaM-X/proofx/model"
)

// ErrSignatureInvalid is returned when a proof signature does not verify.
var ErrSignatureInvalid = errors.New("proofx: signature invalid")

// ParseProof decodes a proof document from JSON bytes.
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

// VerifySignature re-checks the proof's ed25519 signature over the full
// commitment digest.
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

// Verify performs the full static verification pipeline on a proof:
// binding integrity + signature validity. This is the primary entry point
// for consumers that do not need evidence re-collection.
func Verify(p *model.Proof) VerifyResult {
	res := VerifyResult{ProofID: p.ID, Checks: make([]Check, 0, 3)}

	bindErr := VerifyBinding(p)
	res.Checks = append(res.Checks, Check{
		Name:   "binding",
		Status: statusOf(bindErr),
		Detail: detailOf(bindErr, "merkle root matches evidence digests"),
	})

	sigErr := VerifySignature(p)
	res.Checks = append(res.Checks, Check{
		Name:   "signature",
		Status: statusOf(sigErr),
		Detail: detailOf(sigErr, "ed25519 over full commitment"),
	})

	valid := bindErr == nil && sigErr == nil
	res.Valid = valid
	res.Coverage = model.Coverage{
		Total:    len(p.Evidence),
		Verified: boolInt(valid) * len(p.Evidence),
		Score:    boolInt(valid) * 100,
	}
	return res
}

// EncodePublicKey returns the base64 raw public key for embedding in a proof.
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

func statusOf(err error) string {
	if err == nil {
		return StatusOK
	}
	return StatusFail
}

func detailOf(err error, okDetail string) string {
	if err == nil {
		return okDetail
	}
	return err.Error()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
