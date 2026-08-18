// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package verifycore

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/EslaM-X/proofx/model"
)

// commitmentDigest computes a stable digest over the full proof commitment
// (version + project + subject + claims + binding root). This ensures the
// signature commits to the complete semantic content of the proof.
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
