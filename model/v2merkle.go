// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package model provides v0.4 Merkle binding and commitment computation.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
)

// v0.4 domain separation labels.
const (
	DomainLeafV2 = "proofx/leaf/v2\x00"
	DomainNodeV2 = "proofx/node/v2\x00"
	DomainSignV2 = "proofx/sign/v2\x00"
)

// V4BindingEntries computes the canonical ordered leaf list for a v0.4 proof.
// Leaves include evidence, relations, and claims — all bound together.
func V4BindingEntries(p *V4Proof) []BindingEntry {
	var entries []BindingEntry

	// Evidence leaves
	for _, e := range p.Evidence {
		entries = append(entries, BindingEntry{
			ID:     "ev:" + e.ID,
			Digest: e.Digest,
		})
	}

	// Relation leaves
	for _, r := range p.Relations {
		entries = append(entries, BindingEntry{
			ID:     "rel:" + r.ID,
			Digest: RelationDigest(&r),
		})
	}

	// Claim leaves
	for _, c := range p.Claims {
		entries = append(entries, BindingEntry{
			ID:     "claim:" + c.ID,
			Digest: ClaimDigest(&c),
		})
	}

	// Sort by ID for deterministic ordering
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})
	return entries
}

// V4Root computes the v0.4 Merkle root over all binding entries.
func V4Root(entries []BindingEntry) string {
	if len(entries) == 0 {
		return ""
	}

	sorted := append([]BindingEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	level := make([][32]byte, 0, len(sorted))
	for _, e := range sorted {
		level = append(level, sha256.Sum256([]byte(DomainLeafV2+e.ID+":"+e.Digest)))
	}

	for len(level) > 1 {
		var next [][32]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				combined := make([]byte, 0, 64+len(DomainNodeV2))
				combined = append(combined, DomainNodeV2...)
				combined = append(combined, level[i][:]...)
				combined = append(combined, level[i+1][:]...)
				next = append(next, sha256.Sum256(combined))
			} else {
				next = append(next, level[i])
			}
		}
		level = next
	}

	return hex.EncodeToString(level[0][:])
}

// V4CommitmentDigest computes the full commitment digest for a v0.4 proof.
// This is the value signed with Ed25519.
func V4CommitmentDigest(p *V4Proof) string {
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

	// Execution
	h.Write([]byte(p.Execution.ID))
	h.Write([]byte{0})
	h.Write([]byte(p.Execution.Type))
	h.Write([]byte{0})
	h.Write([]byte(p.Execution.StartedAt))
	h.Write([]byte{0})
	h.Write([]byte(p.Execution.CompletedAt))
	h.Write([]byte{0})

	// Claims (sorted by ID for determinism)
	sortedClaims := append([]V4Claim(nil), p.Claims...)
	sort.Slice(sortedClaims, func(i, j int) bool { return sortedClaims[i].ID < sortedClaims[j].ID })
	for _, c := range sortedClaims {
		h.Write([]byte(c.ID))
		h.Write([]byte{0})
		h.Write([]byte(c.Type))
		h.Write([]byte{0})
		h.Write([]byte(c.Statement))
		h.Write([]byte{0})
		h.Write([]byte(c.Status))
		h.Write([]byte{0})
	}

	h.Write([]byte(p.Binding.Algorithm))
	h.Write([]byte{0})
	h.Write([]byte(p.Binding.Root))

	return hex.EncodeToString(h.Sum(nil))
}

// V4SigningPayload returns the exact bytes signed with Ed25519.
func V4SigningPayload(p *V4Proof) []byte {
	return []byte(DomainSignV2 + V4CommitmentDigest(p))
}
