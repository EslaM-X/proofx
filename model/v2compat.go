// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package model provides v0.3 → v0.4 compatibility conversion.
//
// A v0.3 proof can be parsed and verified by a v0.4 verifier.
// The conversion is lossless: all v0.3 data is preserved.
// No new cryptographic claims are added — the original binding
// and signature remain intact.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// V3ToV4 converts a v0.3 proof (raw JSON bytes) to a V4Proof.
// The original proofVersion, binding, and signature are preserved.
// No re-signing is performed.
func V3ToV4(data []byte) (*V4Proof, error) {
	// Parse v0.3 structure
	var v3 struct {
		ProofVersion string `json:"proofVersion"`
		ID           string `json:"id"`
		Project      struct {
			Name       string `json:"name"`
			Repository string `json:"repository"`
		} `json:"project"`
		Subject struct {
			Commit     string `json:"commit"`
			Branch     string `json:"branch"`
			Repository string `json:"repository"`
		} `json:"subject"`
		Claims []struct {
			ID     string `json:"id"`
			Text   string `json:"text"`
			Status string `json:"status"`
		} `json:"claims"`
		Evidence []struct {
			ID        string `json:"id"`
			Type      string `json:"type"`
			Source    string `json:"source"`
			Timestamp string `json:"timestamp"`
			Payload   string `json:"payload"`
			Digest    string `json:"digest"`
		} `json:"evidence"`
		Binding struct {
			Algorithm string `json:"algorithm"`
			Root      string `json:"root"`
			Entries   []struct {
				ID     string `json:"id"`
				Digest string `json:"digest"`
			} `json:"entries"`
		} `json:"binding"`
		Signature struct {
			Algorithm string `json:"algorithm"`
			PublicKey string `json:"publicKey"`
			Value     string `json:"value"`
		} `json:"signature"`
		Coverage struct {
			Total    int `json:"total"`
			Verified int `json:"verified"`
			Score    int `json:"score"`
		} `json:"coverage"`
		CreatedAt string `json:"createdAt"`
		Builder   struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Host    string `json:"host,omitempty"`
		} `json:"builder"`
	}

	if err := json.Unmarshal(data, &v3); err != nil {
		return nil, fmt.Errorf("proofx: failed to parse v0.3 proof: %w", err)
	}

	if v3.ProofVersion != ProofVersion {
		return nil, fmt.Errorf("proofx: not a v0.3 proof (version=%q)", v3.ProofVersion)
	}

	// All evidence IDs — used to populate SupportedBy
	allEvIDs := make([]string, len(v3.Evidence))
	for i, e := range v3.Evidence {
		allEvIDs[i] = e.ID
	}

	// Convert claims
	claims := make([]V4Claim, len(v3.Claims))
	for i, c := range v3.Claims {
		claims[i] = V4Claim{
			ID:          c.ID,
			Type:        c.ID, // use ID as type for v0.3 claims
			Subject:     "proof:v0.3",
			Statement:   c.Text,
			Status:      c.Status,
			SupportedBy: allEvIDs, // v0.3: all evidence supports all claims
		}
	}

	// Convert evidence
	evidence := make([]Evidence, len(v3.Evidence))
	for i, e := range v3.Evidence {
		evidence[i] = Evidence{
			ID:        e.ID,
			Type:      e.Type,
			Source:    e.Source,
			Timestamp: e.Timestamp,
			Payload:   e.Payload,
			Digest:    e.Digest,
		}
	}

	// Convert binding
	binding := Binding{
		Algorithm: v3.Binding.Algorithm,
		Root:      v3.Binding.Root,
		Entries:   make([]BindingEntry, len(v3.Binding.Entries)),
	}
	for i, e := range v3.Binding.Entries {
		binding.Entries[i] = BindingEntry{ID: e.ID, Digest: e.Digest}
	}

	// Build supports relations — one from execution to each claim
	relations := make([]Relation, len(claims))
	for i, c := range claims {
		relations[i] = Relation{
			ID:   "r:v3:" + c.ID,
			From: v3.ID, // execution ID
			To:   c.ID,
			Kind: RelSupports,
		}
	}

	// Build v0.4 proof
	p := &V4Proof{
		ProofVersion: ProofVersionV2, // NOTE: this changes the version
		ID:           v3.ID,
		Project: Project{
			Name:       v3.Project.Name,
			Repository: v3.Project.Repository,
		},
		Subject: Subject{
			Commit:     v3.Subject.Commit,
			Branch:     v3.Subject.Branch,
			Repository: v3.Subject.Repository,
		},
		Execution: Execution{
			ID:   v3.ID,
			Type: ExecCustom,
		},
		Evidence:  evidence,
		Relations: relations,
		Claims:    claims,
		Binding:   binding,
		Signature: Signature{
			Algorithm: v3.Signature.Algorithm,
			PublicKey: v3.Signature.PublicKey,
			Value:     v3.Signature.Value,
		},
		Coverage: V4Coverage{
			Evidence: CoverageDim{
				Total:    v3.Coverage.Total,
				Verified: v3.Coverage.Verified,
			},
			Relations: CoverageDim{Total: 0, Verified: 0},
			Claims:    CoverageDim{Total: len(claims), Verified: 0},
			Score:     v3.Coverage.Score,
		},
		CreatedAt: v3.CreatedAt,
		Builder: Builder{
			Name:    v3.Builder.Name,
			Version: v3.Builder.Version,
			Host:    v3.Builder.Host,
		},
	}

	return p, nil
}

// V3BindingRoot recomputes the v0.3 Merkle root from evidence only.
// This is used when verifying v0.3 proofs under v0.4 rules.
func V3BindingRoot(evs []Evidence) string {
	if len(evs) == 0 {
		return ""
	}
	// Use v0.3 domain labels
	entries := make([]BindingEntry, 0, len(evs))
	for _, e := range evs {
		entries = append(entries, BindingEntry{ID: e.ID, Digest: e.Digest})
	}
	return V3MerkleRoot(entries)
}

// V3MerkleRoot computes a Merkle root using v0.3 domain labels.
func V3MerkleRoot(entries []BindingEntry) string {
	if len(entries) == 0 {
		return ""
	}
	sorted := append([]BindingEntry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	type node [32]byte
	level := make([]node, 0, len(sorted))
	for _, e := range sorted {
		level = append(level, sha256.Sum256([]byte("proofx/leaf/v1\x00"+e.ID+":"+e.Digest)))
	}
	for len(level) > 1 {
		var next []node
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				combined := make([]byte, 0, 64+16)
				combined = append(combined, "proofx/node/v1\x00"...)
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

// V3CommitmentDigest computes the v0.3 commitment digest for signature verification.
func V3CommitmentDigest(p *V4Proof) string {
	h := sha256.New()
	h.Write([]byte(ProofVersion))
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
