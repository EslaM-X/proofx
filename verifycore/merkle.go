// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package verifycore

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/EslaM-X/proofx/model"
)

// BindingAlgorithm is the single supported binding hash.
const BindingAlgorithm = "sha256"

// SigningAlgorithm is the single supported signature scheme.
const SigningAlgorithm = "ed25519"

// Domain-separation labels (see docs/CRYPTOGRAPHY.md).
const (
	DomainLeaf = "proofx/leaf/v1\x00"
	DomainNode = "proofx/node/v1\x00"
	DomainSign = "proofx/sign/v1\x00"
)

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
// adjacent pairs are hashed together upward until one root remains.
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
