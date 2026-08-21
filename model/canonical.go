// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package model provides canonical encoding for ProofX v0.4 objects.
//
// Canonical encoding is deterministic: the same logical object always
// produces the same bytes, regardless of Go struct field ordering or
// JSON serialization quirks. This is critical for cryptographic binding.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// Canonicalize produces a deterministic JSON byte representation of v.
// Field ordering is sorted lexicographically. No extra whitespace.
// This is used for hashing evidence payloads, relation digests, and
// claim digests into the Merkle tree.
func Canonicalize(v interface{}) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// json.Marshal already produces sorted keys for structs in Go,
	// but for maps we need to re-sort. Parse and re-marshal with sort.
	var raw interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return canonicalValue(raw), nil
}

// canonicalValue recursively sorts map keys and re-encodes.
func canonicalValue(v interface{}) []byte {
	switch val := v.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf := []byte("{")
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			km, _ := json.Marshal(k)
			buf = append(buf, km...)
			buf = append(buf, ':')
			buf = append(buf, canonicalValue(val[k])...)
		}
		buf = append(buf, '}')
		return buf
	case []interface{}:
		buf := []byte("[")
		for i, item := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			buf = append(buf, canonicalValue(item)...)
		}
		buf = append(buf, ']')
		return buf
	default:
		b, _ := json.Marshal(val)
		return b
	}
}

// EvidenceDigest computes the domain-separated SHA-256 digest of an
// evidence node's payload. This is the leaf hash used in the Merkle tree.
//
// Domain label: "proofx/evidence/v1\x00"
// Format: domain_label + id + ":" + canonical_payload
func EvidenceDigest(id string, payload string) string {
	h := sha256.Sum256([]byte(DomainEvidence + id + ":" + payload))
	return hex.EncodeToString(h[:])
}

// RelationDigest computes the SHA-256 digest of a relation for binding.
func RelationDigest(r *Relation) string {
	type relCanon struct {
		From string `json:"from"`
		To   string `json:"to"`
		Kind string `json:"kind"`
	}
	c := relCanon{From: r.From, To: r.To, Kind: r.Kind}
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// ClaimDigest computes the SHA-256 digest of a claim for binding.
func ClaimDigest(c *V4Claim) string {
	type claimCanon struct {
		Type        string   `json:"type"`
		Subject     string   `json:"subject"`
		Statement   string   `json:"statement"`
		Status      string   `json:"status"`
		SupportedBy []string `json:"supportedBy"`
	}
	cc := claimCanon{
		Type:        c.Type,
		Subject:     c.Subject,
		Statement:   c.Statement,
		Status:      c.Status,
		SupportedBy: c.SupportedBy,
	}
	b, _ := json.Marshal(cc)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Domain separation labels.
const (
	DomainEvidence = "proofx/evidence/v1\x00"
)
