// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package evidence gathers raw facts about a project: git state, artifact
// digests, dependency lockfiles, test results and the build environment.
// Every collector produces a model.Evidence node whose payload is a
// canonical JSON string; the digest commits that payload.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/EslaM-X/proofx/model"
)

// CanonJSON renders v as a compact canonical JSON string.
func CanonJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// DomainEvidence is the domain-separation label for evidence payload digests.
// Every evidence digest commits this label, so hashes can never be confused
// with hashes of other data (e.g. a Merkle leaf or a file hash).
const DomainEvidence = "proofx/evidence/v1\x00"

// Digests returns the raw hex sha256 of s. Prefer EvidenceDigest for any
// value that will be embedded in a proof.
func Digests(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// EvidenceDigest computes the domain-separated digest of a canonical payload.
func EvidenceDigest(canon string) string {
	return Digests(DomainEvidence + canon)
}

// DigestOf hashes the canonical JSON of v with domain separation.
func DigestOf(v any) (string, error) {
	s, err := CanonJSON(v)
	if err != nil {
		return "", err
	}
	return EvidenceDigest(s), nil
}

// Collectors is the ordered set of evidence collectors.
type Collectors struct {
	Git       func() (any, error)
	Artifacts func() (any, error)
	Depends   func() (any, error)
	Tests     func() (any, error)
	Env       func() (any, error)
}

// Result is one collected evidence node plus its runtime error.
type Result struct {
	Evidence model.Evidence
	Err      error
}

// Collect runs every collector and returns sorted evidence nodes.
func Collect(c *Collectors, now time.Time) []Result {
	steps := []struct {
		typ string
		fn  func() (any, error)
	}{
		{model.TypeGit, c.Git},
		{model.TypeArtifact, c.Artifacts},
		{model.TypeDependency, c.Depends},
		{model.TypeTests, c.Tests},
		{model.TypeEnvironment, c.Env},
	}
	results := make([]Result, 0, len(steps))
	for _, s := range steps {
		if s.fn == nil {
			continue
		}
		payload, err := s.fn()
		if err != nil {
			results = append(results, Result{Err: fmt.Errorf("%s: %w", s.typ, err)})
			continue
		}
		if payload == nil {
			continue // collector intentionally produced nothing
		}
		canon, err := CanonJSON(payload)
		if err != nil {
			results = append(results, Result{Err: fmt.Errorf("%s: %w", s.typ, err)})
			continue
		}
		ev := model.Evidence{
			ID:        s.typ,
			Type:      s.typ,
			Source:    sourceOf(s.typ, payload),
			Timestamp: now.UTC().Format(time.RFC3339),
			Payload:   canon,
			Digest:    EvidenceDigest(canon),
		}
		results = append(results, Result{Evidence: ev})
	}
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Evidence.ID < results[j].Evidence.ID
	})
	return results
}

// sourceOf gives each node a human-readable provenance pointer.
func sourceOf(typ string, payload any) string {
	switch typ {
	case model.TypeGit:
		if m, ok := payload.(map[string]any); ok {
			if repo, ok := m["repository"].(string); ok && repo != "" {
				return "git: " + repo
			}
		}
		return "git metadata"
	case model.TypeArtifact:
		return "sha256 of configured artifacts"
	case model.TypeDependency:
		return "dependency lockfile digest"
	case model.TypeTests:
		return "test result summary"
	case model.TypeEnvironment:
		return "build toolchain + os"
	default:
		return "local collection"
	}
}

// EvidenceByID indexes evidence nodes.
func EvidenceByID(evs []model.Evidence) map[string]model.Evidence {
	m := make(map[string]model.Evidence, len(evs))
	for _, e := range evs {
		m[e.ID] = e
	}
	return m
}
