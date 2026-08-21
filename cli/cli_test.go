// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EslaM-X/proofx/evidence"
	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

func stdoutString(w io.Writer) string {
	if b, ok := w.(*bytes.Buffer); ok {
		return b.String()
	}
	return ""
}

// mkProof builds a minimal signed proof against two evidence nodes.
func mkProof(t *testing.T, artifactDigest, artifactPayload string) *model.Proof {
	t.Helper()
	evs := []model.Evidence{
		{ID: model.TypeArtifact, Type: model.TypeArtifact, Payload: artifactPayload, Digest: artifactDigest},
		{ID: model.TypeGit, Type: model.TypeGit, Payload: `{"commit":"abc"}`, Digest: evidence.EvidenceDigest(`{"commit":"abc"}`)},
	}
	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-test",
		Project:      model.Project{Name: "demo", Repository: "org/demo"},
		Subject:      model.Subject{Commit: "abc"},
		Evidence:     evs,
		Binding:      model.Binding{Algorithm: proof.BindingAlgorithm, Root: proof.Root(proof.BindingEntries(evs)), Entries: proof.BindingEntries(evs)},
		Coverage:     model.Coverage{Total: 2, Verified: 2, Score: 100},
		CreatedAt:    "2026-08-16T00:00:00Z",
		Builder:      model.Builder{Name: model.BuilderName, Version: "test"},
	}
	_, priv, err := proof.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeProof(t *testing.T, dir, name string, p *model.Proof) string {
	t.Helper()
	b, err := proof.MarshalProof(p)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyArtifactPortableMode(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "myapp.bin")
	if err := os.WriteFile(artifact, []byte("payload-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := evidence.HashFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"files": map[string]string{"myapp.bin": digest}})
	p := mkProof(t, evidence.EvidenceDigest(string(payload)), string(payload))
	proofPath := writeProof(t, dir, "proof.json", p)

	c := &CLI{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	code := c.run([]string{"verify", "--artifact", artifact, "--proof", proofPath})
	if code != 0 {
		t.Fatalf("portable verify should pass, got exit %d:\n%s", code, c.Stderr)
	}
	out := stdoutString(c.Stdout)
	if !strings.Contains(out, "VERIFIED") {
		t.Fatalf("expected VERIFIED marker in output:\n%s", out)
	}
}

func TestVerifyArtifactTamperedFails(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "myapp.bin")
	if err := os.WriteFile(artifact, []byte("payload-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _ := evidence.HashFile(artifact)
	payload, _ := json.Marshal(map[string]any{"files": map[string]string{"myapp.bin": digest}})
	p := mkProof(t, evidence.EvidenceDigest(string(payload)), string(payload))
	proofPath := writeProof(t, dir, "proof.json", p)

	// tamper the artifact
	if err := os.WriteFile(artifact, []byte("tampered!"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &CLI{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	code := c.run([]string{"verify", "--artifact", artifact, "--proof", proofPath})
	if code == 0 {
		t.Fatalf("tampered artifact must fail portable verification")
	}
}

func TestExplainReportsFailures(t *testing.T) {
	dir := t.TempDir()
	// create evidence the proof claims, then mutate it
	if err := os.WriteFile(filepath.Join(dir, "app.bin"), []byte("v1"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, _ := evidence.HashFile(filepath.Join(dir, "app.bin"))
	payload, _ := json.Marshal(map[string]any{"files": map[string]string{"app.bin": digest}})
	p := mkProof(t, evidence.EvidenceDigest(string(payload)), string(payload))
	proofPath := writeProof(t, dir, "proof.json", p)

	// change the artifact so current evidence differs
	if err := os.WriteFile(filepath.Join(dir, "app.bin"), []byte("v2"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := &CLI{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	code := c.run([]string{"explain", proofPath})
	if code != 0 {
		t.Fatalf("explain should exit 0 regardless of failure state")
	}
	out := stdoutString(c.Stdout)
	if !strings.Contains(out, "evidence") || !strings.Contains(out, "Conclusion") {
		t.Fatalf("explain should detail the evidence and show conclusion:\n%s", out)
	}
}

func TestDiffReportsChanges(t *testing.T) {
	dir := t.TempDir()
	payloadA, _ := json.Marshal(map[string]any{"files": map[string]string{"app.bin": "aaaa"}})
	payloadB, _ := json.Marshal(map[string]any{"files": map[string]string{"app.bin": "bbbb"}})
	p1 := mkProof(t, evidence.EvidenceDigest(string(payloadA)), string(payloadA))
	p2 := mkProof(t, evidence.EvidenceDigest(string(payloadB)), string(payloadB))
	a := writeProof(t, dir, "v1.json", p1)
	b := writeProof(t, dir, "v2.json", p2)

	c := &CLI{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	code := c.run([]string{"diff", a, b})
	if code != 0 {
		t.Fatalf("diff should exit 0")
	}
	out := stdoutString(c.Stdout)
	if !strings.Contains(out, "CHANGED") {
		t.Fatalf("diff should report CHANGED for modified nodes:\n%s", out)
	}
}

func TestGraphJSONModel(t *testing.T) {
	dir := t.TempDir()
	p := mkProof(t, "d1", `{"files":{}}`)
	proofPath := writeProof(t, dir, "proof.json", p)

	c := &CLI{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	code := c.run([]string{"graph", "--json", proofPath})
	if code != 0 {
		t.Fatalf("graph --json should exit 0")
	}
	var g Graph
	if err := json.Unmarshal([]byte(stdoutString(c.Stdout)), &g); err != nil {
		t.Fatalf("graph must emit valid JSON: %v", err)
	}
	if len(g.Nodes) != 2 || len(g.Relationships) == 0 {
		t.Fatalf("graph should contain nodes and relationships")
	}
	if g.Proof.ID == "" || g.Proof.BindingRoot == "" {
		t.Fatalf("graph proof ref must be populated")
	}
	_ = time.Now()
}
