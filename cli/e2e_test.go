// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package cli contains end-to-end tests for all v0.4 CLI commands.
package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

// ---------------------------------------------------------------------------
// v0.4 test helpers
// ---------------------------------------------------------------------------

// mkV4Proof builds a minimal signed v0.4 proof with 4 evidence nodes,
// 8 relations, and 4 claims.
func mkV4Proof(t *testing.T) *model.V4Proof {
	t.Helper()

	payloadGit := `{"branch":"main","commit":"abc123def456789012345678901234567890abcd","repository":"https://github.com/test/repo"}`
	payloadArtifact := `{"files":{"myapp.bin":"aabbccdd"}}`
	payloadTests := `{"passed":42,"failed":0}`
	payloadEnv := `{"os":"ubuntu-24.04","arch":"amd64","runtime":"go1.26.5"}`

	evGit := model.Evidence{ID: "git", Type: "git", Source: "git", Payload: payloadGit, Digest: model.EvidenceDigest("git", payloadGit)}
	evArtifact := model.Evidence{ID: "artifact", Type: "artifact", Source: "build", Payload: payloadArtifact, Digest: model.EvidenceDigest("artifact", payloadArtifact)}
	evTests := model.Evidence{ID: "tests", Type: "tests", Source: "test-runner", Payload: payloadTests, Digest: model.EvidenceDigest("tests", payloadTests)}
	evEnv := model.Evidence{ID: "environment", Type: "environment", Source: "detect", Payload: payloadEnv, Digest: model.EvidenceDigest("environment", payloadEnv)}

	evs := []model.Evidence{evGit, evArtifact, evTests, evEnv}

	relations := []model.Relation{
		{ID: "r1", From: "exec-001", To: "git", Kind: model.RelProduces},
		{ID: "r2", From: "exec-001", To: "artifact", Kind: model.RelProduces},
		{ID: "r3", From: "exec-001", To: "tests", Kind: model.RelProduces},
		{ID: "r4", From: "exec-001", To: "environment", Kind: model.RelProduces},
		{ID: "r5", From: "tests", To: "claim.tests_passed", Kind: model.RelSupports},
		{ID: "r6", From: "artifact", To: "claim.artifact_integrity", Kind: model.RelSupports},
		{ID: "r7", From: "git", To: "claim.execution_bound", Kind: model.RelSupports},
		{ID: "r8", From: "environment", To: "claim.environment_recorded", Kind: model.RelSupports},
	}

	claims := []model.V4Claim{
		{ID: "claim.tests_passed", Type: "tests_passed", Subject: "execution:exec-001", Statement: "All tests passed", Status: model.ClaimPass, SupportedBy: []string{"tests"}},
		{ID: "claim.artifact_integrity", Type: "artifact_integrity", Subject: "execution:exec-001", Statement: "Artifact digests verified", Status: model.ClaimPass, SupportedBy: []string{"artifact"}},
		{ID: "claim.execution_bound", Type: "execution_bound", Subject: "execution:exec-001", Statement: "Bound to commit abc123", Status: model.ClaimPass, SupportedBy: []string{"git"}},
		{ID: "claim.environment_recorded", Type: "environment_recorded", Subject: "execution:exec-001", Statement: "Build environment documented", Status: model.ClaimPass, SupportedBy: []string{"environment"}},
	}

	entries := model.V4BindingEntries(&model.V4Proof{
		Evidence:  evs,
		Relations: relations,
		Claims:    claims,
	})
	root := model.V4Root(entries)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	p := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           "PX-" + root[:8],
		Project:      model.Project{Name: "test-project", Repository: "https://github.com/test/repo"},
		Subject:      model.Subject{Commit: "abc123def456789012345678901234567890abcd", Branch: "main", Repository: "https://github.com/test/repo"},
		Execution:    model.Execution{ID: "exec-001", Type: model.ExecCIWorkflow, StartedAt: "2026-08-21T02:00:00Z", CompletedAt: "2026-08-21T02:05:00Z", Environment: model.Environment{OS: "ubuntu-24.04", Arch: "amd64", Runtime: "go1.26.5"}},
		Evidence:     evs,
		Relations:    relations,
		Claims:       claims,
		Binding:      model.Binding{Algorithm: "sha256", Root: root, Entries: entries},
		Coverage: model.V4Coverage{
			Evidence:  model.CoverageDim{Total: 4, Verified: 4},
			Relations: model.CoverageDim{Total: 8, Verified: 8},
			Claims:    model.CoverageDim{Total: 4, Verified: 4},
			Score:     100,
		},
		CreatedAt: "2026-08-21T02:05:00Z",
		Builder:   model.Builder{Name: "proofx", Version: "0.4.0-test"},
	}

	p.Signature = model.Signature{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, model.V4SigningPayload(p))),
	}

	return p
}

func writeV4Proof(t *testing.T, dir, name string, p *model.V4Proof) string {
	t.Helper()
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRaw(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLI(args []string) (*CLI, int) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	c := &CLI{Stdout: stdout, Stderr: stderr}
	code := c.run(args)
	return c, code
}

func stdoutStr(c *CLI) string { return c.Stdout.(*bytes.Buffer).String() }
func stderrStr(c *CLI) string { return c.Stderr.(*bytes.Buffer).String() }

func evidenceDigestStr(id, payload string) string {
	return model.EvidenceDigest(id, payload)
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// ===========================================================================
// VERIFY
// ===========================================================================

func TestE2E_Verify_ValidProof(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"verify", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	out := stdoutStr(c)
	if !strings.Contains(out, "PROOF VERIFIED") {
		t.Fatalf("expected 'PROOF VERIFIED':\n%s", out)
	}
	if !strings.Contains(out, p.ID) {
		t.Fatalf("expected proof ID %s:\n%s", p.ID, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "✗") {
			t.Fatalf("unexpected failure: %s", line)
		}
	}
}

func TestE2E_Verify_TamperedProof(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	p.Execution.ID = "tampered-exec"
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"verify", path})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstdout: %s", code, stdoutStr(c))
	}
	if !strings.Contains(stdoutStr(c), "PROOF NOT VERIFIED") {
		t.Fatalf("expected 'PROOF NOT VERIFIED':\n%s", stdoutStr(c))
	}
}

func TestE2E_Verify_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := writeRaw(t, dir, "proof.json", []byte(`{not valid json`))

	c, code := runCLI([]string{"verify", path})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr: %s", code, stderrStr(c))
	}
}

func TestE2E_Verify_MissingFile(t *testing.T) {
	c, code := runCLI([]string{"verify", "/nonexistent/proof.json"})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr: %s", code, stderrStr(c))
	}
}

func TestE2E_Verify_NoArgs(t *testing.T) {
	c, code := runCLI([]string{"verify"})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d\nstderr: %s", code, stderrStr(c))
	}
	if !strings.Contains(stderrStr(c), "usage") {
		t.Fatalf("expected usage:\n%s", stderrStr(c))
	}
}

func TestE2E_Verify_V3BackwardCompat(t *testing.T) {
	dir := t.TempDir()
	evs := []model.Evidence{
		{ID: "artifact", Type: "artifact", Payload: `{"x":"y"}`, Digest: evidenceDigestStr("artifact", `{"x":"y"}`)},
		{ID: "git", Type: "git", Payload: `{"commit":"abc"}`, Digest: evidenceDigestStr("git", `{"commit":"abc"}`)},
	}
	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-v3compat",
		Project:      model.Project{Name: "test", Repository: "org/test"},
		Subject:      model.Subject{Commit: "abc123def456789012345678901234567890abcd"},
		Evidence:     evs,
		Binding:      model.Binding{Algorithm: proof.BindingAlgorithm, Root: proof.Root(proof.BindingEntries(evs)), Entries: proof.BindingEntries(evs)},
		Coverage:     model.Coverage{Total: 2, Verified: 2, Score: 100},
		CreatedAt:    "2026-08-16T00:00:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.3.0"},
	}
	_, priv, err := proof.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := proof.Sign(p, priv); err != nil {
		t.Fatal(err)
	}
	b, err := proof.MarshalProof(p)
	if err != nil {
		t.Fatal(err)
	}
	path := writeRaw(t, dir, "proof.json", b)

	c, code := runCLI([]string{"verify", path})
	if code != 0 {
		t.Fatalf("expected exit 0, got %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	if !strings.Contains(stderrStr(c), "v0.3 proof detected") {
		t.Fatalf("expected v0.3 detection:\n%s", stderrStr(c))
	}
}

func TestE2E_Verify_ArtifactModeTampered(t *testing.T) {
	dir := t.TempDir()

	artifactBytes := []byte("test-binary-content")
	artifactHex := sha256Hex(artifactBytes)

	payloadArtifact, _ := json.Marshal(map[string]any{"files": map[string]string{"myapp.bin": artifactHex}})
	p := mkV4Proof(t)
	p.Evidence[1] = model.Evidence{
		ID:      "artifact",
		Type:    "artifact",
		Source:  "build",
		Payload: string(payloadArtifact),
		Digest:  model.EvidenceDigest("artifact", string(payloadArtifact)),
	}

	entries := model.V4BindingEntries(p)
	p.Binding.Entries = entries
	p.Binding.Root = model.V4Root(entries)
	p.ID = "PX-" + p.Binding.Root[:8]

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p.Signature = model.Signature{
		Algorithm: "ed25519",
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Value:     base64.StdEncoding.EncodeToString(ed25519.Sign(priv, model.V4SigningPayload(p))),
	}

	path := writeV4Proof(t, dir, "proof.json", p)
	os.WriteFile(filepath.Join(dir, "myapp.bin"), artifactBytes, 0o644)

	c, code := runCLI([]string{"verify", "--artifact", filepath.Join(dir, "myapp.bin"), "--proof", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	if !strings.Contains(stdoutStr(c), "artifact") {
		t.Fatalf("expected artifact in output:\n%s", stdoutStr(c))
	}

	// Now tamper the artifact
	os.WriteFile(filepath.Join(dir, "myapp.bin"), []byte("tampered!"), 0o644)
	c2, code2 := runCLI([]string{"verify", "--artifact", filepath.Join(dir, "myapp.bin"), "--proof", path})
	if code2 != 1 {
		t.Fatalf("tampered artifact: expected exit 1, got %d\nstdout: %s", code2, stdoutStr(c2))
	}
}

// ===========================================================================
// INSPECT
// ===========================================================================

func TestE2E_Inspect_ValidProof(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"inspect", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	out := stdoutStr(c)
	if !strings.Contains(out, "execution:") {
		t.Fatalf("expected execution node:\n%s", out)
	}
	if !strings.Contains(out, "git") {
		t.Fatalf("expected evidence node 'git':\n%s", out)
	}
	if !strings.Contains(out, "Claims") {
		t.Fatalf("expected Claims section:\n%s", out)
	}
}

func TestE2E_Inspect_JSON(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"inspect", "--json", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	out := stdoutStr(c)

	var graph map[string]any
	if err := json.Unmarshal([]byte(out), &graph); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	for _, key := range []string{"execution", "evidence", "relations", "claims", "binding", "signature", "coverage"} {
		if _, ok := graph[key]; !ok {
			t.Fatalf("missing key %q in JSON output", key)
		}
	}

	evidence, ok := graph["evidence"].([]any)
	if !ok || len(evidence) != 4 {
		t.Fatalf("expected 4 evidence nodes, got %v", graph["evidence"])
	}
	relations, ok := graph["relations"].([]any)
	if !ok || len(relations) != 8 {
		t.Fatalf("expected 8 relations, got %v", graph["relations"])
	}
	claims, ok := graph["claims"].([]any)
	if !ok || len(claims) != 4 {
		t.Fatalf("expected 4 claims, got %v", graph["claims"])
	}
}

func TestE2E_Inspect_MissingFile(t *testing.T) {
	c, code := runCLI([]string{"inspect", "/nonexistent/proof.json"})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr: %s", code, stderrStr(c))
	}
}

func TestE2E_Inspect_NoArgs(t *testing.T) {
	c, code := runCLI([]string{"inspect"})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d\nstderr: %s", code, stderrStr(c))
	}
}

func TestE2E_Inspect_V3BackwardCompat(t *testing.T) {
	dir := t.TempDir()
	evs := []model.Evidence{
		{ID: "artifact", Type: "artifact", Payload: `{"x":"y"}`, Digest: evidenceDigestStr("artifact", `{"x":"y"}`)},
		{ID: "git", Type: "git", Payload: `{"commit":"abc"}`, Digest: evidenceDigestStr("git", `{"commit":"abc"}`)},
	}
	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-v3inspect",
		Project:      model.Project{Name: "test", Repository: "org/test"},
		Subject:      model.Subject{Commit: "abc123def456789012345678901234567890abcd"},
		Evidence:     evs,
		Binding:      model.Binding{Algorithm: proof.BindingAlgorithm, Root: proof.Root(proof.BindingEntries(evs)), Entries: proof.BindingEntries(evs)},
		Coverage:     model.Coverage{Total: 2, Verified: 2, Score: 100},
		CreatedAt:    "2026-08-16T00:00:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.3.0"},
	}
	_, priv, _ := proof.GenerateKey()
	proof.Sign(p, priv)
	b, _ := proof.MarshalProof(p)
	path := writeRaw(t, dir, "proof.json", b)

	c, code := runCLI([]string{"inspect", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	if !strings.Contains(stdoutStr(c), "artifact") {
		t.Fatalf("expected artifact in graph:\n%s", stdoutStr(c))
	}
}

// ===========================================================================
// CLAIMS
// ===========================================================================

func TestE2E_Claims_ValidProof(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"claims", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	out := stdoutStr(c)
	if !strings.Contains(out, "CLAIMS") {
		t.Fatalf("expected CLAIMS header:\n%s", out)
	}
	if !strings.Contains(out, "4/4 verified") {
		t.Fatalf("expected '4/4 verified':\n%s", out)
	}
	for _, claimID := range []string{"claim.tests_passed", "claim.artifact_integrity", "claim.execution_bound", "claim.environment_recorded"} {
		if !strings.Contains(out, claimID) {
			t.Fatalf("expected claim %s:\n%s", claimID, out)
		}
	}
}

func TestE2E_Claims_TamperedProof(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	// Tampering claim text breaks binding/signature, but per-claim verdicts
	// are structural; the command still exits 0 and lists every claim.
	p.Claims[0].Statement = "tampered statement"
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"claims", path})
	// claims always exits 0
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	if !strings.Contains(stdoutStr(c), p.ID) {
		t.Fatalf("expected proof ID %s:\n%s", p.ID, stdoutStr(c))
	}

	// Breaking the claim graph (relation to a nonexistent node) fails
	// schema validation, leaving no verifiable claims.
	p2 := mkV4Proof(t)
	p2.Relations[4].To = "claim.tampered"
	path2 := writeV4Proof(t, dir, "proof-broken.json", p2)

	c2, code2 := runCLI([]string{"claims", path2})
	if code2 != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code2, stderrStr(c2), stdoutStr(c2))
	}
	if !strings.Contains(stdoutStr(c2), "No claims in this proof.") {
		t.Fatalf("expected 'No claims in this proof.':\n%s", stdoutStr(c2))
	}
}

func TestE2E_Claims_MissingFile(t *testing.T) {
	c, code := runCLI([]string{"claims", "/nonexistent/proof.json"})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr: %s", code, stderrStr(c))
	}
}

func TestE2E_Claims_NoArgs(t *testing.T) {
	c, code := runCLI([]string{"claims"})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d\nstderr: %s", code, stderrStr(c))
	}
}

// ===========================================================================
// EXPLAIN
// ===========================================================================

func TestE2E_Explain_ValidProof(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"explain", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	out := stdoutStr(c)
	if !strings.Contains(out, "PROOFX EXPLAIN") {
		t.Fatalf("expected PROOFX EXPLAIN header:\n%s", out)
	}
	if !strings.Contains(out, "Why is this proof valid?") {
		t.Fatalf("expected 'Why is this proof valid?':\n%s", out)
	}
	if !strings.Contains(out, "Conclusion:") {
		t.Fatalf("expected Conclusion:\n%s", out)
	}
	if !strings.Contains(out, "Ed25519") {
		t.Fatalf("expected Ed25519 reference:\n%s", out)
	}
}

func TestE2E_Explain_TamperedProof(t *testing.T) {
	dir := t.TempDir()
	p := mkV4Proof(t)
	p.Signature.Value = "tampered-sig"
	path := writeV4Proof(t, dir, "proof.json", p)

	c, code := runCLI([]string{"explain", path})
	// explain always exits 0
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	out := stdoutStr(c)
	if !strings.Contains(out, "Why did this proof fail?") {
		t.Fatalf("expected failure explanation:\n%s", out)
	}
	if !strings.Contains(out, "Cryptographic integrity: FAILED") {
		t.Fatalf("expected cryptographic failure:\n%s", out)
	}
	if !strings.Contains(out, "Conclusion:") {
		t.Fatalf("expected Conclusion:\n%s", out)
	}
}

func TestE2E_Explain_MissingFile(t *testing.T) {
	c, code := runCLI([]string{"explain", "/nonexistent/proof.json"})
	if code != 1 {
		t.Fatalf("expected exit 1, got %d\nstderr: %s", code, stderrStr(c))
	}
}

func TestE2E_Explain_NoArgs(t *testing.T) {
	c, code := runCLI([]string{"explain"})
	if code != 2 {
		t.Fatalf("expected exit 2, got %d\nstderr: %s", code, stderrStr(c))
	}
}

func TestE2E_Explain_V3BackwardCompat(t *testing.T) {
	dir := t.TempDir()
	evs := []model.Evidence{
		{ID: "artifact", Type: "artifact", Payload: `{"x":"y"}`, Digest: evidenceDigestStr("artifact", `{"x":"y"}`)},
		{ID: "git", Type: "git", Payload: `{"commit":"abc"}`, Digest: evidenceDigestStr("git", `{"commit":"abc"}`)},
	}
	p := &model.Proof{
		ProofVersion: model.ProofVersion,
		ID:           "PX-v3explain",
		Project:      model.Project{Name: "test", Repository: "org/test"},
		Subject:      model.Subject{Commit: "abc123def456789012345678901234567890abcd"},
		Evidence:     evs,
		Binding:      model.Binding{Algorithm: proof.BindingAlgorithm, Root: proof.Root(proof.BindingEntries(evs)), Entries: proof.BindingEntries(evs)},
		Coverage:     model.Coverage{Total: 2, Verified: 2, Score: 100},
		CreatedAt:    "2026-08-16T00:00:00Z",
		Builder:      model.Builder{Name: "proofx", Version: "0.3.0"},
	}
	_, priv, _ := proof.GenerateKey()
	proof.Sign(p, priv)
	b, _ := proof.MarshalProof(p)
	path := writeRaw(t, dir, "proof.json", b)

	c, code := runCLI([]string{"explain", path})
	if code != 0 {
		t.Fatalf("exit %d\nstderr: %s\nstdout: %s", code, stderrStr(c), stdoutStr(c))
	}
	out := stdoutStr(c)
	if !strings.Contains(out, "Conclusion:") {
		t.Fatalf("expected Conclusion:\n%s", out)
	}
}
