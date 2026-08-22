package verifycore

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/EslaM-X/proofx/model"
)

// TestGoldenVectors verifies all golden vector fixtures against expected outcomes.
// Run with: go test ./verifycore/... -run TestGoldenVectors -v
func TestGoldenVectors(t *testing.T) {
	// Use repo root relative path — tests run from repo root via `go test`
	dir := filepath.Join("conformance", "golden")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("golden vectors directory not found, skipping")
	}

	// Read and verify each golden vector
	tests := []struct {
		name     string
		file     string
		expectOK bool
		failChk  string
	}{
		{"valid", "golden-v04-valid.json", true, ""},
		{"tampered-sig", "golden-v04-tampered-sig.json", false, "signature"},
		{"tampered-claim", "golden-v04-tampered-claim.json", false, "binding"},
		{"missing-relation", "golden-v04-missing-relation.json", false, "schema"},
		{"wrong-version", "golden-v04-wrong-version.json", false, "schema"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, tc.file))
			if err != nil {
				t.Fatalf("read %s: %v", tc.file, err)
			}

			var p model.V4Proof
			if err := json.Unmarshal(b, &p); err != nil {
				t.Fatalf("parse %s: %v", tc.file, err)
			}

			res := V4Verify(&p)
			if tc.expectOK && !res.Valid {
				t.Errorf("expected PASS but got FAIL")
				for _, ch := range res.Checks {
					if ch.Status != "ok" {
						t.Errorf("  failed: %s — %s", ch.Name, ch.Detail)
					}
				}
			}
			if !tc.expectOK && res.Valid {
				t.Errorf("expected FAIL but got PASS")
			}
			if !tc.expectOK && tc.failChk != "" {
				found := false
				for _, ch := range res.Checks {
					if ch.Name == tc.failChk && ch.Status != "ok" {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected failing check %q, got checks: %v", tc.failChk, res.Checks)
				}
			}

			t.Logf("%s: valid=%v version=%s", tc.name, res.Valid, p.ProofVersion)
		})
	}
}

// TestGoldenVectors_Generate generates the golden vector fixtures.
// Run once to create/update fixtures, then commit.
// Run with: go test ./verifycore/... -run TestGoldenVectors_Generate -v
func TestGoldenVectors_Generate(t *testing.T) {
	dir := filepath.Join("conformance", "golden")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	priv := goldenPrivKey()
	vectors := generateGoldenVectors(priv)

	for name, p := range vectors {
		b, _ := json.MarshalIndent(p, "", "  ")
		path := filepath.Join(dir, name+".json")
		if err := os.WriteFile(path, b, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		t.Logf("wrote %s (%d bytes)", name+".json", len(b))
	}

	// Write manifest
	manifest := map[string]interface{}{
		"version":   "1.0",
		"protocol":  "proofx/v0.4",
		"generated": "by TestGoldenVectors_Generate — do not edit manually",
		"fixtures": []map[string]interface{}{
			{"file": "golden-v04-valid.json", "expect": "pass"},
			{"file": "golden-v04-tampered-sig.json", "expect": "fail", "failing_check": "signature"},
			{"file": "golden-v04-tampered-claim.json", "expect": "fail", "failing_check": "binding"},
			{"file": "golden-v04-missing-relation.json", "expect": "fail", "failing_check": "schema"},
			{"file": "golden-v04-wrong-version.json", "expect": "fail", "failing_check": "schema"},
		},
	}
	manifestB, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifestB, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

func goldenPrivKey() ed25519.PrivateKey {
	seed := make([]byte, 32)
	copy(seed, []byte("proofx-golden-vector"))
	return ed25519.NewKeyFromSeed(seed)
}

func cloneGoldenV4(src *model.V4Proof) *model.V4Proof {
	b, _ := json.Marshal(src)
	var dst model.V4Proof
	json.Unmarshal(b, &dst) //nolint:errcheck
	return &dst
}

func generateGoldenVectors(priv ed25519.PrivateKey) map[string]*model.V4Proof {
	v4 := &model.V4Proof{
		ProofVersion: model.ProofVersionV2,
		ID:           "PX-golden0001",
		Project:      model.Project{Name: "proofx", Repository: "https://github.com/EslaM-X/proofx"},
		Subject:      model.Subject{Commit: "deadbeef00000000000000000000000000000000", Branch: "main", Repository: "https://github.com/EslaM-X/proofx"},
		Execution:    model.Execution{ID: "exec-golden", Type: model.ExecCIWorkflow},
		Evidence: []model.Evidence{
			{ID: "git", Type: "git", Payload: `{"commit":"deadbeef","branch":"main"}`},
			{ID: "tests", Type: "tests", Payload: `{"passed":42,"failed":0}`},
		},
		Relations: []model.Relation{
			{ID: "r1", From: "git", To: "c1", Kind: model.RelSupports},
			{ID: "r2", From: "tests", To: "c1", Kind: model.RelSupports},
			{ID: "r3", From: "git", To: "c2", Kind: model.RelSupports},
			{ID: "r4", From: "tests", To: "c2", Kind: model.RelSupports},
		},
		Claims: []model.V4Claim{
			{ID: "c1", Type: "assertion", Subject: "proof:ci", Statement: "commit is correct", Status: "pass", SupportedBy: []string{"git", "tests"}},
			{ID: "c2", Type: "assertion", Subject: "proof:ci", Statement: "tests passed", Status: "pass", SupportedBy: []string{"git", "tests"}},
		},
		Builder: model.Builder{Name: "proofx", Version: "0.4.0-golden"},
	}
	for i := range v4.Evidence {
		v4.Evidence[i].Digest = model.EvidenceDigest(v4.Evidence[i].ID, v4.Evidence[i].Payload)
	}
	entries := model.V4BindingEntries(v4)
	v4.Binding = model.Binding{Algorithm: "sha256", Root: model.V4Root(entries), Entries: entries}
	signProof(v4, priv)
	v4.Coverage = model.V4Coverage{
		Evidence:  model.CoverageDim{Total: 2, Verified: 2},
		Relations: model.CoverageDim{Total: 4, Verified: 4},
		Claims:    model.CoverageDim{Total: 2, Verified: 2},
		Score:     100,
	}

	result := make(map[string]*model.V4Proof)
	result["golden-v04-valid"] = v4

	bad1 := cloneGoldenV4(v4)
	bad1.Signature.Value = " tampered " + bad1.Signature.Value
	result["golden-v04-tampered-sig"] = bad1

	bad2 := cloneGoldenV4(v4)
	bad2.Claims[0].Statement = "TAMPERED"
	result["golden-v04-tampered-claim"] = bad2

	bad3 := cloneGoldenV4(v4)
	bad3.Relations = bad3.Relations[:2]
	result["golden-v04-missing-relation"] = bad3

	bad4 := cloneGoldenV4(v4)
	bad4.ProofVersion = "3.0"
	result["golden-v04-wrong-version"] = bad4

	return result
}
