// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package main runs the native (Go) verification against every corpus case
// and writes result.json files for comparison with WASM results.
//
// v0.3 proofs use verifycore.Verify(); v0.4 proofs use verifycore.V4Verify().
//
// Run: go run ./conformance/native
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/verifycore"
)

type NativeResult struct {
	Name    string                    `json:"name"`
	Result  verifycore.V4VerifyResult `json:"result"`
	Version string                    `json:"version"`
	Success bool                      `json:"success"`
}

// v3ToV4Result wraps a v0.3 VerifyResult into a V4VerifyResult for uniform output.
func v3ToV4Result(r verifycore.VerifyResult, p *model.Proof) verifycore.V4VerifyResult {
	return verifycore.V4VerifyResult{
		ProofID: r.ProofID,
		Valid:   r.Valid,
		Checks:  r.Checks,
		Coverage: model.V4Coverage{
			Evidence:  model.CoverageDim{Total: r.Coverage.Total, Verified: r.Coverage.Verified},
			Claims:    model.CoverageDim{Total: len(p.Claims), Verified: r.Coverage.Verified},
			Relations: model.CoverageDim{Total: 0},
			Score:     r.Coverage.Score,
		},
	}
}

func main() {
	corpusDir := filepath.Join("conformance", "corpus")
	expectedDir := filepath.Join("conformance", "expected")
	outputDir := filepath.Join("conformance", "native")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error creating output dir: %v\n", err)
		os.Exit(1)
	}

	results := []NativeResult{}

	subdirs := []string{"valid", "invalid", "malformed"}
	for _, subdir := range subdirs {
		dir := filepath.Join(corpusDir, subdir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			name := strings.TrimSuffix(entry.Name(), ".json")
			proofPath := filepath.Join(dir, entry.Name())
			expectedPath := filepath.Join(expectedDir, entry.Name())

			b, err := os.ReadFile(proofPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error reading %s: %v\n", proofPath, err)
				continue
			}

			var res verifycore.V4VerifyResult
			var version string

			// Try v0.4 first
			p4, err := verifycore.V4ParseProof(b)
			if err == nil {
				res = verifycore.V4Verify(p4)
				version = "0.4"
			} else {
				// Try v0.3 (use v0.3 verifier directly, matching CLI behavior)
				p3, err3 := verifycore.ParseProof(b)
				if err3 != nil {
					res = verifycore.V4VerifyResult{
						Valid:  false,
						Checks: []verifycore.Check{{Name: "parse", Status: verifycore.StatusFail, Detail: "parse error: " + err3.Error()}},
					}
					version = "error"
				} else {
					v3res := verifycore.Verify(p3)
					res = v3ToV4Result(v3res, p3)
					version = "0.3"
				}
			}

			// Load expected and compare
			expectedBytes, err := os.ReadFile(expectedPath)
			success := false
			if err == nil {
				// Try v0.4 expected first
				var expected4 verifycore.V4VerifyResult
				if json.Unmarshal(expectedBytes, &expected4) == nil && expected4.Checks != nil {
					success = (res.Valid == expected4.Valid)
				} else {
					// Try v0.3 expected
					var expected3 verifycore.VerifyResult
					if json.Unmarshal(expectedBytes, &expected3) == nil {
						success = (res.Valid == expected3.Valid)
					}
				}
			}

			nr := NativeResult{Name: name, Result: res, Version: version, Success: success}
			results = append(results, nr)

			outPath := filepath.Join(outputDir, name+".result.json")
			ob, _ := json.MarshalIndent(nr, "", "  ")
			if err := os.WriteFile(outPath, ob, 0o644); err != nil {
				fmt.Fprintf(os.Stderr, "error writing %s: %v\n", outPath, err)
			}
			status := "PASS"
			if !success {
				status = "FAIL"
			}
			fmt.Printf("  [%s] %s (valid=%v, version=%s)\n", status, name, res.Valid, version)
		}
	}

	fmt.Printf("Native runner: %d cases\n", len(results))
}
