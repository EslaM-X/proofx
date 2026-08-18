// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package main runs the native (Go) verification against every corpus case
// and writes result.json files for comparison with WASM results.
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
	Name    string                  `json:"name"`
	Result  verifycore.VerifyResult `json:"result"`
	Success bool                    `json:"success"` // true if result matches expected
}

func main() {
	corpusDir := filepath.Join("conformance", "corpus")
	expectedDir := filepath.Join("conformance", "expected")
	outputDir := filepath.Join("conformance", "native")
	os.MkdirAll(outputDir, 0o755)

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

			p, err := verifycore.ParseProof(b)
			var res verifycore.VerifyResult
			if err != nil {
				res = verifycore.VerifyResult{
					Valid:    false,
					Checks:   []verifycore.Check{{Name: "parse", Status: verifycore.StatusFail, Detail: "parse error: " + err.Error()}},
					Coverage: model.Coverage{Total: 0, Verified: 0, Score: 0},
				}
			} else {
				res = verifycore.Verify(p)
			}

			// Load expected and compare
			expectedBytes, err := os.ReadFile(expectedPath)
			success := false
			if err == nil {
				var expected verifycore.VerifyResult
				if json.Unmarshal(expectedBytes, &expected) == nil {
					success = (res.Valid == expected.Valid)
				}
			}

			nr := NativeResult{Name: name, Result: res, Success: success}
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
			fmt.Printf("  [%s] %s (valid=%v)\n", status, name, res.Valid)
		}
	}

	fmt.Printf("Native runner: %d cases\n", len(results))
}
