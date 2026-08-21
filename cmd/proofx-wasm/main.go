// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Command proofx-wasm is the WASM entry point for browser-based proof
// verification. It exposes a single global function `verifyProof(input)` that
// accepts a JSON string and returns a JSON string.
//
// Supports both v0.4 (proof_version "2.0") and v0.3 (proof_version "1.0")
// proofs. v0.4 is tried first; on version mismatch, v0.3 fallback is attempted.
//
// Both v0.3 and v0.4 proofs output the same V4-shaped result for conformance.
// v0.3 proofs use verifycore.Verify(); v0.4 proofs use verifycore.V4Verify().
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o proofx.wasm ./cmd/proofx-wasm

//go:build js && wasm

package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/verifycore"
)

// verifyResult is the unified WASM output shape for all proof versions.
type verifyResult struct {
	ProofID  string                     `json:"proofId"`
	Valid    bool                       `json:"valid"`
	Version  string                     `json:"version"`
	Checks   []verifycore.Check         `json:"checks"`
	Coverage model.V4Coverage           `json:"coverage"`
	Claims   []verifycore.V4ClaimResult `json:"claims,omitempty"`
}

func verifyProof(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorJSON("missing proof argument")
	}
	input := args[0].String()
	if input == "" {
		return errorJSON("empty proof input")
	}
	data := []byte(input)

	// Try v0.4 first
	p4, err := verifycore.V4ParseProof(data)
	if err == nil {
		res := verifycore.V4Verify(p4)
		out := verifyResult{
			ProofID:  res.ProofID,
			Valid:    res.Valid,
			Version:  "0.4",
			Checks:   res.Checks,
			Coverage: res.Coverage,
			Claims:   res.Claims,
		}
		b, err := json.Marshal(out)
		if err != nil {
			return errorJSON("marshal error: " + err.Error())
		}
		return js.ValueOf(string(b))
	}

	// Fallback: try v0.3 (use v0.3 verifier, wrap in V4 coverage shape)
	p3, err := verifycore.ParseProof(data)
	if err != nil {
		return errorJSON("parse error: " + err.Error())
	}
	res := verifycore.Verify(p3)

	// Wrap v0.3 coverage in V4 shape to match native runner output
	v4Coverage := model.V4Coverage{
		Evidence:  model.CoverageDim{Total: res.Coverage.Total, Verified: res.Coverage.Verified},
		Relations: model.CoverageDim{Total: 0},
		Claims:    model.CoverageDim{Total: len(p3.Claims), Verified: res.Coverage.Verified},
		Score:     res.Coverage.Score,
	}

	out := verifyResult{
		ProofID:  res.ProofID,
		Valid:    res.Valid,
		Version:  "0.3",
		Checks:   res.Checks,
		Coverage: v4Coverage,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return errorJSON("marshal error: " + err.Error())
	}
	return js.ValueOf(string(b))
}

func errorJSON(msg string) js.Value {
	res := verifyResult{
		Valid:   false,
		Version: "error",
		Checks:  []verifycore.Check{{Name: "parse", Status: verifycore.StatusFail, Detail: msg}},
	}
	b, _ := json.Marshal(res)
	return js.ValueOf(string(b))
}

func main() {
	c := make(chan struct{})
	js.Global().Set("verifyProof", js.FuncOf(verifyProof))
	<-c
}
