// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Command proofx-wasm is the WASM entry point for browser-based proof
// verification. It exposes a single global function `verifyProof(input)` that
// accepts a JSON string and returns a JSON string.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -ldflags="-s -w" -o proofx.wasm ./cmd/proofx-wasm
//go:build js && wasm
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/EslaM-X/proofx/verifycore"
)

// verifyProof is the WASM-exported function. It accepts a JSON string
// containing a proof document and returns a JSON string with the structured
// verification result.
//
// Input:  JSON string → proof document
// Output: JSON string → { "valid": bool, "checks": [...], "coverage": {...} }
func verifyProof(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorJSON("missing proof argument")
	}
	input := args[0].String()
	if input == "" {
		return errorJSON("empty proof input")
	}

	p, err := verifycore.ParseProof([]byte(input))
	if err != nil {
		return errorJSON("parse error: " + err.Error())
	}

	res := verifycore.Verify(p)

	b, err := json.Marshal(res)
	if err != nil {
		return errorJSON("marshal error: " + err.Error())
	}
	return js.ValueOf(string(b))
}

func errorJSON(msg string) js.Value {
	res := verifycore.VerifyResult{
		Valid:  false,
		Checks: []verifycore.Check{{Name: "parse", Status: verifycore.StatusFail, Detail: msg}},
	}
	b, _ := json.Marshal(res)
	return js.ValueOf(string(b))
}

func main() {
	c := make(chan struct{})
	js.Global().Set("verifyProof", js.FuncOf(verifyProof))
	<-c
}
