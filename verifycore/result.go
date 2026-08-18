// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package verifycore is the single source of truth for ProofX verification.
//
// It depends ONLY on model + stdlib. It does NOT import proof, cli, or
// evidence. This makes it safe for CLI, WASM, and future SDK consumers.
//
// Architecture:
//
//	model ← verifycore ← CLI / WASM / SDK
package verifycore

import "github.com/EslaM-X/proofx/model"

// Check is one line of a verification report.
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"` // ok | fail | skipped
	Detail string `json:"detail,omitempty"`
}

// VerifyResult is the structured outcome of verification.
type VerifyResult struct {
	ProofID  string         `json:"proofId"`
	Valid    bool           `json:"valid"`
	Checks   []Check        `json:"checks"`
	Coverage model.Coverage `json:"coverage"`
}

// Verification status constants.
const (
	StatusOK      = "ok"
	StatusFail    = "fail"
	StatusSkipped = "skipped"
)
