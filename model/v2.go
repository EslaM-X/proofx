// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
//
// Package model defines the ProofX v0.4 Execution Proof Model types.
//
// v0.4 extends v0.3 with an execution-centric evidence model:
// Execution → Evidence → Relations → Claims → Binding → Signature.
package model

// ProofVersionV2 is the schema version for v0.4 proofs.
const ProofVersionV2 = "2.0"

// --- Execution ---

// Execution represents the CI/build run that produced the evidence.
type Execution struct {
	ID          string      `json:"id"`
	Type        string      `json:"type"`
	StartedAt   string      `json:"startedAt"`
	CompletedAt string      `json:"completedAt"`
	Environment Environment `json:"environment"`
}

// Execution types (extensible).
const (
	ExecCIWorkflow = "ci-workflow"
	ExecLocalBuild = "local-build"
	ExecAgentRun   = "agent-run"
	ExecCustom     = "custom"
)

// Environment describes the build/runtime environment.
type Environment struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Runtime string `json:"runtime"`
}

// --- Relations ---

// Relation describes how evidence nodes, claims, and the execution connect.
type Relation struct {
	ID   string `json:"id"`
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// Relation kinds.
const (
	RelProduces    = "produces"
	RelDependsOn   = "depends_on"
	RelSupports    = "supports"
	RelDerivedFrom = "derived_from"
	RelEvaluates   = "evaluates"
	RelSignedBy    = "signed_by"
	RelBinds       = "binds"
)

// --- V4Claim ---

// V4Claim is a structured assertion about the execution, backed by evidence.
type V4Claim struct {
	ID          string   `json:"id"`
	Type        string   `json:"type"`
	Subject     string   `json:"subject"`
	Statement   string   `json:"statement"`
	Status      string   `json:"status"`
	SupportedBy []string `json:"supportedBy"`
}

// Claim statuses.
const (
	ClaimPass          = "pass"
	ClaimFail          = "fail"
	ClaimPending       = "pending"
	ClaimNotApplicable = "not_applicable"
)

// --- V4Coverage ---

// V4Coverage tracks verification across three dimensions.
type V4Coverage struct {
	Evidence  CoverageDim `json:"evidence"`
	Relations CoverageDim `json:"relations"`
	Claims    CoverageDim `json:"claims"`
	Score     int         `json:"score"`
}

// CoverageDim is one dimension of coverage.
type CoverageDim struct {
	Total    int `json:"total"`
	Verified int `json:"verified"`
}

// --- V4Proof ---

// V4Proof is the v0.4 top-level verifiable document.
type V4Proof struct {
	ProofVersion string     `json:"proofVersion"`
	ID           string     `json:"id"`
	Project      Project    `json:"project"`
	Subject      Subject    `json:"subject"`
	Execution    Execution  `json:"execution"`
	Evidence     []Evidence `json:"evidence"`
	Relations    []Relation `json:"relations"`
	Claims       []V4Claim  `json:"claims"`
	Binding      Binding    `json:"binding"`
	Signature    Signature  `json:"signature"`
	Coverage     V4Coverage `json:"coverage"`
	CreatedAt    string     `json:"createdAt"`
	Builder      Builder    `json:"builder"`
}

// --- Validation ---

// Validate checks structural invariants of a V4Proof.
// It does NOT verify cryptographic binding — that requires VerifyBinding + VerifySignature.
func Validate(p *V4Proof) error {
	if p.ProofVersion != ProofVersionV2 {
		return &ValidationError{Field: "proofVersion", Msg: "must be " + ProofVersionV2}
	}
	if err := validateExecution(&p.Execution); err != nil {
		return err
	}
	if err := validateEvidence(p.Evidence); err != nil {
		return err
	}
	if err := validateRelations(p); err != nil {
		return err
	}
	if err := validateClaims(p); err != nil {
		return err
	}
	return nil
}

func validateExecution(e *Execution) error {
	if e.ID == "" {
		return &ValidationError{Field: "execution.id", Msg: "must not be empty"}
	}
	if e.Type == "" {
		return &ValidationError{Field: "execution.type", Msg: "must not be empty"}
	}
	return nil
}

func validateEvidence(evs []Evidence) error {
	seen := make(map[string]bool, len(evs))
	for _, e := range evs {
		if e.ID == "" {
			return &ValidationError{Field: "evidence.id", Msg: "must not be empty"}
		}
		if seen[e.ID] {
			return &ValidationError{Field: "evidence.id", Msg: "duplicate: " + e.ID}
		}
		seen[e.ID] = true
	}
	return nil
}

func validateRelations(p *V4Proof) error {
	// Build set of all node IDs
	nodeIDs := make(map[string]bool)
	nodeIDs[p.Execution.ID] = true
	for _, e := range p.Evidence {
		nodeIDs[e.ID] = true
	}
	for _, c := range p.Claims {
		nodeIDs[c.ID] = true
	}

	seen := make(map[string]bool, len(p.Relations))
	for _, r := range p.Relations {
		if r.ID == "" {
			return &ValidationError{Field: "relation.id", Msg: "must not be empty"}
		}
		if seen[r.ID] {
			return &ValidationError{Field: "relation.id", Msg: "duplicate: " + r.ID}
		}
		seen[r.ID] = true

		if !nodeIDs[r.From] {
			return &ValidationError{Field: "relation[" + r.ID + "].from", Msg: "references nonexistent node: " + r.From}
		}
		if !nodeIDs[r.To] {
			return &ValidationError{Field: "relation[" + r.ID + "].to", Msg: "references nonexistent node: " + r.To}
		}
	}
	return nil
}

func validateClaims(p *V4Proof) error {
	// Build set of evidence IDs
	evIDs := make(map[string]bool, len(p.Evidence))
	for _, e := range p.Evidence {
		evIDs[e.ID] = true
	}

	// Build set of evidence IDs that support claims (via supports relations)
	supported := make(map[string]bool)
	for _, r := range p.Relations {
		if r.Kind == RelSupports {
			supported[r.To] = true
		}
	}

	for _, c := range p.Claims {
		if c.ID == "" {
			return &ValidationError{Field: "claim.id", Msg: "must not be empty"}
		}
		if len(c.SupportedBy) == 0 {
			return &ValidationError{Field: "claim[" + c.ID + "].supportedBy", Msg: "must not be empty"}
		}
		// Each supportedBy reference must be existing evidence
		for _, ref := range c.SupportedBy {
			if !evIDs[ref] {
				return &ValidationError{Field: "claim[" + c.ID + "].supportedBy", Msg: "references nonexistent evidence: " + ref}
			}
		}
		// Claim must have a supports relation
		if !supported[c.ID] {
			return &ValidationError{Field: "claim[" + c.ID + "]", Msg: "has no supports relation"}
		}
	}
	return nil
}

// --- ValidationError ---

// ValidationError describes a structural invariant violation.
type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string {
	return "proofx: validation error on " + e.Field + ": " + e.Msg
}
