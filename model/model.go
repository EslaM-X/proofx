// Package model defines the ProofX evidence and proof data structures.
//
// ProofX turns software claims into independently verifiable evidence.
// Every Proof bundles a set of Evidence nodes, a cryptographic Binding
// (Merkle root over the evidence digests) and a Signature over that root,
// so the whole proof can be verified without trusting the prover.
package model

// ProofVersion is the schema version emitted by this release.
const ProofVersion = "1.0"

// BuilderName identifies the tool that produced the proof.
const BuilderName = "proofx"

// Evidence types (the Evidence Graph node kinds).
const (
	TypeGit         = "git"          // repository/commit/branch identity
	TypeArtifact    = "artifact"     // sha256 of released/built artifacts
	TypeDependency  = "dependencies" // lockfile digest + manifest snapshot
	TypeTests       = "tests"        // test result summary (pass/fail counts)
	TypeEnvironment = "environment"  // toolchain + OS the proof was made in
)

// Proof is the top-level verifiable document emitted by `proofx prove`.
type Proof struct {
	ProofVersion string     `json:"proofVersion"`
	ID           string     `json:"id"` // PX-<prefix of binding root>
	Project      Project    `json:"project"`
	Subject      Subject    `json:"subject"`  // what the proof is about
	Claims       []Claim    `json:"claims"`   // claims being evidenced
	Evidence     []Evidence `json:"evidence"` // evidence graph nodes
	Binding      Binding    `json:"binding"`  // merkle root over evidence
	Signature    Signature  `json:"signature"`
	Coverage     Coverage   `json:"coverage"` // verification coverage snapshot
	CreatedAt    string     `json:"createdAt"`
	Builder      Builder    `json:"builder"`
}

// Project identifies the software project the proof belongs to.
type Project struct {
	Name       string `json:"name"`
	Repository string `json:"repository"`
}

// Subject pins exactly what is being attested.
type Subject struct {
	Commit     string `json:"commit"` // full git commit sha at proof time
	Branch     string `json:"branch"`
	Repository string `json:"repository"`
}

// Claim is a human statement that the evidence is expected to back.
type Claim struct {
	ID     string `json:"id"`
	Text   string `json:"text"`
	Status string `json:"status"` // pending|evidenced|verified
}

// Evidence is one node in the Evidence Graph. The Digest commits the
// canonicalized Payload so tampering is detectable.
type Evidence struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Source    string `json:"source"`
	Timestamp string `json:"timestamp"`
	Payload   string `json:"payload"` // canonical JSON string
	Digest    string `json:"digest"`  // sha256 hex of payload
}

// Binding commits the ordered list of evidence digests to a single root.
type Binding struct {
	Algorithm string         `json:"algorithm"`
	Root      string         `json:"root"`
	Entries   []BindingEntry `json:"entries"`
}

// BindingEntry is one leaf of the binding tree.
type BindingEntry struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

// Signature is an ed25519 signature over the binding root.
type Signature struct {
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"publicKey"` // base64 raw ed25519 public key
	Value     string `json:"value"`     // base64 signature
}

// Coverage is a truthful summary of how many evidence nodes could be
// independently re-verified. It is explicitly NOT a security score.
type Coverage struct {
	Total    int `json:"total"`
	Verified int `json:"verified"`
	Score    int `json:"score"` // round(100 * verified/total)
}

// Builder records the tool that created the proof.
type Builder struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Host    string `json:"host,omitempty"`
}
