// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"encoding/json"
	"fmt"

	"github.com/EslaM-X/proofx/model"
)

// Graph is the machine-readable Evidence Graph of a proof: the node set,
// the directed relationships between them, the claims and the proof ref.
type Graph struct {
	Nodes         []GraphNode    `json:"nodes"`
	Relationships []Relationship `json:"relationships"`
	Claims        []model.Claim  `json:"claims"`
	Proof         GraphProof     `json:"proof"`
}

// GraphNode is one evidence node plus its verification-relevant metadata.
type GraphNode struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Digest    string `json:"digest"`
	Timestamp string `json:"timestamp"`
	Source    string `json:"source"`
}

// Relationship is a directed edge between two evidence nodes.
type Relationship struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// GraphProof identifies the proof the graph is rooted at.
type GraphProof struct {
	ID           string `json:"id"`
	ProofVersion string `json:"proofVersion"`
	BindingRoot  string `json:"bindingRoot"`
	Signature    string `json:"signature"`
	Coverage     int    `json:"coverage"`
}

// cmdGraph emits the Evidence Graph of a proof: JSON when --json is given,
// otherwise a compact ASCII rendering.
func (c *CLI) cmdGraph(args []string) int {
	asJSON := false
	file := "proof.json"
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "-j":
			asJSON = true
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) > 0 {
		file = rest[0]
	}
	p, err := loadProof(file)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: graph: %v\n", err)
		return 1
	}
	g := buildGraph(p)
	if asJSON {
		b, err := json.MarshalIndent(g, "", "  ")
		if err != nil {
			fmt.Fprintf(c.Stderr, "proofx: graph: %v\n", err)
			return 1
		}
		fmt.Fprintln(c.Stdout, string(b))
		return 0
	}
	renderGraph(c.Stdout, g)
	return 0
}

// buildGraph derives the Evidence Graph data model from a proof.
func buildGraph(p *model.Proof) Graph {
	g := Graph{Claims: p.Claims, Proof: GraphProof{
		ID:           p.ID,
		ProofVersion: p.ProofVersion,
		BindingRoot:  p.Binding.Root,
		Signature:    p.Signature.Algorithm,
		Coverage:     p.Coverage.Score,
	}}
	nodes := make([]GraphNode, 0, len(p.Evidence))
	rels := []Relationship{
		{From: "commit", To: "proof", Kind: "binds"},
		{From: "proof", To: "signature", Kind: "signedBy"},
	}
	for _, e := range p.Evidence {
		nodes = append(nodes, GraphNode{
			ID:        e.ID,
			Type:      e.Type,
			Digest:    e.Digest,
			Timestamp: e.Timestamp,
			Source:    e.Source,
		})
		rels = append(rels, Relationship{From: e.ID, To: "proof", Kind: "evidenceOf"})
	}
	g.Nodes = nodes
	g.Relationships = rels
	return g
}

// renderGraph prints a compact ASCII tree of the Evidence Graph.
func renderGraph(w interface{ Write([]byte) (int, error) }, g Graph) {
	fmt.Fprintf(w, "EVIDENCE GRAPH — %s\n", g.Proof.ID)
	fmt.Fprintf(w, "  binding root: %s\n", g.Proof.BindingRoot)
	fmt.Fprintf(w, "  signature   : %s\n", g.Proof.Signature)
	fmt.Fprintf(w, "  coverage    : %d/100\n", g.Proof.Coverage)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "  commit\n")
	for _, n := range g.Nodes {
		fmt.Fprintf(w, "    │\n")
		fmt.Fprintf(w, "    ├── %s\n", n.ID)
	}
	fmt.Fprintf(w, "    │\n")
	fmt.Fprintf(w, "    ▼\n")
	fmt.Fprintf(w, "  PROOF  (PX-%s)\n", shortID(g.Proof.BindingRoot))
	fmt.Fprintf(w, "    │\n")
	fmt.Fprintf(w, "    ▼\n")
	fmt.Fprintf(w, "  SIGNATURE (ed25519)\n")
}
