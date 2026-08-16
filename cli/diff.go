// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

// cmdDiff compares two proof documents evidence-node by evidence-node.
func (c *CLI) cmdDiff(args []string) int {
	if len(args) < 2 {
		fmt.Fprintf(c.Stderr, "proofx: diff: usage: proofx diff <proof-v1.json> <proof-v2.json>\n")
		return 2
	}
	p1, err := loadProof(args[0])
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: diff: %v\n", err)
		return 1
	}
	p2, err := loadProof(args[1])
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: diff: %v\n", err)
		return 1
	}
	renderDiff(c.Stdout, p1, p2)
	return 0
}

func loadProof(path string) (*model.Proof, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return proof.ParseProof(b)
}

// renderDiff prints a compact evidence diff between two proofs.
func renderDiff(w interface{ Write([]byte) (int, error) }, p1, p2 *model.Proof) {
	fmt.Fprintf(w, "EVIDENCE DIFF\n")
	fmt.Fprintf(w, "  %s  ->  %s\n", p1.ID, p2.ID)
	fmt.Fprintln(w, strings.Repeat("─", 40))

	idx1 := evidenceByID(p1.Evidence)
	idx2 := evidenceByID(p2.Evidence)
	ids := orderedUnion(p1.Evidence, p2.Evidence)

	for _, id := range ids {
		e1, has1 := idx1[id]
		e2, has2 := idx2[id]
		switch {
		case has1 && has2:
			if e1.Digest == e2.Digest {
				fmt.Fprintf(w, "  %-12s SAME\n", id)
			} else {
				fmt.Fprintf(w, "  %-12s CHANGED  (%s → %s)\n", id, shortDigest(e1.Digest), shortDigest(e2.Digest))
				printPayloadDelta(w, id, e1.Payload, e2.Payload)
			}
		case has1:
			fmt.Fprintf(w, "  %-12s REMOVED\n", id)
		case has2:
			fmt.Fprintf(w, "  %-12s ADDED\n", id)
		}
	}

	// summary lines
	fmt.Fprintln(w, strings.Repeat("─", 40))
	if p1.Builder.Name != "" || p2.Builder.Name != "" {
		same := p1.Builder.Version == p2.Builder.Version && p1.Builder.Name == p2.Builder.Name
		fmt.Fprintf(w, "  %-12s %s\n", "Builder", sameStatus(same))
	}
	sig1 := proof.VerifySignature(p1)
	sig2 := proof.VerifySignature(p2)
	fmt.Fprintf(w, "  %-12s %s / %s\n", "Signature", sigText(sig1), sigText(sig2))
	fmt.Fprintf(w, "  %-12s %d/%d  ->  %d/%d\n", "Coverage", p1.Coverage.Verified, p1.Coverage.Total, p2.Coverage.Verified, p2.Coverage.Total)
	if p1.Subject.Commit != p2.Subject.Commit {
		fmt.Fprintf(w, "  %-12s %s → %s\n", "Commit", shortCommit(p1.Subject.Commit), shortCommit(p2.Subject.Commit))
	}
}

func sigText(err error) string {
	if err == nil {
		return "VALID"
	}
	return "INVALID"
}

func sameStatus(ok bool) string {
	if ok {
		return "SAME"
	}
	return "DIFF"
}

// printPayloadDelta shows what changed inside a node's payload.
func printPayloadDelta(w interface{ Write([]byte) (int, error) }, id, a, b string) {
	pa, paOK := payloadMap(a)
	pb, pbOK := payloadMap(b)
	if !paOK || !pbOK {
		return
	}
	switch id {
	case "artifact":
		fa := stringMap(pa["files"])
		fb := stringMap(pb["files"])
		for name := range fa {
			if _, ok := fb[name]; !ok {
				fmt.Fprintf(w, "    - file: %s\n", name)
			}
		}
		for name := range fb {
			if _, ok := fa[name]; !ok {
				fmt.Fprintf(w, "    + file: %s\n", name)
			}
		}
	case "tests":
		fmt.Fprintf(w, "    tests: %v → %v\n", pa["pass"], pb["pass"])
	case "environment":
		if pa["go_version"] != pb["go_version"] {
			fmt.Fprintf(w, "    go: %v → %v\n", pa["go_version"], pb["go_version"])
		}
		if pa["os"] != pb["os"] {
			fmt.Fprintf(w, "    os: %v → %v\n", pa["os"], pb["os"])
		}
	}
}

func payloadMap(s string) (map[string]any, bool) {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, false
	}
	return m, true
}

func stringMap(v any) map[string]string {
	m := map[string]string{}
	if vv, ok := v.(map[string]any); ok {
		for k, val := range vv {
			if s, ok := val.(string); ok {
				m[k] = s
			}
		}
	}
	return m
}

func evidenceByID(evs []model.Evidence) map[string]model.Evidence {
	m := make(map[string]model.Evidence, len(evs))
	for _, e := range evs {
		m[e.ID] = e
	}
	return m
}

func orderedUnion(a, b []model.Evidence) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range append(append([]model.Evidence{}, a...), b...) {
		if !seen[e.ID] {
			seen[e.ID] = true
			out = append(out, e.ID)
		}
	}
	return out
}

func shortCommit(c string) string {
	if len(c) <= 8 {
		return c
	}
	return c[:8]
}
