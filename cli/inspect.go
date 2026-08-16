// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"fmt"
	"os"

	"github.com/EslaM-X/proofx/model"
	"github.com/EslaM-X/proofx/proof"
)

// cmdInspect prints a proof document in human-readable form.
func (c *CLI) cmdInspect(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(c.Stderr, "proofx: inspect: usage: proofx inspect <proof.json>\n")
		return 2
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: inspect: %v\n", err)
		return 1
	}
	p, err := proof.ParseProof(b)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: inspect: %v\n", err)
		return 1
	}
	printInspect(c.Stdout, p)
	return 0
}

func printInspect(w interface{ Write([]byte) (int, error) }, p *model.Proof) {
	fmt.Fprintf(w, "Proof %s\n", p.ID)
	fmt.Fprintf(w, "  project      : %s\n", p.Project.Name)
	if p.Project.Repository != "" {
		fmt.Fprintf(w, "  repository   : %s\n", p.Project.Repository)
	}
	fmt.Fprintf(w, "  commit       : %s\n", shortDigest(p.Subject.Commit))
	fmt.Fprintf(w, "  branch       : %s\n", p.Subject.Branch)
	fmt.Fprintf(w, "  created      : %s\n", p.CreatedAt)
	fmt.Fprintf(w, "  builder      : %s %s\n", p.Builder.Name, p.Builder.Version)
	fmt.Fprintf(w, "  binding root : %s\n", p.Binding.Root)
	fmt.Fprintf(w, "  signature    : %s (pub %s)\n", p.Signature.Algorithm, shortDigest(p.Signature.PublicKey))
	fmt.Fprintf(w, "  coverage     : %d/%d (%d%%)\n", p.Coverage.Verified, p.Coverage.Total, p.Coverage.Score)
	fmt.Fprintln(w, "  evidence:")
	for _, e := range p.Evidence {
		fmt.Fprintf(w, "    - %-12s digest %s\n", e.ID, shortDigest(e.Digest))
		fmt.Fprintf(w, "        source: %s\n", e.Source)
	}
	fmt.Fprintln(w, "  claims:")
	for _, cl := range p.Claims {
		fmt.Fprintf(w, "    - [%s] %s\n", cl.Status, cl.Text)
	}
}
