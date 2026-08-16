// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EslaM-X/proofx/proof"
)

// cmdExplain analyzes a proof against the current repository and explains
// exactly why each node passes or fails, with likely causes and fixes.
func (c *CLI) cmdExplain(args []string) int {
	if len(args) < 1 {
		fmt.Fprintf(c.Stderr, "proofx: explain: usage: proofx explain <proof.json> [dir]\n")
		return 2
	}
	proofFile := args[0]
	dir := "."
	if len(args) > 1 {
		dir = args[1]
	}
	b, err := os.ReadFile(proofFile)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: explain: %v\n", err)
		return 1
	}
	p, err := proof.ParseProof(b)
	if err != nil {
		fmt.Fprintf(c.Stderr, "proofx: explain: %v\n", err)
		return 1
	}
	current := collectCurrent(dir, time.Now())
	index := map[string]string{}
	for _, r := range current {
		if r.Err == nil {
			index[r.Evidence.ID] = r.Evidence.Digest
		}
	}

	fmt.Fprintf(c.Stdout, "ProofX Explain — %s\n", p.ID)
	fmt.Fprintln(c.Stdout, strings.Repeat("─", 72))

	// signature + binding (structural health)
	if err := proof.VerifySignature(p); err != nil {
		printExplain(c.Stdout, "signature", "FAIL", "", "signature does not verify over the binding root",
			"the proof was altered or signed by a different key", "re-obtain the original signed proof; the public key changed")
	} else {
		printExplain(c.Stdout, "signature", "OK", "", "signature is a valid ed25519 over the binding root", "", "")
	}
	if err := proof.VerifyBinding(p); err != nil {
		printExplain(c.Stdout, "binding", "FAIL", "proof="+p.Binding.Root, "the merkle root does not match the recorded evidence digests",
			"an evidence node was modified after signing", "re-produce the proof with `proofx collect && proofx prove`")
	} else {
		printExplain(c.Stdout, "binding", "OK", "", "merkle root matches the recorded evidence digests", "", "")
	}

	// per-node comparison
	for _, e := range p.Evidence {
		cur, ok := index[e.ID]
		switch {
		case !ok:
			printExplain(c.Stdout, e.ID, "SKIPPED", "", "this evidence source is not present in the current repository",
				"the source may be absent or the collector is not configured", "check the file/collector this node needs")
		case cur == e.Digest:
			printExplain(c.Stdout, e.ID, "OK", shortDigest(e.Digest), "current state matches the recorded evidence", "", "")
		default:
			printExplain(c.Stdout, e.ID, "FAIL",
				fmt.Sprintf("expected %s actual %s", shortDigest(e.Digest), shortDigest(cur)),
				"the current state differs from the recorded evidence",
				explainCause(e.ID), explainFix(e.ID))
		}
	}
	return 0
}

// explainCause gives the most likely reason an evidence node drifted.
func explainCause(id string) string {
	switch id {
	case "artifact":
		return "an artifact file changed after the proof was created"
	case "git":
		return "the repository advanced to a new commit since the proof"
	case "dependencies":
		return "a lockfile changed after the proof was created"
	case "tests":
		return "the test results changed after the proof was created"
	case "environment":
		return "the toolchain or OS changed after the proof was created"
	default:
		return "the underlying source changed after the proof was created"
	}
}

// explainFix recommends the action to take.
func explainFix(id string) string {
	switch id {
	case "artifact":
		return "rebuild the artifact, then regenerate the proof"
	case "git":
		return "checkout the recorded commit and re-verify, or create a new proof"
	case "dependencies":
		return "restore the recorded lockfile, or regenerate the proof"
	case "tests":
		return "re-run the tests, or regenerate the proof"
	case "environment":
		return "use the recorded toolchain, or regenerate the proof"
	default:
		return "investigate the change, then regenerate the proof"
	}
}

func printExplain(w interface{ Write([]byte) (int, error) }, name, status, detail, verdict, cause, fix string) {
	mark := "·"
	switch status {
	case "OK":
		mark = "✓"
	case "FAIL":
		mark = "✗"
	case "SKIPPED":
		mark = "·"
	}
	fmt.Fprintf(w, "%s %s  [%s]\n", mark, name, status)
	if detail != "" {
		fmt.Fprintf(w, "    %s\n", detail)
	}
	if verdict != "" {
		fmt.Fprintf(w, "    %s.\n", verdict)
	}
	if cause != "" {
		fmt.Fprintf(w, "    Likely cause: %s.\n", cause)
	}
	if fix != "" {
		fmt.Fprintf(w, "    Recommended:  %s.\n", fix)
	}
}
