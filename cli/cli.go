// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Package cli implements the proofx command-line interface.
//
//	proofx init     scaffold proofx.yaml
//	proofx collect  gather evidence nodes (evidence.json)
//	proofx prove    bind + sign evidence into proof.json
//	proofx verify   re-verify a proof against the current repo
//	proofx inspect  human-readable dump of a proof
//	proofx keygen   generate a signing key pair
package cli

import (
	"fmt"
	"io"
	"os"
)

// CLI holds the command dispatch and output streams (for testability).
type CLI struct {
	Stdout io.Writer
	Stderr io.Writer
}

// Run executes the full command line.
func Run(args []string) int {
	c := &CLI{Stdout: os.Stdout, Stderr: os.Stderr}
	return c.run(args)
}

// run routes args (excluding the program name).
func (c *CLI) run(args []string) int {
	if len(args) == 0 {
		usage(c.Stderr)
		return 2
	}
	switch args[0] {
	case "init":
		return c.cmdInit(args[1:])
	case "collect":
		return c.cmdCollect(args[1:])
	case "prove":
		return c.cmdProve(args[1:])
	case "verify":
		return c.cmdVerifyV4(args[1:])
	case "inspect":
		return c.cmdInspectGraph(args[1:])
	case "explain":
		return c.cmdExplainV4(args[1:])
	case "claims":
		return c.cmdClaimsV4(args[1:])
	case "diff":
		return c.cmdDiff(args[1:])
	case "graph":
		return c.cmdGraph(args[1:])
	case "keygen":
		return c.cmdKeygen(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(c.Stdout, "proofx %s\n", Version)
		return 0
	case "help", "-h", "--help":
		usage(c.Stdout)
		return 0
	default:
		fmt.Fprintf(c.Stderr, "proofx: unknown command %q\n\n", args[0])
		usage(c.Stderr)
		return 2
	}
}

// Version is the CLI release version (overridden at build time).
var Version = "0.4.0-rc1"

func usage(w io.Writer) {
	fmt.Fprintf(w, `proofx %s — Evidence Infrastructure for Software
Turn "trust me" into "verify it yourself".

Usage:
  proofx <command> [flags]

Commands:
  init       scaffold proofx.yaml in the current directory
  collect    gather evidence nodes into .proofx/evidence.json
  prove      bind + sign evidence into proof.json
  verify     re-verify a proof against the current repository,
             or verify an artifact against a proof (portable):
               proofx verify --artifact <file> [--proof proof.json]
  explain    explain why a proof passes or fails, with likely causes
  diff       compare two proofs evidence-node by evidence-node
  graph      render the Evidence Graph of a proof (--json for the model)
  inspect    print a proof in human-readable form
  keygen     generate an ed25519 signing key pair
  version    print the proofx version
  help       show this help

Examples:
  proofx init
  proofx collect
  proofx prove
  proofx verify proof.json
  proofx verify --artifact myapp-linux-amd64 --proof proof.json
  proofx explain proof.json
  proofx diff proof-v1.json proof-v2.json
  proofx graph --json proof.json
`, Version)
}
