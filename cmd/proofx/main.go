// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>
// Command proofx is the ProofX CLI — Evidence Infrastructure for Software.
//
//	proofx init && proofx collect && proofx prove && proofx verify proof.json
package main

import (
	"os"

	"github.com/EslaM-X/proofx/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
