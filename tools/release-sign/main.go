// SPDX-License-Identifier: MIT
// Copyright (c) 2026 EslaM-X <eslam.kora60@gmail.com>

// Command release-sign signs a file with an ed25519 key and prints the
// base64 signature. Used by .github/workflows/release.yml to produce
// checksums.txt.sig for release artifacts.
//
// Usage:
//
//	release-sign <key.pem> <file>
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: release-sign <key.pem> <file>")
		os.Exit(2)
	}
	keyPEM, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read key:", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		fmt.Fprintln(os.Stderr, "decode key: no PEM block")
		os.Exit(1)
	}
	privAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse key:", err)
		os.Exit(1)
	}
	priv, ok := privAny.(ed25519.PrivateKey)
	if !ok {
		fmt.Fprintln(os.Stderr, "key is not ed25519")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, "read file:", err)
		os.Exit(1)
	}
	sig := ed25519.Sign(priv, data)
	fmt.Println(base64.StdEncoding.EncodeToString(sig))
}
