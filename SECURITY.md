# Security Policy

ProofX is an **evidence infrastructure for software**. It deals with
cryptographic signatures, hashing, artifact integrity and verification —
so this policy matters. Please report any suspected vulnerability.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| v0.4.x  | ✅ Active          |
| v0.3.x  | ⚠️ Maintenance     |
| < v0.3  | ❌ Not supported   |

Only the latest minor release receives security fixes. Please upgrade to the
latest release before reporting.

## Reporting a vulnerability

**Do not open a public issue for security bugs.** Report privately.

- 📧 Email: **eslam.kora60@gmail.com**
- 🔐 Preferred: encrypt if you can; otherwise plain text is acceptable.
- 🐙 If you prefer GitHub-native disclosure, report through the
  [Security Advisory page](https://github.com/EslaM-X/proofx/security/advisories/new)
  (private, visible only to maintainers).

### What to include

A great report makes it dramatically faster to fix:

1. **Summary** — one or two sentences: what breaks, and why it matters.
2. **Affected version** — `proofx version` output.
3. **Severity estimate** — low / moderate / high / critical, if you can.
4. **Reproduction** — minimal steps, files, or a proof JSON that triggers it.
5. **Impact** — what an attacker gains (integrity, availability, ...).
6. **Suggested fix** — optional, but welcome.

### Response times

| Stage          | Target time |
|----------------|-------------|
| Acknowledgment | within 48 hours |
| Triage decision | within 5 business days |
| Fix + release  | depends on severity (critical: as fast as possible) |
| Disclosure     | coordinated with the reporter |

We disclose after a fix ships; we do not hold embargoes indefinitely.

## Private disclosure process

1. Report arrives via email or a Security Advisory.
2. Maintainer acknowledges within 48h and starts triage.
3. We reproduce, confirm impact, and draft a fix **without** public discussion.
4. We release the fix and a GHSA (GitHub Security Advisory) if warranted.
5. We credit the reporter (unless they prefer anonymity).

## Key compromise procedure

ProofX uses ed25519 keys stored in `.proofx/key.pem`. If your signing key is
compromised, or you believe it may be:

1. **Immediately** rotate: `proofx keygen` generates a fresh key pair.
2. Update the public key everywhere it is pinned (CI, badges, docs).
3. Re-produce proofs for every release signed with the old key.
4. **Publicly announce** the compromise and the new key fingerprint so
   consumers can re-verify.
5. Audit for any proof that might have been forged under the old key.

If the ProofX **project's own** signing key is ever compromised, the same
procedure applies to this repository, and this file will document it.

## Proof format security considerations

- `proof.json` is versioned (`proofVersion: "2.0"` for v0.4). The v0.4
  verifier also accepts `"1.0"` proofs via a compatibility layer. Older
  verifiers reject `"2.0"` proofs.
- The **binding root** is a domain-separated SHA-256 Merkle root over
  evidence, relations, and claims. Domain separation labels mean a digest
  produced in one protocol step can never be reused in another.
- Signatures are **ed25519** (RFC 8032) over a commitment digest that
  includes the execution context, binding root, and claims. Verify
  signatures before trusting any content.
- Evidence **digests are not secrets**: they are commitments. Anyone can
  recompute them from the canonical payload — that is the point.

## Signature & key handling

- Private keys are written with `0600` permissions and **must never be
  committed**. `.proofx/key.pem` is in `.gitignore`.
- Public keys are embedded in every proof so verification is self-contained.
- CI-issued proofs use per-repo keys; keep the private key in a secret store.
- Never sign a proof you have not reviewed. Signing is a commitment.

## What ProofX does NOT guarantee

This is important. ProofX verifies that **claims match recorded evidence**.
It does **not** mean the software is "safe", "secure", or "trustworthy".

- ❌ ProofX does not prove the source code is free of vulnerabilities.
- ❌ ProofX does not prove the build was not tampered with by a compromised
  CI runner or maintainer.
- ❌ ProofX does not validate test methodology.
- ❌ ProofX does not protect against a compromised signing key.
- ❌ A "verified" proof is not a security certification.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the precise boundary.

## Security tooling (defense in depth)

CI runs, on every push:

- `go vet ./...`
- `golangci-lint` (govet, staticcheck, errcheck, ineffassign, unused, ...)
- `go test -race -cover ./...`
- property-based tests and fuzzing seeds (`go test ./...`)

Maintainers additionally run `govulncheck` and `gosec` before releases.
Security fixes take priority over feature work.

## Scope

In scope:

- The `proofx` CLI (`cmd/proofx`, `cli/`, `proof/`, `evidence/`, `model/`, `verifycore/`, `config/`).
- The proof format and JSON schema.
- The GitHub Action (`action.yml`).
- The conformance test vectors (`conformance/`).

Out of scope (third-party responsibility):

- The Go standard library, `gopkg.in/yaml.v3`, and any other dependency.
- GitHub Actions infrastructure itself.

## Hall of fame

We will list researchers who report valid security issues here (with consent).

---

_Thanks for helping keep ProofX worthy of the word "evidence"._
